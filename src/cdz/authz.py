"""Offline authorization check for topology transactions.

Mirrors `requiredAuth` in canton v3.5.19 `TopologyMapping.scala` for the mappings this toolkit
uses (NamespaceDelegation, DecentralizedNamespaceDefinition, PartyToParticipant). It tells each
signer what is still missing before anything is sent to a node. Participant approvals cannot be
checked offline (their keys live in the nodes) and are reported separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cdz import crypto
from cdz.topology import (
    CODE_DNS,
    CODE_NSD,
    CODE_P2P,
    PERMISSION_RANK,
    Tx,
    mapping_key,
    restriction_of,
    split_uid,
)
from cdz._proto.com.digitalasset.canton.protocol.v30 import topology_pb2 as tpb

_CODES = {
    "namespace_delegation": CODE_NSD,
    "decentralized_namespace_definition": CODE_DNS,
    "party_to_participant": CODE_P2P,
}


@dataclass
class State:
    """Topology state relevant for authorization (head state of a synchronizer store)."""

    nsds: dict[tuple[str, str], tpb.NamespaceDelegation] = field(default_factory=dict)
    dns: dict[str, tpb.DecentralizedNamespaceDefinition] = field(default_factory=dict)
    p2p: dict[str, tpb.PartyToParticipant] = field(default_factory=dict)
    serials: dict[tuple, int] = field(default_factory=dict)

    def apply(self, tx: Tx) -> None:
        key = mapping_key(tx.mapping)
        self.serials[key] = tx.tx.serial
        kind = tx.kind
        if kind == "namespace_delegation":
            n = tx.mapping.namespace_delegation
            k = (n.namespace, crypto.PublicKey.from_proto(n.target_key).fingerprint)
            self.nsds.pop(k, None) if tx.is_remove else self.nsds.__setitem__(k, n)
        elif kind == "decentralized_namespace_definition":
            d = tx.mapping.decentralized_namespace_definition
            self.dns.pop(d.decentralized_namespace, None) if tx.is_remove else self.dns.__setitem__(
                d.decentralized_namespace, d
            )
        elif kind == "party_to_participant":
            p = tx.mapping.party_to_participant
            self.p2p.pop(p.party, None) if tx.is_remove else self.p2p.__setitem__(p.party, p)

    def expected_serial(self, tx: Tx) -> int:
        return self.serials.get(mapping_key(tx.mapping), 0) + 1

    def keys(self) -> dict[str, crypto.PublicKey]:
        out = {}
        for n in self.nsds.values():
            k = crypto.PublicKey.from_proto(n.target_key)
            out[k.fingerprint] = k
        for p in self.p2p.values():
            for kp in p.party_signing_keys.keys:
                k = crypto.PublicKey.from_proto(kp)
                out[k.fingerprint] = k
        return out


# --- requirement formulas: ("ns", namespace) | ("key", fp) | ("participant", uid) | ("and"|"or", [..])


def _and(*xs):
    xs = [x for x in xs if x is not None]
    return xs[0] if len(xs) == 1 else ("and", xs)


def _or(*xs):
    return ("or", list(xs))


def required(tx: Tx, state: State):
    m = tx.mapping
    kind = tx.kind
    if kind == "namespace_delegation":
        return ("ns", m.namespace_delegation.namespace)
    if kind == "decentralized_namespace_definition":
        d = m.decentralized_namespace_definition
        prev = state.dns.get(d.decentralized_namespace)
        if prev is None:
            return _and(*[("ns", o) for o in sorted(set(d.owners))])
        added = sorted(set(d.owners) - set(prev.owners))
        return _and(("ns", d.decentralized_namespace), *[("ns", o) for o in added])
    if kind == "party_to_participant":
        return _p2p_required(tx, state.p2p.get(m.party_to_participant.party))
    raise ValueError(f"no authorization model for mapping {kind}")


def _p2p_required(tx: Tx, prev: tpb.PartyToParticipant | None):
    cur = tx.mapping.party_to_participant
    party_ns = split_uid(cur.party)[1]
    party = ("ns", party_ns)
    if tx.is_remove:
        return party
    parts = []
    if prev is None or prev.threshold != cur.threshold:
        parts.append(party)
    cur_keys = {crypto.PublicKey.from_proto(k).fingerprint for k in cur.party_signing_keys.keys}
    prev_keys = {crypto.PublicKey.from_proto(k).fingerprint for k in prev.party_signing_keys.keys} if prev else set()
    cur_ks = cur.party_signing_keys if cur.HasField("party_signing_keys") else None
    prev_ks = prev.party_signing_keys if prev is not None and prev.HasField("party_signing_keys") else None
    added_keys = sorted(cur_keys - prev_keys)
    if cur_ks != prev_ks:
        parts.append(_and(party, *[("key", k) for k in added_keys]))
    cur_hosts = {h.participant_uid: h for h in cur.participants}
    prev_hosts = {h.participant_uid: h for h in prev.participants} if prev else {}
    added = [u for u in cur_hosts if u not in prev_hosts]
    if added:
        parts.append(_and(party, *[("participant", u) for u in added]))
    for u in prev_hosts:
        if u not in cur_hosts:
            parts.append(_or(party, ("participant", u)))
    for u, h in cur_hosts.items():
        if u in prev_hosts:
            before, after = PERMISSION_RANK[prev_hosts[u].permission], PERMISSION_RANK[h.permission]
            if after > before:
                parts.append(_and(party, ("participant", u)))
            elif after < before:
                parts.append(_or(party, ("participant", u)))
            was, now = prev_hosts[u].HasField("onboarding"), h.HasField("onboarding")
            if was and not now:
                parts.append(("participant", u))
            elif now and not was:
                parts.append(party)
    if not parts:
        return _and(party, *[("participant", u) for u in added], *[("key", k) for k in added_keys])
    return _and(*parts)


# --- evaluation -----------------------------------------------------------------------------


@dataclass
class Report:
    satisfied: bool
    missing: list[str]  # what our own key holders can still sign
    participants: list[str]  # hosting approvals that only the participant nodes can give
    valid_signers: list[str]
    invalid_signers: list[str]
    unknown_signers: list[str]


class _Ctx:
    def __init__(self, tx: Tx, state: State, sigs, multi, extra_keys: dict, assume_participants: bool):
        self.tx, self.state, self.assume_participants = tx, state, assume_participants
        self.code = _CODES.get(tx.kind)
        keys = dict(state.keys())
        keys.update(extra_keys)
        m = tx.mapping
        if tx.kind == "namespace_delegation":
            k = crypto.PublicKey.from_proto(m.namespace_delegation.target_key)
            keys[k.fingerprint] = k
        if tx.kind == "party_to_participant":
            for kp in m.party_to_participant.party_signing_keys.keys:
                k = crypto.PublicKey.from_proto(kp)
                keys[k.fingerprint] = k
        self.valid, self.invalid, self.unknown = set(), set(), set()
        signed = [(s, tx.hash) for s in sigs]
        for hashes, msigs in multi:
            if tx.hash in hashes:
                combined = crypto.multi_tx_hash(list(hashes))
                signed += [(s, combined) for s in msigs]
        for s, data in signed:
            k = keys.get(s.signed_by)
            if k is None:
                self.unknown.add(s.signed_by)
            elif k.verify(s.signature, data):
                self.valid.add(s.signed_by)
            else:
                self.invalid.add(s.signed_by)
        self.participants: set[str] = set()

    def ns_ok(self, ns: str, missing: list[str]) -> bool:
        dns = self.state.dns.get(ns)
        if dns is not None:
            ok = [o for o in sorted(set(dns.owners)) if self.ns_ok(o, [])]
            if len(ok) >= dns.threshold:
                return True
            need = dns.threshold - len(ok)
            todo = [o for o in sorted(set(dns.owners)) if o not in ok]
            missing.append(f"{need} more of DNS {ns[:12]}… owners {', '.join(o[:12] + '…' for o in todo)}")
            return False
        for fp in self.valid:
            if self._key_authorizes(ns, fp):
                return True
        missing.append(f"namespace {ns[:12]}… (root key {ns[:12]}… or a delegate)")
        return False

    def _key_authorizes(self, ns: str, fp: str) -> bool:
        m = self.tx.mapping
        if self.tx.kind == "namespace_delegation":
            n = m.namespace_delegation
            target = crypto.PublicKey.from_proto(n.target_key).fingerprint
            if n.namespace == ns == fp == target:
                return True  # self-signed root certificate
        if self.tx.kind == "party_to_participant" and fp == ns:
            # self-signed PTP: the party's namespace key is one of its signing keys
            if any(crypto.PublicKey.from_proto(k).fingerprint == ns for k in m.party_to_participant.party_signing_keys.keys):
                return True
        nsd = self.state.nsds.get((ns, fp))
        if nsd is None:
            return False
        r = restriction_of(nsd)
        if r == "all":
            return True
        if r == "all-but-nsd":
            return self.code != CODE_NSD
        return self.code is not None and self.code in nsd.can_sign_specific_mapings.mappings

    def eval(self, f, missing: list[str]) -> bool:
        tag = f[0]
        if tag == "and":
            res = [self.eval(x, missing) for x in f[1]]
            return all(res)
        if tag == "or":
            tmp: list[str] = []
            for x in f[1]:
                if self.eval(x, tmp):
                    return True
            missing.append("one of: " + " | ".join(tmp))
            return False
        if tag == "ns":
            return self.ns_ok(f[1], missing)
        if tag == "key":
            if f[1] in self.valid:
                return True
            missing.append(f"signing key {f[1][:12]}… (proof of possession)")
            return False
        if tag == "participant":
            self.participants.add(f[1])
            return self.assume_participants
        raise ValueError(f)


def check(
    tx: Tx,
    sigs: list[crypto.Sig],
    state: State,
    multi: list[tuple[list[bytes], list[crypto.Sig]]] = (),
    extra_keys: dict[str, crypto.PublicKey] | None = None,
    assume_participants: bool = True,
) -> Report:
    """Evaluate the signatures on `tx` against Canton's rules, given the state before `tx`.

    With `assume_participants` (default), hosting participants are assumed to approve on their
    side (AllocateExternalParty on each node, or an explicit authorize by the node operator)."""
    ctx = _Ctx(tx, state, sigs, multi, extra_keys or {}, assume_participants)
    missing: list[str] = []
    ok = ctx.eval(required(tx, state), missing)
    return Report(
        satisfied=ok,
        missing=missing,
        participants=sorted(ctx.participants),
        valid_signers=sorted(ctx.valid),
        invalid_signers=sorted(ctx.invalid),
        unknown_signers=sorted(ctx.unknown),
    )


def relevant_signers(tx: Tx, state: State) -> set[str]:
    """Fingerprints whose signature can contribute to `tx` (namespace owners/delegates, new keys)."""
    out: set[str] = set()

    def ns_keys(ns: str):
        d = state.dns.get(ns)
        if d is not None:
            for o in d.owners:
                ns_keys(o)
            return
        out.add(ns)
        for (n, fp), _ in state.nsds.items():
            if n == ns:
                out.add(fp)

    def walk(f):
        if f[0] in ("and", "or"):
            for x in f[1]:
                walk(x)
        elif f[0] == "ns":
            ns_keys(f[1])
        elif f[0] == "key":
            out.add(f[1])

    walk(required(tx, state))
    return out
