"""Plan topology changes for an existing party as signing bundles (DNS, signing keys, hosting)."""

from __future__ import annotations

from cdz import authz, crypto, topology
from cdz.bundle import Item, TopologyBundle
from cdz.topology import Tx
from cdz._proto.com.digitalasset.canton.protocol.v30 import topology_pb2 as tpb


class PlanError(ValueError):
    pass


def _base_txs(state: authz.State, keys: list[tuple]) -> list[Tx]:
    out = []
    for k in keys:
        kind = k[0]
        serial = state.serials.get(k)
        if serial is None:
            continue
        if kind == "decentralized_namespace_definition":
            m = tpb.TopologyMapping(decentralized_namespace_definition=state.dns[k[1]])
        elif kind == "party_to_participant":
            m = tpb.TopologyMapping(party_to_participant=state.p2p[k[1]])
        elif kind == "namespace_delegation":
            m = tpb.TopologyMapping(namespace_delegation=state.nsds[(k[1], k[2])])
        else:
            continue
        out.append(Tx.build(m, serial))
    return out


def _dns_base(state: authz.State, ns: str) -> list[tuple]:
    keys = [("decentralized_namespace_definition", ns)]
    d = state.dns.get(ns)
    for o in d.owners if d else ():
        keys += [k for k in state.serials if k[0] == "namespace_delegation" and k[1] == o]
    return keys


def _current_p2p(state: authz.State, party: str) -> tpb.PartyToParticipant:
    p = state.p2p.get(party)
    if p is None:
        raise PlanError(f"no active PartyToParticipant for {party}")
    return p


def _serial(state: authz.State, key: tuple) -> int:
    return state.serials.get(key, 0) + 1


def _diff(before: dict, after: dict) -> dict:
    return {k: {"from": before.get(k), "to": after.get(k)} for k in set(before) | set(after) if before.get(k) != after.get(k)}


def plan_party_change(
    state: authz.State,
    party: str,
    network: str,
    synchronizer_id: str | None,
    add_keys: list[crypto.PublicKey] = (),
    remove_keys: list[str] = (),
    signing_threshold: int | None = None,
    add_hosts: list[tuple[str, str]] = (),
    remove_hosts: list[str] = (),
    confirmation_threshold: int | None = None,
    onboarding: bool = True,
) -> TopologyBundle:
    """One new PartyToParticipant serial covering key, threshold and hosting changes."""
    prev = _current_p2p(state, party)
    keys = {crypto.PublicKey.from_proto(k).fingerprint: crypto.PublicKey.from_proto(k) for k in prev.party_signing_keys.keys}
    for fp in remove_keys:
        if fp not in keys:
            raise PlanError(f"signing key {fp} is not registered")
        del keys[fp]
    for k in add_keys:
        keys[k.fingerprint] = k
    if not keys:
        raise PlanError("an external party needs at least one signing key")
    hosts = [(h.participant_uid, topology.PERMISSION_NAMES[h.permission]) for h in prev.participants]
    onboarding_now = {h.participant_uid for h in prev.participants if h.HasField("onboarding")}
    gone = {topology.participant_uid(u) for u in remove_hosts}
    if not gone <= {u for u, _ in hosts}:
        raise PlanError(f"not a current host: {sorted(gone - {u for u, _ in hosts})}")
    hosts = [(u, p) for u, p in hosts if u not in gone]
    for uid, perm in add_hosts:
        uid = topology.participant_uid(uid)
        if any(u == uid for u, _ in hosts):
            hosts = [(u, perm if u == uid else p) for u, p in hosts]  # permission change
        else:
            hosts.append((uid, perm))
            if onboarding:
                onboarding_now.add(uid)
    mapping = topology.party_to_participant(
        party,
        confirmation_threshold or prev.threshold,
        hosts,
        list(keys.values()),
        signing_threshold or prev.party_signing_keys.threshold,
        onboarding=onboarding_now - gone,
    )
    key = ("party_to_participant", party)
    tx = Tx.build(mapping, _serial(state, key))
    base_keys = [key] + _dns_base(state, party.split("::")[1])
    before = topology.describe_mapping(tpb.TopologyMapping(party_to_participant=prev))
    after = topology.describe_mapping(mapping)
    return TopologyBundle(
        network,
        synchronizer_id,
        f"Update PartyToParticipant of {party}",
        [Item("p2p", tx)],
        base=_base_txs(state, base_keys),
        meta={"party_id": party, "operation": "party-update", "diff": _diff(before, after)},
    )


def plan_clear_onboarding(state: authz.State, party: str, participant: str, network: str, synchronizer_id: str | None):
    """After the ACS import the new host clears its own onboarding flag (needs only that participant)."""
    prev = _current_p2p(state, party)
    uid = topology.participant_uid(participant)
    if not any(h.participant_uid == uid and h.HasField("onboarding") for h in prev.participants):
        raise PlanError(f"{uid} has no onboarding flag on {party}")
    m = tpb.PartyToParticipant()
    m.CopyFrom(prev)
    for h in m.participants:
        if h.participant_uid == uid:
            h.ClearField("onboarding")
    key = ("party_to_participant", party)
    tx = Tx.build(tpb.TopologyMapping(party_to_participant=m), _serial(state, key))
    return TopologyBundle(
        network, synchronizer_id, f"Clear onboarding flag of {uid}", [Item("p2p", tx)],
        base=_base_txs(state, [key]), meta={"party_id": party, "operation": "clear-onboarding"},
    )


def plan_dns_change(
    state: authz.State,
    namespace: str,
    network: str,
    synchronizer_id: str | None,
    add_owners: list[crypto.PublicKey] = (),
    remove_owners: list[str] = (),
    threshold: int | None = None,
) -> TopologyBundle:
    """New DNS serial (+ root NSDs for new owner keys that have none yet)."""
    prev = state.dns.get(namespace)
    if prev is None:
        raise PlanError(f"no DecentralizedNamespaceDefinition {namespace}")
    owners = set(prev.owners) - set(remove_owners)
    if set(remove_owners) - set(prev.owners):
        raise PlanError(f"not an owner: {sorted(set(remove_owners) - set(prev.owners))}")
    items = []
    for k in add_owners:
        owners.add(k.fingerprint)
        if (k.fingerprint, k.fingerprint) not in state.nsds:
            items.append(Item(f"nsd:{k.fingerprint[:12]}", Tx.build(topology.root_namespace_delegation(k), 1)))
    t = threshold or prev.threshold
    if t > len(owners):
        raise PlanError(f"threshold {t} exceeds {len(owners)} owners")
    key = ("decentralized_namespace_definition", namespace)
    dns = Tx.build(topology.decentralized_namespace(sorted(owners), t, namespace), _serial(state, key))
    items.append(Item("dns", dns))
    before = topology.describe_mapping(tpb.TopologyMapping(decentralized_namespace_definition=prev))
    after = dns.describe()
    after.pop("namespace_derived_from_owners", None)
    before.pop("namespace_derived_from_owners", None)
    return TopologyBundle(
        network, synchronizer_id, f"Update decentralized namespace {namespace[:16]}…", items,
        base=_base_txs(state, _dns_base(state, namespace)),
        meta={"namespace": namespace, "operation": "dns-update",
              "diff": {k: v for k, v in _diff(before, after).items() if k not in ("op", "serial", "hash")}},
    )
