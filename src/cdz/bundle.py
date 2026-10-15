"""Signing bundles: JSON files passed between offline signers.

A bundle carries the exact bytes to be signed. Every reader recomputes hashes from those bytes;
stored hashes are only compared, never trusted. Two kinds:
- topology: serialized topology transactions (+ the base state they apply to),
- submission: a PreparedTransaction from interactive submission.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from cdz import authz, crypto, prepared, topology
from cdz.topology import Tx

FORMAT = "cdz-bundle/1"


class BundleError(ValueError):
    pass


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Item:
    label: str
    tx: Tx
    sigs: list[crypto.Sig] = field(default_factory=list)


@dataclass
class TopologyBundle:
    network: str
    synchronizer_id: str | None
    description: str
    items: list[Item]
    base: list[Tx] = field(default_factory=list)  # head mappings the items apply to (unsigned copies)
    multi: list[tuple[list[bytes], list[crypto.Sig]]] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    kind = "topology"

    # --- state / checks -------------------------------------------------------------------

    def state_before(self, index: int) -> authz.State:
        st = authz.State()
        for t in self.base:
            st.apply(t)
        for it in self.items[:index]:
            st.apply(it.tx)
        return st

    def multi_for(self, tx: Tx):
        return [(h, s) for h, s in self.multi if tx.hash in h]

    def check(self, extra_keys=None, assume_participants: bool = True) -> list[tuple[Item, authz.Report, int]]:
        out = []
        for i, it in enumerate(self.items):
            st = self.state_before(i)
            rep = authz.check(it.tx, it.sigs, st, self.multi_for(it.tx), extra_keys, assume_participants)
            out.append((it, rep, st.expected_serial(it.tx)))
        return out

    def relevant(self, fingerprint: str) -> list[int]:
        return [i for i, it in enumerate(self.items) if fingerprint in authz.relevant_signers(it.tx, self.state_before(i))]

    # --- signing --------------------------------------------------------------------------

    def sign(self, keys: list[crypto.SigningKey], use_multi: bool = False) -> list[str]:
        """Sign every item a key can contribute to. With `use_multi`, each relevant key signs the
        combined hash of ALL items once (what AllocateExternalParty's multiHashSignatures expects)."""
        done = []
        all_hashes = [it.tx.hash for it in self.items]
        for k in keys:
            idx = self.relevant(k.fingerprint)
            if not idx:
                continue
            if use_multi:
                if any(sorted(h) == sorted(all_hashes) and any(s.signed_by == k.fingerprint for s in ss) for h, ss in self.multi):
                    continue
                self.multi.append((all_hashes, [k.signature(crypto.multi_tx_hash(all_hashes))]))
                done.append(f"multi[all {len(all_hashes)}] <- {k.name or k.fingerprint[:12]}")
                continue
            for i in idx:
                it = self.items[i]
                if any(s.signed_by == k.fingerprint for s in it.sigs):
                    continue
                it.sigs.append(k.signature(it.tx.hash))
                done.append(f"{it.label} <- {k.name or k.fingerprint[:12]}")
        return done

    def multi_over_all(self) -> list[crypto.Sig]:
        all_hashes = sorted(it.tx.hash for it in self.items)
        return [s for h, ss in self.multi if sorted(h) == all_hashes for s in ss]

    def merge(self, other: "TopologyBundle") -> int:
        if [it.tx.serialized for it in self.items] != [it.tx.serialized for it in other.items]:
            raise BundleError("bundles contain different transactions")
        added = 0
        for a, b in zip(self.items, other.items):
            have = {(s.signed_by, s.signature) for s in a.sigs}
            for s in b.sigs:
                if (s.signed_by, s.signature) not in have:
                    a.sigs.append(s)
                    added += 1
        for h, s in other.multi:
            if (h, s) not in self.multi:
                self.multi.append((h, s))
                added += len(s)
        return added

    def signed_transactions(self, proposal: bool = False):
        return [topology.signed_tx(it.tx, it.sigs, proposal, self.multi_for(it.tx)) for it in self.items]

    # --- json -----------------------------------------------------------------------------

    def to_json(self) -> dict:
        return {
            "format": FORMAT,
            "kind": self.kind,
            "network": self.network,
            "synchronizer_id": self.synchronizer_id,
            "description": self.description,
            "created_at": self.created_at,
            "meta": self.meta,
            "base_state": [{"serialized": crypto.b64(t.serialized), "describe": t.describe()} for t in self.base],
            "transactions": [
                {
                    "label": it.label,
                    "serialized": crypto.b64(it.tx.serialized),
                    "hash": it.tx.hash.hex(),
                    "describe": it.tx.describe(),
                    "signatures": [s.to_json() for s in it.sigs],
                }
                for it in self.items
            ],
            "multi_signatures": [
                {"hashes": [h.hex() for h in hs], "signatures": [s.to_json() for s in ss]} for hs, ss in self.multi
            ],
        }

    @classmethod
    def from_json(cls, d: dict) -> "TopologyBundle":
        _check_header(d, "topology")
        items = []
        for t in d["transactions"]:
            tx = Tx(crypto.unb64(t["serialized"]))
            if t.get("hash") and t["hash"] != tx.hash.hex():
                raise BundleError(f"{t.get('label')}: stored hash does not match the transaction bytes")
            items.append(Item(t.get("label", ""), tx, [crypto.Sig.from_json(s) for s in t.get("signatures", [])]))
        multi = [
            ([bytes.fromhex(h) for h in m["hashes"]], [crypto.Sig.from_json(s) for s in m["signatures"]])
            for m in d.get("multi_signatures", [])
        ]
        return cls(
            network=d.get("network", ""),
            synchronizer_id=d.get("synchronizer_id"),
            description=d.get("description", ""),
            items=items,
            base=[Tx(crypto.unb64(b["serialized"])) for b in d.get("base_state", [])],
            multi=multi,
            meta=d.get("meta", {}),
            created_at=d.get("created_at", ""),
        )


@dataclass
class SubmissionBundle:
    network: str
    synchronizer_id: str | None
    party: str
    prepared_b64: str
    scheme: int
    node_hash: bytes
    intent: dict
    signing_keys: list[crypto.PublicKey]
    signing_threshold: int
    description: str = ""
    sigs: list[crypto.Sig] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    kind = "submission"

    @property
    def prepared(self):
        return prepared.decode(self.prepared_b64)

    def verify(self, synchronizer_id: str | None = None) -> bytes:
        """Recompute the hash, require it to match the node's, check act_as/roots/intent."""
        return prepared.check(
            self.prepared, self.scheme, self.node_hash, self.party, self.intent, synchronizer_id or self.synchronizer_id
        )

    def sign(self, keys: list[crypto.SigningKey]) -> list[str]:
        h = self.verify()
        registered = {k.fingerprint for k in self.signing_keys}
        done = []
        for k in keys:
            if k.fingerprint not in registered or any(s.signed_by == k.fingerprint for s in self.sigs):
                continue
            self.sigs.append(k.signature(h))
            done.append(k.name or k.fingerprint[:12])
        return done

    def valid_signatures(self) -> list[crypto.Sig]:
        h = self.verify()
        by_fp = {k.fingerprint: k for k in self.signing_keys}
        out, seen = [], set()
        for s in self.sigs:
            k = by_fp.get(s.signed_by)
            if k and s.signed_by not in seen and k.verify(s.signature, h):
                out.append(s)
                seen.add(s.signed_by)
        return out

    def merge(self, other: "SubmissionBundle") -> int:
        if other.prepared_b64 != self.prepared_b64:
            raise BundleError("bundles contain different prepared transactions")
        have = {(s.signed_by, s.signature) for s in self.sigs}
        new = [s for s in other.sigs if (s.signed_by, s.signature) not in have]
        self.sigs.extend(new)
        return len(new)

    def to_json(self) -> dict:
        return {
            "format": FORMAT,
            "kind": self.kind,
            "network": self.network,
            "synchronizer_id": self.synchronizer_id,
            "description": self.description,
            "created_at": self.created_at,
            "meta": self.meta,
            "party": self.party,
            "intent": self.intent,
            "hashing_scheme_version": prepared.SCHEME_NAMES[self.scheme],
            "hash": self.node_hash.hex(),
            "summary": prepared.summarize(self.prepared),
            "signing": {"threshold": self.signing_threshold, "keys": [k.to_json() for k in self.signing_keys]},
            "prepared_transaction": self.prepared_b64,
            "signatures": [s.to_json() for s in self.sigs],
        }

    @classmethod
    def from_json(cls, d: dict) -> "SubmissionBundle":
        _check_header(d, "submission")
        return cls(
            network=d.get("network", ""),
            synchronizer_id=d.get("synchronizer_id"),
            party=d["party"],
            prepared_b64=d["prepared_transaction"],
            scheme=prepared.scheme_of(d["hashing_scheme_version"]),
            node_hash=bytes.fromhex(d["hash"]),
            intent=d.get("intent") or {},
            signing_keys=[crypto.PublicKey.from_json(k) for k in d["signing"]["keys"]],
            signing_threshold=int(d["signing"]["threshold"]),
            description=d.get("description", ""),
            sigs=[crypto.Sig.from_json(s) for s in d.get("signatures", [])],
            meta=d.get("meta", {}),
            created_at=d.get("created_at", ""),
        )


def _check_header(d: dict, kind: str) -> None:
    if d.get("format") != FORMAT:
        raise BundleError(f"not a {FORMAT} file")
    if d.get("kind") != kind:
        raise BundleError(f"expected a {kind} bundle, got {d.get('kind')}")


def load(path: str | Path):
    d = json.loads(Path(path).read_text())
    if d.get("kind") == "topology":
        return TopologyBundle.from_json(d)
    if d.get("kind") == "submission":
        return SubmissionBundle.from_json(d)
    raise BundleError(f"{path}: unknown bundle kind {d.get('kind')}")


def save(b, path: str | Path) -> None:
    Path(path).write_text(json.dumps(b.to_json(), indent=2) + "\n")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s)
