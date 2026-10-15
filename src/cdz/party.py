"""Party definition file (party.json): public keys, thresholds and hosts. Contains no secrets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cdz import crypto, topology
from cdz.topology import Tx


@dataclass
class Member:
    name: str
    key: crypto.PublicKey

    def to_json(self) -> dict:
        return {"name": self.name, **self.key.to_json()}

    @classmethod
    def from_json(cls, d: dict) -> "Member":
        return cls(d.get("name", ""), crypto.PublicKey.from_json(d))


@dataclass
class PartySpec:
    hint: str
    owners: list[Member]
    dns_threshold: int
    signing_keys: list[Member]
    signing_threshold: int
    hosts: list[tuple[str, str]]  # (participant uid, permission)
    confirmation_threshold: int
    network: str = "devnet"
    namespace: str = ""  # fixed at creation; owners may change later, the namespace does not
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.namespace:
            self.namespace = crypto.dns_namespace([m.key.fingerprint for m in self.owners])
        self.hosts = [(topology.participant_uid(u), p) for u, p in self.hosts]

    @property
    def party_id(self) -> str:
        return topology.party_id(self.hint, self.namespace)

    @property
    def owner_namespaces(self) -> list[str]:
        return sorted(m.key.fingerprint for m in self.owners)

    def dns_mapping(self):
        return topology.decentralized_namespace(self.owner_namespaces, self.dns_threshold, self.namespace)

    def p2p_mapping(self):
        return topology.party_to_participant(
            self.party_id,
            self.confirmation_threshold,
            self.hosts,
            [m.key for m in self.signing_keys],
            self.signing_threshold,
        )

    def onboarding_txs(self, skip_owner_nsds: set[str] = frozenset()) -> list[tuple[str, Tx]]:
        """Root NSD per owner, then the DNS, then the PartyToParticipant (all serial 1)."""
        if self.namespace != crypto.dns_namespace(self.owner_namespaces):
            raise topology.TopologyError("party namespace does not derive from the current owners (not a new party?)")
        out = []
        for m in sorted(self.owners, key=lambda m: m.key.fingerprint):
            if m.key.fingerprint not in skip_owner_nsds:
                out.append((f"nsd:{m.name}", Tx.build(topology.root_namespace_delegation(m.key), 1)))
        out.append(("dns", Tx.build(self.dns_mapping(), 1)))
        out.append(("p2p", Tx.build(self.p2p_mapping(), 1)))
        return out

    def known_keys(self) -> dict[str, crypto.PublicKey]:
        return {m.key.fingerprint: m.key for m in self.owners + self.signing_keys}

    def member_name(self, fingerprint: str) -> str:
        for m in self.owners + self.signing_keys:
            if m.key.fingerprint == fingerprint:
                return m.name
        return fingerprint[:12] + "…"

    def to_json(self) -> dict:
        return {
            "network": self.network,
            "party_hint": self.hint,
            "party_id": self.party_id,
            "namespace": {
                "id": self.namespace,
                "threshold": self.dns_threshold,
                "owners": [m.to_json() for m in self.owners],
            },
            "signing": {"threshold": self.signing_threshold, "keys": [m.to_json() for m in self.signing_keys]},
            "hosting": {
                "threshold": self.confirmation_threshold,
                "participants": [{"uid": u, "permission": p} for u, p in self.hosts],
            },
            **({"extra": self.extra} if self.extra else {}),
        }

    @classmethod
    def from_json(cls, d: dict) -> "PartySpec":
        spec = cls(
            hint=d["party_hint"],
            owners=[Member.from_json(x) for x in d["namespace"]["owners"]],
            dns_threshold=int(d["namespace"]["threshold"]),
            signing_keys=[Member.from_json(x) for x in d["signing"]["keys"]],
            signing_threshold=int(d["signing"]["threshold"]),
            hosts=[(h["uid"], h.get("permission", "confirmation")) for h in d["hosting"]["participants"]],
            confirmation_threshold=int(d["hosting"]["threshold"]),
            network=d.get("network", "devnet"),
            namespace=d["namespace"].get("id", ""),
            extra=d.get("extra", {}),
        )
        if d.get("party_id") and d["party_id"] != spec.party_id:
            raise topology.TopologyError(f"party_id {d['party_id']} does not match hint/namespace ({spec.party_id})")
        return spec

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), indent=2) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> "PartySpec":
        return cls.from_json(json.loads(Path(path).read_text()))
