"""Topology mappings and transactions (protocol v30), built and hashed locally.

The serialized form is `UntypedVersionedMessage{data=TopologyTransaction, version=30}`; the hash
that gets signed is `canton_hash(11, serialized)` (see docs: external-signing-topology, steps 5-7).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from cdz import crypto
from cdz._proto.com.digitalasset.canton.crypto.v30 import crypto_pb2 as cpb
from cdz._proto.com.digitalasset.canton.protocol.v30 import topology_pb2 as tpb
from cdz._proto.com.digitalasset.canton.version.v1 import untyped_versioned_message_pb2 as uvm

TX_PROTO_VERSION = 30  # topology transaction protobuf version for protocol versions 34 and 35
MAX_SIGNING_KEYS = 20  # KeyMapping.MaxKeys

ADD_REPLACE = tpb.Enums.TOPOLOGY_CHANGE_OP_ADD_REPLACE
REMOVE = tpb.Enums.TOPOLOGY_CHANGE_OP_REMOVE

PERMISSIONS = {
    "submission": tpb.Enums.PARTICIPANT_PERMISSION_SUBMISSION,
    "confirmation": tpb.Enums.PARTICIPANT_PERMISSION_CONFIRMATION,
    "observation": tpb.Enums.PARTICIPANT_PERMISSION_OBSERVATION,
}
PERMISSION_NAMES = {v: k for k, v in PERMISSIONS.items()}
# Canton orders permissions Submission > Confirmation > Observation (an "upgrade" goes up).
PERMISSION_RANK = {PERMISSIONS["observation"]: 1, PERMISSIONS["confirmation"]: 2, PERMISSIONS["submission"]: 3}

USAGE_NAMESPACE = cpb.SIGNING_KEY_USAGE_NAMESPACE
USAGE_PROTOCOL = cpb.SIGNING_KEY_USAGE_PROTOCOL
# Canton normalizes party signing keys to PROTOCOL + PROOF_OF_OWNERSHIP (seen in GenerateTransactions).
PARTY_KEY_USAGE = [cpb.SIGNING_KEY_USAGE_PROTOCOL, cpb.SIGNING_KEY_USAGE_PROOF_OF_OWNERSHIP]

CODE_NSD = tpb.Enums.TOPOLOGY_MAPPING_CODE_NAMESPACE_DELEGATION
CODE_DNS = tpb.Enums.TOPOLOGY_MAPPING_CODE_DECENTRALIZED_NAMESPACE_DEFINITION
CODE_P2P = tpb.Enums.TOPOLOGY_MAPPING_CODE_PARTY_TO_PARTICIPANT


class TopologyError(ValueError):
    pass


# --- identifiers ----------------------------------------------------------------------------


def split_uid(uid: str) -> tuple[str, str]:
    """`name::1220…` -> (name, namespace). Accepts member ids such as `PAR::name::1220…`."""
    parts = uid.split("::")
    if len(parts) == 3 and parts[0] in ("PAR", "MED", "SEQ"):
        parts = parts[1:]
    if len(parts) != 2 or not parts[0] or not is_fingerprint(parts[1]):
        raise TopologyError(f"not a unique identifier: {uid!r}")
    return parts[0], parts[1]


def participant_uid(value: str) -> str:
    name, ns = split_uid(value)
    return f"{name}::{ns}"


def is_fingerprint(value: str) -> bool:
    if len(value) != 68 or not value.startswith("1220"):
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def party_id(hint: str, namespace: str) -> str:
    if "::" in hint or not hint:
        raise TopologyError(f"invalid party hint {hint!r}")
    return f"{hint}::{namespace}"


# --- mappings -------------------------------------------------------------------------------


def root_namespace_delegation(key: crypto.PublicKey) -> tpb.TopologyMapping:
    """Self-signed root certificate for the namespace `key.fingerprint` (is_root_delegation is
    deprecated; Canton itself serializes root delegations as is_root=false + can_sign_all_mappings)."""
    return namespace_delegation(key.fingerprint, key, "all")


def namespace_delegation(namespace: str, target: crypto.PublicKey, restriction="all") -> tpb.TopologyMapping:
    nsd = tpb.NamespaceDelegation(
        namespace=namespace, target_key=target.to_proto([USAGE_NAMESPACE]), is_root_delegation=False
    )
    if restriction == "all":
        nsd.can_sign_all_mappings.SetInParent()
    elif restriction == "all-but-nsd":
        nsd.can_sign_all_but_namespace_delegations.SetInParent()
    else:
        nsd.can_sign_specific_mapings.mappings.extend(restriction)
    return tpb.TopologyMapping(namespace_delegation=nsd)


def decentralized_namespace(owners: list[str], threshold: int, namespace: str | None = None) -> tpb.TopologyMapping:
    owners = sorted(set(owners))
    if not owners:
        raise TopologyError("a decentralized namespace needs at least one owner")
    if not 1 <= threshold <= len(owners):
        raise TopologyError(f"DNS threshold {threshold} out of range 1..{len(owners)}")
    for o in owners:
        if not is_fingerprint(o):
            raise TopologyError(f"owner is not a namespace fingerprint: {o}")
    ns = namespace or crypto.dns_namespace(owners)
    return tpb.TopologyMapping(
        decentralized_namespace_definition=tpb.DecentralizedNamespaceDefinition(
            decentralized_namespace=ns, threshold=threshold, owners=owners
        )
    )


def party_to_participant(
    party: str,
    threshold: int,
    hosts: list[tuple[str, str]],
    signing_keys: list[crypto.PublicKey] | None,
    signing_threshold: int | None,
    onboarding: set[str] | None = None,
) -> tpb.TopologyMapping:
    """`hosts`: [(participant uid, permission name)]. External parties use confirmation/observation."""
    onboarding = onboarding or set()
    p2p = tpb.PartyToParticipant(party=party, threshold=threshold)
    for uid, perm in hosts:
        hp = p2p.participants.add(participant_uid=participant_uid(uid), permission=PERMISSIONS[perm])
        if participant_uid(uid) in onboarding:
            hp.onboarding.SetInParent()
    if signing_keys:
        p2p.party_signing_keys.threshold = signing_threshold or 1
        # Canton serializes the key set sorted by fingerprint (SigningKeysWithThreshold.toProtoV30)
        keys = sorted(set(signing_keys), key=lambda k: k.fingerprint)
        p2p.party_signing_keys.keys.extend(k.to_proto(PARTY_KEY_USAGE) for k in keys)
    mapping = tpb.TopologyMapping(party_to_participant=p2p)
    validate_mapping(mapping)
    return mapping


def validate_mapping(mapping: tpb.TopologyMapping) -> None:
    """Client-side sanity checks mirroring Canton's (PartyToParticipant.create, topology.proto)."""
    kind = mapping.WhichOneof("mapping")
    if kind == "party_to_participant":
        p = mapping.party_to_participant
        split_uid(p.party)
        if p.threshold < 1:
            raise TopologyError("confirmation threshold must be >= 1")
        uids = [h.participant_uid for h in p.participants]
        if len(set(uids)) != len(uids):
            raise TopologyError("a participant is listed twice")
        perms = [h.permission for h in p.participants]
        if p.threshold > 1 and PERMISSIONS["submission"] in perms:
            raise TopologyError("threshold > 1 requires Confirmation/Observation hosts (no Submission)")
        confirming = sum(1 for x in perms if x in (PERMISSIONS["submission"], PERMISSIONS["confirmation"]))
        if confirming and p.threshold > confirming:
            raise TopologyError(f"threshold {p.threshold} exceeds the {confirming} confirming hosts")
        if p.HasField("party_signing_keys"):
            ks = p.party_signing_keys
            if not 1 <= len(ks.keys) <= MAX_SIGNING_KEYS:
                raise TopologyError(f"party signing keys must be 1..{MAX_SIGNING_KEYS}")
            if not 1 <= ks.threshold <= len(ks.keys):
                raise TopologyError(f"signing threshold {ks.threshold} out of range 1..{len(ks.keys)}")
            fps = [crypto.PublicKey.from_proto(k).fingerprint for k in ks.keys]
            if len(set(fps)) != len(fps):
                raise TopologyError("duplicate party signing key")
            for k in ks.keys:
                if USAGE_PROTOCOL not in k.usage:
                    raise TopologyError("party signing keys need PROTOCOL usage")
    elif kind == "decentralized_namespace_definition":
        d = mapping.decentralized_namespace_definition
        if not 1 <= d.threshold <= len(set(d.owners)):
            raise TopologyError("DNS threshold out of range")


# --- transactions ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tx:
    """A serialized (versioned) topology transaction; the bytes are the source of truth."""

    serialized: bytes

    @classmethod
    def build(cls, mapping: tpb.TopologyMapping, serial: int, op: int = ADD_REPLACE) -> "Tx":
        if serial < 1:
            raise TopologyError("serial starts at 1")
        tx = tpb.TopologyTransaction(operation=op, serial=serial, mapping=mapping)
        return cls(uvm.UntypedVersionedMessage(data=tx.SerializeToString(), version=TX_PROTO_VERSION).SerializeToString())

    @cached_property
    def tx(self) -> tpb.TopologyTransaction:
        msg = uvm.UntypedVersionedMessage.FromString(self.serialized)
        if msg.version != TX_PROTO_VERSION:
            raise TopologyError(f"unsupported topology transaction version {msg.version}")
        return tpb.TopologyTransaction.FromString(msg.data)

    @cached_property
    def hash(self) -> bytes:
        return crypto.topology_tx_hash(self.serialized)

    @property
    def mapping(self) -> tpb.TopologyMapping:
        return self.tx.mapping

    @property
    def kind(self) -> str:
        return self.tx.mapping.WhichOneof("mapping") or "unknown"

    @property
    def is_remove(self) -> bool:
        return self.tx.operation == REMOVE

    def unique_key(self) -> tuple:
        return mapping_key(self.mapping)

    def canonical(self) -> bytes:
        """Re-serialization of the decoded content (to detect non-canonical encodings)."""
        return Tx.build(self.mapping, self.tx.serial, self.tx.operation).serialized

    def describe(self) -> dict:
        d = {"op": "REMOVE" if self.is_remove else "ADD_REPLACE", "serial": self.tx.serial, "hash": self.hash.hex()}
        d.update(describe_mapping(self.mapping))
        return d


def mapping_key(m: tpb.TopologyMapping) -> tuple:
    kind = m.WhichOneof("mapping")
    if kind == "namespace_delegation":
        n = m.namespace_delegation
        return (kind, n.namespace, crypto.PublicKey.from_proto(n.target_key).fingerprint)
    if kind == "decentralized_namespace_definition":
        return (kind, m.decentralized_namespace_definition.decentralized_namespace)
    if kind == "party_to_participant":
        return (kind, m.party_to_participant.party)
    if kind == "party_to_key_mapping":
        return (kind, m.party_to_key_mapping.party)
    return (kind,)


def restriction_of(n: tpb.NamespaceDelegation):
    r = n.WhichOneof("restriction")
    if r == "can_sign_all_mappings" or (r is None and n.is_root_delegation):
        return "all"
    if r == "can_sign_all_but_namespace_delegations" or r is None:
        return "all-but-nsd"
    return [tpb.Enums.TopologyMappingCode.Name(c) for c in n.can_sign_specific_mapings.mappings]


def describe_mapping(m: tpb.TopologyMapping) -> dict:
    kind = m.WhichOneof("mapping")
    if kind == "namespace_delegation":
        n = m.namespace_delegation
        target = crypto.PublicKey.from_proto(n.target_key).fingerprint
        return {
            "mapping": "NamespaceDelegation",
            "namespace": n.namespace,
            "target_key": target,
            "target_spec": crypto.spec_for_proto(n.target_key.key_spec).name,
            "root": target == n.namespace,
            "restriction": restriction_of(n),
        }
    if kind == "decentralized_namespace_definition":
        d = m.decentralized_namespace_definition
        return {
            "mapping": "DecentralizedNamespaceDefinition",
            "namespace": d.decentralized_namespace,
            "threshold": d.threshold,
            "owners": list(d.owners),
            "namespace_derived_from_owners": d.decentralized_namespace == crypto.dns_namespace(list(d.owners)),
        }
    if kind == "party_to_participant":
        p = m.party_to_participant
        out = {
            "mapping": "PartyToParticipant",
            "party": p.party,
            "confirmation_threshold": p.threshold,
            "hosts": [
                {
                    "participant": h.participant_uid,
                    "permission": PERMISSION_NAMES.get(h.permission, str(h.permission)),
                    **({"onboarding": True} if h.HasField("onboarding") else {}),
                }
                for h in p.participants
            ],
        }
        if p.HasField("party_signing_keys"):
            out["signing_threshold"] = p.party_signing_keys.threshold
            out["signing_keys"] = [crypto.PublicKey.from_proto(k).fingerprint for k in p.party_signing_keys.keys]
        return out
    return {"mapping": kind}


def signed_tx(tx: Tx, sigs: list[crypto.Sig], proposal: bool = False, multi: list[tuple[list[bytes], list[crypto.Sig]]] = ()):
    st = tpb.SignedTopologyTransaction(transaction=tx.serialized, proposal=proposal)
    st.signatures.extend(s.to_canton() for s in sigs)
    for hashes, msigs in multi:
        m = st.multi_transaction_signatures.add()
        m.transaction_hashes.extend(hashes)
        m.signatures.extend(s.to_canton() for s in msigs)
    return st
