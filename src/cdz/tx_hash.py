"""Hash of a PreparedTransaction (interactive submission), hashing schemes V2 and V3.

Spec: docs.canton.network appdev/deep-dives/external-signing-hashing-algorithm; cross-checked
against the reference implementation shipped in the Canton release
(examples/08-interactive-submission/daml_transaction_hashing_v{2,3}.py, Apache-2.0) and Canton's
own golden vectors (tests/test_tx_hash.py). Unknown schemes or fields a scheme does not cover
fail closed: a hash that cannot be reproduced must not be signed.
"""

from __future__ import annotations

import hashlib

from cdz._proto.com.daml.ledger.api.v2.interactive import interactive_submission_service_pb2 as isp

PURPOSE = b"\x00\x00\x00\x30"  # HashPurpose.PreparedSubmission = 48
V2 = isp.HASHING_SCHEME_VERSION_V2
V3 = isp.HASHING_SCHEME_VERSION_V3
SUPPORTED = (V2, V3)


class HashError(ValueError):
    pass


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _i32(v: int) -> bytes:
    if not -(2**31) <= v < 2**32:
        raise HashError(f"int32 out of range: {v}")
    return (v & 0xFFFFFFFF).to_bytes(4, "big")


def _i64(v: int) -> bytes:  # Java long: unsigned values keep their bit pattern
    if not -(2**63) <= v < 2**64:
        raise HashError(f"int64 out of range: {v}")
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


def _bytes(b: bytes) -> bytes:
    return _i32(len(b)) + b


def _str(s: str) -> bytes:
    return _bytes(s.encode("utf-8"))


def _hex(s: str) -> bytes:
    try:
        return _bytes(bytes.fromhex(s))
    except ValueError:
        raise HashError(f"not a hex string: {s!r}") from None


def _bool(b: bool) -> bytes:
    return b"\x01" if b else b"\x00"


def _rep(items, fn) -> bytes:
    return _i32(len(items)) + b"".join(fn(x) for x in items)


def _opt(msg, field: str, fn) -> bytes:
    return b"\x01" + fn(getattr(msg, field)) if msg.HasField(field) else b"\x00"


def _ident(i) -> bytes:
    return _str(i.package_id) + _rep(i.module_name.split("."), _str) + _rep(i.entity_name.split("."), _str)


def encode_value(v) -> bytes:
    k = v.WhichOneof("sum")
    if k == "unit":
        return b"\x00"
    if k == "bool":
        return b"\x01" + _bool(v.bool)
    if k == "int64":
        return b"\x02" + _i64(v.int64)
    if k == "numeric":
        return b"\x03" + _str(v.numeric)
    if k == "timestamp":
        return b"\x04" + _i64(v.timestamp)
    if k == "date":
        return b"\x05" + _i32(v.date)
    if k == "party":
        return b"\x06" + _str(v.party)
    if k == "text":
        return b"\x07" + _str(v.text)
    if k == "contract_id":
        return b"\x08" + _hex(v.contract_id)
    if k == "optional":
        return b"\x09" + _opt(v.optional, "value", encode_value)
    if k == "list":
        return b"\x0a" + _rep(v.list.elements, encode_value)
    if k == "text_map":
        return b"\x0b" + _rep(v.text_map.entries, lambda e: _str(e.key) + encode_value(e.value))
    if k == "record":
        return (
            b"\x0c"
            + _opt(v.record, "record_id", _ident)
            + _rep(v.record.fields, lambda f: b"\x01" + _str(f.label) + encode_value(f.value))
        )
    if k == "variant":
        return b"\x0d" + _opt(v.variant, "variant_id", _ident) + _str(v.variant.constructor) + encode_value(v.variant.value)
    if k == "enum":
        return b"\x0e" + _opt(v.enum, "enum_id", _ident) + _str(v.enum.constructor)
    if k == "gen_map":
        return b"\x0f" + _rep(v.gen_map.entries, lambda e: encode_value(e.key) + encode_value(e.value))
    raise HashError(f"unsupported value: {k}")


def _key_with_maintainers(k) -> bytes:
    g = k.key
    return _str(g.package_name) + _ident(g.template_id) + encode_value(g.key) + g.hash + _rep(k.maintainers, _str)


class _Hasher:
    def __init__(self, scheme: int, tx):
        if scheme not in SUPPORTED:
            raise HashError(f"hashing scheme {scheme} is not supported; refusing to sign")
        self.v3 = scheme == V3
        self.nodes = {}
        for n in tx.nodes:
            if n.node_id in self.nodes:
                raise HashError(f"duplicate node id {n.node_id}")
            self.nodes[n.node_id] = n
        self.seeds = {str(s.node_id): s.seed for s in tx.node_seeds}
        self.memo: dict[str, bytes] = {}
        self.visiting: set[str] = set()

    def node_hash(self, node_id: str) -> bytes:
        if node_id in self.memo:
            return self.memo[node_id]
        if node_id in self.visiting:
            raise HashError("transaction nodes reference each other cyclically")
        node = self.nodes.get(node_id)
        if node is None:
            raise HashError(f"missing node {node_id}")
        if not node.HasField("v1"):
            raise HashError("unsupported node version")
        self.visiting.add(node_id)
        h = _sha(self.encode_node(node.v1, node_id))
        self.visiting.discard(node_id)
        self.memo[node_id] = h
        return h

    def _prefix(self) -> bytes:
        return b"" if self.v3 else b"\x01"  # V2: node encoding version

    def _check_no_keys(self, n, *, by_key: bool = False):
        if not self.v3 and (n.HasField("key") or by_key):
            raise HashError("contract keys need hashing scheme V3")

    def encode_create(self, c, node_id: str | None) -> bytes:
        self._check_no_keys(c)
        seed = self.seeds.get(node_id) if node_id is not None else None
        out = (
            self._prefix()
            + _str(c.lf_version)
            + b"\x00"
            + (b"\x01" + seed if seed is not None else b"\x00")
            + _hex(c.contract_id)
            + _str(c.package_name)
            + _ident(c.template_id)
            + encode_value(c.argument)
            + _rep(c.signatories, _str)
            + _rep(c.stakeholders, _str)
        )
        if self.v3:
            out += _opt(c, "key", _key_with_maintainers)
        return out

    def encode_node(self, n, node_id: str) -> bytes:
        kind = n.WhichOneof("node_type")
        if kind == "create":
            return self.encode_create(n.create, node_id)
        if kind == "exercise":
            e = n.exercise
            self._check_no_keys(e, by_key=e.by_key)
            if len(e.external_call_results):
                raise HashError("external call results need hashing scheme V4 (unsupported)")
            seed = self.seeds.get(node_id)
            if seed is None:
                raise HashError(f"exercise node {node_id} has no seed")
            out = (
                self._prefix()
                + _str(e.lf_version)
                + b"\x01"
                + seed
                + _hex(e.contract_id)
                + _str(e.package_name)
                + _ident(e.template_id)
                + _rep(e.signatories, _str)
                + _rep(e.stakeholders, _str)
                + _rep(e.acting_parties, _str)
                + _opt(e, "interface_id", _ident)
                + _str(e.choice_id)
                + encode_value(e.chosen_value)
                + _bool(e.consuming)
                + _opt(e, "exercise_result", encode_value)
                + _rep(e.choice_observers, _str)
            )
            if self.v3:
                out += _bool(e.by_key) + _opt(e, "key", _key_with_maintainers)
            return out + _rep(e.children, self.node_hash)
        if kind == "fetch":
            f = n.fetch
            self._check_no_keys(f, by_key=f.by_key)
            out = (
                self._prefix()
                + _str(f.lf_version)
                + b"\x02"
                + _hex(f.contract_id)
                + _str(f.package_name)
                + _ident(f.template_id)
                + _rep(f.signatories, _str)
                + _rep(f.stakeholders, _str)
                + _opt(f, "interface_id", _ident)
                + _rep(f.acting_parties, _str)
            )
            if self.v3:
                out += _bool(f.by_key) + _opt(f, "key", _key_with_maintainers)
            return out
        if kind == "rollback":
            return self._prefix() + b"\x03" + _rep(n.rollback.children, self.node_hash)
        if kind == "query_by_key":
            if not self.v3:
                raise HashError("QueryByKey nodes need hashing scheme V3")
            q = n.query_by_key
            return (
                _str(q.lf_version)
                + b"\x04"
                + _str(q.package_name)
                + _ident(q.template_id)
                + _bool(q.exhaustive)
                + _key_with_maintainers(q.key)
                + _rep(q.result, _hex)
            )
        raise HashError(f"unsupported node type {kind}")


def hash_transaction(scheme: int, tx) -> bytes:
    h = _Hasher(scheme, tx)
    return _sha(PURPOSE + _str(tx.version) + _rep(tx.roots, h.node_hash))


def hash_metadata(scheme: int, md) -> bytes:
    h = _Hasher(scheme, isp.DamlTransaction())

    def input_contract(c):
        if not c.HasField("v1"):
            raise HashError("unsupported input contract version")
        return _i64(c.created_at) + _sha(h.encode_create(c.v1, None))

    out = (b"" if scheme == V3 else b"\x01") + (
        _rep(md.submitter_info.act_as, _str)
        + _str(md.submitter_info.command_id)
        + _str(md.transaction_uuid)
        + _i32(md.mediator_group)
        + _str(md.synchronizer_id)
        + _opt(md, "min_ledger_effective_time", _i64)
        + _opt(md, "max_ledger_effective_time", _i64)
        + _i64(md.preparation_time)
        + _rep(md.input_contracts, input_contract)
    )
    if scheme == V3:
        out += _opt(md, "max_record_time", _i64)
    return _sha(PURPOSE + out)


def hash_prepared(scheme: int, prepared) -> bytes:
    """The 32-byte hash an external party signs."""
    if not prepared.HasField("transaction") or not prepared.HasField("metadata"):
        raise HashError("prepared transaction lacks transaction or metadata")
    version = bytes([scheme]) if scheme in SUPPORTED else None
    if version is None:
        raise HashError(f"hashing scheme {scheme} is not supported; refusing to sign")
    return _sha(PURPOSE + version + hash_transaction(scheme, prepared.transaction) + hash_metadata(scheme, prepared.metadata))
