"""Decode, summarize and check a PreparedTransaction before anyone signs it."""

from __future__ import annotations

import base64
import time
from decimal import Decimal

from cdz import tx_hash
from cdz._proto.com.daml.ledger.api.v2.interactive import interactive_submission_service_pb2 as isp

SCHEMES = {"HASHING_SCHEME_VERSION_V2": tx_hash.V2, "HASHING_SCHEME_VERSION_V3": tx_hash.V3}
SCHEME_NAMES = {v: k for k, v in SCHEMES.items()}


class PreparedCheckError(ValueError):
    pass


def decode(prepared_b64: str) -> isp.PreparedTransaction:
    return isp.PreparedTransaction.FromString(base64.b64decode(prepared_b64))


def scheme_of(value) -> int:
    if isinstance(value, int):
        return value
    if value not in SCHEMES:
        raise PreparedCheckError(f"unsupported hashing scheme {value}")
    return SCHEMES[value]


def tid(i) -> str:
    return f"{i.package_id}:{i.module_name}:{i.entity_name}"


def value_to_py(v):
    """Compact JSON-ish rendering of a Ledger API Value for human review."""
    k = v.WhichOneof("sum")
    if k is None:
        return None
    if k == "unit":
        return {}
    if k in ("bool", "text", "party"):
        return getattr(v, k)
    if k == "numeric":
        return str(Decimal(v.numeric).normalize()) if v.numeric else v.numeric
    if k == "int64":
        return str(v.int64)
    if k == "contract_id":
        return "cid:" + v.contract_id
    if k == "timestamp":
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(v.timestamp / 1e6)) + f".{v.timestamp % 1_000_000:06d}Z"
    if k == "date":
        return time.strftime("%Y-%m-%d", time.gmtime(v.date * 86400))
    if k == "optional":
        return value_to_py(v.optional.value) if v.optional.HasField("value") else None
    if k == "list":
        return [value_to_py(x) for x in v.list.elements]
    if k == "text_map":
        return {e.key: value_to_py(e.value) for e in v.text_map.entries}
    if k == "gen_map":
        return [[value_to_py(e.key), value_to_py(e.value)] for e in v.gen_map.entries]
    if k == "record":
        return {f.label or str(i): value_to_py(f.value) for i, f in enumerate(v.record.fields)}
    if k == "variant":
        return {"tag": v.variant.constructor, "value": value_to_py(v.variant.value)}
    if k == "enum":
        return v.enum.constructor
    return f"<{k}>"


def summarize(p: isp.PreparedTransaction) -> dict:
    nodes = {n.node_id: n.v1 for n in p.transaction.nodes}

    def node(nid: str, depth: int = 0) -> dict:
        n = nodes[nid]
        kind = n.WhichOneof("node_type")
        if kind == "create":
            c = n.create
            return {
                "create": tid(c.template_id),
                "package_name": c.package_name,
                "signatories": list(c.signatories),
                "stakeholders": list(c.stakeholders),
                "argument": value_to_py(c.argument),
            }
        if kind == "exercise":
            e = n.exercise
            out = {
                "exercise": e.choice_id,
                "template": tid(e.template_id),
                **({"interface": tid(e.interface_id)} if e.HasField("interface_id") else {}),
                "contract_id": e.contract_id,
                "consuming": e.consuming,
                "acting_parties": list(e.acting_parties),
                "argument": value_to_py(e.chosen_value),
            }
            if depth < 6 and e.children:
                out["children"] = [node(c, depth + 1) for c in e.children]
            elif e.children:
                out["children"] = f"{len(e.children)} more nodes"
            return out
        if kind == "fetch":
            f = n.fetch
            return {"fetch": tid(f.template_id), "contract_id": f.contract_id, "acting_parties": list(f.acting_parties)}
        if kind == "rollback":
            return {"rollback": [node(c, depth + 1) for c in n.rollback.children]}
        return {kind: "…"}

    md = p.metadata
    return {
        "act_as": list(md.submitter_info.act_as),
        "command_id": md.submitter_info.command_id,
        "synchronizer_id": md.synchronizer_id,
        "transaction_uuid": md.transaction_uuid,
        "preparation_time_us": md.preparation_time,
        **({"max_record_time_us": md.max_record_time} if md.HasField("max_record_time") else {}),
        "input_contracts": len(md.input_contracts),
        "roots": [node(r) for r in p.transaction.roots],
        "parties_involved": sorted(all_parties(p)),
    }


def all_parties(p: isp.PreparedTransaction) -> set[str]:
    out: set[str] = set(p.metadata.submitter_info.act_as)
    for n in p.transaction.nodes:
        x = n.v1
        kind = x.WhichOneof("node_type")
        if kind in ("create", "exercise", "fetch"):
            node = getattr(x, kind)
            out.update(node.signatories, node.stakeholders)
            if kind != "create":
                out.update(node.acting_parties)
    return out


def check(
    p: isp.PreparedTransaction,
    scheme: int,
    node_hash: bytes | None,
    party: str,
    intent: dict | None = None,
    synchronizer_id: str | None = None,
    clock_skew_s: int = 120,
) -> bytes:
    """Recompute the hash and check the transaction against what was asked. Returns the hash."""
    h = tx_hash.hash_prepared(scheme, p)
    if node_hash is not None and h != node_hash:
        raise PreparedCheckError(
            f"hash mismatch: node says {node_hash.hex()}, transaction hashes to {h.hex()}; do not sign"
        )
    md = p.metadata
    if list(md.submitter_info.act_as) != [party]:
        raise PreparedCheckError(f"act_as is {list(md.submitter_info.act_as)}, expected only {party}")
    if len(p.transaction.roots) != 1:
        raise PreparedCheckError("external parties support a single root node only")
    if synchronizer_id and md.synchronizer_id != synchronizer_id and not md.synchronizer_id.startswith(synchronizer_id + "::"):
        raise PreparedCheckError(f"synchronizer {md.synchronizer_id} is not the expected {synchronizer_id}")
    now_us = int(time.time() * 1e6)
    if md.preparation_time > now_us + clock_skew_s * 1_000_000:
        raise PreparedCheckError("preparation_time is ahead of the local clock")
    if intent:
        _check_intent(p, intent)
    return h


def _micros(text: str) -> int | None:
    import datetime as dt

    try:
        t = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return int(t.timestamp()) * 1_000_000 + t.microsecond


def compare_value(want, v, path: str = "$") -> list[str]:
    """Best-effort check that a JSON (Daml-LF JSON) value matches a Ledger API Value.

    Only what the JSON states is compared (omitted record fields are ignored); returns the
    paths that definitely differ."""
    k = v.WhichOneof("sum")
    if want is None:
        return [] if k in (None, "unit") or (k == "optional" and not v.optional.HasField("value")) else [f"{path}: expected none"]
    if k == "optional":
        return compare_value(want, v.optional.value, path) if v.optional.HasField("value") else [f"{path}: missing value"]
    if k == "record":
        if not isinstance(want, dict):
            return [f"{path}: expected record"]
        fields = {f.label: f.value for f in v.record.fields}
        out = []
        for key, sub in want.items():
            if key not in fields:
                if fields and all(fields):  # labelled record without that field
                    out.append(f"{path}.{key}: not in transaction")
                continue
            out += compare_value(sub, fields[key], f"{path}.{key}")
        return out
    if k == "variant":
        if isinstance(want, dict) and "tag" in want:
            if want["tag"] != v.variant.constructor:
                return [f"{path}: variant {v.variant.constructor} != {want['tag']}"]
            return compare_value(want.get("value"), v.variant.value, f"{path}.{want['tag']}")
        return []
    if k == "list":
        if not isinstance(want, list):
            return [f"{path}: expected list"]
        if len(want) != len(v.list.elements):
            return [f"{path}: {len(v.list.elements)} elements != {len(want)}"]
        return [m for i, (a, b) in enumerate(zip(want, v.list.elements, strict=True)) for m in compare_value(a, b, f"{path}[{i}]")]
    if k == "text_map":
        if not isinstance(want, dict):
            return [f"{path}: expected map"]
        got = {e.key: e.value for e in v.text_map.entries}
        if set(got) != set(want):
            return [f"{path}: keys {sorted(got)} != {sorted(want)}"]
        return [m for key in want for m in compare_value(want[key], got[key], f"{path}.{key}")]
    if k == "numeric":
        try:
            return [] if Decimal(str(want)) == Decimal(v.numeric) else [f"{path}: {v.numeric} != {want}"]
        except Exception:
            return [f"{path}: not a number: {want!r}"]
    if k == "int64":
        return [] if str(want) == str(v.int64) else [f"{path}: {v.int64} != {want}"]
    if k == "timestamp":
        m = _micros(str(want))
        return [] if m is None or m == v.timestamp else [f"{path}: timestamp differs"]
    if k in ("text", "party", "contract_id"):
        got = getattr(v, k)
        return [] if want == got else [f"{path}: {got!r} != {want!r}"]
    if k == "bool":
        return [] if want is v.bool else [f"{path}: {v.bool} != {want}"]
    if k == "enum":
        return [] if want == v.enum.constructor else [f"{path}: {v.enum.constructor} != {want}"]
    return []  # date, gen_map, unit: not compared


def _check_intent(p: isp.PreparedTransaction, command: dict) -> None:
    """`command` is the JSON Ledger API command that was prepared ({"CreateCommand": {...}} etc.)."""
    ((cmd_kind, body),) = command.items()
    root_id = p.transaction.roots[0]
    root = next(n.v1 for n in p.transaction.nodes if n.node_id == root_id)
    kind = root.WhichOneof("node_type")
    want = body.get("templateId", "")
    module_entity = ":".join(want.split(":")[-2:]) if want else ""
    if cmd_kind == "CreateCommand":
        if kind != "create":
            raise PreparedCheckError(f"root node is {kind}, expected create")
        got = root.create.template_id
        if module_entity and f"{got.module_name}:{got.entity_name}" != module_entity:
            raise PreparedCheckError(f"creates {tid(got)}, expected {want}")
        diffs = compare_value(body.get("createArguments"), root.create.argument)
        if diffs:
            raise PreparedCheckError("create arguments differ from the request: " + "; ".join(diffs[:5]))
    elif cmd_kind == "ExerciseCommand":
        if kind != "exercise":
            raise PreparedCheckError(f"root node is {kind}, expected exercise")
        e = root.exercise
        if e.choice_id != body["choice"]:
            raise PreparedCheckError(f"root exercises {e.choice_id}, expected {body['choice']}")
        if e.contract_id != body["contractId"]:
            raise PreparedCheckError(f"root exercises on {e.contract_id}, expected {body['contractId']}")
        target = e.interface_id if e.HasField("interface_id") else e.template_id
        if module_entity and f"{target.module_name}:{target.entity_name}" != module_entity:
            raise PreparedCheckError(f"root exercises on {tid(target)}, expected {want}")
        diffs = compare_value(body.get("choiceArgument"), e.chosen_value)
        if diffs:
            raise PreparedCheckError("choice argument differs from the request: " + "; ".join(diffs[:5]))
    else:
        raise PreparedCheckError(f"unsupported command kind {cmd_kind}")
