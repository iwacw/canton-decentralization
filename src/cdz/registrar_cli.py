"""`cdz registrar ...`: DA Utilities flows for the external registrar.

Each command prepares ONE transaction (interactive submission allows one command per
transaction) and writes a submission bundle; `--execute` signs with local CDZ_TX_KEY_* keys
and executes when they reach the signing threshold.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
import sys
import time
from decimal import Decimal
from pathlib import Path

from cdz import utilities as U


def _cli():
    from cdz import cli

    return cli


def _duration(text: str) -> dt.timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if not m:
        raise U.UtilitiesError(f"bad duration {text!r} (e.g. 30m, 24h, 7d)")
    n, unit = int(m.group(1)), m.group(2)
    return dt.timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


def _ctx(args):
    c = _cli()
    s = c.settings(args)
    p = c.load_party(s)
    return c, s, p


def _utilities(s) -> dict:
    return s.network.get("utilities", {})


def _operator(s, args) -> str:
    op = getattr(args, "operator", None) or s.env.get("CDZ_UTILITIES_OPERATOR") or _utilities(s).get("operator_party")
    if op:
        return op
    return _registry(s).operator_party()


def _registry(s):
    from cdz.registry import RegistryClient

    return RegistryClient(s.env.get("CDZ_UTILITIES_API") or _utilities(s).get("api", ""), token=s.env.get("CDZ_UTILITIES_TOKEN") or None)


def _run(args, s, p, command, description, disclosed=(), meta=None):
    c = _cli()
    b = c.prepare_bundle(s, p, command, description, disclosed, getattr(args, "ttl", None), meta=meta)
    c.finish_prepared(args, s, b)
    return b


def _find(lc, party: str, template: str, pred=lambda a: True) -> list[dict]:
    return [e for e in lc.active_contracts(party, templates=[template]) if pred(e.get("createArgument") or {})]


def _one(rows: list[dict], what: str) -> dict:
    if len(rows) != 1:
        raise U.UtilitiesError(f"expected exactly one {what}, found {len(rows)}; pass the contract id explicitly")
    return rows[0]


def _registrar_service(args, s, p) -> str:
    if args.registrar_service:
        return args.registrar_service
    c = _cli()
    rows = _find(c.ledger(s), p.party_id, U.T["registrar_service"], lambda a: a.get("registrar") == p.party_id)
    return _one(rows, "RegistrarService")["contractId"]


def _instrument_config(lc, party: str, instrument: str) -> str:
    rows = _find(lc, party, U.T["instrument_configuration"],
                 lambda a: a.get("registrar") == party and (a.get("defaultIdentifier") or {}).get("id") == instrument)
    return _one(rows, f"InstrumentConfiguration for {instrument}")["contractId"]


# --- commands -------------------------------------------------------------------------------


def cmd_request_service(args):
    c, s, p = _ctx(args)
    cmd = U.registrar_service_request(_operator(s, args), args.provider, p.party_id, not args.no_transfer_rule, not args.no_allocation_factory)
    _run(args, s, p, cmd, f"RegistrarServiceRequest to provider {args.provider}")


def cmd_credential_accept(args):
    c, s, p = _ctx(args)
    _run(args, s, p, U.credential_offer_accept(args.offer), f"Accept credential offer {args.offer[:16]}…")


def cmd_credential_issue(args):
    c, s, p = _ctx(args)
    claims = []
    for cl in args.claim:
        parts = [x.strip() for x in cl.split(",")]
        if len(parts) != 3:
            raise U.UtilitiesError(f"--claim wants SUBJECT,PROPERTY,VALUE, got {cl!r}")
        claims.append(tuple(parts))
    observers = args.observer or [_operator(s, args)]
    cmd = U.self_credential(p.party_id, args.id, args.description or args.id, claims, observers)
    _run(args, s, p, cmd, f"Issue self-held credential {args.id} ({len(claims)} claims)")


def cmd_credential_revoke(args):
    c, s, p = _ctx(args)
    _run(args, s, p, U.credential_revoke(args.cid, p.party_id), f"Revoke credential {args.cid[:16]}…")


def _payload(args, p):
    ids = []
    for ident in args.identifier or []:
        scheme, _, value = ident.partition("=")
        ids.append(U.additional_identifier(p.party_id, value, scheme))
    return U.instrument_payload(
        args.instrument,
        holder_reqs=[U.parse_requirement(r, p.party_id) for r in args.holder_req or []],
        issuer_reqs=[U.parse_requirement(r, p.party_id) for r in args.issuer_req or []],
        extra_ids=ids,
        use_block_list=True if args.block_list else None,
    )


def cmd_instrument_create(args):
    c, s, p = _ctx(args)
    rs = _registrar_service(args, s, p)
    _run(args, s, p, U.instrument_create(rs, _payload(args, p)), f"Create InstrumentConfiguration {args.instrument}")


def cmd_instrument_update(args):
    c, s, p = _ctx(args)
    rs = _registrar_service(args, s, p)
    cfg = args.config or _instrument_config(c.ledger(s), p.party_id, args.instrument)
    _run(args, s, p, U.instrument_update(rs, cfg, _payload(args, p)), f"Replace InstrumentConfiguration {args.instrument}")


def cmd_instrument_archive(args):
    c, s, p = _ctx(args)
    rs = _registrar_service(args, s, p)
    _run(args, s, p, U.instrument_archive(rs, args.config), f"Archive InstrumentConfiguration {args.config[:16]}…")


def cmd_beneficiaries(args):
    c, s, p = _ctx(args)
    weights = []
    for b in args.beneficiary:
        party, _, w = b.rpartition("=")
        weights.append((party, w))
    print("note: the controller is the provider; this only works if the registrar is also the provider", file=sys.stderr)
    _run(args, s, p, U.set_provider_beneficiaries(args.config, weights or None), "Set provider app-reward beneficiaries")


def cmd_markers_proxy(args):
    c, s, p = _ctx(args)
    _run(args, s, p, U.markers_proxy(_operator(s, args), p.party_id), "Create DelegatedBatchedMarkersProxy (featured-app markers)")


def _mint_context(args, s, p, lc):
    if args.local_context:
        cfg = args.config or _instrument_config(lc, p.party_id, args.instrument)
        return U.local_context(cfg, args.credential or [], args.block_list_shard if args.block_list_shard else None), []
    return None


def cmd_mint_accept(args):
    c, s, p = _ctx(args)
    lc = c.ledger(s)
    req = _find(lc, p.party_id, U.T["mint_request"], lambda a: True)
    req = [r for r in req if r["contractId"] == args.request]
    if req:
        m = req[0]["createArgument"]["mint"]
        print(f"mint request: {m['amount']} {m['instrumentId']['id']} to {m['holder']} (ref {m.get('reference')}, executeBefore {m['executeBefore']})", file=sys.stderr)
        if m["instrumentId"]["admin"] != p.party_id:
            raise U.UtilitiesError("this mint request is for another instrument admin")
        args.instrument = m["instrumentId"]["id"]
    local = _mint_context(args, s, p, lc) if req else None
    ctx, disclosed = local or _registry(s).mint_request_accept_context(args.request)
    _run(args, s, p, U.mint_request_accept(args.request, ctx), f"Accept mint request {args.request[:16]}…", disclosed)


def cmd_mint_reject(args):
    c, s, p = _ctx(args)
    _run(args, s, p, U.mint_request_reject(args.request, args.reason), f"Reject mint request {args.request[:16]}…")


def cmd_mint_offer(args):
    c, s, p = _ctx(args)
    lc = c.ledger(s)
    req_at, exp = U.window(_duration(args.valid_for))
    mint = U.mint_record(p.party_id, args.instrument, args.amount, args.holder, args.reference or "", req_at, exp)
    if args.local_context:
        factory = args.factory or _one(_find(lc, p.party_id, U.T["allocation_factory"], lambda a: a.get("registrar") == p.party_id), "AllocationFactory")["contractId"]
        ctx, disclosed = _mint_context(args, s, p, lc)
    else:
        factory, ctx, disclosed = _registry(s).mint_offer_factory(args.holder, p.party_id, args.instrument)
    _run(args, s, p, U.offer_mint(factory, p.party_id, mint, ctx), f"Offer mint of {mint['amount']} {args.instrument} to {args.holder}", disclosed,
         meta={"executeBefore": exp})


def cmd_mint_request(args):
    """Treasury mint: the registrar requests a mint to itself (then mint-accept)."""
    c, s, p = _ctx(args)
    req_at, exp = U.window(_duration(args.valid_for))
    mint = U.mint_record(p.party_id, args.instrument, args.amount, p.party_id, args.reference or "", req_at, exp)
    factory, ctx, disclosed = _registry(s).mint_request_factory(p.party_id, p.party_id, args.instrument)
    _run(args, s, p, U.request_mint(factory, p.party_id, mint, ctx), f"Request mint of {mint['amount']} {args.instrument} to the registrar",
         disclosed, meta={"executeBefore": exp})


def cmd_mint_offer_accept(args):
    c, s, p = _ctx(args)
    ctx, disclosed = _registry(s).mint_offer_accept_context(args.offer)
    _run(args, s, p, U.mint_offer_accept(args.offer, ctx), f"Accept mint offer {args.offer[:16]}… (registrar as holder)", disclosed)


def cmd_burn_accept(args):
    c, s, p = _ctx(args)
    ctx, disclosed = _registry(s).burn_request_accept_context(args.request)
    _run(args, s, p, U.burn_request_accept(args.request, ctx), f"Accept burn request {args.request[:16]}…", disclosed)


def _holdings(lc, party):
    return U.holding_views(lc.active_contracts(party, interfaces=[U.T["holding_v1"]]))


def _prepare_transfer(args, s, p, lc, receiver, amount, reason, inputs, valid_for, out):
    c = _cli()
    req_at, exp = U.window(valid_for)
    targs = U.transfer_args(p.party_id, p.party_id, receiver, amount, args.instrument, req_at, exp, inputs, reason)
    factory, kind, ctx, disclosed = _registry(s).transfer_factory(p.party_id, targs)
    targs["extraArgs"] = U.extra_args(ctx)
    b = c.prepare_bundle(s, p, U.transfer(factory, targs), f"Transfer {targs['transfer']['amount']} {args.instrument} to {receiver} ({kind or 'unknown'} transfer)",
                         disclosed, getattr(args, "ttl", None), lc=lc, meta={"executeBefore": exp, "transferKind": kind,
                                                                  "expect_template_package": "utility-registry-app-v0"})
    c.write_bundle(b, out)
    return b


def cmd_transfer(args):
    c, s, p = _ctx(args)
    lc = c.ledger(s)
    inputs = args.input or U.pick_inputs(_holdings(lc, p.party_id), p.party_id, p.party_id, args.instrument, args.amount)
    b = _prepare_transfer(args, s, p, lc, args.to, args.amount, args.reason, inputs, _duration(args.valid_for), args.output)
    args.output = None
    c.finish_prepared(args, s, b)


def read_transfer_csv(path: str) -> list[dict]:
    from cdz import topology

    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:  # tolerate an Excel BOM
        for i, r in enumerate(csv.DictReader(f), start=2):
            r = {k.strip().lower(): (v or "").strip() for k, v in r.items() if k}
            if not r.get("receiver") or not r.get("amount"):
                raise U.UtilitiesError(f"{path}:{i}: receiver and amount are required")
            try:
                topology.split_uid(r["receiver"])
            except topology.TopologyError:
                raise U.UtilitiesError(f"{path}:{i}: receiver is not a party id") from None
            rows.append({"line": i, "receiver": r["receiver"], "amount": U.decimal(r["amount"]), "reason": r.get("reason") or None})
    if not rows:
        raise U.UtilitiesError(f"{path}: no rows")
    return rows


def assign_exact_holdings(rows: list[dict], holdings: list[dict]) -> dict[int, str] | None:
    free = {}
    for h in holdings:
        free.setdefault(Decimal(h["amount"]), []).append(h["contract_id"])
    out = {}
    for r in rows:
        lst = free.get(Decimal(r["amount"]))
        if not lst:
            return None
        out[r["line"]] = lst.pop()
    return out


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)[:24] or "party"


def _bundle_state(path: str | None) -> str | None:
    """executed | prepared | None (no bundle file)."""
    from cdz import bundle

    if not path or not Path(path).exists():
        return None
    return "executed" if bundle.load(path).meta.get("executed") else "prepared"


def cmd_transfers(args):
    """Batch from CSV (receiver,amount[,reason]), resumable. Each transfer is its own transaction
    with its own exact-amount input holding, so the bundles can be signed offline in one go.
    Progress lives in <out-dir>/manifest.json and each bundle's `executed` mark: a rerun never
    prepares or executes a line twice."""
    from cdz import bundle

    c, s, p = _ctx(args)
    lc = c.ledger(s)
    rows = read_transfer_csv(args.csv)
    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    mpath = outdir / "manifest.json"
    manifest = {e["line"]: e for e in json.loads(mpath.read_text())} if mpath.exists() else {}
    for r in rows:
        e = manifest.get(r["line"])
        if e and (e["receiver"] != r["receiver"] or Decimal(e["amount"]) != Decimal(r["amount"])):
            raise U.UtilitiesError(f"CSV line {r['line']} differs from {mpath}; use a new --out-dir for a new CSV")

    def save():
        mpath.write_text(json.dumps([manifest[k] for k in sorted(manifest)], indent=2) + "\n")

    state = {r["line"]: _bundle_state((manifest.get(r["line"]) or {}).get("bundle")) for r in rows}
    todo = [r for r in rows if state[r["line"]] is None]
    print(f"{sum(v == 'executed' for v in state.values())} executed, {sum(v == 'prepared' for v in state.values())} prepared, "
          f"{len(todo)} to prepare", file=sys.stderr)
    if todo:
        pending_aux = [x for x in sorted(outdir.glob("00-*.json")) if _bundle_state(str(x)) == "prepared"]
        if pending_aux:
            raise U.UtilitiesError(f"{pending_aux[0]} is prepared but not executed: execute it (cdz tx execute) or delete it, then rerun")
        reserved = {manifest[r["line"]]["input"] for r in rows if state[r["line"]] == "prepared"}
        mine = [h for h in _holdings(lc, p.party_id) if h["owner"] == p.party_id and h["admin"] == p.party_id
                and h["instrument"] == args.instrument and not h["locked"] and h["contract_id"] not in reserved]
        assignment = assign_exact_holdings(todo, mine)
        if assignment is None:
            if getattr(args, "_after_split", False):
                raise U.UtilitiesError("exact-amount holdings are not visible yet after the split; rerun in a moment")
            total = sum(Decimal(r["amount"]) for r in todo)
            big = sorted(mine, key=lambda h: Decimal(h["amount"]), reverse=True)
            n = len(list(outdir.glob("00-*.json"))) + 1
            if not big or Decimal(big[0]["amount"]) < total:
                have = sum(Decimal(h["amount"]) for h in mine)
                if have < total:
                    raise U.UtilitiesError(f"registrar holds {have} free unlocked {args.instrument}, the remaining lines need {total}")
                kind, cmd = "merge", U.holding_merge(big[0]["contract_id"], [h["contract_id"] for h in big[1:]])
                desc = f"Merge {len(big)} holdings of {args.instrument} (CSV needs {total})"
            else:
                kind, cmd = "split", U.holding_split(big[0]["contract_id"], [r["amount"] for r in todo])
                desc = f"Split {big[0]['amount']} {args.instrument} into {len(todo)} exact amounts for the CSV"
            aux = outdir / f"00-{kind}-{n}.json"
            b = c.prepare_bundle(s, p, cmd, desc, lc=lc)
            c.write_bundle(b, aux)
            if not args.execute:
                print(f"sign and execute {aux}, then rerun this command", file=sys.stderr)
                return
            args.output = str(aux)
            c.finish_prepared(args, s, b)
            for _ in range(10):  # wait until the new holdings are visible; never split twice per run
                time.sleep(2)
                mine = [h for h in _holdings(lc, p.party_id) if h["owner"] == p.party_id and h["admin"] == p.party_id
                        and h["instrument"] == args.instrument and not h["locked"] and h["contract_id"] not in reserved]
                if assign_exact_holdings(todo, mine) is not None or (kind == "merge" and len(mine) <= 1 + len(reserved)):
                    break
            args._after_split = kind == "split"
            return cmd_transfers(args)
        for r in todo:
            out = outdir / f"{r['line']:04d}-{_safe(r['receiver'].split('::')[0])}.json"
            _prepare_transfer(args, s, p, lc, r["receiver"], r["amount"], r["reason"], [assignment[r["line"]]], _duration(args.valid_for), out)
            manifest[r["line"]] = {"line": r["line"], "receiver": r["receiver"], "amount": r["amount"], "reason": r["reason"],
                                   "bundle": str(out), "input": assignment[r["line"]]}
            save()
    if not args.execute:
        print(f"bundles in {outdir} (manifest.json); signers: `cdz bundle sign {outdir}/0[0-9]*-*.json`, "
              f"then `cdz tx execute ...` (executed bundles are skipped)", file=sys.stderr)
        return
    pending = [r for r in rows if _bundle_state(manifest[r["line"]]["bundle"]) == "prepared"]
    if not pending:
        print("nothing left to execute", file=sys.stderr)
        return
    total = sum(Decimal(r["amount"]) for r in pending)
    for r in pending:
        print(f"  line {r['line']}: {r['amount']} -> {r['receiver']}", file=sys.stderr)
    c.confirm(args, f"Sign with local keys and execute {len(pending)} transfer(s), {total} {args.instrument} in total?")
    keys = s.protocol_keys()
    for r in pending:
        path = manifest[r["line"]]["bundle"]
        b = bundle.load(path)
        b.sign(keys)
        c.write_bundle(b, path)
        res = c.execute_bundle(s, b, None)
        b.meta["executed"] = {"update_id": res.get("updateId"), "offset": res.get("completionOffset")}
        c.write_bundle(b, path)
        manifest[r["line"]]["executed"] = b.meta["executed"]
        save()


def cmd_split(args):
    c, s, p = _ctx(args)
    _run(args, s, p, U.holding_split(args.holding, [a.strip() for a in args.amounts.split(",")]), f"Split holding {args.holding[:16]}…")


def cmd_holdings(args):
    c, s, p = _ctx(args)
    rows = _holdings(c.ledger(s), p.party_id)
    if args.instrument:
        rows = [r for r in rows if r["instrument"] == args.instrument]
    if args.owner:
        rows = [r for r in rows if r["owner"] == args.owner]
    res = {"summary": U.summarize_holdings(rows)}
    if args.list:
        res["holdings"] = rows
    c.out(res)


def cmd_contracts(args):
    c, s, p = _ctx(args)
    lc = c.ledger(s)
    names = ["registrar_service_request", "registrar_service", "allocation_factory", "transfer_rule", "instrument_configuration",
             "credential_offer", "credential", "mint_request", "mint_offer", "burn_request", "transfer_offer", "markers_proxy"]
    res = {}
    for n in names:
        try:
            evs = lc.active_contracts(p.party_id, templates=[U.T[n]])
        except Exception as e:  # unknown package on this node
            res[n] = f"unavailable: {str(e)[:120]}"
            continue
        res[n] = [{"contract_id": e["contractId"], "argument": e.get("createArgument")} for e in evs]
    c.out(res)


# --- parser ---------------------------------------------------------------------------------


def register(sub, add, yes):
    reg = sub.add_parser("registrar", help="DA Utilities registrar flows").add_subparsers(dest="sub", required=True)

    def common(p, out):
        p.add_argument("-o", "--output", default=out)
        p.add_argument("--execute", action="store_true", help="sign with local CDZ_TX_KEY_* and execute")
        p.add_argument("--ttl", type=int, help="max record time, seconds from now")
        yes(p)
        return p

    def rs(p):
        p.add_argument("--registrar-service", help="RegistrarService contract id (default: look up)")
        return p

    p = common(add(reg, "request-service", cmd_request_service, "create RegistrarServiceRequest (provider accepts)"), "request-service.bundle.json")
    p.add_argument("--provider", required=True)
    p.add_argument("--operator", help="DA operator party (default: network profile / API)")
    p.add_argument("--no-transfer-rule", action="store_true")
    p.add_argument("--no-allocation-factory", action="store_true")

    p = common(add(reg, "credential-accept", cmd_credential_accept, "accept a free CredentialOffer addressed to the registrar"), "credential-accept.bundle.json")
    p.add_argument("--offer", required=True)
    p = common(add(reg, "credential-issue", cmd_credential_issue, "issue a self-held credential (e.g. holder allowlist)"), "credential-issue.bundle.json")
    p.add_argument("--id", required=True)
    p.add_argument("--description")
    p.add_argument("--claim", action="append", required=True, help="SUBJECT_PARTY,PROPERTY,VALUE e.g. alice::1220..,isHolderOf,MYTOKEN")
    p.add_argument("--observer", action="append", help="default: DA operator")
    p.add_argument("--operator")
    p = common(add(reg, "credential-revoke", cmd_credential_revoke, "revoke a credential the registrar issued or holds"), "credential-revoke.bundle.json")
    p.add_argument("--cid", required=True)

    for name, fn, help_ in [("instrument-create", cmd_instrument_create, "create an InstrumentConfiguration"),
                            ("instrument-update", cmd_instrument_update, "archive-and-recreate an InstrumentConfiguration")]:
        p = rs(common(add(reg, name, fn, help_), f"{name}.bundle.json"))
        p.add_argument("--instrument", required=True, help="instrument id (e.g. CSOL)")
        p.add_argument("--holder-req", action="append", help="[ISSUER@]property=value[,..] (default issuer: registrar)")
        p.add_argument("--issuer-req", action="append", help="requirement checked on mint recipients")
        p.add_argument("--identifier", action="append", help="SCHEME=ID additional identifier, e.g. ISIN=US0000000000")
        p.add_argument("--block-list", action="store_true")
        if name == "instrument-update":
            p.add_argument("--config", help="current InstrumentConfiguration cid (default: look up)")
    p = rs(common(add(reg, "instrument-archive", cmd_instrument_archive, "archive an InstrumentConfiguration"), "instrument-archive.bundle.json"))
    p.add_argument("--config", required=True)

    p = common(add(reg, "beneficiaries", cmd_beneficiaries, "set provider app-reward beneficiaries (provider-controlled)"), "beneficiaries.bundle.json")
    p.add_argument("--config", required=True)
    p.add_argument("--beneficiary", action="append", default=[], help="PARTY=WEIGHT (weights sum to 1.0); none = unset")
    p = common(add(reg, "markers-proxy", cmd_markers_proxy, "opt in to DA batched featured-app markers"), "markers-proxy.bundle.json")
    p.add_argument("--operator")

    def mint_ctx(p):
        p.add_argument("--local-context", action="store_true", help="build the choice context from own ACS instead of DA's API (inferred)")
        p.add_argument("--config", help="InstrumentConfiguration cid (local context)")
        p.add_argument("--credential", action="append", help="issuer credential cid (local context)")
        p.add_argument("--block-list-shard", action="append", help="block list shard cid (local context, if enabled)")

    p = common(add(reg, "mint-accept", cmd_mint_accept, "MintRequest_Accept (holder-initiated mint)"), "mint-accept.bundle.json")
    p.add_argument("--request", required=True)
    p.add_argument("--instrument")
    mint_ctx(p)
    p = common(add(reg, "mint-reject", cmd_mint_reject, "MintRequest_Reject"), "mint-reject.bundle.json")
    p.add_argument("--request", required=True)
    p.add_argument("--reason", required=True)
    p = common(add(reg, "mint-offer", cmd_mint_offer, "AllocationFactory_OfferMint (registrar-initiated; holder accepts)"), "mint-offer.bundle.json")
    p.add_argument("--holder", required=True)
    p.add_argument("--instrument", required=True)
    p.add_argument("--amount", required=True)
    p.add_argument("--reference")
    p.add_argument("--valid-for", default="7d", help="executeBefore = now + this (e.g. 24h)")
    p.add_argument("--factory", help="AllocationFactory cid (local context)")
    mint_ctx(p)
    p = common(add(reg, "mint-request", cmd_mint_request, "AllocationFactory_RequestMint to the registrar itself (treasury)"), "mint-request.bundle.json")
    p.add_argument("--instrument", required=True)
    p.add_argument("--amount", required=True)
    p.add_argument("--reference")
    p.add_argument("--valid-for", default="7d")
    p = common(add(reg, "mint-offer-accept", cmd_mint_offer_accept, "MintOffer_Accept for an offer to the registrar"), "mint-offer-accept.bundle.json")
    p.add_argument("--offer", required=True)
    p = common(add(reg, "burn-accept", cmd_burn_accept, "BurnRequest_Accept"), "burn-accept.bundle.json")
    p.add_argument("--request", required=True)

    p = common(add(reg, "transfer", cmd_transfer, "TransferFactory_Transfer from the registrar's own holdings"), "transfer.bundle.json")
    p.add_argument("--to", required=True)
    p.add_argument("--amount", required=True)
    p.add_argument("--instrument", required=True)
    p.add_argument("--reason")
    p.add_argument("--input", action="append", help="input holding cid(s); default: picked largest-first")
    p.add_argument("--valid-for", default="24h")
    p = add(reg, "transfers", cmd_transfers, "batch transfers from CSV (receiver,amount[,reason])")
    p.add_argument("--csv", required=True)
    p.add_argument("--instrument", required=True)
    p.add_argument("--out-dir", default="transfers")
    p.add_argument("--valid-for", default="24h")
    p.add_argument("--ttl", type=int)
    p.add_argument("--execute", action="store_true", help="split if needed, then sign+execute each transfer")
    yes(p)
    p = common(add(reg, "split", cmd_split, "Holding_Split into exact amounts"), "split.bundle.json")
    p.add_argument("--holding", required=True)
    p.add_argument("--amounts", required=True, help="comma separated")

    p = add(reg, "holdings", cmd_holdings, "holdings visible to the registrar (HoldingV1 interface), totals per instrument")
    p.add_argument("--instrument")
    p.add_argument("--owner")
    p.add_argument("--list", action="store_true", help="also list individual holdings")
    add(reg, "contracts", cmd_contracts, "registrar-relevant contracts in the party's ACS")
