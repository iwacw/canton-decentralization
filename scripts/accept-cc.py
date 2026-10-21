#!/usr/bin/env python3
"""Accept every pending incoming Canton Coin (Amulet) transfer of the party in party.json.

For each AmuletTransferInstruction where the party is the receiver: fetch the accept choice
context from Scan's token-standard registry, prepare TransferInstruction_Accept on the
participant, show it, sign it with the local CDZ_TX_KEY_* keys and execute it.

    .venv/bin/python scripts/accept-cc.py [--dry-run] [--yes] [--scan URL] [--env .env]

Without enough local keys for the signing threshold the bundle is written to --out-dir for
`cdz bundle sign` / `cdz tx execute` instead.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cdz import cli
from cdz.utilities import strip_disclosed

TI = "#splice-api-token-transfer-instruction-v1:Splice.Api.Token.TransferInstructionV1:TransferInstruction"
AMULET_TI = "Splice.AmuletTransferInstruction:AmuletTransferInstruction"
SCAN = {"devnet": "https://scan.sv-1.dev.global.canton.network.digitalasset.com"}


def scan_post(base: str, path: str, body=None):
    method = "POST" if body is not None else "GET"
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(body).encode() if body is not None else None, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise cli.CliError(f"Scan {method} {path} -> HTTP {e.code}: {e.read().decode(errors='replace')[:300]}") from None


def status_tag(view: dict) -> str:
    st = view.get("status") or {}
    return st.get("tag", "") if isinstance(st, dict) else str(st)


def pending(lc, party: str, dso: str) -> list[dict]:
    """Amulet transfer instructions to `party` that wait for its acceptance and have not expired."""
    now = dt.datetime.now(dt.timezone.utc)
    rows = []
    for ev in lc.active_contracts(party, interfaces=[TI]):
        view = next((iv.get("viewValue") or {} for iv in ev.get("interfaceViews") or []
                     if iv.get("interfaceId", "").endswith(":Splice.Api.Token.TransferInstructionV1:TransferInstruction")
                     and (iv.get("viewStatus") or {}).get("code", 0) == 0), None)
        if view is None:
            continue
        t = view.get("transfer") or {}
        why = None
        if not ev.get("templateId", "").endswith(":" + AMULET_TI) or ev.get("packageName") not in (None, "splice-amulet"):
            why = f"not an Amulet transfer instruction ({ev.get('templateId')})"
        elif t.get("instrumentId") != {"admin": dso, "id": "Amulet"}:
            why = f"instrument {t.get('instrumentId')} is not Canton Coin"
        elif t.get("receiver") != party:
            why = "outgoing (this party is the sender)"
        elif status_tag(view) != "TransferPendingReceiverAcceptance":
            why = f"status {status_tag(view)}"
        elif dt.datetime.fromisoformat(t["executeBefore"].replace("Z", "+00:00")) <= now:
            why = f"expired at {t['executeBefore']}"
        rows.append({"cid": ev["contractId"], "sender": t.get("sender"), "amount": t.get("amount"),
                     "executeBefore": t.get("executeBefore"), "skip": why})
    return rows


def accept(args, s, p, lc, scan: str, row: dict) -> str:
    ctx = scan_post(scan, f"/registry/transfer-instruction/v1/{row['cid']}/choice-contexts/accept", {"meta": {}})
    context = ctx.get("choiceContextData") or {}
    if not context.get("values"):
        raise cli.CliError(f"Scan returned an empty accept context for {row['cid'][:16]}…")
    command = {"ExerciseCommand": {
        "templateId": TI,
        "contractId": row["cid"],
        "choice": "TransferInstruction_Accept",
        "choiceArgument": {"extraArgs": {"context": context, "meta": {"values": {}}}},
    }}
    b = cli.prepare_bundle(s, p, command, f"Accept {row['amount']} CC from {row['sender']}",
                           strip_disclosed(ctx.get("disclosedContracts", [])), lc=lc,
                           meta={"executeBefore": row["executeBefore"], "expect_template_package": "splice-amulet"})
    out = Path(args.out_dir) / f"accept-{row['cid'][:16]}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    cli.write_bundle(b, str(out))
    cli.show_submission(b, synchronizer_id=s.synchronizer_id)
    cli.confirm(args, f"Sign and execute the acceptance of {row['amount']} CC from {row['sender']}?")
    b.sign(s.protocol_keys())
    cli.write_bundle(b, str(out))
    if len(b.valid_signatures()) < b.signing_threshold:
        return f"needs more signatures: cdz bundle sign {out} (each signer), then cdz tx execute {out}"
    r = cli.execute_bundle(s, b, None)
    b.meta["executed"] = {"update_id": r.get("updateId"), "offset": r.get("completionOffset")}
    cli.write_bundle(b, str(out))
    return f"accepted, update {r.get('updateId')}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--env", default=".env")
    ap.add_argument("--network")
    ap.add_argument("--party", help="party file (default CDZ_PARTY_FILE / party.json)")
    ap.add_argument("--scan", help="Scan base URL (default CDZ_SCAN_URL, or the network's known Scan)")
    ap.add_argument("--out-dir", default="cc-accept", help="where the signed bundles are kept")
    ap.add_argument("--dry-run", action="store_true", help="only list the pending transfers")
    ap.add_argument("--yes", "-y", action="store_true", help="do not ask before each acceptance")
    args = ap.parse_args(argv)
    try:
        s = cli.settings(args)
        p = cli.load_party(s)
        scan = args.scan or s.env.get("CDZ_SCAN_URL") or SCAN.get(s.network["name"])
        if not scan:
            raise cli.CliError(f"no Scan URL known for {s.network['name']}; pass --scan or set CDZ_SCAN_URL")
        dso = scan_post(scan, "/registry/metadata/v1/info")["adminId"]
        lc = cli.ledger(s)
        rows = pending(lc, p.party_id, dso)
        todo = [r for r in rows if not r["skip"]]
        for r in rows:
            state = f"skip: {r['skip']}" if r["skip"] else "pending"
            print(f"{r['cid'][:16]}…  {r['amount']} CC from {r['sender']}  (before {r['executeBefore']})  {state}", file=sys.stderr)
        print(f"{len(todo)} incoming Canton Coin transfer(s) to accept for {p.party_id}", file=sys.stderr)
        if args.dry_run or not todo:
            return 0
        failed = 0
        for r in todo:
            try:
                print(f"{r['cid'][:16]}…: {accept(args, s, p, lc, scan, r)}", file=sys.stderr)
            except cli.CliError as e:
                if str(e) == "aborted":
                    print(f"{r['cid'][:16]}…: skipped", file=sys.stderr)
                    continue
                failed += 1
                print(f"{r['cid'][:16]}…: FAILED: {e}", file=sys.stderr)
            except Exception as e:  # keep going with the other transfers
                failed += 1
                print(f"{r['cid'][:16]}…: FAILED: {e}", file=sys.stderr)
        return 1 if failed else 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
