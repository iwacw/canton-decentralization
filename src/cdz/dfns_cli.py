"""`cdz dfns ...`: party signing keys held in DFNS (Keys API).

- `keys list|create|pub`: DFNS keys and their cdz public-key JSON (`role: tx`);
- `sign-bundle`: DFNS signs exactly the hashes of a topology or submission bundle that its key
  is needed for; every signature is verified locally before the bundle copy is written, so the
  output always merges cleanly with `cdz bundle merge`;
- `sign-hash`: ad-hoc signature over any hex message (verified, printed in cdz format).

Credentials: CDZ_DFNS_AUTH_TOKEN (+ CDZ_DFNS_CRED_ID / CDZ_DFNS_PRIVATE_KEY for mutating calls).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from cdz import bundle, crypto, dfns


def _cli():
    from cdz import cli

    return cli


def client(s) -> dfns.DfnsClient:
    return dfns.DfnsClient(dfns.DfnsConfig.from_env(s.env))


def _write_pub(path: str, pub: dict, force: bool) -> None:
    p = Path(path)
    if p.exists() and not force:
        raise _cli().CliError(f"{path} exists (use --force)")
    p.write_text(json.dumps(pub, indent=2) + "\n")
    print(f"wrote public key {path}", file=sys.stderr)


def _row(k: dict) -> dict:
    r = {x: k.get(x) for x in ("id", "scheme", "curve", "status", "name", "publicKey", "custodial", "dateCreated")}
    r["gateway_visible"] = dfns.is_canton_key(k)
    try:
        r["fingerprint"] = dfns.public_key(k).fingerprint
    except ValueError:
        r["fingerprint"] = None
    for extra in ("wallets", "store", "delegatedTo"):
        if k.get(extra):
            r[extra] = k[extra]
    return r


# --- keys -----------------------------------------------------------------------------------


def cmd_keys_list(args):
    c = _cli()
    s = c.settings(args)
    d = client(s)
    keys = d.list_keys()
    if not args.all:
        keys = [k for k in keys if k.get("status") == "Active"]
    if args.wallets:  # GET /keys/{id} carries the wallet linkage; the list does not
        keys = [{**k, **d.get_key(k["id"])} if k.get("scheme") == "EdDSA" else k for k in keys]
    rows = [_row(k) for k in keys]
    if args.json:
        c.out(rows)
        return
    vis = [r for r in rows if r["gateway_visible"]]
    print(f"org {d.org_id or '?'}: {len(rows)} key(s){'' if args.all else ' (Active)'}, "
          f"{len(vis)} visible to a Wallet Gateway DFNS provider (Active EdDSA/ed25519, marked GW)")
    for r in rows:
        mark = "GW" if r["gateway_visible"] else "  "
        line = f"{mark} {r['id']}  {r['scheme']}/{r['curve']}  {r['status']}  {r['name'] or '-'}  publicKey={r['publicKey']}"
        if r["fingerprint"]:
            line += f"  fingerprint={r['fingerprint']}"
        if r.get("wallets"):
            line += "  WALLETS: " + ", ".join(f"{w.get('network')} {w.get('id')}" for w in r["wallets"])
        print(line)
    if vis:
        print("note: the gateway's service account can request signatures with ANY GW key (incl. keys of other "
              "wallets, e.g. Solana); restrict it with a DFNS approval policy or a separate org", file=sys.stderr)
    if not args.wallets and vis:
        print("hint: --wallets shows which GW keys back DFNS wallets (one GET per key)", file=sys.stderr)


def cmd_keys_create(args):
    c = _cli()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", args.name):
        raise c.CliError("key name: letters, digits, '-' and '_' only (max 100)")
    if args.pub_out and Path(args.pub_out).exists() and not args.force:
        raise c.CliError(f"{args.pub_out} exists (use --force)")
    s = c.settings(args)
    k = client(s).create_key(args.name)
    try:
        pub = dfns.pub_json(k, args.name)
    except ValueError as e:
        raise c.CliError(f"created DFNS key {k.get('id')}, but it is unusable for Canton: {e}") from None
    if args.pub_out:
        _write_pub(args.pub_out, pub, True)
    c.out({"id": k["id"], "status": k.get("status"), "publicKey": k.get("publicKey"), **pub})


def cmd_keys_pub(args):
    c = _cli()
    s = c.settings(args)
    k = client(s).get_key(args.key_id)
    if k.get("status") != "Active":
        raise c.CliError(f"DFNS key {args.key_id} is {k.get('status')}, not Active")
    pub = dfns.pub_json(k, args.name)
    if args.pub_out:
        _write_pub(args.pub_out, pub, args.force)
    c.out(pub)


# --- signing --------------------------------------------------------------------------------


class _Signer:
    """Gets verified signatures over hashes from one DFNS key; reuses given signature ids."""

    def __init__(self, d: dfns.DfnsClient, key_id: str, args):
        self.d, self.key_id, self.args = d, key_id, args
        k = d.get_key(key_id)
        if not dfns.is_canton_key(k):
            raise _cli().CliError(f"DFNS key {key_id} is {k.get('scheme')}/{k.get('curve')} {k.get('status')}; need Active EdDSA/ed25519")
        self.key = dfns.public_key(k)
        self.name = k.get("name") or key_id
        self.existing: dict[bytes, dict] = {}
        for sid in getattr(args, "signature_id", None) or []:
            r = d.get_signature(key_id, sid)
            m = dfns.signed_message(r)
            if m is None:
                raise _cli().CliError(f"{sid} is not a kind=Message signature request of {key_id}")
            self.existing[m] = r

    def check_reuse(self, needed: list[bytes], done: list[bytes] = ()) -> None:
        """Before anything is requested: every --signature-id must sign a needed (or already signed) hash."""
        for m in done:
            self.existing.pop(m, None)
        stray = [r.get("id", "?") for m, r in self.existing.items() if m not in needed]
        if stray:
            raise _cli().CliError(f"--signature-id {', '.join(stray)} does not sign any hash this key is still needed for")

    def sign_all(self, items: list[tuple[str, bytes]]) -> list[crypto.Sig]:
        """Create (or reuse) all signature requests first, then wait for each; verify every result."""
        reqs = []
        for label, data in items:
            req = self.existing.pop(data, None)
            verb = "reusing" if req else "new"
            req = req or self.d.generate_signature(self.key_id, data)
            print(f"[{label}] {verb} DFNS signature request {req.get('id')}: {req.get('status')}", file=sys.stderr)
            reqs.append(req)
        ids = " ".join(f"--signature-id {r.get('id')}" for r in reqs)
        out = []
        for (label, data), req in zip(items, reqs, strict=True):
            def pending(r, label=label):
                print(f"[{label}] {r.get('id')} is {r.get('status')}"
                      f"{' (approval ' + r['approvalId'] + ')' if r.get('approvalId') else ''}: approval needed in DFNS; "
                      f"waiting up to {self.args.timeout:.0f}s", file=sys.stderr)

            try:
                req = self.d.wait_signature(self.key_id, req, self.args.timeout, self.args.poll_interval, pending)
            except TimeoutError as e:
                raise TimeoutError(f"{e}; nothing written. After approval rerun with {ids}") from None
            try:
                out.append(dfns.verified_signature(self.key, data, req))
            except ValueError as e:
                raise _cli().CliError(str(e)) from None
        return out


def cmd_sign_bundle(args):
    c = _cli()
    s = c.settings(args)
    b = bundle.load(args.bundle)
    c.require_network(s, b)
    signer = _Signer(client(s), args.key_id, args)
    fp = signer.key.fingerprint
    if isinstance(b, bundle.TopologyBundle):
        p = c._party_or_none(s)
        for note in b.prune(p.known_keys() if p else None):
            print(f"dropped {note}", file=sys.stderr)
        c.print_topology_bundle(b, p)
        idx = b.relevant(fp)
        if args.label:
            unknown = set(args.label) - {it.label for it in b.items}
            if unknown:
                raise c.CliError(f"no transaction labelled {', '.join(sorted(unknown))} in {args.bundle}")
            idx = [i for i in idx if b.items[i].label in args.label]
        if not idx:
            raise c.CliError(f"DFNS key {args.key_id} ({fp[:16]}…) is not needed by "
                             f"{'the selected transactions of ' if args.label else ''}{args.bundle}")

        def signed(i):
            return any(sg.signed_by == fp and signer.key.verify(sg.signature, b.items[i].tx.hash) for sg in b.items[i].sigs)

        todo = [i for i in idx if not signed(i)]
        for i in idx:
            if i not in todo:
                print(f"[{b.items[i].label}] already signed by {signer.name}", file=sys.stderr)
        signer.check_reuse([b.items[i].tx.hash for i in todo], [b.items[i].tx.hash for i in idx if i not in todo])
        if todo:
            for i in todo:
                print(f"to sign with DFNS key {signer.name}: [{b.items[i].label}] {b.items[i].tx.hash.hex()}", file=sys.stderr)
            c.confirm(args, f"Request {len(todo)} DFNS signature(s) with {args.key_id}?")
            sigs = signer.sign_all([(b.items[i].label, b.items[i].tx.hash) for i in todo])
            for i, sig in zip(todo, sigs, strict=True):
                it = b.items[i]
                it.sigs = [sg for sg in it.sigs if sg.signed_by != fp] + [sig]
                print(f"signed: {it.label} <- {signer.name} (verified)", file=sys.stderr)
        c.write_bundle(b, args.output)
        ok = c.print_topology_bundle(b, p)
        print("status: " + ("fully signed" if ok else "incomplete (merge the other signers' copies)"), file=sys.stderr)
    else:
        c.require_party_match(s, b)
        h = b.verify(s.synchronizer_id)
        if fp not in {k.fingerprint for k in b.signing_keys}:
            raise c.CliError(f"DFNS key {args.key_id} ({fp[:16]}…) is not a signing key of {b.party}")
        c.show_submission(b, synchronizer_id=s.synchronizer_id)
        done = any(sg.signed_by == fp and signer.key.verify(sg.signature, h) for sg in b.sigs)
        signer.check_reuse([] if done else [h], [h] if done else [])
        if done:
            print(f"already signed by {signer.name}", file=sys.stderr)
        else:
            c.confirm(args, f"Sign this transaction for {b.party} with DFNS key {args.key_id}?")
            (sig,) = signer.sign_all([("tx", h)])
            b.sigs = [sg for sg in b.sigs if sg.signed_by != fp] + [sig]
            print(f"signed: tx <- {signer.name} (verified)", file=sys.stderr)
        c.write_bundle(b, args.output)
        c.show_submission(b, synchronizer_id=s.synchronizer_id)


def cmd_sign_hash(args):
    c = _cli()
    s = c.settings(args)
    try:
        data = dfns._hex(args.hex, "message")
    except ValueError as e:
        raise c.CliError(str(e)) from None
    if not data:
        raise c.CliError("empty message")
    signer = _Signer(client(s), args.key_id, args)
    signer.check_reuse([data])
    c.confirm(args, f"Request a DFNS signature with {args.key_id} over {data.hex()}?")
    (sig,) = signer.sign_all([("hash", data)])
    c.out({"message": data.hex(), "key_id": args.key_id, "verified": True,
           "signature_hex": sig.signature.hex(), "signature": sig.to_json()})


# --- parser ---------------------------------------------------------------------------------


def _interval(text: str) -> float:
    v = float(text)
    if v < 1:
        raise argparse.ArgumentTypeError("must be >= 1 second")
    return v


def register(sub, add, yes):
    top = sub.add_parser("dfns", help="party signing keys held in DFNS (Keys API)").add_subparsers(dest="sub", required=True)
    keys = top.add_parser("keys", help="DFNS keys").add_subparsers(dest="sub2", required=True)
    p = add(keys, "list", cmd_keys_list, "list DFNS keys (read-only); GW = visible to a Wallet Gateway DFNS provider")
    p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="include Archived keys")
    p.add_argument("--wallets", action="store_true", help="fetch each EdDSA key for its wallet linkage")
    p = add(keys, "create", cmd_keys_create, "create an EdDSA/ed25519 key in DFNS and export its cdz public JSON")
    p.add_argument("--name", required=True)
    p.add_argument("--pub-out", help="write the cdz public key JSON (role tx) here")
    p.add_argument("--force", action="store_true", help="overwrite --pub-out")
    p = add(keys, "pub", cmd_keys_pub, "cdz public key JSON (role tx) of an existing DFNS key")
    p.add_argument("key_id")
    p.add_argument("--name", help="name in the JSON (default: the DFNS key name)")
    p.add_argument("--pub-out")
    p.add_argument("--force", action="store_true")

    def signing(p):
        p.add_argument("--key-id", required=True, help="DFNS key id (key-…)")
        p.add_argument("--signature-id", action="append", help="reuse an existing DFNS signature request (e.g. after approval)")
        p.add_argument("--timeout", type=float, default=600, help="seconds to wait for a pending approval (default 600)")
        p.add_argument("--poll-interval", type=_interval, default=3, help="seconds between status polls (>= 1)")
        yes(p)

    p = add(top, "sign-bundle", cmd_sign_bundle, "DFNS-sign what a bundle needs from the key; verified before writing")
    p.add_argument("bundle")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--label", action="append", help="only these transactions (default: all that need the key)")
    signing(p)
    p = add(top, "sign-hash", cmd_sign_hash, "ad-hoc DFNS signature over a hex message, verified locally")
    p.add_argument("hex")
    signing(p)
