"""`cdz` command line."""

from __future__ import annotations

import argparse
import builtins
import datetime as dt
import functools
import json
import os
import re
import sys
from pathlib import Path

from cdz import __version__, authz, bundle, crypto, manage, prepared, topology
from cdz.config import ConfigError, Settings
from cdz.party import Member, PartySpec
from cdz.utilities import UtilitiesError


class CliError(Exception):
    pass


# --- helpers --------------------------------------------------------------------------------


def out(obj) -> None:
    print(json.dumps(obj, indent=2) if not isinstance(obj, str) else obj)


def confirm(args, question: str) -> None:
    if getattr(args, "yes", False):
        return
    if not sys.stdin.isatty():
        raise CliError(f"{question} (refusing without a TTY; pass --yes)")
    sys.stderr.write(f"{question} [y/N] ")
    sys.stderr.flush()
    if sys.stdin.readline().strip().lower() not in ("y", "yes"):
        raise CliError("aborted")


def settings(args) -> Settings:
    s = Settings.load(args.env, args.network)
    if args.party:
        s.party_file = args.party
    return s


def load_party(s: Settings) -> PartySpec:
    if not Path(s.party_file).is_file():
        raise CliError(f"party file {s.party_file} not found (create it with `cdz party new`)")
    p = PartySpec.load(s.party_file)
    if p.network != s.network["name"]:
        raise CliError(f"party file is for {p.network}, but the selected network is {s.network['name']}")
    return p


def ledger(s: Settings, url: str | None = None):
    from cdz.ledger import LedgerClient, TokenProvider

    url = url or s.require("ledger_url", "CDZ_LEDGER_URL")
    return LedgerClient(url, TokenProvider(s.env), user_id=s.ledger_user)


def admin_client(s: Settings, addr: str | None = None):
    from cdz.admin import AdminClient

    return AdminClient(addr or s.require("admin_addr", "CDZ_ADMIN_ADDR"), tls=s.admin_tls, ca_file=s.admin_ca,
                       cert_file=s.env.get("CDZ_ADMIN_CERT") or None, key_file=s.env.get("CDZ_ADMIN_KEY") or None)


def sync_id(s: Settings, lc=None) -> str:
    if s.synchronizer_id and not lc:
        return s.synchronizer_id
    if lc is None:
        raise CliError("set CDZ_SYNCHRONIZER_ID (or CDZ_LEDGER_URL to discover it)")
    return lc.synchronizer_id(s.synchronizer_id)


def read_pub(path: str, role: str | None = None) -> Member:
    d = json.loads(Path(path).read_text()) if path != "-" else json.load(sys.stdin)
    if role and d.get("role") and d["role"] != role:
        raise CliError(f"{path} is a {d['role']} key, expected a {role} key")
    return Member(d.get("name", Path(path).stem), crypto.PublicKey.from_json(d))


def parse_host(text: str) -> tuple[str, str]:
    uid, _, perm = text.partition("=")
    perm = perm or "confirmation"
    if perm not in topology.PERMISSIONS:
        raise CliError(f"unknown permission {perm}")
    return topology.participant_uid(uid), perm


def local_keys(s: Settings, names: list[str] | None, roles: str = "ns,tx") -> list[crypto.SigningKey]:
    keys = []
    if "ns" in roles:
        keys += s.namespace_keys()
    if "tx" in roles:
        keys += s.protocol_keys()
    if names:
        keys = [k for k in keys if k.name in names or k.fingerprint in names]
    return keys


def write_bundle(b, path: str) -> None:
    bundle.save(b, path)
    print(f"wrote {path}", file=sys.stderr)


def print_topology_bundle(b: bundle.TopologyBundle, party: PartySpec | None = None, strict: bool = False, file=None) -> bool:
    """Human review of a topology bundle (stderr by default; stdout carries JSON results).
    Everything shown is decoded from the transaction bytes; the change summary is recomputed."""
    file = file or sys.stderr
    print = functools.partial(builtins.print, file=file)
    names = party.member_name if party else (lambda fp: fp[:12] + "…")
    print(f"{b.description}  [{b.network} {b.synchronizer_id or ''}]")
    if b.base:
        print(f"note: READY/MISSING and serials are computed against the {len(b.base)} base mapping(s) supplied with "
              "the bundle; `cdz bundle show --live` checks them against the node")
    ok = True
    diffs = b.diffs()
    for (it, rep, expected), diff in zip(b.check(party.known_keys() if party else None, assume_participants=not strict), diffs, strict=True):
        d = it.tx.describe()
        status = "READY" if rep.satisfied else "MISSING"
        ok &= rep.satisfied
        print(f"\n[{it.label}] {d['mapping']} op={d['op']} serial={d['serial']} (expected {expected}) {status}")
        print(f"  hash {d['hash']}")
        if not diff.get("new"):
            print("  CHANGE: " + (json.dumps(diff) if diff else "none (same content as the current mapping)"))
        for k, v in d.items():
            if k not in ("mapping", "op", "serial", "hash"):
                print(f"  {k}: {json.dumps(v)}")
        if rep.valid_signers:
            print("  signed by: " + ", ".join(names(f) for f in rep.valid_signers))
        if rep.invalid_signers:
            print("  INVALID signatures from: " + ", ".join(rep.invalid_signers))
        if rep.unknown_signers:
            print("  unverifiable signatures from: " + ", ".join(f[:12] + "…" for f in rep.unknown_signers))
        for m in rep.missing:
            print(f"  missing: {m}")
        for p in rep.participants:
            print(f"  needs approval by participant {p}")
        if d["serial"] != expected:
            print(f"  WARNING: serial {d['serial']} but the base state implies {expected}")
    return ok


def require_network(s: Settings, b) -> None:
    if b.network != s.network["name"]:
        raise CliError(f"bundle is for network {b.network!r}, the selected network is {s.network['name']!r}")


def require_party_match(s: Settings, b: bundle.SubmissionBundle) -> PartySpec:
    """Submission bundles are checked against the local party.json, never only against themselves."""
    p = load_party(s)
    if b.party != p.party_id:
        raise CliError(f"bundle is for {b.party}, party.json is {p.party_id}")
    want = {m.key.fingerprint for m in p.signing_keys}
    if {k.fingerprint for k in b.signing_keys} != want or b.signing_threshold != p.signing_threshold:
        raise CliError("the bundle's signing keys/threshold differ from party.json (update party.json after checking `cdz party status`)")
    if not s.synchronizer_id:
        raise CliError("set CDZ_SYNCHRONIZER_ID (public) so the bundle's synchronizer can be checked")
    return p


# --- keys -----------------------------------------------------------------------------------


def cmd_keys_generate(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", args.name):
        raise CliError("key name: letters, digits, '-' and '_' only")
    k = crypto.SigningKey.generate(args.spec, args.name)
    prefix = "CDZ_NS_KEY_" if args.role == "ns" else "CDZ_TX_KEY_"
    var = f"{prefix}{args.name.upper().replace('-', '_')}"
    line = f"{var}={k.pkcs8_b64()}\n"
    if args.env_out:
        p = Path(args.env_out)
        existing = p.read_text() if p.exists() else ""
        if f"{var}=" in existing:
            raise CliError(f"{var} already exists in {p}")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(("\n" if existing and not existing.endswith("\n") else "") + line)
        os.chmod(p, 0o600)
        print(f"appended {var} to {p}", file=sys.stderr)
    elif args.print_private:
        print("# private key, keep secret:", file=sys.stderr)
        print(line, end="", file=sys.stderr)
    else:
        raise CliError("pass --env-out FILE (or --print-private to show the private key on the terminal)")
    pub = {"name": args.name, "role": args.role, **k.public.to_json()}
    if args.pub_out:
        Path(args.pub_out).write_text(json.dumps(pub, indent=2) + "\n")
        print(f"wrote public key {args.pub_out}", file=sys.stderr)
    out(pub)


def cmd_keys_list(args):
    s = settings(args)
    rows = [{"role": "ns", "name": k.name, **k.public.to_json()} for k in s.namespace_keys()]
    rows += [{"role": "tx", "name": k.name, **k.public.to_json()} for k in s.protocol_keys()]
    for r in rows:
        r.pop("spki")
    out(rows)


def cmd_keys_public(args):
    s = settings(args)
    keys = local_keys(s, [args.name], args.role)
    if len(keys) != 1:
        raise CliError(f"expected exactly one {args.role} key named {args.name}, found {len(keys)}")
    out({"name": keys[0].name, "role": args.role, **keys[0].public.to_json()})


# --- party ----------------------------------------------------------------------------------


def cmd_party_new(args):
    s = settings(args)
    owners = [read_pub(x, "ns") for x in args.owner]
    signers = [read_pub(x, "tx") for x in args.signing_key]
    if {m.key.fingerprint for m in owners} & {m.key.fingerprint for m in signers}:
        raise CliError("use separate keys for namespace ownership and transaction signing")
    hosts = [parse_host(h) for h in args.host]
    spec = PartySpec(
        hint=args.hint,
        owners=owners,
        dns_threshold=args.owners_threshold,
        signing_keys=signers,
        signing_threshold=args.signing_threshold,
        hosts=hosts,
        confirmation_threshold=args.confirmation_threshold,
        network=s.network["name"],
    )
    spec.p2p_mapping()  # validates thresholds and permissions
    topology.decentralized_namespace(spec.owner_namespaces, spec.dns_threshold)
    if Path(args.output).exists() and not args.force:
        raise CliError(f"{args.output} exists (use --force)")
    spec.save(args.output)
    print(f"wrote {args.output}", file=sys.stderr)
    out({"party_id": spec.party_id, "namespace": spec.namespace})


def cmd_party_show(args):
    s = settings(args)
    p = load_party(s)
    out(p.to_json())


def cmd_party_onboard_bundle(args):
    s = settings(args)
    p = load_party(s)
    skip, base = set(), []
    sync = s.synchronizer_id
    if args.check_existing:
        a = admin_client(s)
        sync = sync or sync_id(s, ledger(s))
        for o in p.owner_namespaces:
            for r in a.namespace_delegations(sync, o):
                n = admin_item(r)
                if n.namespace == o and crypto.PublicKey.from_proto(n.target_key).fingerprint == o:
                    skip.add(o)  # root certificate already on the synchronizer: reuse it
                    base.append(topology.Tx.build(topology.tpb.TopologyMapping(namespace_delegation=n), max(r.context.serial, 1)))
    b = bundle.TopologyBundle(
        s.network["name"],
        sync,
        f"Onboard external party {p.party_id}",
        [bundle.Item(l, t) for l, t in p.onboarding_txs(skip)],
        base=base,
        meta={"party_id": p.party_id, "operation": "onboard"},
    )
    write_bundle(b, args.output)
    print_topology_bundle(b, p)


def admin_item(res):
    from cdz.admin import item

    return item(res)


def cmd_party_allocate(args):
    """Run on EACH hosting participant (needs a ParticipantAdmin token for that node)."""
    s = settings(args)
    b = bundle.load(args.bundle)
    if not isinstance(b, bundle.TopologyBundle):
        raise CliError("not a topology bundle")
    require_network(s, b)
    pp = _party_or_none(s)
    for note in b.prune(pp.known_keys() if pp else None):
        print(f"dropped {note}", file=sys.stderr)
    lc = ledger(s, args.ledger_url)
    sync = b.synchronizer_id or sync_id(s, lc)
    me = lc.participant_id()
    party = b.meta.get("party_id")
    p2p = [it.tx.mapping.party_to_participant for it in b.items if it.tx.kind == "party_to_participant"]
    if p2p and not any(topology.participant_uid(me) == h.participant_uid for h in p2p[0].participants):
        raise CliError(f"this node ({me}) is not a host in the bundle's PartyToParticipant")
    if not print_topology_bundle(b) and not args.allow_incomplete:
        raise CliError("bundle is not fully signed by the party (see MISSING); use --allow-incomplete to send anyway")
    confirm(args, f"Allocate {party} on {me}?")
    multi = b.multi_over_all()
    txs = [(it.tx.serialized, it.sigs) for it in b.items]
    pid = lc.allocate_external_party(sync, txs, multi=multi, user_id=args.user)
    out({"party_id": pid, "participant": me, "note": "becomes active once every host has allocated; check `cdz party status`"})


def cmd_party_grant_user(args):
    """Node operator: give an app user read + execute rights for the party on THIS node."""
    s = settings(args)
    p = load_party(s)
    lc = ledger(s, args.ledger_url)
    created = lc.ensure_user(args.user) if args.create else False
    rights = {"read_as": [p.party_id], "execute_as": [p.party_id]}
    if args.act_as:
        rights = {"act_as": [p.party_id]}
    lc.grant_rights(args.user, **rights)
    out({"user": args.user, "created": created, "party": p.party_id, "rights": sorted(rights)})


def cmd_party_status(args):
    s = settings(args)
    p = load_party(s)
    a = admin_client(s)
    sync = sync_id(s, ledger(s) if not s.synchronizer_id else None)
    st = a.state(sync, namespaces=[p.namespace], parties=[p.party_id])
    res = {"party_id": p.party_id, "synchronizer_id": sync}
    d = st.dns.get(p.namespace)
    res["dns"] = (
        {"serial": st.serials.get(("decentralized_namespace_definition", p.namespace)), "threshold": d.threshold, "owners": list(d.owners)}
        if d
        else None
    )
    pp = st.p2p.get(p.party_id)
    res["party_to_participant"] = (
        {"serial": st.serials.get(("party_to_participant", p.party_id)), **topology.describe_mapping(topology.tpb.TopologyMapping(party_to_participant=pp))}
        if pp
        else None
    )
    res["proposals"] = [
        {"serial": r.context.serial, "hash": r.context.transaction_hash.hex(), "signed_by": list(r.context.signed_by_fingerprints)}
        for r in a.party_to_participant(sync, p.party_id, proposals=True)
    ]
    drift = []
    if d and (sorted(d.owners) != p.owner_namespaces or d.threshold != p.dns_threshold):
        drift.append("DNS owners/threshold differ from party.json")
    if pp:
        want = topology.describe_mapping(p.p2p_mapping())
        have = res["party_to_participant"]
        for k in ("confirmation_threshold", "hosts", "signing_threshold", "signing_keys"):
            if want.get(k) != have.get(k):
                drift.append(f"{k} differs from party.json")
    delegates = authz.namespace_delegates(st, p.namespace)
    if delegates:
        drift.append(f"WARNING: {len(delegates)} key(s) delegated directly in the party namespace can act WITHOUT the "
                     f"owner threshold: {', '.join(delegates)}")
    res["drift"] = drift
    out(res)


# --- bundles --------------------------------------------------------------------------------


def _party_or_none(s):
    try:
        return load_party(s)
    except CliError:
        return None


def cmd_bundle_show(args):
    s = settings(args)
    b = bundle.load(args.file)
    if isinstance(b, bundle.TopologyBundle):
        ok = print_topology_bundle(b, _party_or_none(s), strict=args.strict, file=sys.stdout)
        if args.live:
            for line in live_base_check(s, b):
                print(line)
        print("\nstatus: " + ("fully signed" if ok else "incomplete"))
    else:
        show_submission(b, file=sys.stdout, synchronizer_id=s.synchronizer_id)


def live_base_check(s: Settings, b: bundle.TopologyBundle) -> list[str]:
    """Compare the bundle's base state with the node's head state."""
    namespaces, parties = set(), set()
    for t in b.base + [it.tx for it in b.items]:
        key = t.unique_key()
        if key[0] == "party_to_participant":
            parties.add(key[1])
            namespaces.add(key[1].split("::")[1])
        elif key[0] in ("decentralized_namespace_definition", "namespace_delegation"):
            namespaces.add(key[1])
    st = admin_client(s).state(b.synchronizer_id or sync_id(s), namespaces=sorted(namespaces), parties=sorted(parties))
    out = []
    for t in b.base:
        live = authz.previous_mapping(st, t)
        if live is None:
            out.append(f"LIVE MISMATCH: base mapping {t.unique_key()[:2]} is not active on the node")
        elif live != t.mapping or st.serials.get(t.unique_key()) != t.tx.serial:
            out.append(f"LIVE MISMATCH: base mapping {t.unique_key()[:2]} differs from the node (serial {st.serials.get(t.unique_key())})")
    return out or ["live check: base state matches the node"]


def cmd_bundle_sign(args):
    s = settings(args)
    if args.output and len(args.files) > 1:
        raise CliError("-o works with a single bundle only")
    for path in args.files:
        b = bundle.load(path)
        require_network(s, b)
        if isinstance(b, bundle.TopologyBundle):
            p = _party_or_none(s)
            for note in b.prune(p.known_keys() if p else None):
                print(f"dropped {note}", file=sys.stderr)
            print_topology_bundle(b, p)
            if args.live:
                for line in live_base_check(s, b):
                    print(line, file=sys.stderr)
            keys = local_keys(s, args.key, args.roles)
            relevant = [k for k in keys if b.relevant(k.fingerprint)]
            if not relevant:
                raise CliError(f"{path}: none of the local keys is needed by this bundle")
            confirm(args, f"Sign with {', '.join(k.name for k in relevant)}?")
            done = b.sign(relevant, use_multi=args.multi)
        else:
            require_party_match(s, b)
            keys = local_keys(s, args.key, "tx")  # only party signing keys sign transactions
            if not keys:
                raise CliError("no local party signing keys (CDZ_TX_KEY_*) matched")
            b.verify(s.synchronizer_id)
            show_submission(b, synchronizer_id=s.synchronizer_id)
            confirm(args, f"Sign this transaction for {b.party}?")
            done = b.sign(keys)
        for d in done:
            print(f"signed: {d}", file=sys.stderr)
        if not done:
            print(f"{path}: nothing new to sign", file=sys.stderr)
        write_bundle(b, args.output or path)


def cmd_bundle_merge(args):
    s = settings(args)
    p = _party_or_none(s)
    bs = [bundle.load(f) for f in args.inputs]
    base = bs[0]
    if isinstance(base, bundle.TopologyBundle):
        extra = p.known_keys() if p else None
        for note in base.prune(extra):
            print(f"dropped {note}", file=sys.stderr)
        n = sum(base.merge(o, extra) for o in bs[1:])
    else:
        n = sum(base.merge(o) for o in bs[1:])
        base.sigs = base.valid_signatures()
    write_bundle(base, args.output)
    print(f"merged {n} signatures", file=sys.stderr)


# --- topology -------------------------------------------------------------------------------


def cmd_topology_submit(args):
    s = settings(args)
    b = bundle.load(args.bundle)
    require_network(s, b)
    p = _party_or_none(s)
    extra = p.known_keys() if p else None
    for note in b.prune(extra):
        print(f"dropped {note}", file=sys.stderr)
    complete = print_topology_bundle(b, p, strict=True)
    a = admin_client(s)
    sync = b.synchronizer_id or sync_id(s)
    if s.synchronizer_id and sync != s.synchronizer_id:
        raise CliError(f"bundle targets {sync}, CDZ_SYNCHRONIZER_ID is {s.synchronizer_id}")
    if not complete and not args.proposal:
        raise CliError("not fully authorized yet (participants and/or signers missing); pass --proposal to submit as proposal")
    confirm(args, f"Submit {len(b.items)} topology transaction(s) to {sync}?")
    flags = [not rep.satisfied for _, rep, _ in b.check(extra, assume_participants=False)]
    a.add_transactions(sync, b.signed_transactions(proposal=flags, extra=extra), force=args.force or [])
    out({"submitted": [{"label": it.label, "hash": it.tx.hash.hex(), "proposal": f} for it, f in zip(b.items, flags, strict=True)]})


def cmd_topology_approve(args):
    """For a hosting participant's operator: sign with the NODE's keys via its Admin API.
    With --hash the pending proposal is fetched, decoded and checked before anything is signed."""
    s = settings(args)
    a = admin_client(s, args.admin_addr)
    sync = s.synchronizer_id or sync_id(s, ledger(s))
    if args.hash:
        if not args.participant:
            raise CliError("--hash needs --participant <this node's uid> to check what the proposal changes for it")
        p = load_party(s)
        me = topology.participant_uid(args.participant)
        props = [r for r in a.party_to_participant(sync, p.party_id, proposals=True)
                 if r.context.transaction_hash.hex() == args.hash.lower()]
        if not props:
            raise CliError(f"no pending PartyToParticipant proposal {args.hash} for {p.party_id}")
        proposed = admin_item(props[0])
        current = a.state(sync, parties=[p.party_id]).p2p.get(p.party_id)
        serial = max(props[0].context.serial, 1)
        tx = topology.Tx.build(topology.tpb.TopologyMapping(party_to_participant=proposed), serial)
        base = ([topology.Tx.build(topology.tpb.TopologyMapping(party_to_participant=current), max(serial - 1, 1))]
                if current is not None else [])
        diff = bundle.TopologyBundle(s.network["name"], sync, "", [bundle.Item("p2p", tx)], base=base).diffs()[0]
        print(json.dumps({"proposal": topology.describe_mapping(tx.mapping), "change": diff}, indent=2), file=sys.stderr)
        hosts_before = {h.participant_uid: h for h in (current.participants if current else [])}
        hosts_after = {h.participant_uid: h for h in proposed.participants}
        if me not in hosts_after:
            raise CliError(f"refusing: {me} is not a host in this proposal")
        if current is None:
            # new party: the proposal must be exactly the hosting defined in party.json
            want, got = topology.describe_mapping(p.p2p_mapping()), topology.describe_mapping(tx.mapping)
            norm = lambda d: {**d, "hosts": sorted(d["hosts"], key=lambda h: h["participant"]),  # noqa: E731
                              "signing_keys": sorted(d.get("signing_keys", []))}
            if norm(want) != norm(got):
                raise CliError("refusing: the proposal differs from the PartyToParticipant defined in party.json")
        else:
            touched = {u for u in hosts_after if u not in hosts_before or hosts_after[u] != hosts_before[u]}
            if touched - {me}:
                raise CliError(f"refusing: the proposal must only add or change {me} (it touches {sorted(touched)})")
            if proposed.threshold != current.threshold or authz.signing_keys_value(proposed) != authz.signing_keys_value(current):
                raise CliError("refusing: the proposal also changes thresholds or signing keys; approve it only after review by the party owners")
        confirm(args, f"Authorize proposal {args.hash} with this node's keys?")
        t = a.authorize_hash(sync, args.hash)
    else:
        b = bundle.load(args.bundle)
        require_network(s, b)
        it = b.items[args.index]
        print_topology_bundle(b, _party_or_none(s))
        confirm(args, f"Propose/approve [{it.label}] with this node's keys?")
        t = a.authorize_mapping(sync, it.tx.mapping, it.tx.tx.serial, it.tx.tx.operation)
        if t.transaction != it.tx.serialized:
            print("note: node serialized the mapping differently from the bundle", file=sys.stderr)
    out({"authorized": topology.Tx(t.transaction).hash.hex(), "proposal": t.proposal})


def _state_for_party(s, p: PartySpec, extra_namespaces=()):
    a = admin_client(s)
    sync = s.synchronizer_id or sync_id(s, ledger(s))
    return a.state(sync, namespaces=[p.namespace, *extra_namespaces], parties=[p.party_id]), sync


def cmd_topology_plan_party(args):
    s = settings(args)
    p = load_party(s)
    st, sync = _state_for_party(s, p)
    b = manage.plan_party_change(
        st,
        p.party_id,
        s.network["name"],
        sync,
        add_keys=[read_pub(x, "tx").key for x in args.add_key],
        remove_keys=args.remove_key,
        signing_threshold=args.signing_threshold,
        add_hosts=[parse_host(h) for h in args.add_host],
        remove_hosts=args.remove_host,
        confirmation_threshold=args.confirmation_threshold,
        onboarding=not args.no_onboarding,
    )
    write_bundle(b, args.output)
    print_topology_bundle(b, p)


def cmd_topology_plan_dns(args):
    s = settings(args)
    p = load_party(s)
    new_owners = [read_pub(x, "ns").key for x in args.add_owner]
    st, sync = _state_for_party(s, p, [k.fingerprint for k in new_owners])
    b = manage.plan_dns_change(
        st,
        p.namespace,
        s.network["name"],
        sync,
        add_owners=new_owners,
        remove_owners=args.remove_owner,
        threshold=args.threshold,
    )
    write_bundle(b, args.output)
    print_topology_bundle(b, p)


def cmd_topology_plan_clear_onboarding(args):
    s = settings(args)
    p = load_party(s)
    st, sync = _state_for_party(s, p)
    b = manage.plan_clear_onboarding(st, p.party_id, args.participant, s.network["name"], sync)
    write_bundle(b, args.output)
    print_topology_bundle(b, p)


# --- interactive submission -----------------------------------------------------------------


def show_submission(b: bundle.SubmissionBundle, file=None, synchronizer_id: str | None = None) -> None:
    file = file or sys.stderr
    print = functools.partial(builtins.print, file=file)
    try:
        h = b.verify(synchronizer_id)
        verdict = f"hash verified locally: {h.hex()}"
    except Exception as e:  # show the reason, signing will refuse
        verdict = f"VERIFICATION FAILED: {e}"
    summary = prepared.summarize(b.prepared)
    print(f"{b.description or 'transaction'} for {b.party}  [{b.network}]")
    print(f"scheme {prepared.SCHEME_NAMES[b.scheme]}; {verdict}")
    if b.scheme == prepared.SCHEMES["HASHING_SCHEME_VERSION_V2"] and b.prepared.metadata.HasField("max_record_time"):
        print("WARNING: max_record_time is NOT covered by a V2 signature; the executing node may ignore it")
    shown = {k: v for k, v in b.meta.items() if k in ("executeBefore", "transferKind", "executed", "prepared_via")}
    if shown:
        print("meta: " + json.dumps(shown))
    print(json.dumps(summary, indent=2))
    valid = b.valid_signatures() if verdict.startswith("hash") else []
    names = ", ".join(s.signed_by[:12] + "…" for s in valid) or "none"
    print(f"signatures: {len(valid)}/{b.signing_threshold} valid ({names})")


def prepare_bundle(s: Settings, p: PartySpec, command: dict, description: str, disclosed=(), ttl_s: int | None = None,
                   scheme: str = "HASHING_SCHEME_VERSION_V2", lc=None, meta: dict | None = None) -> bundle.SubmissionBundle:
    lc = lc or ledger(s)
    sync = sync_id(s, lc)
    mrt = None
    if ttl_s and scheme == "HASHING_SCHEME_VERSION_V2":
        # max_record_time is only covered by the signature from hashing scheme V3 on
        print("note: --ttl needs hashing scheme V3 to be signed; using V3", file=sys.stderr)
        scheme = "HASHING_SCHEME_VERSION_V3"
    if ttl_s:
        mrt = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl_s)).isoformat().replace("+00:00", "Z")
    r = lc.prepare(p.party_id, command, synchronizer_id=sync, disclosed=list(disclosed), max_record_time=mrt, scheme=scheme)
    b = bundle.SubmissionBundle(
        network=s.network["name"],
        synchronizer_id=sync,
        party=p.party_id,
        prepared_b64=r["preparedTransaction"],
        scheme=prepared.scheme_of(r["hashingSchemeVersion"]),
        node_hash=crypto.unb64(r["preparedTransactionHash"]),
        intent=command,
        signing_keys=[m.key for m in p.signing_keys],
        signing_threshold=p.signing_threshold,
        description=description,
        meta={"prepared_via": lc.base, **(meta or {})},
    )
    b.verify()
    return b


def finish_prepared(args, s: Settings, b: bundle.SubmissionBundle) -> None:
    """Write the bundle; with --execute, sign with local keys and execute if the threshold is met."""
    output = getattr(args, "output", None)
    if output:
        write_bundle(b, output)
    show_submission(b)
    if getattr(args, "execute", False):
        keys = s.protocol_keys()
        confirm(args, f"Sign with {len(keys)} local key(s) and execute?")
        b.sign(keys)
        if output:
            write_bundle(b, output)
        r = execute_bundle(s, b, None)
        b.meta["executed"] = {"update_id": r.get("updateId"), "offset": r.get("completionOffset")}
        if output:
            write_bundle(b, output)


def execute_bundle(s: Settings, b: bundle.SubmissionBundle, url: str | None):
    require_network(s, b)
    require_party_match(s, b)
    b.verify(s.synchronizer_id)
    valid = b.valid_signatures()
    if len(valid) < b.signing_threshold:
        raise CliError(f"{len(valid)} valid signatures, threshold is {b.signing_threshold}")
    r = ledger(s, url).execute_and_wait(b.prepared_b64, b.party, valid, prepared.SCHEME_NAMES[b.scheme])
    out({"executed": True, **r})
    return r


def cmd_tx_prepare(args):
    s = settings(args)
    p = load_party(s)
    if args.command_file:
        command = json.loads(Path(args.command_file).read_text())
    elif args.create:
        command = {"CreateCommand": {"templateId": args.create, "createArguments": json.loads(args.args or "{}")}}
    elif args.exercise:
        if not (args.cid and args.choice):
            raise CliError("--exercise needs --cid and --choice")
        command = {
            "ExerciseCommand": {
                "templateId": args.exercise,
                "contractId": args.cid,
                "choice": args.choice,
                "choiceArgument": json.loads(args.args or "{}"),
            }
        }
    else:
        raise CliError("give --command-file, --create or --exercise")
    disclosed = json.loads(Path(args.disclosed).read_text()) if args.disclosed else []
    if args.ttl and args.scheme == "v2":
        raise CliError("--ttl is not covered by a V2 signature; use --scheme v3 (or omit --scheme)")
    scheme = args.scheme or ("v3" if args.ttl else "v2")
    b = prepare_bundle(s, p, command, args.description or "", disclosed, args.ttl, f"HASHING_SCHEME_VERSION_{scheme.upper()}")
    finish_prepared(args, s, b)


def cmd_tx_execute(args):
    s = settings(args)
    for path in args.bundles:
        b = bundle.load(path)
        if not isinstance(b, bundle.SubmissionBundle):
            raise CliError(f"{path}: not a submission bundle")
        if b.meta.get("executed"):
            print(f"{path}: already executed ({b.meta['executed']}), skipping", file=sys.stderr)
            continue
        show_submission(b)
        confirm(args, f"Execute {path}?")
        r = execute_bundle(s, b, args.ledger_url)
        b.meta["executed"] = {"update_id": r.get("updateId"), "offset": r.get("completionOffset")}
        write_bundle(b, path)


# --- status ---------------------------------------------------------------------------------


def cmd_status(args):
    s = settings(args)
    res = {"network": s.network["name"], "version": __version__, "party_file": s.party_file}
    lc = None
    if s.ledger_url:
        try:
            lc = ledger(s)
            res["participant"] = lc.participant_id()
            res["synchronizers"] = lc.connected_synchronizers()
        except Exception as e:
            res["ledger_error"] = str(e)
            lc = None
    if s.admin_addr:
        try:
            sync = s.synchronizer_id or (lc.synchronizer_id() if lc else None)
            if sync:
                res["signing_windows"] = admin_client(s).signing_windows(sync)
        except Exception as e:
            res["admin_error"] = str(e)
    res["local_keys"] = {"ns": [k.fingerprint for k in s.namespace_keys()], "tx": [k.fingerprint for k in s.protocol_keys()]}
    out(res)


# --- parser ---------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cdz", description=__doc__)
    ap.add_argument("--env", default=os.environ.get("CDZ_ENV_FILE", ".env"), help="dotenv file (default .env)")
    ap.add_argument("--network", help="devnet | mainnet | path to a network TOML (default CDZ_NETWORK)")
    ap.add_argument("--party", help="party definition file (default CDZ_PARTY_FILE or party.json)")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(parent, name, fn, help_):
        p = parent.add_parser(name, help=help_, description=help_)
        p.set_defaults(fn=fn)
        return p

    def yes(p):
        p.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")

    add(sub, "status", cmd_status, "connectivity and local key check")

    keys = sub.add_parser("keys", help="key management").add_subparsers(dest="sub", required=True)
    p = add(keys, "generate", cmd_keys_generate, "generate a key; private part goes to an env file")
    p.add_argument("--role", choices=["ns", "tx"], required=True, help="ns = DNS owner (namespace) key, tx = party signing key")
    p.add_argument("--spec", choices=list(crypto.SPECS), default="ed25519")
    p.add_argument("--name", required=True)
    p.add_argument("--env-out", help="append CDZ_*_KEY_<NAME>=... to this file (0600)")
    p.add_argument("--print-private", action="store_true", help="print the private key to stderr instead")
    p.add_argument("--pub-out", help="write the public key JSON here")
    add(keys, "list", cmd_keys_list, "list local keys (fingerprints only)")
    p = add(keys, "public", cmd_keys_public, "print a local key's public JSON for the coordinator")
    p.add_argument("--name", required=True)
    p.add_argument("--role", choices=["ns", "tx"], required=True)

    party = sub.add_parser("party", help="party definition and onboarding").add_subparsers(dest="sub", required=True)
    p = add(party, "new", cmd_party_new, "create party.json from public keys")
    p.add_argument("--hint", required=True, help="party id prefix, e.g. acme-registrar")
    p.add_argument("--owner", action="append", required=True, help="DNS owner public key JSON (repeat)")
    p.add_argument("--owners-threshold", type=int, required=True)
    p.add_argument("--signing-key", action="append", required=True, help="party signing public key JSON (repeat)")
    p.add_argument("--signing-threshold", type=int, required=True)
    p.add_argument("--host", action="append", required=True, help="participant uid[=confirmation|observation] (repeat)")
    p.add_argument("--confirmation-threshold", type=int, required=True)
    p.add_argument("-o", "--output", default="party.json")
    p.add_argument("--force", action="store_true")
    add(party, "show", cmd_party_show, "print the party definition")
    p = add(party, "onboard-bundle", cmd_party_onboard_bundle, "build the onboarding bundle (NSDs, DNS, PartyToParticipant)")
    p.add_argument("-o", "--output", default="onboard.bundle.json")
    p.add_argument("--check-existing", action="store_true", help="skip owner NSDs already on the synchronizer (Admin API)")
    p = add(party, "allocate", cmd_party_allocate, "AllocateExternalParty on one hosting node (run on each host)")
    p.add_argument("bundle")
    p.add_argument("--ledger-url", help="JSON Ledger API of this host (default CDZ_LEDGER_URL)")
    p.add_argument("--user", help="ledger user that gets actAs on the new party on this node")
    p.add_argument("--allow-incomplete", action="store_true")
    yes(p)
    add(party, "status", cmd_party_status, "topology state of the party on the synchronizer (Admin API)")
    p = add(party, "grant-user", cmd_party_grant_user, "node operator: grant a ledger user read+execute rights for the party")
    p.add_argument("--user", required=True)
    p.add_argument("--create", action="store_true", help="create the user if missing")
    p.add_argument("--act-as", action="store_true", help="grant CanActAs instead (implies read and execute)")
    p.add_argument("--ledger-url")

    bun = sub.add_parser("bundle", help="offline signing bundles").add_subparsers(dest="sub", required=True)
    p = add(bun, "show", cmd_bundle_show, "decode, re-hash and check a bundle")
    p.add_argument("file")
    p.add_argument("--strict", action="store_true", help="do not assume participant approvals")
    p.add_argument("--live", action="store_true", help="compare the bundle's base state with the node (Admin API)")
    p = add(bun, "sign", cmd_bundle_sign, "sign with local keys (only where they are needed)")
    p.add_argument("files", nargs="+")
    p.add_argument("-o", "--output", help="write here instead of in place")
    p.add_argument("--key", action="append", help="only these key names/fingerprints")
    p.add_argument("--roles", default="ns,tx")
    p.add_argument("--multi", action="store_true", help="one signature over the combined hash of all transactions")
    p.add_argument("--live", action="store_true", help="compare the bundle's base state with the node (Admin API)")
    yes(p)
    p = add(bun, "merge", cmd_bundle_merge, "merge signatures from several copies of a bundle")
    p.add_argument("output")
    p.add_argument("inputs", nargs="+")

    top = sub.add_parser("topology", help="topology management (Admin API)").add_subparsers(dest="sub", required=True)
    p = add(top, "submit", cmd_topology_submit, "AddTransactions with the bundle's signatures")
    p.add_argument("bundle")
    p.add_argument("--proposal", action="store_true", help="allow submitting an incomplete bundle as proposal")
    p.add_argument("--force", action="append", choices=sorted(__import__("cdz.admin").admin.FORCE_FLAGS))
    yes(p)
    p = add(top, "approve", cmd_topology_approve, "node operator: authorize with the node's own keys")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--hash", help="hex hash of a pending proposal")
    g.add_argument("--bundle", help="propose/approve the bundle's transaction")
    p.add_argument("--participant", help="this node's participant uid (required with --hash)")
    p.add_argument("--index", type=int, default=0)
    p.add_argument("--admin-addr", help="Admin API of the approving node")
    yes(p)
    p = add(top, "plan-party", cmd_topology_plan_party, "new PartyToParticipant: keys, thresholds, hosts")
    p.add_argument("--add-key", action="append", default=[], help="public key JSON")
    p.add_argument("--remove-key", action="append", default=[], help="fingerprint")
    p.add_argument("--signing-threshold", type=int)
    p.add_argument("--add-host", action="append", default=[], help="uid[=permission]; also changes a permission")
    p.add_argument("--remove-host", action="append", default=[])
    p.add_argument("--confirmation-threshold", type=int)
    p.add_argument("--no-onboarding", action="store_true", help="do not flag new hosts as onboarding (party without contracts)")
    p.add_argument("-o", "--output", default="party-update.bundle.json")
    p = add(top, "plan-dns", cmd_topology_plan_dns, "new DecentralizedNamespaceDefinition: owners, threshold")
    p.add_argument("--add-owner", action="append", default=[], help="namespace public key JSON")
    p.add_argument("--remove-owner", action="append", default=[], help="owner namespace fingerprint")
    p.add_argument("--threshold", type=int)
    p.add_argument("-o", "--output", default="dns-update.bundle.json")
    p = add(top, "plan-clear-onboarding", cmd_topology_plan_clear_onboarding, "after ACS import: clear a host's onboarding flag")
    p.add_argument("--participant", required=True)
    p.add_argument("-o", "--output", default="clear-onboarding.bundle.json")

    tx = sub.add_parser("tx", help="interactive submission").add_subparsers(dest="sub", required=True)
    p = add(tx, "prepare", cmd_tx_prepare, "prepare a command; writes a submission bundle")
    p.add_argument("--command-file", help="JSON Ledger API command ({\"CreateCommand\":...} / {\"ExerciseCommand\":...})")
    p.add_argument("--create", metavar="TEMPLATE_ID")
    p.add_argument("--exercise", metavar="TEMPLATE_OR_INTERFACE_ID")
    p.add_argument("--cid")
    p.add_argument("--choice")
    p.add_argument("--args", help="JSON create/choice argument")
    p.add_argument("--disclosed", help="JSON file with disclosed contracts")
    p.add_argument("--ttl", type=int, help="max record time in seconds from now")
    p.add_argument("--scheme", choices=["v2", "v3"], help="default v2, or v3 with --ttl")
    p.add_argument("--description")
    p.add_argument("-o", "--output", default="tx.bundle.json")
    p.add_argument("--execute", action="store_true", help="sign with local keys and execute right away")
    yes(p)
    p = add(tx, "execute", cmd_tx_execute, "execute signed submission bundle(s), in order")
    p.add_argument("bundles", nargs="+")
    p.add_argument("--ledger-url")
    yes(p)

    from cdz import registrar_cli

    registrar_cli.register(sub, add, yes)
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        args.fn(args)
        return 0
    except (CliError, ConfigError, bundle.BundleError, topology.TopologyError, manage.PlanError,
            prepared.PreparedCheckError, UtilitiesError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # network/API errors: concise message
        name = type(e).__name__
        if name in ("LedgerError", "AdminError", "RegistryError", "URLError", "HTTPError", "TimeoutError",
                    "ConnectionRefusedError", "ConnectionResetError", "RemoteDisconnected"):
            print(f"error: {e}", file=sys.stderr)
            return 3
        raise


if __name__ == "__main__":
    sys.exit(main())
