"""`cdz dfns`: Keys API client, User Action Signing, bundle signing. Only a local mock DFNS."""

import base64
import hashlib
import json
import os
import struct
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from dfns_mock import MockServer, b64url, unb64url

from cdz import bundle, cli, crypto, dfns


def gateway_fingerprint(raw32: bytes) -> str:
    """Wallet Gateway party-allocation-service.ts: 0x1220 || sha256(be32(12) || raw key)."""
    return "1220" + hashlib.sha256(struct.pack(">I", 12) + raw32).hexdigest()


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    real = time.sleep
    monkeypatch.setattr(time, "sleep", lambda s: real(min(s, 0.005)))


@pytest.fixture
def srv():
    with MockServer() as s:
        yield s


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(env_file, *args, ok=True):
    """Run the CLI in-process with ONLY this env file (load_env_file writes into os.environ)."""
    for k in [k for k in os.environ if k.startswith("CDZ_")]:
        del os.environ[k]
    try:
        rc = cli.main(["--env", str(env_file), *args])
    finally:
        for k in [k for k in os.environ if k.startswith("CDZ_")]:
            del os.environ[k]
    if ok:
        assert rc == 0, f"cdz {' '.join(args)} -> {rc}"
    return rc


def write_env(path, **kv):
    path.write_text("".join(f"{k}={v}\n" for k, v in kv.items()))
    path.chmod(0o600)
    return path


def client(srv, **over):
    env = {**srv.mock.env(srv.url), **over}
    return dfns.DfnsClient(dfns.DfnsConfig.from_env(env))


# --- conversions ----------------------------------------------------------------------------


def test_public_key_and_fingerprint_match_wallet_gateway():
    for _ in range(5):
        priv = ed25519.Ed25519PrivateKey.generate()
        raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for hx in (raw.hex(), "0x" + raw.hex(), raw.hex().upper()):
            pk = dfns.public_key({"id": "key-1", "scheme": "EdDSA", "curve": "ed25519", "publicKey": hx})
            assert pk.fingerprint == gateway_fingerprint(raw) == crypto.canton_hash(12, raw).hex()
        pub = dfns.pub_json({"id": "key-1", "name": "dfns-tx", "scheme": "EdDSA", "curve": "ed25519", "publicKey": raw.hex()})
        assert pub["role"] == "tx" and pub["spec"] == "ed25519" and pub["name"] == "dfns-tx"
        assert pub["dfns"]["gateway_public_key"] == base64.b64encode(raw).decode()  # what the gateway lists
        assert crypto.PublicKey.from_json(pub).fingerprint == pub["fingerprint"]


@pytest.mark.parametrize("hx,err", [("00" * 33, "33 bytes"), ("02" + "11" * 32, "33 bytes"), ("11" * 31, "31 bytes"), ("zz", "not hex")])
def test_public_key_rejects_non_raw_ed25519(hx, err):
    with pytest.raises(ValueError, match=err):
        dfns.public_key({"id": "key-1", "scheme": "EdDSA", "curve": "ed25519", "publicKey": hx})
    with pytest.raises(ValueError, match="EdDSA/ed25519"):
        dfns.public_key({"id": "key-1", "scheme": "ECDSA", "curve": "secp256k1", "publicKey": "11" * 33})


def test_signature_decoding_variants():
    priv = ed25519.Ed25519PrivateKey.generate()
    pk = crypto.PublicKey.from_crypto(priv.public_key())
    h = crypto.canton_hash(11, b"tx")
    sig = priv.sign(h)
    for obj in ({"encoded": sig.hex()}, {"encoded": "0x" + sig.hex()}, {"r": sig[:32].hex(), "s": sig[32:].hex()},
                {"r": "0x" + sig[:32].hex(), "s": "0x" + sig[32:].hex(), "encoded": "0x" + sig.hex()},
                {"encoded": "ff" * 64, "r": sig[:32].hex(), "s": sig[32:].hex()}):  # falls back to r||s
        s = dfns.verified_signature(pk, h, {"id": "sig-1", "signature": obj})
        assert s.signature == sig and s.signed_by == pk.fingerprint
        j = s.to_json()
        assert j["format"] == "SIGNATURE_FORMAT_CONCAT" and j["algorithm"] == "SIGNING_ALGORITHM_SPEC_ED25519"
        assert base64.b64decode(j["signature"]) == sig
    with pytest.raises(ValueError, match="does NOT verify"):
        dfns.verified_signature(pk, h[:-1] + b"\0", {"id": "sig-1", "signature": {"encoded": sig.hex()}})
    with pytest.raises(ValueError, match="no 64-byte"):
        dfns.verified_signature(pk, h, {"id": "sig-1", "signature": {"encoded": sig.hex() + "00"}})
    with pytest.raises(ValueError, match="no 64-byte"):
        dfns.verified_signature(pk, h, {"id": "sig-1"})


# --- user action signing --------------------------------------------------------------------

# docs.dfns.co/api-reference/auth/create-user-action-signature.md, example "Key Credential"
DOC_CLIENT_DATA = ("eyJ0eXBlIjoia2V5LmdldCIsImNoYWxsZW5nZSI6Ik1XTTBNbVk1WVRRME1EUmlOemRoTlRGaE56WTVPRFF3TldJNVpUUTRZMlJoT0RaaU5Ea3"
                   "paVFl6T1RFNU9HWXlNRGN4WmpCall6azRNbVE1WXpZMU1BIiwib3JpZ2luIjoiaHR0cHM6Ly9hcHAuZGZucy5uaW5qYSIsImNyb3NzT3JpZ2luIjpmYWxzZX0")


def _pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def test_client_data_matches_documented_example():
    doc = unb64url(DOC_CLIENT_DATA)
    challenge = json.loads(doc)["challenge"]
    s = dfns.CredentialSigner("cr-1", _pem(ed25519.Ed25519PrivateKey.generate()), origin="https://app.dfns.ninja")
    assert s.client_data(challenge) == doc  # byte-identical, incl. key order and compact JSON
    assert b64url(s.client_data(challenge)) == DOC_CLIENT_DATA
    plain = dfns.CredentialSigner("cr-1", _pem(ed25519.Ed25519PrivateKey.generate()))
    assert plain.client_data("abc") == b'{"type":"key.get","challenge":"abc"}'  # @dfns/sdk-keysigner 0.8.31


@pytest.mark.parametrize("kind", ["ed25519", "p256"])
def test_assertion_signature_verifies(kind):
    key = ed25519.Ed25519PrivateKey.generate() if kind == "ed25519" else ec.generate_private_key(ec.SECP256R1())
    s = dfns.CredentialSigner("cr-1", _pem(key).replace("\n", "\\n"))  # one-line env form
    a = s.assertion({"challenge": "Y2hhbGxlbmdl", "allowCredentials": {"key": [{"type": "public-key", "id": "cr-1"}], "webauthn": []}})
    assert a["kind"] == "Key" and a["credentialAssertion"]["credId"] == "cr-1"
    cd = unb64url(a["credentialAssertion"]["clientData"])
    assert json.loads(cd) == {"type": "key.get", "challenge": "Y2hhbGxlbmdl"}
    sig = unb64url(a["credentialAssertion"]["signature"])
    if kind == "ed25519":
        key.public_key().verify(sig, cd)
    else:
        key.public_key().verify(sig, cd, ec.ECDSA(hashes.SHA256()))  # DER, like node crypto.sign(undefined, ..)
    with pytest.raises(dfns.DfnsConfigError, match="not among the allowed"):
        s.assertion({"challenge": "x", "allowCredentials": {"key": [{"id": "cr-other"}]}})


def test_private_key_errors_do_not_leak():
    secret = "-----BEGIN PRIVATE KEY-----\nTOPSECRETTOPSECRET\n-----END PRIVATE KEY-----"
    with pytest.raises(dfns.DfnsConfigError) as e:
        dfns.CredentialSigner("cr-1", secret)
    assert "TOPSECRET" not in str(e.value)


def test_user_action_request_shape(srv):
    d = client(srv)
    k = d.create_key("dfns-tx")
    reqs = srv.mock.requests
    assert [(r["method"], r["path"]) for r in reqs] == [("POST", "/auth/action/init"), ("POST", "/auth/action"), ("POST", "/keys")]
    init = json.loads(reqs[0]["body"])
    assert init == {"userActionPayload": reqs[2]["body"].decode(), "userActionHttpMethod": "POST",
                    "userActionHttpPath": "/keys", "userActionServerKind": "Api"}
    assert json.loads(init["userActionPayload"]) == {"scheme": "EdDSA", "curve": "ed25519", "name": "dfns-tx"}
    act = json.loads(reqs[1]["body"])
    assert set(act) == {"challengeIdentifier", "firstFactor"} and act["firstFactor"]["kind"] == "Key"
    assert set(act["firstFactor"]["credentialAssertion"]) == {"credId", "clientData", "signature"}
    assert reqs[2]["headers"]["x-dfns-useraction"].startswith("ua.")
    assert all(r["headers"]["authorization"] == f"Bearer {srv.mock.token}" for r in reqs)
    assert all(r["headers"]["user-agent"].startswith("cdz/") for r in reqs)
    assert all("x-dfns-useraction" not in r["headers"] for r in reqs[:2])
    # reads are not user-action signed; signature request body is the bare multihash in hex
    n = len(reqs)
    d.get_key(k["id"])
    assert len(srv.mock.requests) == n + 1
    h = crypto.canton_hash(11, b"x")
    r = d.generate_signature(k["id"], h)
    body = json.loads(srv.mock.requests[-1]["body"])
    assert body == {"kind": "Message", "message": h.hex()} and len(h) == 34 and body["message"].startswith("1220")
    assert r["status"] == "Signed"


def test_config_checks(srv):
    with pytest.raises(dfns.DfnsConfigError, match="not scoped"):
        client(srv, CDZ_DFNS_ORG_ID="or-other")
    with pytest.raises(dfns.DfnsConfigError, match="https"):
        client(srv, CDZ_DFNS_BASE_URL="http://api.dfns.io")
    with pytest.raises(dfns.DfnsConfigError, match="not set"):
        client(srv, CDZ_DFNS_AUTH_TOKEN="")
    with pytest.raises(dfns.DfnsConfigError, match="not a JWT"):
        client(srv, CDZ_DFNS_AUTH_TOKEN="opaque-token")
    with pytest.raises(dfns.DfnsConfigError, match="CDZ_DFNS_CRED_ID"):
        client(srv, CDZ_DFNS_CRED_ID="").create_key("x")
    assert client(srv, CDZ_DFNS_ORG_ID="").org_id == srv.mock.org_id


def test_errors_redact_secrets_and_no_redirects(srv, monkeypatch):
    d = client(srv)
    tok = srv.mock.token
    monkeypatch.setattr(srv.mock, "_handle", lambda *a: (400, {"error": {"message": f"bad token {tok} here"}}))
    with pytest.raises(dfns.DfnsError) as e:
        d.list_keys()
    assert tok not in str(e.value) and "<redacted>" in str(e.value) and "HTTP 400" in str(e.value)
    monkeypatch.undo()
    n = len(srv.mock.requests)
    with pytest.raises(dfns.DfnsError, match="HTTP 302"):
        d.get("/redirect-me")
    assert len(srv.mock.requests) == n + 1  # the redirect target was never requested


def test_wrong_credential_is_refused_by_server(srv):
    other = _pem(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(dfns.DfnsError, match="bad credential signature"):
        client(srv, CDZ_DFNS_PRIVATE_KEY=other).create_key("x")


# --- CLI: keys ------------------------------------------------------------------------------


def dfns_env(work, srv, name="dfns.env", **extra):
    return write_env(work / name, CDZ_NETWORK="devnet", **srv.mock.env(srv.url), **extra)


def test_cli_keys_list(work, srv, capsys):
    m = srv.mock
    tx = m.add_key("canton-tx")
    sol = m.add_key("solana-hot", wallets=["Solana"])
    m.add_key("eth", scheme="ECDSA", curve="secp256k1", wallets=["Ethereum"])
    m.add_key("old", status="Archived")
    env = dfns_env(work, srv)
    run(env, "dfns", "keys", "list", "--json")
    rows = json.loads(capsys.readouterr().out)
    assert {r["name"] for r in rows} == {"canton-tx", "solana-hot", "eth"}  # pagination (2 per page), Active only
    by = {r["name"]: r for r in rows}
    assert by["canton-tx"]["gateway_visible"] and by["solana-hot"]["gateway_visible"] and not by["eth"]["gateway_visible"]
    raw = bytes.fromhex(m.keys[tx]["publicKey"])
    assert by["canton-tx"]["fingerprint"] == gateway_fingerprint(raw) and by["eth"]["fingerprint"] is None
    run(env, "dfns", "keys", "list", "--all", "--wallets")
    o = capsys.readouterr()
    assert "4 key(s), 2 visible to a Wallet Gateway" in o.out and "old" in o.out
    assert f"WALLETS: Solana {m.keys[sol]['_wallets'][0]['id']}" in o.out
    assert "ANY GW key" in o.err
    assert all(r["method"] == "GET" for r in m.requests)  # read-only
    assert m.token not in o.out + o.err


def test_cli_keys_create_and_pub(work, srv, capsys):
    env = dfns_env(work, srv)
    run(env, "dfns", "keys", "create", "--name", "dfns-tx", "--pub-out", "dfns-tx.pub.json")
    res = json.loads(capsys.readouterr().out)
    pub = json.loads((work / "dfns-tx.pub.json").read_text())
    k = srv.mock.keys[res["id"]]
    assert pub["fingerprint"] == gateway_fingerprint(bytes.fromhex(k["publicKey"])) == res["fingerprint"]
    assert pub["role"] == "tx" and pub["name"] == "dfns-tx" and pub["dfns"]["key_id"] == res["id"]
    assert run(env, "dfns", "keys", "create", "--name", "dfns-tx", "--pub-out", "dfns-tx.pub.json", ok=False) == 2  # no overwrite
    run(env, "dfns", "keys", "pub", res["id"], "--name", "renamed", "--pub-out", "again.json")
    again = json.loads((work / "again.json").read_text())
    assert again["fingerprint"] == pub["fingerprint"] and again["name"] == "renamed"
    srv.mock.bad_public_key = True
    assert run(env, "dfns", "keys", "create", "--name", "bad", ok=False) == 2
    assert "64 hex chars" in capsys.readouterr().err
    assert run(env, "dfns", "keys", "create", "--name", "bad name", ok=False) == 2


# --- CLI: sign-bundle (DNS onboarding) ------------------------------------------------------


@pytest.fixture
def onboarding(work, srv, capsys):
    """3 offline owners (2-of-3), signing key 1-of-1 held in DFNS, one host."""
    common = {"CDZ_NETWORK": "devnet"}
    for i in range(3):
        e = write_env(work / f"own{i}.env", **common)
        run(e, "keys", "generate", "--role", "ns", "--name", f"own{i}", "--env-out", str(e), "--pub-out", f"own{i}.pub.json")
    env = dfns_env(work, srv)
    capsys.readouterr()
    run(env, "dfns", "keys", "create", "--name", "dfns-tx", "--pub-out", "dfns-tx.pub.json")
    key_id = json.loads(capsys.readouterr().out)["id"]
    coord = write_env(work / "coord.env", **common)
    run(coord, "party", "new", "--hint", "dfns-dns", *[a for i in range(3) for a in ("--owner", f"own{i}.pub.json")],
        "--owners-threshold", "2", "--signing-key", "dfns-tx.pub.json", "--signing-threshold", "1",
        "--host", "participant1::1220" + "11" * 32, "--confirmation-threshold", "1")
    run(coord, "party", "onboard-bundle", "-o", "onboard.json")
    for i in range(3):
        run(work / f"own{i}.env", "bundle", "sign", "onboard.json", "-o", f"onboard.own{i}.json", "--yes")
    capsys.readouterr()
    return {"env": env, "coord": coord, "key_id": key_id}


def test_sign_bundle_onboarding_end_to_end(work, srv, onboarding, capsys):
    o = onboarding
    run(o["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", o["key_id"], "-o", "onboard.dfns.json", "--yes")
    err = capsys.readouterr().err
    assert "signed: p2p <- dfns-tx (verified)" in err
    reqs = srv.mock.sig_requests()
    p2p = next(t for t in json.loads((work / "onboard.json").read_text())["transactions"] if t["label"] == "p2p")
    assert len(reqs) == 1 and json.loads(reqs[0]["body"]) == {"kind": "Message", "message": p2p["hash"]}  # only the PoO
    out = json.loads((work / "onboard.dfns.json").read_text())
    s = next(t for t in out["transactions"] if t["label"] == "p2p")["signatures"]
    fp = json.loads((work / "dfns-tx.pub.json").read_text())["fingerprint"]
    assert s == [{"signed_by": fp, "format": "SIGNATURE_FORMAT_CONCAT", "algorithm": "SIGNING_ALGORITHM_SPEC_ED25519",
                  "signature": s[0]["signature"]}]
    run(o["coord"], "bundle", "merge", "onboard.signed.json", "onboard.own0.json", "onboard.own1.json", "onboard.own2.json", "onboard.dfns.json")
    assert "merged" in capsys.readouterr().err
    run(o["coord"], "bundle", "show", "onboard.signed.json")
    shown = capsys.readouterr().out
    assert "status: fully signed" in shown and "dfns-tx" in shown.split("[p2p]")[1]
    # idempotent: a second run does not ask DFNS again
    run(o["env"], "dfns", "sign-bundle", "onboard.dfns.json", "--key-id", o["key_id"], "-o", "again.json", "--yes")
    assert "already signed" in capsys.readouterr().err and len(srv.mock.sig_requests()) == 1


def test_sign_bundle_pending_then_signed(work, srv, onboarding, capsys):
    srv.mock.pending_polls = 2
    run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "out.json",
        "--poll-interval", "1", "--yes")
    err = capsys.readouterr().err
    assert "Pending" in err and "approval needed in DFNS" in err and "ap-mock0" in err and "(verified)" in err
    assert len(srv.mock.sig_requests()) == 1


def test_sign_bundle_pending_timeout_then_resume(work, srv, onboarding, capsys):
    srv.mock.approve = False
    rc = run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "out.json",
             "--timeout", "0.05", "--poll-interval", "1", "--yes", ok=False)
    err = capsys.readouterr().err
    assert rc == 3 and "--signature-id sig-" in err and not (work / "out.json").exists()
    sid = err.split("--signature-id ")[1].split()[0]
    srv.mock.approve_all()
    run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "out.json",
        "--signature-id", sid, "--yes")
    assert f"reusing DFNS signature request {sid}" in capsys.readouterr().err
    assert len(srv.mock.sig_requests()) == 1 and (work / "out.json").exists()


def test_sign_bundle_rejects_bad_or_refused_signatures(work, srv, onboarding, capsys):
    srv.mock.tamper = True
    rc = run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "out.json", "--yes", ok=False)
    assert rc == 2 and "does NOT verify" in capsys.readouterr().err and not (work / "out.json").exists()
    srv.mock.tamper, srv.mock.reject = False, True
    rc = run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "out.json", "--yes", ok=False)
    assert rc == 3 and "Rejected: policy rejected" in capsys.readouterr().err and not (work / "out.json").exists()


@pytest.mark.parametrize("encoding", ["rs", "0x"])
def test_sign_bundle_signature_encodings(work, srv, onboarding, encoding):
    srv.mock.encoding = encoding
    run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "out.json", "--yes")
    b = bundle.load(work / "out.json")
    fp = json.loads((work / "dfns-tx.pub.json").read_text())["fingerprint"]
    assert not b.prune() and [s.signed_by for it in b.items if it.label == "p2p" for s in it.sigs] == [fp]


def test_sign_bundle_key_not_needed_and_label_filter(work, srv, onboarding, capsys):
    other = srv.mock.add_key("unrelated")
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", other, "-o", "o.json", "--yes", ok=False) == 2
    assert "is not needed by" in capsys.readouterr().err
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "o.json",
               "--label", "dns", "--yes", ok=False) == 2
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "o.json",
               "--label", "nope", "--yes", ok=False) == 2
    eth = srv.mock.add_key("eth", scheme="ECDSA", curve="secp256k1")
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", eth, "-o", "o.json", "--yes", ok=False) == 2
    assert not srv.mock.sig_requests()


def test_sign_bundle_refuses_without_tty(work, srv, onboarding, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", onboarding["key_id"], "-o", "o.json", ok=False) == 2
    assert "pass --yes" in capsys.readouterr().err and not srv.mock.sig_requests()


def test_sign_hash(work, srv, capsys):
    env = dfns_env(work, srv)
    kid = srv.mock.add_key("adhoc")
    run(env, "dfns", "sign-hash", "0x" + "ab" * 32, "--key-id", kid, "--yes")
    r = json.loads(capsys.readouterr().out)
    pub = bytes.fromhex(srv.mock.keys[kid]["publicKey"])
    ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(r["signature_hex"]), bytes.fromhex("ab" * 32))
    assert r["verified"] and r["signature"]["signed_by"] == gateway_fingerprint(pub)
    assert run(env, "dfns", "sign-hash", "xyz", "--key-id", kid, "--yes", ok=False) == 2


# --- CLI: sign-bundle (interactive submission, `cdz tx prepare` output) -----------------------


def test_sign_submission_bundle_and_execute(work, srv, onboarding, capsys, monkeypatch):
    from test_utilities import SYNC, FakeLedger

    lc = FakeLedger([])
    monkeypatch.setattr(cli, "ledger", lambda s, url=None: lc)
    o = onboarding
    coord = write_env(work / "coord2.env", CDZ_NETWORK="devnet", CDZ_LEDGER_URL="http://fake", CDZ_SYNCHRONIZER_ID=SYNC)
    dfns_env(work, srv, "dfns2.env", CDZ_SYNCHRONIZER_ID=SYNC)
    party = json.loads((work / "party.json").read_text())["party_id"]
    tid = "#canton-builtin-admin-workflow-ping:Canton.Internal.Ping:Ping"
    run(coord, "tx", "prepare", "--create", tid, "--args", json.dumps({"id": "1", "initiator": party, "responder": party}), "-o", "tx.json")
    assert run(coord, "tx", "execute", "tx.json", "--yes", ok=False) == 2  # 0 of 1 signatures
    run(work / "dfns2.env", "dfns", "sign-bundle", "tx.json", "--key-id", o["key_id"], "-o", "tx.signed.json", "--yes")
    b = json.loads((work / "tx.json").read_text())
    body = json.loads(srv.mock.sig_requests()[-1]["body"])
    assert body == {"kind": "Message", "message": b["hash"]} and len(bytes.fromhex(b["hash"])) == 32  # V2 hash, as is
    run(coord, "tx", "execute", "tx.signed.json", "--yes")
    fp = json.loads((work / "dfns-tx.pub.json").read_text())["fingerprint"]
    assert lc.executed == [(party, [fp])]
    # tampered submission bundle: refused before any DFNS call
    bad = dict(b, hash="00" * 32)
    (work / "bad.json").write_text(json.dumps(bad))
    n = len(srv.mock.sig_requests())
    assert run(work / "dfns2.env", "dfns", "sign-bundle", "bad.json", "--key-id", o["key_id"], "-o", "x.json", "--yes", ok=False) == 2
    assert len(srv.mock.sig_requests()) == n


# --- review follow-ups ----------------------------------------------------------------------


def test_token_with_newline_never_printed(work, srv, capsys):
    tok = srv.mock.token
    (work / "tok").write_text(tok[:20] + "\n" + tok[20:] + "\n")
    env = dfns_env(work, srv, "t.env")
    env.write_text(env.read_text().replace(f"CDZ_DFNS_AUTH_TOKEN={tok}", "CDZ_DFNS_AUTH_TOKEN=file:tok"))
    assert run(env, "dfns", "keys", "list", ok=False) == 2
    o = capsys.readouterr()
    assert "not a JWT" in o.err and tok[:20] not in o.out + o.err and tok[20:40] not in o.out + o.err
    assert not srv.mock.requests


def test_file_secrets_and_missing_file(work, srv, capsys):
    (work / "tok").write_text(srv.mock.token + "\n")
    (work / "sa.pem").write_text(srv.mock.private_key_pem())
    env = dfns_env(work, srv, "f.env")
    text = env.read_text()
    text = "\n".join("CDZ_DFNS_AUTH_TOKEN=file:tok" if l.startswith("CDZ_DFNS_AUTH_TOKEN=") else
                     "CDZ_DFNS_PRIVATE_KEY=file:sa.pem" if l.startswith("CDZ_DFNS_PRIVATE_KEY=") else l for l in text.splitlines())
    env.write_text(text + "\n")
    run(env, "dfns", "keys", "create", "--name", "via-files")
    assert json.loads(capsys.readouterr().out)["name"] == "via-files"
    env.write_text(text.replace("file:sa.pem", "file:missing.pem") + "\n")
    assert run(env, "dfns", "keys", "create", "--name", "x", ok=False) == 2
    assert "CDZ_DFNS_PRIVATE_KEY: cannot read missing.pem" in capsys.readouterr().err


def test_base_url_with_path_prefix_signs_canonical_path(srv):
    srv.mock.prefix = "/dfns-proxy/v1"
    d = client(srv, CDZ_DFNS_BASE_URL=srv.url + "/dfns-proxy/v1/")
    d.create_key("pfx")
    init = json.loads(srv.mock.requests[0]["body"])
    assert srv.mock.requests[2]["path"] == "/dfns-proxy/v1/keys" and init["userActionHttpPath"] == "/keys"


def test_empty_allow_credentials_refused():
    s = dfns.CredentialSigner("cr-1", _pem(ed25519.Ed25519PrivateKey.generate()))
    with pytest.raises(dfns.DfnsConfigError, match="not among"):
        s.assertion({"challenge": "x", "allowCredentials": {"key": [], "webauthn": []}})
    assert s.assertion({"challenge": "x"})["kind"] == "Key"  # no allowCredentials at all: like the TS signer


def test_wrong_signature_id_fails_before_any_request(work, srv, onboarding, capsys):
    kid = onboarding["key_id"]
    other = client(srv).generate_signature(kid, b"something else")["id"]
    n = len(srv.mock.sig_requests())
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", kid, "-o", "o.json",
               "--signature-id", other, "--yes", ok=False) == 2
    assert "does not sign any hash" in capsys.readouterr().err and len(srv.mock.sig_requests()) == n


def test_signature_id_rerun_on_signed_bundle_is_fine(work, srv, onboarding, capsys):
    kid = onboarding["key_id"]
    run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", kid, "-o", "o.json", "--yes")
    sid = next(iter(srv.mock.sigs))
    run(onboarding["env"], "dfns", "sign-bundle", "o.json", "--key-id", kid, "-o", "o2.json", "--signature-id", sid, "--yes")
    assert "already signed" in capsys.readouterr().err and len(srv.mock.sig_requests()) == 1


def test_executing_failed_and_202(work, srv, onboarding, capsys):
    kid = onboarding["key_id"]
    srv.mock.pending_status, srv.mock.pending_polls = "Executing", 1
    run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", kid, "-o", "a.json", "--yes")
    assert "Executing" in capsys.readouterr().err
    srv.mock.fail = True
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", kid, "-o", "b.json", "--yes", ok=False) == 3
    assert "Failed: signer unavailable" in capsys.readouterr().err and not (work / "b.json").exists()
    srv.mock.fail, srv.mock.accept_202 = False, True
    assert run(onboarding["env"], "dfns", "sign-bundle", "onboard.json", "--key-id", kid, "-o", "c.json", "--yes", ok=False) == 3
    err = capsys.readouterr().err
    assert "HTTP 202" in err and "approvalId" not in err and "ap-mock0" in err and not (work / "c.json").exists()


def test_multi_item_timeout_lists_every_signature_id(srv):
    m = srv.mock
    kid = m.add_key("multi")
    m.approve = False

    class A:
        timeout, poll_interval, signature_id = 0.05, 1, None

    signer = __import__("cdz.dfns_cli", fromlist=["_Signer"])._Signer(client(srv), kid, A)
    with pytest.raises(TimeoutError) as e:
        signer.sign_all([("a", b"\x01"), ("b", b"\x02")])
    ids = [r["id"] for r in m.sigs.values()]
    assert len(ids) == 2 and all(f"--signature-id {i}" in str(e.value) for i in ids)


def test_poll_interval_floor(work, srv, onboarding):
    with pytest.raises(SystemExit):
        cli.main(["--env", str(onboarding["env"]), "dfns", "sign-hash", "00", "--key-id", "k", "--poll-interval", "0"])
