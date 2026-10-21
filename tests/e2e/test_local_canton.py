"""End-to-end against a local open-source Canton (scripts/local-canton.sh start).

Runs the CLI as separate processes with one .env per key holder, i.e. the offline multi-signer
flow: three DNS owners and three signing-key holders, two hosting participants, 2-of-3 everywhere.
Enable with CDZ_E2E_DIR=<run dir containing synchronizer_id and participants>.
"""

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

RUN = os.environ.get("CDZ_E2E_DIR")
pytestmark = pytest.mark.skipif(not RUN, reason="set CDZ_E2E_DIR to a running local Canton (scripts/local-canton.sh)")

LEDGER = {1: "http://localhost:17373", 2: "http://localhost:17374", 3: "http://localhost:17375"}
ADMIN = {1: "localhost:14002", 2: "localhost:14012", 3: "localhost:14022"}
PING = "#canton-builtin-admin-workflow-ping:Canton.Internal.Ping:Ping"


def cdz(cwd: Path, env_file: str, *args, ok=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CDZ_")}
    r = subprocess.run(
        [sys.executable, "-m", "cdz", "--env", env_file, "--network", "local", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
    )
    if ok and r.returncode != 0:
        raise AssertionError(f"cdz {' '.join(args)} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r


def write_env(path: Path, **kv):
    path.write_text("".join(f"{k}={v}\n" for k, v in kv.items()))
    path.chmod(0o600)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    d = tmp_path_factory.mktemp("e2e")
    run = Path(RUN)
    sync = (run / "synchronizer_id").read_text().strip()
    parts = {p.split("::")[0]: p for p in (run / "participants").read_text().split()}
    common = dict(CDZ_SYNCHRONIZER_ID=sync, CDZ_LEDGER_URL=LEDGER[1], CDZ_ADMIN_ADDR=ADMIN[1], CDZ_LEDGER_USER="cdz-e2e")
    hint = "e2e-" + uuid.uuid4().hex[:6]
    for n in (1, 2, 3):  # node operators create the app user once
        subprocess.run(["curl", "-sf", "-X", "POST", "-H", "Content-Type: application/json", "-d",
                        json.dumps({"user": {"id": "cdz-e2e", "isDeactivated": False, "identityProviderId": ""}, "rights": []}),
                        LEDGER[n] + "/v2/users"], capture_output=True)
    # each key holder generates keys into their own env file; only public JSON is shared
    for i in range(3):
        write_env(d / f"own{i}.env", **common)
        cdz(d, f"own{i}.env", "keys", "generate", "--role", "ns", "--name", f"own{i}", "--env-out", f"own{i}.env", "--pub-out", f"own{i}.pub.json")
        spec = ["ed25519", "p256", "secp256k1"][i]
        write_env(d / f"tx{i}.env", **common)
        cdz(d, f"tx{i}.env", "keys", "generate", "--role", "tx", "--spec", spec, "--name", f"tx{i}", "--env-out", f"tx{i}.env", "--pub-out", f"tx{i}.pub.json")
    write_env(d / "coord.env", **common)
    r = cdz(
        d, "coord.env", "party", "new", "--hint", hint,
        *sum([["--owner", f"own{i}.pub.json"] for i in range(3)], []), "--owners-threshold", "2",
        *sum([["--signing-key", f"tx{i}.pub.json"] for i in range(3)], []), "--signing-threshold", "2",
        "--host", parts["participant1"], "--host", parts["participant2"], "--confirmation-threshold", "2",
    )
    party = json.loads(r.stdout)["party_id"]
    return {"dir": d, "sync": sync, "parts": parts, "party": party}


def test_01_onboard_offline_multisig(world):
    d = world["dir"]
    cdz(d, "coord.env", "party", "onboard-bundle", "-o", "onboard.json")
    # every holder signs their own copy; the coordinator merges
    for who in ["own0", "own1", "own2", "tx0", "tx1", "tx2"]:
        cdz(d, f"{who}.env", "bundle", "sign", "onboard.json", "-o", f"onboard.{who}.json", "--yes")
    cdz(d, "coord.env", "bundle", "merge", "onboard.signed.json", *[f"onboard.{w}.json" for w in ["own0", "own1", "own2", "tx0", "tx1", "tx2"]])
    shown = cdz(d, "coord.env", "bundle", "show", "onboard.signed.json").stdout
    assert "fully signed" in shown
    for n in (1, 2):
        r = cdz(d, "coord.env", "party", "allocate", "onboard.signed.json", "--ledger-url", LEDGER[n], "--user", "cdz-e2e", "--yes")
        assert json.loads(r.stdout)["party_id"] == world["party"]
    for _ in range(30):
        st = json.loads(cdz(d, "coord.env", "party", "status").stdout)
        if st["party_to_participant"]:
            break
        time.sleep(1)
    p2p = st["party_to_participant"]
    assert p2p["confirmation_threshold"] == 2 and len(p2p["hosts"]) == 2 and p2p["signing_threshold"] == 2
    assert st["dns"]["threshold"] == 2 and not st["drift"]


def test_02_interactive_submission_m_of_n(world):
    d = world["dir"]
    alice = json.loads(subprocess.run(
        ["curl", "-sf", "-X", "POST", "-H", "Content-Type: application/json", "-d",
         json.dumps({"partyIdHint": "alice-" + uuid.uuid4().hex[:6]}), LEDGER[1] + "/v2/parties"],
        capture_output=True, text=True).stdout)["partyDetails"]["party"]
    args = json.dumps({"id": "e2e", "initiator": world["party"], "responder": alice})
    cdz(d, "coord.env", "tx", "prepare", "--create", PING, "--args", args, "--ttl", "600", "-o", "tx.json")
    cdz(d, "tx1.env", "bundle", "sign", "tx.json", "--yes")
    r = cdz(d, "coord.env", "tx", "execute", "tx.json", "--yes", ok=False)
    assert r.returncode != 0 and "threshold is 2" in r.stderr
    cdz(d, "tx2.env", "bundle", "sign", "tx.json", "--yes")
    r = cdz(d, "coord.env", "tx", "execute", "tx.json", "--ledger-url", LEDGER[3], "--yes")  # via a non-hosting node
    assert json.loads(r.stdout)["executed"]


def test_03_tampered_bundle_is_refused(world):
    d = world["dir"]
    b = json.loads((d / "tx.json").read_text())
    b["hash"] = "00" * 32
    (d / "bad.json").write_text(json.dumps(b))
    r = cdz(d, "tx0.env", "bundle", "sign", "bad.json", "--yes", ok=False)
    assert r.returncode != 0 and "hash mismatch" in r.stderr


def test_04_signing_threshold_and_hosting_changes(world):
    d = world["dir"]
    # a node operator refuses to approve a proposal that changes another host (checked before signing)
    r = cdz(d, "coord.env", "topology", "approve", "--hash", "12" * 34, "--admin-addr", ADMIN[3],
            "--participant", world["parts"]["participant3"], "--yes", ok=False)
    assert r.returncode != 0 and "no pending" in r.stderr
    cdz(d, "coord.env", "topology", "plan-party", "--signing-threshold", "3", "-o", "thr.json")
    for who in ["own0", "own2"]:
        cdz(d, f"{who}.env", "bundle", "sign", "thr.json", "--yes")
    cdz(d, "coord.env", "topology", "submit", "thr.json", "--yes")
    for _ in range(30):
        st = json.loads(cdz(d, "coord.env", "party", "status").stdout)
        if st["party_to_participant"]["signing_threshold"] == 3:
            break
        time.sleep(1)
    assert st["party_to_participant"]["serial"] == 2
    # add participant3 as a confirming host (no contracts to replicate in this test party: --no-onboarding)
    p3 = world["parts"]["participant3"]
    cdz(d, "coord.env", "topology", "plan-party", "--add-host", p3, "--no-onboarding", "-o", "host.json")
    for who in ["own1", "own2"]:
        cdz(d, f"{who}.env", "bundle", "sign", "host.json", "--yes")
    r = cdz(d, "coord.env", "topology", "submit", "host.json", "--yes", ok=False)
    assert r.returncode != 0 and "--proposal" in r.stderr  # participant approval still missing
    cdz(d, "coord.env", "topology", "submit", "host.json", "--proposal", "--yes")
    h = json.loads((d / "host.json").read_text())["transactions"][0]["hash"]
    time.sleep(2)
    cdz(d, "coord.env", "topology", "approve", "--hash", h, "--admin-addr", ADMIN[3], "--participant", p3, "--yes")
    for _ in range(30):
        st = json.loads(cdz(d, "coord.env", "party", "status").stdout)
        if len(st["party_to_participant"]["hosts"]) == 3:
            break
        time.sleep(1)
    assert len(st["party_to_participant"]["hosts"]) == 3


def test_05_dns_owner_rotation(world):
    d = world["dir"]
    write_env(d / "own3.env", **{k: v for k, v in [l.split("=", 1) for l in (d / "coord.env").read_text().split()]})
    cdz(d, "own3.env", "keys", "generate", "--role", "ns", "--name", "own3", "--env-out", "own3.env", "--pub-out", "own3.pub.json")
    own0 = json.loads((d / "own0.pub.json").read_text())["fingerprint"]
    cdz(d, "coord.env", "topology", "plan-dns", "--add-owner", "own3.pub.json", "--remove-owner", own0, "--threshold", "2", "-o", "dns.json")
    for who in ["own3", "own1", "own2"]:
        cdz(d, f"{who}.env", "bundle", "sign", "dns.json", "--yes")
    cdz(d, "coord.env", "topology", "submit", "dns.json", "--yes")
    for _ in range(30):
        st = json.loads(cdz(d, "coord.env", "party", "status").stdout)
        if st["dns"]["serial"] == 2:
            break
        time.sleep(1)
    own3 = json.loads((d / "own3.pub.json").read_text())["fingerprint"]
    assert own3 in st["dns"]["owners"] and own0 not in st["dns"]["owners"]


def test_06_admin_api_onboarding_path(world):
    """Alternative to AllocateExternalParty: AddTransactions (P2P as proposal) + each host approves."""
    d = world["dir"]
    parts = world["parts"]
    hint = "adm-" + uuid.uuid4().hex[:6]
    r = cdz(
        d, "coord.env", "--party", "party-adm.json", "party", "new", "--hint", hint, "-o", "party-adm.json",
        "--owner", "own1.pub.json", "--owner", "own2.pub.json", "--owners-threshold", "1",
        "--signing-key", "tx1.pub.json", "--signing-threshold", "1",
        "--host", parts["participant2"], "--host", parts["participant3"], "--confirmation-threshold", "1",
    )
    party = json.loads(r.stdout)["party_id"]
    cdz(d, "coord.env", "--party", "party-adm.json", "party", "onboard-bundle", "-o", "adm.json")
    for who in ["own1", "own2", "tx1"]:
        cdz(d, f"{who}.env", "--party", "party-adm.json", "bundle", "sign", "adm.json", "--multi", "--yes")
    cdz(d, "coord.env", "--party", "party-adm.json", "topology", "submit", "adm.json", "--proposal", "--yes")
    p2p_hash = json.loads((d / "adm.json").read_text())["transactions"][-1]["hash"]
    time.sleep(2)
    for n in (2, 3):
        cdz(d, "coord.env", "--party", "party-adm.json", "topology", "approve", "--hash", p2p_hash, "--admin-addr", ADMIN[n],
            "--participant", parts[f"participant{n}"], "--yes")
    for _ in range(30):
        st = json.loads(cdz(d, "coord.env", "--party", "party-adm.json", "party", "status").stdout)
        if st["party_to_participant"]:
            break
        time.sleep(1)
    assert len(st["party_to_participant"]["hosts"]) == 2
    r = cdz(d, "coord.env", "--party", "party-adm.json", "party", "grant-user", "--user", "cdz-adm-" + uuid.uuid4().hex[:4],
            "--create", "--ledger-url", LEDGER[2])
    assert json.loads(r.stdout)["created"] is True
    # transact through one of its hosts
    env2 = d / "coord2.env"
    env2.write_text((d / "coord.env").read_text().replace(LEDGER[1], LEDGER[2]))
    args = json.dumps({"id": "adm", "initiator": party, "responder": party})
    cdz(d, "coord2.env", "--party", "party-adm.json", "tx", "prepare", "--create", PING, "--args", args, "-o", "adm-tx.json")
    cdz(d, "tx1.env", "--party", "party-adm.json", "bundle", "sign", "adm-tx.json", "--yes")
    r = cdz(d, "coord2.env", "--party", "party-adm.json", "tx", "execute", "adm-tx.json", "--yes")
    assert json.loads(r.stdout)["executed"]


def _post(url, body):
    r = subprocess.run(["curl", "-sf", "-X", "POST", "-H", "Content-Type: application/json", "-d", json.dumps(body), url],
                       capture_output=True, text=True)
    return json.loads(r.stdout)


def test_07_exercise_on_disclosed_contract(world):
    """Exercise node + input contract in the hash: a local party creates a Ping, the external party responds."""
    d = world["dir"]
    alice = _post(LEDGER[1] + "/v2/parties", {"partyIdHint": "bob-" + uuid.uuid4().hex[:6]})["partyDetails"]["party"]
    _post(LEDGER[1] + "/v2/users/cdz-e2e/rights",
          {"userId": "cdz-e2e", "rights": [{"kind": {"CanActAs": {"value": {"party": alice}}}}]})
    pid = "disc-" + uuid.uuid4().hex[:6]
    _post(LEDGER[1] + "/v2/commands/submit-and-wait", {
        "commands": [{"CreateCommand": {"templateId": PING, "createArguments": {"id": pid, "initiator": alice, "responder": world["party"]}}}],
        "commandId": str(uuid.uuid4()), "actAs": [alice], "userId": "cdz-e2e"})
    end = int(_post(LEDGER[1] + "/v2/state/active-contracts-page", {
        "eventFormat": {"filtersByParty": {alice: {"cumulative": [{"identifierFilter": {"TemplateFilter": {"value": {"templateId": PING, "includeCreatedEventBlob": True}}}}]}}}
    })["activeAtOffset"])
    page = _post(LEDGER[1] + "/v2/state/active-contracts-page", {"activeAtOffset": end, "eventFormat": {"filtersByParty": {alice: {"cumulative": [
        {"identifierFilter": {"TemplateFilter": {"value": {"templateId": PING, "includeCreatedEventBlob": True}}}}]}}}})
    ev = [e["contractEntry"]["JsActiveContract"]["createdEvent"] for e in page["activeContracts"]
          if e["contractEntry"]["JsActiveContract"]["createdEvent"]["createArgument"]["id"] == pid][0]
    (d / "disc.json").write_text(json.dumps([{"templateId": ev["templateId"], "contractId": ev["contractId"],
                                              "createdEventBlob": ev["createdEventBlob"], "synchronizerId": world["sync"]}]))
    for scheme in ("v2", "v3"):
        r = cdz(d, "coord.env", "tx", "prepare", "--exercise", PING, "--cid", ev["contractId"], "--choice", "Respond",
                "--args", "{}", "--disclosed", "disc.json", "--scheme", scheme, "-o", f"resp-{scheme}.json")
        assert "hash verified locally" in r.stderr
        b = json.loads((d / f"resp-{scheme}.json").read_text())
        assert b["summary"]["input_contracts"] == 1 and b["summary"]["roots"][0]["exercise"] == "Respond"
    for who in ["tx0", "tx1", "tx2"]:
        cdz(d, f"{who}.env", "bundle", "sign", "resp-v3.json", "--yes")
    r = cdz(d, "coord.env", "tx", "execute", "resp-v3.json", "--yes")
    assert json.loads(r.stdout)["executed"]


@pytest.fixture(scope="module")
def mock_dfns():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dfns_mock import MockServer

    with MockServer() as s:
        yield s


def _wait_p2p(d, party_file, pred):
    for _ in range(30):
        st = json.loads(cdz(d, "coord.env", "--party", party_file, "party", "status").stdout)
        if st["party_to_participant"] and pred(st["party_to_participant"]):
            return st
        time.sleep(1)
    raise AssertionError(f"party state not reached: {st}")


def test_08_dfns_held_signing_key(world, mock_dfns):
    """DNS party whose only signing key is held by (mock) DFNS: onboard, transact, rotate to a new DFNS key."""
    d = world["dir"]
    common = dict(l.split("=", 1) for l in (d / "coord.env").read_text().split())
    write_env(d / "dfns.env", **common, **mock_dfns.mock.env(mock_dfns.url))
    pf = "party-dfns.json"
    for i in range(3):  # fresh owners: the same owner set would give the namespace of the module's party
        write_env(d / f"dfo{i}.env", **common)
        cdz(d, f"dfo{i}.env", "keys", "generate", "--role", "ns", "--name", f"dfo{i}", "--env-out", f"dfo{i}.env", "--pub-out", f"dfo{i}.pub.json")
    key1 = json.loads(cdz(d, "dfns.env", "dfns", "keys", "create", "--name", "dfnstx1", "--pub-out", "dfnstx1.pub.json").stdout)["id"]
    r = cdz(d, "coord.env", "--party", pf, "party", "new", "--hint", "dfns-" + uuid.uuid4().hex[:6], "-o", pf,
            *[a for i in range(3) for a in ("--owner", f"dfo{i}.pub.json")], "--owners-threshold", "2",
            "--signing-key", "dfnstx1.pub.json", "--signing-threshold", "1",
            "--host", world["parts"]["participant1"], "--confirmation-threshold", "1")
    party = json.loads(r.stdout)["party_id"]
    cdz(d, "coord.env", "--party", pf, "party", "onboard-bundle", "-o", "dfns-onb.json")
    for i in range(3):
        cdz(d, f"dfo{i}.env", "--party", pf, "bundle", "sign", "dfns-onb.json", "-o", f"dfns-onb.dfo{i}.json", "--yes")
    cdz(d, "dfns.env", "--party", pf, "dfns", "sign-bundle", "dfns-onb.json", "--key-id", key1, "-o", "dfns-onb.dfns.json", "--yes")
    cdz(d, "coord.env", "--party", pf, "bundle", "merge", "dfns-onb.signed.json", *[f"dfns-onb.dfo{i}.json" for i in range(3)], "dfns-onb.dfns.json")
    assert "fully signed" in cdz(d, "coord.env", "--party", pf, "bundle", "show", "dfns-onb.signed.json").stdout
    cdz(d, "coord.env", "--party", pf, "party", "allocate", "dfns-onb.signed.json", "--ledger-url", LEDGER[1], "--user", "cdz-e2e", "--yes")
    fp1 = json.loads((d / "dfnstx1.pub.json").read_text())["fingerprint"]
    st = _wait_p2p(d, pf, lambda p: True)
    assert st["party_to_participant"]["signing_keys"] == [fp1] and not st["drift"]

    def ping(tag, key_id):
        args = json.dumps({"id": tag, "initiator": party, "responder": party})
        cdz(d, "coord.env", "--party", pf, "tx", "prepare", "--create", PING, "--args", args, "-o", f"{tag}.json")
        cdz(d, "dfns.env", "--party", pf, "dfns", "sign-bundle", f"{tag}.json", "--key-id", key_id, "-o", f"{tag}.signed.json", "--yes")
        return json.loads(cdz(d, "coord.env", "--party", pf, "tx", "execute", f"{tag}.signed.json", "--yes").stdout)

    assert ping("dfns-tx1", key1)["executed"]
    # rotation: new DFNS key; owners (2-of-3) authorize, the new key proves ownership via DFNS
    key2 = json.loads(cdz(d, "dfns.env", "dfns", "keys", "create", "--name", "dfnstx2", "--pub-out", "dfnstx2.pub.json").stdout)["id"]
    fp2 = json.loads((d / "dfnstx2.pub.json").read_text())["fingerprint"]
    cdz(d, "coord.env", "--party", pf, "topology", "plan-party", "--add-key", "dfnstx2.pub.json", "--remove-key", fp1, "-o", "dfns-rot.json")
    for who in ("dfo1", "dfo2"):
        cdz(d, f"{who}.env", "--party", pf, "bundle", "sign", "dfns-rot.json", "--yes")
    cdz(d, "dfns.env", "--party", pf, "dfns", "sign-bundle", "dfns-rot.json", "--key-id", key2, "-o", "dfns-rot.json", "--yes")
    cdz(d, "coord.env", "--party", pf, "topology", "submit", "dfns-rot.json", "--yes")
    _wait_p2p(d, pf, lambda p: p["signing_keys"] == [fp2])
    pj = json.loads((d / pf).read_text())  # party.json follows the rotation (submission bundles are checked against it)
    pj["signing"]["keys"] = [{k: v for k, v in json.loads((d / "dfnstx2.pub.json").read_text()).items() if k in ("name", "spec", "spki", "fingerprint")}]
    (d / pf).write_text(json.dumps(pj))
    assert ping("dfns-tx2", key2)["executed"]
    r = cdz(d, "dfns.env", "--party", pf, "dfns", "sign-bundle", "dfns-tx2.json", "--key-id", key1, "-o", "x.json", "--yes", ok=False)
    assert r.returncode != 0 and "not a signing key" in r.stderr
