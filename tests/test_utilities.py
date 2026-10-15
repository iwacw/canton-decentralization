"""Utilities command builders and the registrar CLI wiring, with fake Ledger/Registry clients."""

import base64
import json
import time

import pytest

from cdz import cli, crypto, registrar_cli, tx_hash
from cdz import utilities as U
from cdz.party import Member, PartySpec
from cdz._proto.com.daml.ledger.api.v2 import value_pb2 as vp
from cdz._proto.com.daml.ledger.api.v2.interactive import interactive_submission_service_pb2 as isp
from cdz._proto.com.daml.ledger.api.v2.interactive.transaction.v1 import interactive_submission_data_pb2 as nd

REG = "reg::1220" + "ab" * 32
ALICE = "alice::1220" + "cd" * 32
BOB = "bob::1220" + "ef" * 32
OP = "operator::1220" + "01" * 32
SYNC = "global-domain::1220" + "02" * 32


def test_decimal_and_window():
    assert U.decimal("10") == "10" and U.decimal("1.50") == "1.50" and U.decimal(0.25) == "0.25"
    for bad in ("0", "-1", "abc", "1.00000000001"):
        with pytest.raises(U.UtilitiesError):
            U.decimal(bad)
    a, b = U.window(__import__("datetime").timedelta(hours=1))
    assert a < b and a.endswith("Z")


def test_registrar_flow_builders():
    c = U.registrar_service_request(OP, "prov::1220" + "03" * 32, REG)
    body = c["CreateCommand"]
    assert body["templateId"].endswith("Service.Registrar:RegistrarServiceRequest")
    assert body["createArguments"]["createTransferRule"] is True and body["createArguments"]["registrar"] == REG
    cred = U.self_credential(REG, "allow-1", "allowlist", [(ALICE, "isHolderOf", "TOK")], [OP])["CreateCommand"]["createArguments"]
    assert cred["issuer"] == cred["holder"] == REG and cred["observers"] == {"map": [[OP, {}]]}
    req = U.parse_requirement("isHolderOf=TOK", REG)
    assert req == {"issuer": REG, "requiredClaims": [{"_1": "isHolderOf", "_2": "TOK"}]}
    assert U.parse_requirement(f"{OP}@kyc=yes,tier=1", REG)["issuer"] == OP
    pl = U.instrument_payload("TOK", holder_reqs=[req], extra_ids=[U.additional_identifier(REG, "US0", "ISIN")])
    ex = U.instrument_update("rs-cid", "cfg-cid", pl)["ExerciseCommand"]
    assert ex["choice"] == "RegistrarService_ArchiveAndCreateInstrumentConfiguration" and ex["choiceArgument"]["payload"] == pl
    with pytest.raises(U.UtilitiesError):
        U.beneficiaries([(ALICE, "0.5"), (BOB, "0.4")])
    assert U.set_provider_beneficiaries("cfg", [(ALICE, "0.75"), (BOB, "0.25")])["ExerciseCommand"]["choiceArgument"][
        "providerAppRewardBeneficiaries"][0] == {"beneficiary": ALICE, "weight": "0.75"}


def test_mint_builders_and_burnmint_limit():
    m = U.mint_record(REG, "TOK", "100", ALICE, "ref", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    ex = U.offer_mint("fac", REG, m, {"values": {}})["ExerciseCommand"]
    assert ex["choice"] == "AllocationFactory_OfferMint" and ex["choiceArgument"]["expectedAdmin"] == REG
    acc = U.mint_request_accept("mr", U.local_context("cfg", ["c1"]))["ExerciseCommand"]["choiceArgument"]
    assert acc["extraArgs"]["context"]["values"][U.CTX_INSTRUMENT_CONFIG] == {"tag": "AV_ContractId", "value": "cfg"}
    assert acc["extraArgs"]["context"]["values"][U.CTX_ISSUER_CREDENTIALS]["value"] == [{"tag": "AV_ContractId", "value": "c1"}]
    with pytest.raises(U.UtilitiesError, match="extraActors"):
        U.burn_mint_self("f", REG, "TOK", [(ALICE, "1")])
    assert U.burn_mint_self("f", REG, "TOK", [(REG, "5")])["ExerciseCommand"]["choiceArgument"]["extraActors"] == []


def test_transfer_builder_and_inputs():
    rows = [
        {"contract_id": "h1", "owner": REG, "admin": REG, "instrument": "TOK", "amount": "5", "locked": False},
        {"contract_id": "h2", "owner": REG, "admin": REG, "instrument": "TOK", "amount": "20", "locked": False},
        {"contract_id": "h3", "owner": REG, "admin": REG, "instrument": "TOK", "amount": "50", "locked": True},
        {"contract_id": "h4", "owner": ALICE, "admin": REG, "instrument": "TOK", "amount": "7", "locked": False},
    ]
    assert U.pick_inputs(rows, REG, REG, "TOK", "22") == ["h2", "h1"]
    with pytest.raises(U.UtilitiesError, match="only 25"):
        U.pick_inputs(rows, REG, REG, "TOK", "30")
    s = U.summarize_holdings(rows)["{}|TOK".format(REG)]
    assert s == {"admin": REG, "instrument": "TOK", "total": "82", "unlocked": "32", "holders": 2, "holdings": 4}
    args = U.transfer_args(REG, REG, ALICE, "1.5", "TOK", "a", "b", ["h1"], reason="payout")
    assert args["transfer"]["meta"]["values"][U.REASON_META] == "payout" and args["transfer"]["amount"] == "1.5"
    with pytest.raises(U.UtilitiesError):
        U.transfer_args(REG, REG, ALICE, "1", "TOK", "a", "b", [])


def test_holding_views_and_disclosed():
    ev = {"contractId": "c1", "templateId": "x", "interfaceViews": [
        {"interfaceId": "pkg:Splice.Api.Token.HoldingV1:Holding", "viewStatus": {"code": 0},
         "viewValue": {"owner": ALICE, "instrumentId": {"admin": REG, "id": "TOK"}, "amount": "3.0", "lock": None}}]}
    assert U.holding_views([ev])[0]["amount"] == "3.0"
    d = U.strip_disclosed([{"templateId": "t", "contractId": "c", "createdEventBlob": "b", "synchronizerId": "s", "debugPayload": {}}])
    assert d == [{"templateId": "t", "contractId": "c", "createdEventBlob": "b", "synchronizerId": "s"}]


def test_csv(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text(f"receiver,amount,reason\n{ALICE},10,a\n{BOB},2.5,\n")
    rows = registrar_cli.read_transfer_csv(str(f))
    assert [r["amount"] for r in rows] == ["10", "2.5"] and rows[1]["reason"] is None
    f.write_text("receiver,amount\nnot-a-party,1\n")
    with pytest.raises(U.UtilitiesError, match="party id"):
        registrar_cli.read_transfer_csv(str(f))
    holdings = [{"contract_id": "x", "amount": "10"}, {"contract_id": "y", "amount": "2.5"}]
    assert registrar_cli.assign_exact_holdings(rows, holdings) == {2: "x", 3: "y"}
    assert registrar_cli.assign_exact_holdings(rows, holdings[:1]) is None


# --- CLI wiring with fakes -------------------------------------------------------------------


def _ident(tid: str) -> vp.Identifier:
    pkg, mod, ent = tid.lstrip("#").split(":")
    return vp.Identifier(package_id="pkgid-" + pkg, module_name=mod, entity_name=ent)


def json_to_value(j) -> vp.Value:
    """Untyped JSON -> Ledger API Value, enough for the fake node to echo arguments back."""
    if j is None:
        return vp.Value(optional=vp.Optional())
    if isinstance(j, bool):
        return vp.Value(bool=j)
    if isinstance(j, int):
        return vp.Value(int64=j)
    if isinstance(j, str):
        return vp.Value(text=j)
    if isinstance(j, list):
        return vp.Value(list=vp.List(elements=[json_to_value(x) for x in j]))
    if isinstance(j, dict) and set(j) == {"tag", "value"}:
        return vp.Value(variant=vp.Variant(constructor=j["tag"], value=json_to_value(j["value"])))
    return vp.Value(record=vp.Record(fields=[vp.RecordField(label=k, value=json_to_value(v)) for k, v in j.items()]))


def fake_prepared(party: str, command: dict) -> isp.PreparedTransaction:
    ((kind, body),) = command.items()
    tx = isp.DamlTransaction(version="2.1", roots=["0"])
    if kind == "CreateCommand":
        node = nd.Node(create=nd.Create(lf_version="2.1", contract_id="00" + "11" * 32, package_name="p",
                                        template_id=_ident(body["templateId"]), argument=json_to_value(body["createArguments"]),
                                        signatories=[party], stakeholders=[party]))
    else:
        e = nd.Exercise(lf_version="2.1", contract_id=body["contractId"], package_name="p", choice_id=body["choice"],
                        chosen_value=json_to_value(body["choiceArgument"]), consuming=True, acting_parties=[party],
                        signatories=[party], stakeholders=[party])
        if "Splice.Api" in body["templateId"]:
            e.interface_id.CopyFrom(_ident(body["templateId"]))
            e.template_id.CopyFrom(_ident("#utility-registry-app-v0:Utility.Registry.App.V0.Service.AllocationFactory:AllocationFactory"))
        else:
            e.template_id.CopyFrom(_ident(body["templateId"]))
        node = nd.Node(exercise=e)
        tx.node_seeds.add(node_id=0, seed=bytes(32))
    tx.nodes.add(node_id="0", v1=node)
    md = isp.Metadata(submitter_info=isp.Metadata.SubmitterInfo(act_as=[party], command_id="c"), synchronizer_id=SYNC,
                      transaction_uuid="u", preparation_time=int(time.time() * 1e6))
    return isp.PreparedTransaction(transaction=tx, metadata=md)


class FakeLedger:
    base = "http://fake"

    def __init__(self, acs):
        self.acs, self.prepared, self.executed = acs, [], []

    def synchronizer_id(self, expected=None):
        return SYNC

    def active_contracts(self, party, templates=(), interfaces=(), include_blob=False, page_size=500):
        return [e for e in self.acs if (e["templateId"] in templates) or (interfaces and e.get("interfaceViews"))]

    def prepare(self, party, command, synchronizer_id=None, disclosed=(), max_record_time=None, scheme="HASHING_SCHEME_VERSION_V2", **kw):
        p = fake_prepared(party, command)
        self.prepared.append((command, list(disclosed)))
        return {"preparedTransaction": base64.b64encode(p.SerializeToString()).decode(),
                "preparedTransactionHash": base64.b64encode(tx_hash.hash_prepared(tx_hash.V2, p)).decode(),
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2"}

    def execute_and_wait(self, prepared_b64, party, sigs, scheme):
        self.executed.append((party, [s.signed_by for s in sigs]))
        return {"updateId": "u%d" % len(self.executed), "completionOffset": len(self.executed)}


class FakeRegistry:
    def __init__(self):
        self.calls = []

    def operator_party(self):
        return OP

    def transfer_factory(self, admin, choice_args):
        self.calls.append(("factory", choice_args["transfer"]["receiver"]))
        return _cid("factory"), "offer", {"values": {U.CTX_INSTRUMENT_CONFIG: U.av_cid("cfg")}}, [
            {"templateId": "t", "contractId": "cfg", "createdEventBlob": "YmxvYg==", "synchronizerId": SYNC}]

    def mint_request_accept_context(self, cid):
        return {"values": {}}, []


@pytest.fixture
def env(tmp_path, monkeypatch):
    keys = [crypto.SigningKey.generate(name=f"tx{i}") for i in range(3)]
    owners = [crypto.SigningKey.generate(name="o")]
    spec = PartySpec("reg", [Member("o", owners[0].public)], 1, [Member(k.name, k.public) for k in keys], 2,
                     [("p1::1220" + "aa" * 32, "confirmation")], 1, network="devnet")
    (tmp_path / "party.json").write_text(json.dumps(spec.to_json()))
    (tmp_path / ".env").write_text("CDZ_NETWORK=devnet\nCDZ_LEDGER_URL=http://fake\n"
                                   + "".join(f"CDZ_TX_KEY_{k.name.upper()}={k.pkcs8_b64()}\n" for k in keys[:2]))
    (tmp_path / ".env").chmod(0o600)
    monkeypatch.chdir(tmp_path)
    for k in list(__import__("os").environ):
        if k.startswith("CDZ_"):
            monkeypatch.delenv(k)
    return spec


def _wire(monkeypatch, acs):
    lc, reg = FakeLedger(acs), FakeRegistry()
    monkeypatch.setattr(cli, "ledger", lambda s, url=None: lc)
    monkeypatch.setattr(registrar_cli, "_registry", lambda s: reg)
    return lc, reg


def _cid(name):
    return "00" + __import__("hashlib").sha256(name.encode()).hexdigest()


def _holding(cid, amount, owner):
    return {"contractId": _cid(cid), "templateId": U.T["holding"], "interfaceViews": [
        {"interfaceId": "x:Splice.Api.Token.HoldingV1:Holding", "viewStatus": {"code": 0},
         "viewValue": {"owner": owner, "instrumentId": {"admin": owner, "id": "TOK"}, "amount": amount, "lock": None}}]}


def test_cli_request_service_and_execute(env, monkeypatch):
    lc, reg = _wire(monkeypatch, [])
    assert cli.main(["registrar", "request-service", "--provider", BOB, "--execute", "--yes"]) == 0
    cmd, _ = lc.prepared[0]
    assert cmd["CreateCommand"]["createArguments"]["operator"] == OP  # devnet: operator looked up via DA's API
    assert len(lc.executed) == 1 and len(lc.executed[0][1]) == 2  # 2-of-3 local keys


def test_cli_csv_transfers_split_then_bundles(env, monkeypatch, tmp_path):
    party = env.party_id
    (tmp_path / "pay.csv").write_text(f"receiver,amount,reason\n{ALICE},10,a\n{BOB},2.5,b\n")
    lc, reg = _wire(monkeypatch, [_holding("big", "100", party)])
    assert cli.main(["registrar", "transfers", "--csv", "pay.csv", "--instrument", "TOK", "--out-dir", "out"]) == 0
    split = json.loads((tmp_path / "out/00-split.json").read_text())
    assert split["intent"]["ExerciseCommand"]["choice"] == "Holding_Split"
    assert split["intent"]["ExerciseCommand"]["choiceArgument"]["amounts"] == ["10", "2.5"]
    # after the split: exact holdings exist -> one bundle per row, each with its own input
    lc.acs = [_holding("h10", "10", party), _holding("h25", "2.5", party), _holding("rest", "87.5", party)]
    assert cli.main(["registrar", "transfers", "--csv", "pay.csv", "--instrument", "TOK", "--out-dir", "out"]) == 0
    manifest = json.loads((tmp_path / "out/manifest.json").read_text())
    assert [m["input"] for m in manifest] == [_cid("h10"), _cid("h25")]
    b = json.loads((tmp_path / manifest[0]["bundle"]).read_text())
    t = b["intent"]["ExerciseCommand"]
    assert t["choice"] == "TransferFactory_Transfer" and t["contractId"] == _cid("factory")
    assert t["choiceArgument"]["transfer"]["inputHoldingCids"] == [_cid("h10")]
    assert t["choiceArgument"]["extraArgs"]["context"]["values"][U.CTX_INSTRUMENT_CONFIG]["value"] == "cfg"
    assert lc.prepared[-1][1][0]["contractId"] == "cfg"  # disclosed contracts passed through
    # offline batch signing of all bundles, then execution in order
    assert cli.main(["bundle", "sign", "--yes", *[m["bundle"] for m in manifest]]) == 0
    assert cli.main(["tx", "execute", "--yes", *[m["bundle"] for m in manifest]]) == 0
    assert len(lc.executed) == 2
    assert cli.main(["tx", "execute", "--yes", manifest[0]["bundle"]]) == 0  # already executed: skipped
    assert len(lc.executed) == 2


def test_cli_refuses_wrong_network(env, monkeypatch):
    _wire(monkeypatch, [])
    assert cli.main(["--network", "mainnet", "registrar", "holdings"]) == 2


def test_intent_argument_check():
    from cdz import prepared

    cmd = U.registrar_service_request(OP, BOB, REG)
    p = fake_prepared(REG, cmd)
    prepared.check(p, tx_hash.V2, None, REG, cmd)
    # a node that swaps the provider is caught even though the hash matches its own transaction
    evil = json.loads(json.dumps(cmd))
    evil["CreateCommand"]["createArguments"]["provider"] = ALICE
    with pytest.raises(prepared.PreparedCheckError, match="provider"):
        prepared.check(fake_prepared(REG, evil), tx_hash.V2, None, REG, cmd)
    v = json_to_value({"amount": "10", "when": "2026-01-01T00:00:00Z"})
    v.record.fields[0].value.CopyFrom(vp.Value(numeric="10.0000000000"))
    v.record.fields[1].value.CopyFrom(vp.Value(timestamp=1767225600000000))
    assert prepared.compare_value({"amount": "10", "when": "2026-01-01T00:00:00Z"}, v) == []
    assert prepared.compare_value({"amount": "11"}, v) == ["$.amount: 10.0000000000 != 11"]
