import json
import os

import pytest

from cdz import authz, config, crypto, manage, topology
from cdz.party import Member, PartySpec

P1 = "participant1::1220" + "11" * 32
P2 = "participant2::1220" + "22" * 32
P3 = "participant3::1220" + "33" * 32


def _state(hosts=(P1, P2), conf_t=2):
    owners = [crypto.SigningKey.generate(name=f"o{i}") for i in range(3)]
    tks = [crypto.SigningKey.generate(name=f"t{i}") for i in range(3)]
    spec = PartySpec("reg", [Member(k.name, k.public) for k in owners], 2, [Member(k.name, k.public) for k in tks], 2,
                     [(h, "confirmation") for h in hosts], conf_t)
    st = authz.State()
    for _, t in spec.onboarding_txs():
        st.apply(t)
    return spec, st, owners, tks


def test_plan_party_change_serial_base_and_diff():
    spec, st, owners, tks = _state()
    new = crypto.SigningKey.generate()
    b = manage.plan_party_change(st, spec.party_id, "devnet", None, add_keys=[new.public], remove_keys=[tks[0].fingerprint])
    assert b.items[0].tx.tx.serial == 2
    assert {t.kind for t in b.base} == {"party_to_participant", "decentralized_namespace_definition", "namespace_delegation"}
    assert set(b.meta["diff"]) == {"signing_keys"}
    # the bundle's own base state reproduces the requirement: 2 owners + the new key
    b.sign(owners[:2])
    assert not b.check()[0][1].satisfied
    b.sign([new])
    assert b.check()[0][1].satisfied


def test_plan_party_change_errors():
    spec, st, owners, tks = _state()
    with pytest.raises(manage.PlanError, match="not registered"):
        manage.plan_party_change(st, spec.party_id, "devnet", None, remove_keys=["1220" + "00" * 32])
    with pytest.raises(manage.PlanError, match="not a current host"):
        manage.plan_party_change(st, spec.party_id, "devnet", None, remove_hosts=[P3])
    with pytest.raises(topology.TopologyError, match="exceeds"):
        manage.plan_party_change(st, spec.party_id, "devnet", None, remove_hosts=[P2])
    with pytest.raises(manage.PlanError, match="no active"):
        manage.plan_party_change(st, "other::1220" + "44" * 32, "devnet", None)


def test_add_host_sets_onboarding_and_permission_change_rules():
    spec, st, owners, tks = _state()
    b = manage.plan_party_change(st, spec.party_id, "devnet", None, add_hosts=[(P3, "confirmation")])
    hosts = b.items[0].tx.describe()["hosts"]
    assert hosts[-1] == {"participant": P3, "permission": "confirmation", "onboarding": True}
    rep = b.check(assume_participants=False)[0][1]
    assert rep.participants == [P3] and not rep.satisfied
    # downgrade P2 to observation: party OR participant (assumed participant approval suffices)
    b2 = manage.plan_party_change(st, spec.party_id, "devnet", None, add_hosts=[(P2, "observation")], confirmation_threshold=1)
    p2 = [h for h in b2.items[0].tx.describe()["hosts"] if h["participant"] == P2][0]
    assert p2["permission"] == "observation"
    st2 = b2.state_before(0)
    assert authz.check(b2.items[0].tx, [owners[0].signature(b2.items[0].tx.hash), owners[1].signature(b2.items[0].tx.hash)], st2).satisfied


def test_clear_onboarding_plan_needs_only_participant():
    spec, st, owners, tks = _state()
    b = manage.plan_party_change(st, spec.party_id, "devnet", None, add_hosts=[(P3, "confirmation")])
    st.apply(b.items[0].tx)
    c = manage.plan_clear_onboarding(st, spec.party_id, P3, "devnet", None)
    rep = c.check(assume_participants=False)[0][1]
    assert rep.participants == [P3] and rep.missing == []
    assert "onboarding" not in c.items[0].tx.describe()["hosts"][-1]
    with pytest.raises(manage.PlanError):
        manage.plan_clear_onboarding(st, spec.party_id, P1, "devnet", None)


def test_plan_dns_change():
    spec, st, owners, tks = _state()
    new = crypto.SigningKey.generate()
    b = manage.plan_dns_change(st, spec.namespace, "devnet", None, add_owners=[new.public], remove_owners=[owners[0].fingerprint], threshold=2)
    assert [it.label.split(":")[0] for it in b.items] == ["nsd", "dns"]
    d = b.items[-1].tx.describe()
    assert d["namespace"] == spec.namespace and new.fingerprint in d["owners"] and owners[0].fingerprint not in d["owners"]
    assert d["namespace_derived_from_owners"] is False  # the namespace is fixed at creation
    with pytest.raises(manage.PlanError, match="exceeds"):
        manage.plan_dns_change(st, spec.namespace, "devnet", None, remove_owners=[owners[0].fingerprint, owners[1].fingerprint], threshold=2)


def test_env_file_parsing(tmp_path, monkeypatch):
    k = crypto.SigningKey.generate("p256")
    f = tmp_path / ".env"
    f.write_text(
        "# comment\n"
        "export CDZ_NETWORK=devnet   # inline comment\n"
        f"CDZ_TX_KEY_2='{k.pkcs8_b64()}'\n"
        "CDZ_TX_KEY_10=\n"
        f"CDZ_NS_KEY_A=file:{tmp_path / 'k.pem'}\n"
    )
    (tmp_path / "k.pem").write_text(
        crypto.serialization.load_der_private_key(crypto.unb64(k.pkcs8_b64()), None)
        .private_bytes(crypto.serialization.Encoding.PEM, crypto.serialization.PrivateFormat.PKCS8, crypto.serialization.NoEncryption())
        .decode()
    )
    f.chmod(0o600)
    for v in list(os.environ):
        if v.startswith("CDZ_"):
            monkeypatch.delenv(v)
    s = config.Settings.load(str(f))
    assert s.network["name"] == "devnet" and s.network["utilities"]["api"].endswith("digitalasset-dev.com")
    assert [x.fingerprint for x in s.protocol_keys()] == [k.fingerprint]
    assert [x.fingerprint for x in s.namespace_keys()] == [k.fingerprint]
    with pytest.raises(config.ConfigError):
        config.load_network("nonet")


def test_party_json_roundtrip_and_tamper(tmp_path):
    spec, st, owners, tks = _state()
    f = tmp_path / "party.json"
    spec.save(f)
    again = PartySpec.load(f)
    assert again.party_id == spec.party_id and again.known_keys().keys() == spec.known_keys().keys()
    d = json.loads(f.read_text())
    d["party_id"] = "reg::1220" + "99" * 32
    with pytest.raises(topology.TopologyError):
        PartySpec.from_json(d)
    d = json.loads(f.read_text())
    d["namespace"]["owners"][0]["fingerprint"] = "1220" + "98" * 32
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        PartySpec.from_json(d)
