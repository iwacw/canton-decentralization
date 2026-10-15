import base64

import pytest

from cdz import authz, bundle, crypto, topology
from cdz.party import Member, PartySpec
from cdz.topology import Tx

P1 = "participant1::1220" + "11" * 32
P2 = "participant2::1220" + "22" * 32
P3 = "participant3::1220" + "33" * 32


def test_fingerprint_doc_vector():
    # docs: external-signing-topology, "compute_canton_fingerprint_from_base64"
    raw = base64.b64decode("2RwUiIHVUVdulxzD8NKtPmIaaBqMer1A90rDjoklJPY=")
    assert crypto.canton_hash(12, raw).hex() == "1220205057e331cc8929dd217e2f8e63f503b7081773de60d01fb46839700bc5caaa"


def test_ed25519_fingerprint_uses_raw_key():
    k = crypto.SigningKey.generate("ed25519")
    raw = k.public.spki[-32:]
    assert k.fingerprint == crypto.canton_hash(12, raw).hex()
    p = crypto.SigningKey.generate("p256")
    assert p.fingerprint == crypto.canton_hash(12, p.public.spki).hex()


@pytest.mark.parametrize("spec", ["ed25519", "p256", "secp256k1", "p384"])
def test_sign_verify_roundtrip(spec):
    k = crypto.SigningKey.generate(spec)
    data = b"\x12\x20" + bytes(32)
    s = k.signature(data)
    assert k.public.verify(s.signature, data)
    assert not k.public.verify(s.signature, data[:-1] + b"\x01")
    again = crypto.SigningKey.parse(k.pkcs8_b64())
    assert again.fingerprint == k.fingerprint
    assert crypto.Sig.from_json(s.to_json()) == s


def test_multi_hash_matches_reference_definition():
    hs = [crypto.canton_hash(11, bytes([i])) for i in range(3)]
    ref = sorted(hs, key=lambda h: h.hex())
    body = len(ref).to_bytes(4, "big") + b"".join(len(h).to_bytes(4, "big") + h for h in ref)
    assert crypto.multi_tx_hash(hs[::-1]) == crypto.canton_hash(55, body)


def test_tx_roundtrip_and_hash():
    k = crypto.SigningKey.generate()
    tx = Tx.build(topology.root_namespace_delegation(k.public), 1)
    assert tx.canonical() == tx.serialized
    assert tx.hash == crypto.canton_hash(11, tx.serialized)
    d = tx.describe()
    assert d["mapping"] == "NamespaceDelegation" and d["root"] and d["restriction"] == "all"


def _spec(n_owners=3, dns_t=2, n_keys=3, sig_t=2, hosts=(P1, P2), conf_t=2):
    owners = [crypto.SigningKey.generate(name=f"own{i}") for i in range(n_owners)]
    tks = [crypto.SigningKey.generate(name=f"tx{i}") for i in range(n_keys)]
    spec = PartySpec(
        hint="registrar",
        owners=[Member(k.name, k.public) for k in owners],
        dns_threshold=dns_t,
        signing_keys=[Member(k.name, k.public) for k in tks],
        signing_threshold=sig_t,
        hosts=[(h, "confirmation") for h in hosts],
        confirmation_threshold=conf_t,
    )
    return spec, owners, tks


def test_onboarding_bundle_needs_all_owners_and_all_keys():
    spec, owners, tks = _spec()
    b = bundle.TopologyBundle("devnet", None, "onboard", [bundle.Item(l, t) for l, t in spec.onboarding_txs()])
    assert spec.party_id.startswith("registrar::1220")
    reports = b.check()
    assert not any(r.satisfied for _, r, _ in reports)
    b.sign(owners[:2])
    by_label = {it.label: r for it, r, _ in b.check()}
    assert by_label["dns"].satisfied is False  # creation needs ALL owners
    b.sign([owners[2]])
    by_label = {it.label: r for it, r, _ in b.check()}
    assert by_label["dns"].satisfied
    p2p = by_label["p2p"]
    assert not p2p.satisfied and any("signing key" in m for m in p2p.missing)  # proof of possession
    assert p2p.participants == sorted([P1, P2])
    b.sign(tks)
    assert all(r.satisfied for _, r, _ in b.check())
    # participants cannot be assumed when asked strictly
    assert not [r for it, r, _ in b.check(assume_participants=False) if it.label == "p2p"][0].satisfied


def test_bundle_json_roundtrip_and_tamper(tmp_path):
    spec, owners, tks = _spec()
    b = bundle.TopologyBundle("devnet", "sync::1220" + "00" * 32, "x", [bundle.Item(l, t) for l, t in spec.onboarding_txs()])
    b.sign(owners + tks)
    f = tmp_path / "b.json"
    bundle.save(b, f)
    again = bundle.load(f)
    assert all(r.satisfied for _, r, _ in again.check())
    d = b.to_json()
    d["transactions"][-1]["hash"] = "1220" + "ab" * 32
    with pytest.raises(bundle.BundleError):
        bundle.TopologyBundle.from_json(d)


def test_bundle_multi_signatures():
    spec, owners, tks = _spec(n_owners=2, dns_t=1, n_keys=1, sig_t=1, hosts=(P1,), conf_t=1)
    b = bundle.TopologyBundle("devnet", None, "x", [bundle.Item(l, t) for l, t in spec.onboarding_txs()])
    b.sign(owners + tks, use_multi=True)
    assert b.multi and all(r.satisfied for _, r, _ in b.check())
    st = b.signed_transactions()
    assert all(len(s.multi_transaction_signatures) >= 1 for s in st)


def test_dns_update_rules():
    spec, owners, tks = _spec()
    base = [t for _, t in spec.onboarding_txs()]
    new_owner = crypto.SigningKey.generate(name="new")
    nsd = Tx.build(topology.root_namespace_delegation(new_owner.public), 1)
    upd = Tx.build(
        topology.decentralized_namespace(spec.owner_namespaces + [new_owner.fingerprint], 3, spec.namespace), 2
    )
    b = bundle.TopologyBundle("devnet", None, "add owner", [bundle.Item("nsd", nsd), bundle.Item("dns", upd)], base=base)
    b.sign([new_owner])
    rep = b.check()[1][1]
    assert not rep.satisfied  # also needs the current quorum (2 of 3)
    b.sign(owners[:1])
    assert not b.check()[1][1].satisfied
    b.sign(owners[1:2])
    assert b.check()[1][1].satisfied
    assert b.check()[1][2] == 2  # expected serial


def test_p2p_threshold_and_key_rotation_rules():
    spec, owners, tks = _spec()
    base = [t for _, t in spec.onboarding_txs()]
    st = authz.State()
    for t in base:
        st.apply(t)
    # threshold change only -> party namespace (2 of 3 owners), no key signatures
    spec2 = PartySpec.from_json(spec.to_json())
    spec2.signing_threshold = 3
    tx = Tx.build(spec2.p2p_mapping(), 2)
    sigs = [owners[0].signature(tx.hash), owners[1].signature(tx.hash)]
    assert authz.check(tx, sigs, st).satisfied
    # adding a key needs its proof of possession
    newk = crypto.SigningKey.generate()
    spec3 = PartySpec.from_json(spec.to_json())
    spec3.signing_keys.append(Member("new", newk.public))
    tx3 = Tx.build(spec3.p2p_mapping(), 2)
    sigs3 = [owners[0].signature(tx3.hash), owners[1].signature(tx3.hash)]
    assert not authz.check(tx3, sigs3, st).satisfied
    assert authz.check(tx3, sigs3 + [newk.signature(tx3.hash)], st).satisfied
    # removing a host (threshold unchanged): party OR that participant
    spec, owners, tks = _spec(hosts=(P1, P2, P3))
    st = authz.State()
    for _, t in spec.onboarding_txs():
        st.apply(t)
    spec4 = PartySpec.from_json(spec.to_json())
    spec4.hosts = spec4.hosts[:2]
    tx4 = Tx.build(spec4.p2p_mapping(), 2)
    rep = authz.check(tx4, [], st, assume_participants=True)
    assert rep.satisfied  # the participant may unhost on its own; here assumed to approve
    rep = authz.check(tx4, [owners[0].signature(tx4.hash)], st, assume_participants=False)
    assert not rep.satisfied
    rep = authz.check(tx4, [owners[0].signature(tx4.hash), owners[2].signature(tx4.hash)], st, assume_participants=False)
    assert rep.satisfied


def test_p2p_validation():
    k = crypto.SigningKey.generate()
    with pytest.raises(topology.TopologyError, match="Submission"):
        topology.party_to_participant("p::" + k.fingerprint, 2, [(P1, "submission"), (P2, "confirmation")], [k.public], 1)
    with pytest.raises(topology.TopologyError, match="exceeds"):
        topology.party_to_participant("p::" + k.fingerprint, 3, [(P1, "confirmation"), (P2, "confirmation")], [k.public], 1)
    with pytest.raises(topology.TopologyError, match="signing threshold"):
        topology.party_to_participant("p::" + k.fingerprint, 1, [(P1, "confirmation")], [k.public], 2)


def test_invalid_signature_is_reported():
    spec, owners, tks = _spec(n_owners=1, dns_t=1, n_keys=1, sig_t=1, hosts=(P1,), conf_t=1)
    b = bundle.TopologyBundle("devnet", None, "x", [bundle.Item(l, t) for l, t in spec.onboarding_txs()])
    it = b.items[0]
    bad = crypto.Sig(b"\x00" * 64, owners[0].fingerprint, crypto.SPECS["ed25519"].sig_format, crypto.SPECS["ed25519"].algorithm)
    it.sigs.append(bad)
    rep = b.check()[0][1]
    assert not rep.satisfied and rep.invalid_signers == [owners[0].fingerprint]
