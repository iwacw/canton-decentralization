"""Golden vectors from Canton v3.5.8 NodeHashTest / MetadataHashTest (as mirrored in BitSafe
DecMan crates/decman/src/canton_hash/mod.rs), plus tamper and fail-closed cases."""

import pytest

from cdz import tx_hash
from cdz._proto.com.daml.ledger.api.v2 import value_pb2 as vp
from cdz._proto.com.daml.ledger.api.v2.interactive import interactive_submission_common_data_pb2 as icd
from cdz._proto.com.daml.ledger.api.v2.interactive import interactive_submission_service_pb2 as isp
from cdz._proto.com.daml.ledger.api.v2.interactive.transaction.v1 import interactive_submission_data_pb2 as nd

CID1 = "0007e7b5534931dfca8e1b485c105bae4e10808bd13ddc8e897f258015f9d921c5"
CID2 = "0059b59ad7a6b6066e77b91ced54b8282f0e24e7089944685cb8f22f32fcbc4e1b"
DUMMY_CID = "0097a092402108f5593bac7fb3c909cd316910197dd98d603042a45ab85c81e0fd"
SEED_CREATE = "926bbb6f341bc0092ae65d06c6e284024907148cc29543ef6bff0930f5d52c19"
SEED_FETCH = "4d2a522e9ee44e31b9bef2e3c8a07d43475db87463c6a13c4ea92f898ac8a930"
SEED_EXERCISE = "a867edafa1277f46f879ab92c373a15c2d75c5d86fec741705cee1eb01ef8c9e"
SEED_ROLLBACK = "5483d5df9b245e662c0e4368b8062e8a0fd24c17ce4ded1a0e452e4ee879dd81"
KEY_HASH = "4d1741d27564ab1f1e74873034760583a1a71edaa90dbad6be3a78c0bf3eec7c"
V2, V3 = tx_hash.V2, tx_hash.V3


def ident(module, name, pkg="package"):
    return vp.Identifier(package_id=pkg, module_name=module, entity_name=name)


def text(s):
    return vp.Value(text=s)


def gkey():
    return icd.GlobalKeyWithMaintainers(
        key=icd.GlobalKey(
            template_id=ident("module_key", "name"),
            package_name="package_name_key",
            key=text("hello"),
            hash=bytes.fromhex(KEY_HASH),
        ),
        maintainers=["david"],
    )


def create(lf, cid):
    return nd.Create(
        lf_version=lf,
        contract_id=cid,
        package_name="package-name-0",
        template_id=ident("module", "name"),
        argument=text("hello"),
        signatories=["alice", "bob"],
        stakeholders=["alice", "charlie"],
    )


def fetch(lf, cid):
    return nd.Fetch(
        lf_version=lf,
        contract_id=cid,
        package_name="package-name-0",
        template_id=ident("module", "name"),
        signatories=["alice"],
        stakeholders=["charlie"],
        acting_parties=["alice", "bob"],
    )


def exercise(lf):
    return nd.Exercise(
        lf_version=lf,
        contract_id=CID1,
        package_name="package-name-0",
        template_id=ident("module", "name"),
        signatories=["alice"],
        stakeholders=["charlie"],
        acting_parties=["alice", "bob"],
        interface_id=ident("interface_module", "interface_name"),
        choice_id="choice",
        chosen_value=vp.Value(int64=31380),
        consuming=True,
        children=["0", "2"],
        exercise_result=text("result"),
        choice_observers=["david"],
    )


def transaction(scheme):
    lf = "2.1" if scheme == V2 else "2"
    c, f, e = create(lf, CID1), fetch(lf, CID1), exercise(lf)
    if scheme == V3:
        c.key.CopyFrom(gkey())
        f.key.CopyFrom(gkey())
        f.by_key = True
        e.key.CopyFrom(gkey())
        e.by_key = True

    def node(i, **kw):
        return isp.DamlTransaction.Node(node_id=i, v1=nd.Node(**kw))

    return isp.DamlTransaction(
        version=lf,
        roots=["0", "5"],
        nodes=[
            node("0", create=c),
            node("1", create=create(lf, CID2)),
            node("2", fetch=f),
            node("3", fetch=fetch(lf, CID2)),
            node("4", exercise=e),
            node("5", rollback=nd.Rollback(children=["2", "4"])),
        ],
        node_seeds=[
            isp.DamlTransaction.NodeSeed(node_id=i, seed=bytes.fromhex(s))
            for i, s in [(0, SEED_CREATE), (2, SEED_FETCH), (4, SEED_EXERCISE), (5, SEED_ROLLBACK)]
        ],
    )


def metadata(scheme):
    lf = "2.1" if scheme == V2 else "2"

    def disclosed(cid, party, created_at):
        return isp.Metadata.InputContract(
            created_at=created_at,
            v1=nd.Create(
                lf_version=lf,
                contract_id=cid,
                package_name="PkgName",
                template_id=vp.Identifier(package_id="-dummyPkg-", module_name="DummyModule", entity_name="dummyName"),
                argument=vp.Value(contract_id=DUMMY_CID),
                signatories=[party],
                stakeholders=[party],
            ),
        )

    return isp.Metadata(
        submitter_info=isp.Metadata.SubmitterInfo(act_as=["alice", "bob"], command_id="command-id"),
        synchronizer_id="synchronizer::id",
        mediator_group=0,
        transaction_uuid="4c6471d3-4e09-49dd-addf-6cd90e19c583",
        preparation_time=0,
        input_contracts=[disclosed(CID1, "alice", 864_000_000_000), disclosed(CID2, "bob", 1_728_000_000_000)],
        min_ledger_effective_time=0xAAAA,
        max_ledger_effective_time=0xBBBB,
        max_record_time=2_592_000_000_000,
    )


def prepared(scheme):
    return isp.PreparedTransaction(transaction=transaction(scheme), metadata=metadata(scheme))


@pytest.mark.parametrize(
    "scheme,expected",
    [
        (V2, {"0": "6d2cfe58c2294000592034f4bdfe397fe246901bb8b63e3b9e041bb478e174b7",
              "2": "c962c6098394f3d11cd6f0c795de9517d32a8e3e1979cec76cd2f66254efc610",
              "4": "070970eb4b2de72561dafb67017ca33850650a8103e5134e16044ba78991f48c",
              "5": "7264d5da2fd714427453bedc0d1cdb21f52ac7aec8d4bb5ac0598d25c5fcaed9"}),
        (V3, {"0": "0120d370509f54c07d8209f5af2d23f7f972997deb5fc5e0ebe886354395a3bc",
              "2": "20437df1980bb7d4d94ad53181dc6005bae37b5990719070c48a3960e8dda3a4",
              "4": "516c4689acabf9d1f0087a02a7dafad884d9080c48112a57a6d20b9f72d4b697",
              "5": "ea61ab05f9ab9769ab5c91493a601ccad9e784bd4c0b3bc4b7777f0da68eab4d"}),
    ],
)
def test_node_hashes(scheme, expected):
    h = tx_hash._Hasher(scheme, transaction(scheme))
    for node_id, want in expected.items():
        assert h.node_hash(node_id).hex() == want, node_id


def test_v2_golden():
    assert tx_hash.hash_transaction(V2, transaction(V2)).hex() == "154f334d24a8a5e4d0ce51ac87d93821b3256f885f21d3f779a1640abf481983"
    assert tx_hash.hash_metadata(V2, metadata(V2)).hex() == "6e89fcbcc9605179a47919b5e65a864e470e7a133f4f9f39b1e4545b223db769"
    assert tx_hash.hash_prepared(V2, prepared(V2)).hex() == "8c311c848db25d36b36fbd59f9483714a11688c2214e3c7cae3e028763520250"


def test_v3_golden():
    assert tx_hash.hash_transaction(V3, transaction(V3)).hex() == "36f0d1f4e9742a5cf54795fd1633f46b8235fafa93da006dafe10eb358d465c4"
    assert tx_hash.hash_metadata(V3, metadata(V3)).hex() == "5a4c6aa89bb80d0af05a3f0614ba07bc7469795fff66d7b9e87c876eb0137e0a"
    assert tx_hash.hash_prepared(V3, prepared(V3)).hex() == "db37e4e251b83196260900fd43aacf934e1893b7ac58db4c1bfa8ced432b3b84"


def test_tampering_changes_hash():
    p = prepared(V2)
    base = tx_hash.hash_prepared(V2, p)
    p.transaction.nodes[0].v1.create.signatories.append("mallory")
    assert tx_hash.hash_prepared(V2, p) != base
    p = prepared(V2)
    p.metadata.submitter_info.act_as[:] = ["alice"]
    assert tx_hash.hash_prepared(V2, p) != base


def test_fail_closed():
    with pytest.raises(tx_hash.HashError):
        tx_hash.hash_prepared(4, prepared(V3))
    with pytest.raises(tx_hash.HashError, match="V3"):
        tx_hash.hash_prepared(V2, prepared(V3))  # keys under V2
    p = prepared(V2)
    p.transaction.nodes[5].v1.rollback.children.append("5")
    with pytest.raises(tx_hash.HashError, match="cyclic"):
        tx_hash.hash_prepared(V2, p)
    p = prepared(V2)
    p.transaction.roots.append("9")
    with pytest.raises(tx_hash.HashError, match="missing"):
        tx_hash.hash_prepared(V2, p)
    p = prepared(V2)
    del p.transaction.node_seeds[2]  # exercise seed
    with pytest.raises(tx_hash.HashError, match="seed"):
        tx_hash.hash_prepared(V2, p)


def test_shared_subtree_hashed_once():
    tx = isp.DamlTransaction(version="2.1", roots=["0"])
    levels = 64
    for i in range(levels):
        kids = [str(i + 1), str(i + 1)] if i < levels - 1 else []
        e = exercise("2.1")
        e.children[:] = kids
        tx.nodes.add(node_id=str(i), v1=nd.Node(exercise=e))
        tx.node_seeds.add(node_id=i, seed=bytes(32))
    assert len(tx_hash.hash_transaction(V2, tx)) == 32
