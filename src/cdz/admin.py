"""Participant Admin API (gRPC): topology read/write services."""

from __future__ import annotations

import grpc
from google.protobuf import duration_pb2, empty_pb2

from cdz import authz, crypto
from cdz._proto.com.digitalasset.canton.protocol.v30 import topology_pb2 as tpb
from cdz._proto.com.digitalasset.canton.topology.admin.v30 import common_pb2 as cmn
from cdz._proto.com.digitalasset.canton.topology.admin.v30 import topology_manager_read_service_pb2 as rd
from cdz._proto.com.digitalasset.canton.topology.admin.v30 import topology_manager_read_service_pb2_grpc as rdg
from cdz._proto.com.digitalasset.canton.topology.admin.v30 import topology_manager_write_service_pb2 as wr
from cdz._proto.com.digitalasset.canton.topology.admin.v30 import topology_manager_write_service_pb2_grpc as wrg

FORCE_FLAGS = {n[len("FORCE_FLAG_"):].lower().replace("_", "-"): v for n, v in wr.ForceFlag.items() if v}


class AdminError(RuntimeError):
    pass


def rpc_error_text(e: grpc.RpcError) -> str:
    """Canton puts the error code into google.rpc.ErrorInfo in the status details."""
    text = f"{e.code().name}: {e.details()}"
    try:
        from google.rpc import error_details_pb2, status_pb2

        for k, v in e.trailing_metadata() or ():
            if k == "grpc-status-details-bin":
                st = status_pb2.Status.FromString(v)
                for d in st.details:
                    if d.Is(error_details_pb2.ErrorInfo.DESCRIPTOR):
                        info = error_details_pb2.ErrorInfo()
                        d.Unpack(info)
                        text += f" [{info.reason}] {dict(info.metadata)}"
    except Exception:  # details are best effort
        pass
    return text


def store_id(synchronizer_id: str | None) -> cmn.StoreId:
    if synchronizer_id is None:
        return cmn.StoreId(authorized=cmn.StoreId.Authorized())
    if synchronizer_id.count("::") >= 2:
        return cmn.StoreId(synchronizer=cmn.Synchronizer(physical_id=synchronizer_id))
    return cmn.StoreId(synchronizer=cmn.Synchronizer(id=synchronizer_id))


def item(res):
    """List results carry the mapping as `item` or as the oneof `item { v30 }` (3.5)."""
    which = res.WhichOneof("item") if "item" in res.DESCRIPTOR.oneofs_by_name else None
    return getattr(res, which) if which else res.item


class AdminClient:
    def __init__(self, target: str, tls: bool = False, ca_file: str | None = None, timeout: float = 30.0):
        if tls:
            ca = open(ca_file, "rb").read() if ca_file else None
            self.channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(root_certificates=ca))
        else:
            self.channel = grpc.insecure_channel(target)
        self.read = rdg.TopologyManagerReadServiceStub(self.channel)
        self.write = wrg.TopologyManagerWriteServiceStub(self.channel)
        self.timeout = timeout

    def _call(self, fn, req):
        try:
            return fn(req, timeout=self.timeout)
        except grpc.RpcError as e:
            raise AdminError(rpc_error_text(e)) from None

    def _q(self, sync: str, proposals: bool = False) -> rd.BaseQuery:
        return rd.BaseQuery(store=store_id(sync), proposals=proposals, head_state=empty_pb2.Empty())

    # --- reads -------------------------------------------------------------------------------

    def namespace_delegations(self, sync: str, namespace: str = "", proposals: bool = False):
        r = self._call(
            self.read.ListNamespaceDelegation,
            rd.ListNamespaceDelegationRequest(base_query=self._q(sync, proposals), filter_namespace=namespace),
        )
        return list(r.results)

    def decentralized_namespaces(self, sync: str, namespace: str = "", proposals: bool = False):
        r = self._call(
            self.read.ListDecentralizedNamespaceDefinition,
            rd.ListDecentralizedNamespaceDefinitionRequest(base_query=self._q(sync, proposals), filter_namespace=namespace),
        )
        return list(r.results)

    def party_to_participant(self, sync: str, party: str = "", participant: str = "", proposals: bool = False):
        r = self._call(
            self.read.ListPartyToParticipant,
            rd.ListPartyToParticipantRequest(
                base_query=self._q(sync, proposals), filter_party=party, filter_participant=participant
            ),
        )
        return list(r.results)

    def state(self, sync: str, namespaces: list[str] = (), parties: list[str] = ()) -> authz.State:
        """Head state for the given namespaces (incl. DNS owners) and parties."""
        st = authz.State()
        seen: set[str] = set()
        todo = list(namespaces) + [p.split("::")[-1] for p in parties]
        while todo:
            ns = todo.pop()
            if ns in seen:
                continue
            seen.add(ns)
            for res in self.decentralized_namespaces(sync, ns):
                d = item(res)
                if d.decentralized_namespace == ns:
                    st.dns[ns] = d
                    st.serials[("decentralized_namespace_definition", ns)] = res.context.serial
                    todo.extend(d.owners)
            for res in self.namespace_delegations(sync, ns):
                n = item(res)
                if n.namespace == ns:
                    fp = crypto.PublicKey.from_proto(n.target_key).fingerprint
                    st.nsds[(ns, fp)] = n
                    st.serials[("namespace_delegation", ns, fp)] = res.context.serial
        for party in parties:
            for res in self.party_to_participant(sync, party):
                if item(res).party == party:
                    st.p2p[party] = item(res)
                    st.serials[("party_to_participant", party)] = res.context.serial
        return st

    # --- writes ------------------------------------------------------------------------------

    def add_transactions(self, sync: str, signed: list[tpb.SignedTopologyTransaction], force: list[str] = (), wait_s: float = 0):
        req = wr.AddTransactionsRequest(transactions=signed, store=store_id(sync))
        req.force_changes.extend(FORCE_FLAGS[f] for f in force)
        if wait_s:
            req.wait_to_become_effective.CopyFrom(duration_pb2.Duration(seconds=int(wait_s)))
        self._call(self.write.AddTransactions, req)

    def authorize_hash(self, sync: str, tx_hash_hex: str, must_fully: bool = False, force: list[str] = ()):
        """Node operator side: sign a pending proposal (e.g. accept hosting the party) with node keys."""
        req = wr.AuthorizeRequest(transaction_hash=tx_hash_hex, must_fully_authorize=must_fully, store=store_id(sync))
        req.force_changes.extend(FORCE_FLAGS[f] for f in force)
        return self._call(self.write.Authorize, req).transaction

    def authorize_mapping(self, sync: str, mapping: tpb.TopologyMapping, serial: int, op: int, must_fully: bool = False):
        """Node operator side: propose a mapping signed with this node's keys (e.g. clearing its own
        onboarding flag, which only the participant may authorize)."""
        req = wr.AuthorizeRequest(must_fully_authorize=must_fully, store=store_id(sync))
        req.proposal.change = op
        req.proposal.serial = serial
        req.proposal.v30.CopyFrom(mapping)
        return self._call(self.write.Authorize, req).transaction

    def generate(self, sync: str, items: list[tuple[tpb.TopologyMapping, int, int]]) -> list[tuple[bytes, bytes]]:
        """Ask the node to serialize mappings ((mapping, serial, op)); used only to cross-check ours."""
        req = wr.GenerateTransactionsRequest()
        for mapping, serial, op in items:
            p = req.proposals.add(operation=op, serial=serial, store=store_id(sync))
            p.v30.CopyFrom(mapping)
        r = self._call(self.write.GenerateTransactions, req)
        return [(g.serialized_transaction, g.transaction_hash) for g in r.generated_transactions]
