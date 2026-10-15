"""DA Canton Network Utilities (Registry) commands for an EXTERNAL registrar.

Every builder returns ONE JSON Ledger API command whose only required authorizer is the
registrar, because interactive submission supports a single command, a single root node and a
single submitting party. Identifiers use package-name references (`#pkg:Module:Entity`) so the
participant picks the vetted version. Shapes: DA registry docs + Utility 0.14.4 models.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal, InvalidOperation

P = "utility.digitalasset.com/"  # choice-context key prefix (Token Standard V1)
CTX_INSTRUMENT_CONFIG = P + "instrument-configuration"
CTX_ISSUER_CREDENTIALS = P + "issuer-credentials"
CTX_SENDER_CREDENTIALS = P + "sender-credentials"
CTX_RECEIVER_CREDENTIALS = P + "receiver-credentials"
CTX_BLOCK_LIST = P + "block-list"
REASON_META = "splice.lfdecentralizedtrust.org/reason"

T = {
    "registrar_service_request": "#utility-registry-app-v0:Utility.Registry.App.V0.Service.Registrar:RegistrarServiceRequest",
    "registrar_service": "#utility-registry-app-v0:Utility.Registry.App.V0.Service.Registrar:RegistrarService",
    "allocation_factory": "#utility-registry-app-v0:Utility.Registry.App.V0.Service.AllocationFactory:AllocationFactory",
    "mint_request": "#utility-registry-app-v0:Utility.Registry.App.V0.Model.Mint:MintRequest",
    "mint_offer": "#utility-registry-app-v0:Utility.Registry.App.V0.Model.Mint:MintOffer",
    "burn_request": "#utility-registry-app-v0:Utility.Registry.App.V0.Model.Burn:BurnRequest",
    "transfer_offer": "#utility-registry-app-v0:Utility.Registry.App.V0.Model.Transfer:TransferOffer",
    "instrument_configuration": "#utility-registry-v0:Utility.Registry.V0.Configuration.Instrument:InstrumentConfiguration",
    "transfer_rule": "#utility-registry-v0:Utility.Registry.V0.Rule.Transfer:TransferRule",
    "block_list_shard": "#utility-registry-v0:Utility.Registry.V0.Rule.BlockList:StoredBlockListPartyShas",
    "holding": "#utility-registry-holding-v0:Utility.Registry.Holding.V0.Holding:Holding",
    "credential": "#utility-credential-v0:Utility.Credential.V0.Credential:Credential",
    "credential_offer": "#utility-credential-app-v0:Utility.Credential.App.V0.Model.Offer:CredentialOffer",
    "markers_proxy": "#utility-commercials-v0:Utility.Commercials.V0.Model.DelegatedBatchedMarkersProxy:DelegatedBatchedMarkersProxy",
    "holding_v1": "#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding",
    "transfer_factory_v1": "#splice-api-token-transfer-instruction-v1:Splice.Api.Token.TransferInstructionV1:TransferFactory",
    "transfer_instruction_v1": "#splice-api-token-transfer-instruction-v1:Splice.Api.Token.TransferInstructionV1:TransferInstruction",
    "burn_mint_factory_v1": "#splice-api-token-burn-mint-v1:Splice.Api.Token.BurnMintV1:BurnMintFactory",
}

# Holding interface view fields (Splice HoldingV1): owner, instrumentId{admin,id}, amount, lock, meta


class UtilitiesError(ValueError):
    pass


# --- value helpers (Daml-LF JSON encoding of the JSON Ledger API) --------------------------


def decimal(x) -> str:
    try:
        d = Decimal(str(x))
    except InvalidOperation:
        raise UtilitiesError(f"not a decimal: {x!r}") from None
    if not d.is_finite() or d <= 0:
        raise UtilitiesError(f"amount must be positive: {x!r}")
    if -d.as_tuple().exponent > 10:
        raise UtilitiesError(f"at most 10 decimal places: {x!r}")
    return format(d.normalize(), "f") if d == d.to_integral() else format(d, "f")


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def window(valid_for: dt.timedelta, now: dt.datetime | None = None, backdate: dt.timedelta = dt.timedelta(minutes=1)):
    """(requestedAt, executeBefore): requestedAt slightly in the past, as the models assert."""
    now = now or dt.datetime.now(dt.timezone.utc)
    return iso(now - backdate), iso(now + valid_for)


def party_set(parties) -> dict:
    return {"map": [[p, {}] for p in sorted(set(parties))]}


def meta(values: dict | None = None) -> dict:
    return {"values": dict(values or {})}


def extra_args(context: dict | None = None, meta_values: dict | None = None) -> dict:
    return {"context": context or {"values": {}}, "meta": meta(meta_values)}


def av_cid(cid: str) -> dict:
    return {"tag": "AV_ContractId", "value": cid}


def av_list(items: list) -> dict:
    return {"tag": "AV_List", "value": list(items)}


def requirement(issuer: str, claims: list[tuple[str, str]]) -> dict:
    """PartyCredentialRequirement: issuer + required (property, value) claims."""
    return {"issuer": issuer, "requiredClaims": [{"_1": p, "_2": v} for p, v in claims]}


def parse_requirement(text: str, default_issuer: str) -> dict:
    """`[ISSUER@]property=value[,property=value]` -> requirement."""
    issuer, _, claims = text.rpartition("@")
    pairs = []
    for c in claims.split(","):
        k, sep, v = c.partition("=")
        if not sep or not k:
            raise UtilitiesError(f"bad claim {c!r} in {text!r} (want property=value)")
        pairs.append((k.strip(), v.strip()))
    return requirement(issuer or default_issuer, pairs)


def _exercise(template: str, cid: str, choice: str, arg: dict) -> dict:
    return {"ExerciseCommand": {"templateId": template, "contractId": cid, "choice": choice, "choiceArgument": arg}}


def _create(template: str, args: dict) -> dict:
    return {"CreateCommand": {"templateId": template, "createArguments": args}}


# --- A. registrar service ------------------------------------------------------------------


def registrar_service_request(operator: str, provider: str, registrar: str, transfer_rule=True, allocation_factory=True):
    return _create(
        T["registrar_service_request"],
        {
            "operator": operator,
            "provider": provider,
            "registrar": registrar,
            "createTransferRule": transfer_rule,
            "createAllocationFactory": allocation_factory,
        },
    )


def registrar_service_request_cancel(cid: str):
    return _exercise(T["registrar_service_request"], cid, "RegistrarServiceRequest_Cancel", {})


# --- B. credentials ------------------------------------------------------------------------


def credential_offer_accept(offer_cid: str):
    """Accept a FREE credential offer addressed to the registrar (controller: holder)."""
    return _exercise(T["credential_offer"], offer_cid, "CredentialOffer_AcceptFree", {})


def self_credential(registrar: str, cred_id: str, description: str, claims: list[tuple[str, str, str]], observers=()):
    """Registrar-issued, registrar-held credential (issuer = holder = registrar), e.g. allowlists:
    claims are (subject party, property, value) such as (holder, "isHolderOf", instrument)."""
    if not claims:
        raise UtilitiesError("a credential needs at least one claim")
    return _create(
        T["credential"],
        {
            "issuer": registrar,
            "holder": registrar,
            "id": cred_id,
            "description": description,
            "validFrom": None,
            "validUntil": None,
            "claims": [{"subject": s, "property": p, "value": v} for s, p, v in claims],
            "observers": party_set(observers),
        },
    )


def credential_revoke(cid: str, actor: str):
    return _exercise(T["credential"], cid, "Credential_Revoke", {"actor": actor})


# --- C. instrument configuration -----------------------------------------------------------


def instrument_payload(instrument_id: str, holder_reqs=(), issuer_reqs=(), extra_ids=(), use_block_list=None) -> dict:
    if not instrument_id:
        raise UtilitiesError("instrument id must not be empty")
    return {
        "instrumentId": instrument_id,
        "additionalIdentifiers": list(extra_ids),
        "issuerRequirements": list(issuer_reqs),
        "holderRequirements": list(holder_reqs),
        "useBlockList": use_block_list,
    }


def instrument_create(registrar_service_cid: str, payload: dict):
    return _exercise(T["registrar_service"], registrar_service_cid, "RegistrarService_CreateInstrumentConfiguration", payload)


def instrument_update(registrar_service_cid: str, config_cid: str, payload: dict):
    """Archive-and-recreate. NOTE: resets provider app-reward beneficiaries on the new config."""
    return _exercise(
        T["registrar_service"],
        registrar_service_cid,
        "RegistrarService_ArchiveAndCreateInstrumentConfiguration",
        {"cid": config_cid, "payload": payload},
    )


def instrument_archive(registrar_service_cid: str, config_cid: str):
    return _exercise(T["registrar_service"], registrar_service_cid, "RegistrarService_ArchiveInstrumentConfiguration", {"cid": config_cid})


def additional_identifier(source: str, ident: str, scheme: str) -> dict:
    return {"source": source, "id": ident, "scheme": scheme}


# --- D. rewards / markers -----------------------------------------------------------------


def beneficiaries(weights: list[tuple[str, str]]) -> list[dict]:
    total = sum(Decimal(w) for _, w in weights)
    if total != Decimal(1):
        raise UtilitiesError(f"beneficiary weights must sum to 1.0 (got {total})")
    if len({p for p, _ in weights}) != len(weights) or len(weights) >= 20:
        raise UtilitiesError("beneficiaries must be unique and fewer than 20")
    for _, w in weights:
        if not Decimal(0) < Decimal(w) <= Decimal(1):
            raise UtilitiesError(f"weight {w} not in (0, 1]")
    return [{"beneficiary": p, "weight": str(Decimal(w))} for p, w in weights]


def set_provider_beneficiaries(config_cid: str, weights: list[tuple[str, str]] | None):
    """Controller is the PROVIDER: usable only when the registrar party is also the provider."""
    return _exercise(
        T["instrument_configuration"],
        config_cid,
        "InstrumentConfiguration_SetProviderAppRewardBeneficiaries",
        {"providerAppRewardBeneficiaries": beneficiaries(weights) if weights else None},
    )


def markers_proxy(operator: str, featured_party: str):
    """Opt in to DA's batched featured-app marker creation (signatory: the featured party)."""
    return _create(T["markers_proxy"], {"operator": operator, "provider": featured_party})


# --- E. mint / burn ------------------------------------------------------------------------


def mint_request_accept(cid: str, context: dict):
    return _exercise(T["mint_request"], cid, "MintRequest_Accept", {"extraArgs": extra_args(context)})


def mint_request_reject(cid: str, reason: str):
    return _exercise(T["mint_request"], cid, "MintRequest_Reject", {"reason": reason, "extraArgs": None})


def mint_record(registrar: str, instrument: str, amount, holder: str, reference: str, requested_at: str, execute_before: str):
    return {
        "instrumentId": {"admin": registrar, "id": instrument},
        "amount": decimal(amount),
        "holder": holder,
        "reference": reference,
        "requestedAt": requested_at,
        "executeBefore": execute_before,
        "meta": meta(),
    }


def offer_mint(factory_cid: str, registrar: str, mint: dict, context: dict):
    """Registrar offers a mint; the holder accepts with MintOffer_Accept. (RegistrarService_OfferMint
    is deprecated in the 0.14 models.)"""
    return _exercise(
        T["allocation_factory"],
        factory_cid,
        "AllocationFactory_OfferMint",
        {"expectedAdmin": registrar, "mint": mint, "extraArgs": extra_args(context)},
    )


def mint_offer_cancel(cid: str):
    return _exercise(T["mint_offer"], cid, "MintOffer_Cancel", {"extraArgs": None})


def burn_request_accept(cid: str, context: dict):
    return _exercise(T["burn_request"], cid, "BurnRequest_Accept", {"extraArgs": extra_args(context)})


def burn_request_reject(cid: str, reason: str):
    return _exercise(T["burn_request"], cid, "BurnRequest_Reject", {"reason": reason, "extraArgs": None})


def burn_mint_self(factory_cid: str, registrar: str, instrument: str, outputs: list[tuple[str, str]], inputs=(), context=None):
    """BurnMintFactory_BurnMint is jointly controlled by the admin AND `extraActors` (every
    non-registrar owner). An external registrar can only use it when all inputs and outputs are
    its own (extraActors = []), e.g. mint-to-self; anything else needs a multi-party submission."""
    if any(owner != registrar for owner, _ in outputs):
        raise UtilitiesError(
            "BurnMint with a third-party owner needs that owner in extraActors (multi-party "
            "authorization), which interactive submission does not support; use MintRequest_Accept "
            "or AllocationFactory_OfferMint, or mint to the registrar and transfer"
        )
    return _exercise(
        T["burn_mint_factory_v1"],
        factory_cid,
        "BurnMintFactory_BurnMint",
        {
            "expectedAdmin": registrar,
            "instrumentId": {"admin": registrar, "id": instrument},
            "inputHoldingCids": list(inputs),
            "outputs": [{"owner": o, "amount": decimal(a), "context": {"values": {}}} for o, a in outputs],
            "extraActors": [],
            "extraArgs": extra_args(context),
        },
    )


# --- F. transfers --------------------------------------------------------------------------


def transfer_args(
    registrar: str,
    sender: str,
    receiver: str,
    amount,
    instrument: str,
    requested_at: str,
    execute_before: str,
    input_holding_cids: list[str],
    reason: str | None = None,
    context: dict | None = None,
) -> dict:
    if not input_holding_cids:
        raise UtilitiesError("a transfer needs at least one input holding")
    return {
        "expectedAdmin": registrar,
        "transfer": {
            "sender": sender,
            "receiver": receiver,
            "amount": decimal(amount),
            "instrumentId": {"admin": registrar, "id": instrument},
            "requestedAt": requested_at,
            "executeBefore": execute_before,
            "inputHoldingCids": list(input_holding_cids),
            "meta": meta({REASON_META: reason} if reason else None),
        },
        "extraArgs": extra_args(context),
    }


def transfer(factory_cid: str, args: dict):
    return _exercise(T["transfer_factory_v1"], factory_cid, "TransferFactory_Transfer", args)


def transfer_instruction_withdraw(cid: str, context: dict):
    return _exercise(T["transfer_instruction_v1"], cid, "TransferInstruction_Withdraw", {"extraArgs": extra_args(context)})


def holding_split(holding_cid: str, amounts: list):
    """Registrar-controlled split of an unlocked holding into exact amounts (+ remainder)."""
    return _exercise(T["holding"], holding_cid, "Holding_Split", {"amounts": [decimal(a) for a in amounts]})


def holding_merge(holding_cid: str, others: list[str]):
    if not others:
        raise UtilitiesError("nothing to merge")
    return _exercise(T["holding"], holding_cid, "Holding_Merge", {"holdingCids": list(others)})


# --- G. holdings ---------------------------------------------------------------------------


def holding_views(events: list[dict]) -> list[dict]:
    """Flatten created events (interface filter on HoldingV1) into view rows."""
    rows = []
    for ev in events:
        for iv in ev.get("interfaceViews") or []:
            if not iv.get("interfaceId", "").endswith(":Splice.Api.Token.HoldingV1:Holding"):
                continue
            if (iv.get("viewStatus") or {}).get("code", 0) != 0:
                continue
            v = iv.get("viewValue") or {}
            rows.append(
                {
                    "contract_id": ev["contractId"],
                    "owner": v.get("owner"),
                    "admin": (v.get("instrumentId") or {}).get("admin"),
                    "instrument": (v.get("instrumentId") or {}).get("id"),
                    "amount": v.get("amount"),
                    "locked": v.get("lock") is not None,
                    "template": ev.get("templateId"),
                }
            )
    return rows


def summarize_holdings(rows: list[dict]) -> dict:
    out: dict = {}
    for r in rows:
        k = f"{r['admin']}|{r['instrument']}"
        s = out.setdefault(k, {"admin": r["admin"], "instrument": r["instrument"], "total": Decimal(0), "unlocked": Decimal(0), "holders": set(), "holdings": 0})
        a = Decimal(r["amount"])
        s["total"] += a
        if not r["locked"]:
            s["unlocked"] += a
        s["holders"].add(r["owner"])
        s["holdings"] += 1
    return {
        k: {**v, "total": str(v["total"]), "unlocked": str(v["unlocked"]), "holders": len(v["holders"])}
        for k, v in out.items()
    }


def pick_inputs(rows: list[dict], owner: str, admin: str, instrument: str, amount) -> list[str]:
    """Largest-first unlocked holdings of `owner` covering `amount`."""
    need = Decimal(decimal(amount))
    mine = sorted(
        (r for r in rows if r["owner"] == owner and r["admin"] == admin and r["instrument"] == instrument and not r["locked"]),
        key=lambda r: Decimal(r["amount"]),
        reverse=True,
    )
    picked, total = [], Decimal(0)
    for r in mine:
        if total >= need:
            break
        picked.append(r["contract_id"])
        total += Decimal(r["amount"])
    if total < need:
        raise UtilitiesError(f"{owner} holds only {total} unlocked {instrument}, need {need}")
    return picked


def strip_disclosed(disclosed: list[dict]) -> list[dict]:
    """Keep only the fields of the JSON Ledger API DisclosedContract schema."""
    keep = ("templateId", "contractId", "createdEventBlob", "synchronizerId")
    return [{k: d[k] for k in keep if d.get(k) is not None} for d in disclosed or []]


def local_context(instrument_config_cid: str, credentials: list[str] = (), block_list_shards: list[str] | None = None,
                  credential_key: str = CTX_ISSUER_CREDENTIALS) -> dict:
    """Choice context built from contracts the registrar sees itself (when DA's API is unavailable)."""
    values = {CTX_INSTRUMENT_CONFIG: av_cid(instrument_config_cid), credential_key: av_list([av_cid(c) for c in credentials])}
    if block_list_shards is not None:
        values[CTX_BLOCK_LIST] = av_list([av_cid(c) for c in block_list_shards])
    return {"values": values}
