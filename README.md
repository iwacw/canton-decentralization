# canton-decentralization (`cdz`)

Toolkit to create a Canton **external party with a decentralized namespace** and run it as a
DA Canton Network Utilities **registrar** (token admin), with every key held offline by its
owner.

- **Keys**: 1..n namespace keys and 1..n transaction keys per machine, loaded from `.env`.
- **Onboarding**: `NamespaceDelegation` per owner, `DecentralizedNamespaceDefinition`, and
  `PartyToParticipant` (Confirmation-only hosts plus `party_signing_keys`). Every topology hash
  is recomputed locally.
- **Topology management**: DNS owners and threshold, signing keys and threshold, hosting
  participants and confirmation threshold. Each change is a bundle that offline signers sign
  separately and then merge.
- **Interactive submission**: prepare, recompute the hash locally (V2/V3), sign m-of-n, execute.
- **DA Utilities flows**:
  - registrar service request
  - credentials
  - `InstrumentConfiguration`
  - rewards and markers
  - mint via `MintRequest_Accept` and `AllocationFactory_OfferMint`
  - burn accept
  - CSV batch transfers via `TransferFactory_Transfer`
  - holdings
- **Networks**: DevNet, TestNet and MainNet profiles in `src/cdz/networks/*.toml`.

> Status: the generic Canton parts were tested against a local open-source Canton 3.5.19.
> The DA Utilities parts were not run against DA's backend. See
> [What is verified](#what-is-verified).

## Contents

1. [Party model](#party-model)
2. [Install and configure](#install-and-configure)
3. [Runbook: DevNet](#runbook-devnet)
4. [Runbook: MainNet](#runbook-mainnet)
5. [Topology management](#topology-management)
6. [Interactive submission](#interactive-submission)
7. [Utilities flows and limits](#utilities-flows-and-limits)
8. [Decentralization roadmap](#decentralization-roadmap)
9. [Open questions for DA](#open-questions-for-da)
10. [What is verified](#what-is-verified)
11. [Development](#development)

## Party model

```
party id = <hint>::<dns>          dns = H(37, sorted owner namespace fingerprints)

DecentralizedNamespaceDefinition  owners = N namespace keys (one per person/org), threshold k
  └─ authorizes every topology change of the party (hosting, signing keys, thresholds, owners)
PartyToParticipant                hosts = H participants, all Confirmation, threshold t
  └─ party_signing_keys           n protocol keys (max 20), threshold m
       └─ authorize Daml transactions (interactive submission), checked by every CPN
```

**No host has Submission permission.** No node can act for the party: every transaction needs
m-of-n party signatures, and the hosting participants (CPNs) verify them. With `t > 1`, fewer
than `t` malicious CPNs can neither confirm an invalid transaction nor accept a forged signature.

Security is the weakest of the three thresholds:

- **k-of-N owners.** They can replace the signing keys, hosts and thresholds.
- **m-of-n signers.** They can sign any transaction the Daml model allows.
- **t-of-H hosts.** That many colluding hosts can approve anything.

Choose `t >= 2` across independent operators. `t` must be at least the governance threshold
of any on-ledger m-of-n model, otherwise that many colluding hosts bypass it.

Rules this toolkit enforces before it sends anything (mirroring Canton 3.5 `requiredAuth`):

| Change | Required signatures |
|---|---|
| create DNS (serial 1) | **all** owners |
| DNS owners or threshold | threshold of the *current* owners + every *added* owner |
| P2P confirmation threshold, remove or lower a signing key | party (DNS threshold) |
| add a signing key | party + the new key (proof of possession) |
| add a host / raise its permission | party + that participant |
| remove a host / lower its permission | party **or** that participant |
| clear a host's onboarding flag | that participant only |

## Install and configure

Requires Python 3.11 or newer and `pip`. The generated protobuf stubs are committed, so
`protoc` is not needed.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # installs the `cdz` command
cp .env.example .env && chmod 600 .env
cdz status                  # participant, synchronizers, signing windows, local key fingerprints
```

| File | What | Secret? |
|---|---|---|
| `.env` | endpoints, tokens, **private keys** of this machine (`CDZ_NS_KEY_*`, `CDZ_TX_KEY_*`) | yes, never commit |
| `party.json` | public keys, thresholds, hosts, party id | no |
| `*.bundle.json` | transactions to sign + collected signatures | no (public data) |
| `src/cdz/networks/<net>.toml` | DA Utilities API base, operator party, synchronizer pin | no |

Select the network with `CDZ_NETWORK` or `--network`. `party.json` records its network, and
the CLI refuses to mix networks. Pin `CDZ_SYNCHRONIZER_ID` once you have checked it with
`cdz status`, because the global synchronizer id changes on hard migrations.

Endpoints:

- **JSON Ledger API.** `CDZ_LEDGER_URL` points at any node; hosts are only needed for reads.
  It is used for prepare and execute, the ACS, and `AllocateExternalParty`. The JWT comes from
  `CDZ_LEDGER_TOKEN` or OAuth2 client credentials (`CDZ_OAUTH_*`).
- **Admin API.** `CDZ_ADMIN_ADDR` is gRPC, usually through `kubectl port-forward` to port 5002.
  It is used for topology reads and writes.

## Runbook: DevNet

Roles in this runbook:

- **Owners** A, B, C each hold one namespace key.
- **Signers** A, B, C each hold one transaction key. The same people are fine, but each holds
  a separate key.
- **Coordinator** builds bundles and has no keys.
- **CPN operators** run hosts P1 and P2.

1. **Key ceremony.** Every key holder runs this on their own machine:
   ```bash
   cdz keys generate --role ns --name alice-ns --env-out .env --pub-out alice-ns.pub.json
   cdz keys generate --role tx --name alice-tx --spec ed25519 --env-out .env --pub-out alice-tx.pub.json
   ```
   Only `*.pub.json` files go to the coordinator. Specs: `ed25519` (default), `p256`,
   `secp256k1`, `p384`.

2. **Party definition.** The coordinator runs this, with participant uids from each operator
   (`cdz status`):
   ```bash
   cdz party new --hint acme-registrar \
     --owner alice-ns.pub.json --owner bob-ns.pub.json --owner carol-ns.pub.json --owners-threshold 2 \
     --signing-key alice-tx.pub.json --signing-key bob-tx.pub.json --signing-key carol-tx.pub.json --signing-threshold 2 \
     --host participant::1220…P1 --host participant::1220…P2 --confirmation-threshold 2
   cdz party onboard-bundle -o onboard.json        # root NSD per owner, DNS, P2P (serial 1)
   ```
   Distribute `party.json` and `onboard.json`. Both are public.

3. **Offline signatures.** Every key holder reviews what they sign and signs their own copy.
   The tool decodes, re-hashes and prints each transaction, and refuses if a stored hash
   differs from the bytes.
   ```bash
   cdz bundle sign onboard.json -o onboard.alice.json      # signs only where this key is needed
   ```
   The coordinator then merges the copies:
   ```bash
   cdz bundle merge onboard.signed.json onboard.*.json
   cdz bundle show onboard.signed.json                     # "fully signed"
   ```
   Onboarding needs **all** owners (DNS creation) and **all** signing keys (proof of
   possession). Use `--multi` for one signature per key over the combined hash.

4. **Allocate on every host.** Each CPN operator runs this with an admin token for their own
   node:
   ```bash
   cdz party allocate onboard.signed.json --ledger-url https://p1…/ --user acme-registrar-app
   ```
   The party becomes active once all hosts have allocated. Check with `cdz party status`:
   serials, hosts, thresholds, pending proposals, and drift against `party.json`.

   *Admin API alternative:*
   ```bash
   cdz topology submit onboard.signed.json --proposal   # NSDs + DNS complete, P2P pending
   cdz topology approve --hash <p2p hash> --admin-addr <each host>
   ```

5. **App user.** Each CPN operator grants the coordinator's ledger user read and execute
   rights on their node:
   ```bash
   cdz party grant-user --user acme-registrar-app --create
   ```

6. **Utilities onboarding.** Each step prepares a bundle; signers sign it, then
   `cdz tx execute`. On DevNet, `--execute` signs with local keys and executes in one go.
   ```bash
   cdz registrar request-service --provider <provider party>   # provider accepts in the Registry UI
   cdz registrar credential-accept --offer <cid>               # if the provider requires registrar credentials
   cdz registrar credential-issue --id allow-registrar \
       --claim <registrar>,isHolderOf,ACME --claim <holder>,isHolderOf,ACME   # self-held allowlist
   cdz registrar instrument-create --instrument ACME --holder-req isHolderOf=ACME --issuer-req isHolderOf=ACME
   # claim names are yours: a requirement matches credentials whose claims carry the same property=value
   cdz registrar markers-proxy                                 # featured registrar only
   cdz registrar contracts                                     # RegistrarService, configs, requests …
   ```

7. **Mint.**
   ```bash
   cdz registrar mint-accept --request <MintRequest cid>        # holder-initiated (wallet / AllocationFactory_RequestMint)
   cdz registrar mint-offer --holder <party> --instrument ACME --amount 1000 --valid-for 7d   # holder accepts
   cdz registrar mint-request --instrument ACME --amount 1000     # treasury: mint to the registrar itself …
   cdz registrar mint-accept --request <its MintRequest cid>     # … then distribute with transfers
   ```

8. **Distribute.**
   ```bash
   cdz registrar transfers --csv payouts.csv --instrument ACME --out-dir payouts
   ```
   This first emits a `Holding_Split` bundle into exact amounts. Sign and execute it, then
   rerun the command. You get one transfer bundle per CSV row, each with its own input holding.
   ```bash
   cdz bundle sign payouts/0*.json        # every signer, once, offline
   cdz tx execute payouts/0*.json         # coordinator, in order
   ```
   CSV columns: `receiver,amount[,reason]`. Receivers without a preapproval get a pending
   `TransferOffer`, which they accept in their wallet.

9. **Holdings.** The registrar is a signatory of every holding of its instruments:
   ```bash
   cdz registrar holdings --instrument ACME [--list] [--owner <party>]   # totals = supply
   ```

## Runbook: MainNet

Same commands as DevNet, with `CDZ_NETWORK=mainnet`. What changes:

- **Commercials and onboarding go through DA.**
  - The provider must have a MainNet `ProviderService`, and the commercial agreement must cover
    it.
  - Ask DA in `#utility-ops` for credential offers. DevNet auto-approves, MainNet does not.
  - A featured registrar needs a Featured App Right (CIP-116 lock) and reward-share setup
    (CIP-104 guidance: feature exactly one of registrar or provider).
  - The operator party in `mainnet.toml` comes from DA's docs. Re-check it with
    `GET https://api.utilities.digitalasset.com/api/utilities/v0/operator`.
- **Keys.**
  - Generate them on the holders' own hardware, not on a shared server.
  - Keep one owner key cold (backup) and use k-of-N with k ≥ 2.
  - The toolkit only needs private keys at signing time. Use `file:/path` values or a
    short-lived `.env` on an offline machine.
- **Hosts.**
  - At least 2 CPNs in different failure domains, with `t = 2` (the 2-of-3 shape survives one
    outage and one compromise).
  - Before adding a host to a party that already has contracts, pause all registrar activity
    and replicate the ACS (see [Adding a host](#adding-a-host-to-an-active-party)).
- **Rehearse every change on DevNet first.** Same keys policy, same thresholds, same commands.
- **Signing window.**
  - Registrar choices bound time with ledger-time assertions, not `getTime`. A prepared
    transaction stays signable until the choice deadline (`--valid-for`) and the synchronizer's
    `preparationTimeRecordTimeTolerance`. `cdz status` prints it; Canton's default is 24 h.
  - Choices that use `getTime` must be signed and executed within the ~1 minute
    `ledgerTimeRecordTimeTolerance`. These are paid credential offers and commercial
    agreements, so collect signatures live for them.
- **Monitoring.** Alert on any new serial of the party's `PartyToParticipant` or DNS
  (`cdz party status` shows serials and drift). Every change there is a change of who controls
  the registrar.

## Topology management

Every change follows the same five steps:

1. Plan: read the current state from the Admin API and write a bundle that also carries the
   base state, so signers can review offline.
2. Sign: each holder runs `cdz bundle sign` on their own copy.
3. Merge the copies.
4. `cdz topology submit` (Admin API).
5. Approve: participants approve if needed.

```bash
# signing keys / signing threshold (party = DNS threshold; added keys sign too)
cdz topology plan-party --add-key dave-tx.pub.json --remove-key 1220…old --signing-threshold 2 -o keys.json
# hosts / confirmation threshold (added host must approve: `cdz topology approve --hash … --admin-addr <its admin>`)
cdz topology plan-party --add-host participant::1220…P3 --confirmation-threshold 2 -o hosts.json
cdz topology plan-party --remove-host participant::1220…P1 -o drop.json
# DNS owners / threshold (current threshold of owners + every new owner sign; root NSDs for new owners included)
cdz topology plan-dns --add-owner dave-ns.pub.json --remove-owner 1220…alice --threshold 3 -o dns.json

cdz bundle sign keys.json -o keys.alice.json          # each holder
cdz bundle merge keys.signed.json keys.*.json
cdz bundle show keys.signed.json                      # lists what is still missing
cdz topology submit keys.signed.json                  # --proposal when a participant must still approve
```

The tool refuses to build invalid mappings:

- threshold above the number of confirming hosts
- Submission permission together with threshold > 1
- duplicate keys, or more than 20 keys
- a DNS threshold above the number of owners

Serials come from the head state. A concurrent change makes Canton reject the bundle; plan it
again.

### Adding a host to an active party

A new host must receive the party's active contracts. `plan-party --add-host` therefore sets
the host's **onboarding flag**. Then:

1. Pause all registrar activity.
2. Export and import the ACS with the Canton party-replication procedure (node operator, Admin
   API or console).
3. Have the new host clear its own flag:
   `cdz topology plan-clear-onboarding --participant <uid>`, then
   `cdz topology approve --bundle … --admin-addr <its admin>`. Only the participant can
   authorize this.

Only raise `t` to count the new host after that. BitSafe's DecMan documents a MainNet
participant crash on 2026-09-16 caused by activity during this window. Use `--no-onboarding`
only for a party without contracts.

## Interactive submission

```bash
cdz tx prepare --exercise <template or interface id> --cid <cid> --choice <Choice> --args '{…}' [--disclosed d.json] [--scheme v2|v3] [--ttl 3600] -o t.json
cdz bundle sign t.json         # every signer: hash recomputed from the PreparedTransaction, intent and act_as checked
cdz tx execute t.json          # needs >= signing threshold valid, distinct signatures
```

Before anything is signed, a bundle is checked for the following:

1. The hash recomputed from the transaction (V2 or V3; V4 is refused) equals the node's.
2. `act_as` is exactly `[party]`.
3. There is a single root node.
4. The root node matches the command that was asked for (template/interface, choice, contract
   id).
5. The synchronizer is the expected one.
6. The preparation time is not ahead of the local clock.

Signatures are verified against the party's registered keys before execution.

Canton limits for external parties, quoted from the docs and the 3.5 protos:

- "Only single command transaction are currently supported by the API."
- "Only transactions with a single root node are supported."
- "Only transactions requiring authorization from a single party are supported" /
  "only single party submissions are supported".

## Utilities flows and limits

Every flow below is a single command with the registrar as its only authorizer:

| Flow | Command (choice) | Who completes it |
|---|---|---|
| registrar service | `RegistrarServiceRequest` create | provider: `RegistrarServiceRequest_Accept` |
| credential offer | `CredentialOffer_AcceptFree` | — |
| allowlist | `Credential` create (issuer = holder = registrar) | — |
| revoke | `Credential_Revoke {actor = registrar}` | — |
| instrument | `RegistrarService_CreateInstrumentConfiguration` / `…_ArchiveAndCreate…` / `…_Archive…` | — |
| markers | `DelegatedBatchedMarkersProxy` create | DA automation |
| mint (holder asks) | `MintRequest_Accept` / `_Reject` | holder created the request |
| mint (registrar offers) | `AllocationFactory_OfferMint` | holder: `MintOffer_Accept` |
| treasury mint | `AllocationFactory_RequestMint` (holder = registrar), then `MintRequest_Accept` | — |
| burn | `BurnRequest_Accept` | holder created the request |
| transfer | `TransferFactory_Transfer` (sender = registrar) | receiver: `TransferInstruction_Accept`, unless preapproved |
| UTXO | `Holding_Split` / `Holding_Merge` | — |

Choice contexts and disclosed contracts come from DA's off-ledger APIs (`src/cdz/registry.py`):

- token standard:
  `{api}/api/token-standard/v0/registrars/<admin>/registry/transfer-instruction/v1/transfer-factory`
- utilities backend:
  `{api}/api/utilities/v0/registry/mint/v0/{request,offer}…`
- `mint-accept` and `mint-offer` also take `--local-context`, which builds the context from the
  registrar's own ACS (inferred from the models).

Provider-side settings belong to the provider party, not the registrar:

- `InstrumentConfiguration_SetProviderAppRewardBeneficiaries` is provider-controlled.
  `cdz registrar beneficiaries` works only when registrar = provider.
- An instrument update (archive-and-recreate) resets those beneficiaries.

### Why `BurnMintFactory_BurnMint` is not used

`BurnMintFactory_BurnMint` (Splice Token Standard burn-mint API, implemented by DA's
`AllocationFactory`) is controlled jointly by the admin **and** `extraActors`. A Utility
`Holding` has `signatory registrar, owner`, so creating or archiving a holding of any owner
other than the registrar needs that owner as an authorizer. DA's own example submits with
`actAs = [admin, holder]`, which works only when one user may act as both.

An external registrar submits through interactive submission, which supports **only
single-party submissions**. A transaction that needs the registrar plus a holder cannot be
expressed, whoever signs.

The remaining paths are:

- `MintRequest_Accept`: the holder authorized the request earlier.
- `AllocationFactory_OfferMint`: the holder accepts later.
- Mint to the registrar itself, then `TransferFactory_Transfer`.

`utilities.burn_mint_self` exists only for registrar-owned outputs (`extraActors = []`). DA's
backend support for that is unconfirmed.

## Decentralization roadmap

1. **DevNet PoC (now).**
   - DNS 2-of-3 and signing 2-of-3, keys on three people's machines.
   - Two of our nodes as CPNs, `t = 2`.
   - Exercise every flow in this README, including key rotation and adding a host with ACS
     replication.
2. **MainNet launch: one organization, no single point.**
   - DNS 2-of-3 plus one cold backup owner, held by different people (hardware or HSM-backed
     keys).
   - Signing 2-of-3.
   - 2–3 CPNs in separate clouds or accounts, `t = 2`.
   - Topology-change alerting.
   - Removes the participant-admin-party exposure of the current cETH registrar, whose
     namespace is a participant key.
3. **Organizational decentralization.**
   - Add independent owners and signers (custodian, auditor, partner) with
     `plan-dns --add-owner` and `plan-party --add-key`.
   - Reach for example DNS 3-of-5 with at least 2 external organizations.
   - Move hosts to independent operators.
   - Pick `t` so that no single organization controls `t` hosts.
4. **Policy on-ledger.**
   - Move mint policy into Daml: a separate minter party with an m-of-n guard or supply cap
     (cSOL MintGuard design), confirmed by the same CPNs.
   - Adopt DA's on-ledger supply cap when it ships.
   - The confirmation threshold stays ≥ the governance threshold.
5. **Existing instruments.** A party's namespace is permanent, and Canton has no migration
   primitive. An existing registrar (e.g. cETH, admin = participant admin party) cannot be
   decentralized in place: it needs a new instrument and holder migration.

## Open questions for DA

1. Is an **external, multi-hosted (Confirmation-only, t > 1) registrar** supported by the
   Registry operator backend on MainNet? This covers choice-context and disclosure endpoints,
   indexing, and the Registry UI (or is the Ledger API the only path)?
2. **Featured external registrar.** Does the batched marker automation
   (`DelegatedBatchedMarkersProxy`) work with an external featured party? What does CIP-104
   reward sharing require it to sign?
3. **Mint to third parties without a holder request.** Is there a single-party path planned
   (BurnMint needs `extraActors`)? Is self-mint via the burn-mint-factory endpoint
   (`extraActors = []`) supported?
4. **Time bounds.** Do `MintRequest_Accept`, `AllocationFactory_OfferMint`,
   `TransferFactory_Transfer` and `CredentialOffer_AcceptFree` use only ledger-time
   assertions (no `getTime`)? What is MainNet's `preparationTimeRecordTimeTolerance`?
5. **Contexts without the API.** Is building choice contexts from the registrar's own ACS
   supported, for example when DA's API is unavailable?
6. **Adding a CPN to an active registrar.** What is the recommended ACS-replication
   procedure, and is there any impact on operator/provider-side contracts?
7. **Code vs docs.** `RegistrarService_Terminate` is provider-only in the 0.14 models, but the
   docs say either side can terminate. `InstrumentConfiguration` updates reset provider
   beneficiaries. Are both intended?
8. **On-ledger supply cap.** Timeline (DA, 2026-10-12: "in our backlog, not started")?
9. **Migration.** Confirm that a registrar party cannot be replaced for an existing
   instrument, and that a new instrument is the only path.

## What is verified

Every row below was run against a local open-source **Canton 3.5.19** (1 sequencer, 1
mediator, 3 participants, in memory; `tests/e2e`). Nothing ran against DevNet/MainNet, DA's
backend, or a Splice validator.

| Area | Status |
|---|---|
| topology tx bytes and hashes | **byte-identical** to the node's `GenerateTransactions` for NSD, DNS and P2P (incl. key ordering and usages) |
| DNS external party onboarding | Ledger API `AllocateExternalParty` on 2 hosts and Admin API `AddTransactions` + host approval; per-tx and multi-hash signatures |
| topology changes | signing threshold, key rotation (incl. P-384), DNS owner add/remove + threshold, add host (proposal + approval), clear onboarding flag, confirmation threshold, remove host |
| prepared-transaction hash V2/V3 | equals the node's hash for create and for exercise on a disclosed contract (input contracts); Canton's own golden vectors pass |
| m-of-n execution | below-threshold signatures refused by the node; 2-of-3 and 3-of-3 (Ed25519/P-256/secp256k1/P-384) accepted, also via a non-hosting node |
| offline multi-signer flow | separate `.env` per holder; sign copies, merge, submit (CLI e2e) |
| Utilities commands | **unverified against DA.** Choice and field names match the Utility 0.14.4 models; context/API shapes follow DA's docs; CLI wiring tested with fakes |
| Admin API TLS, OAuth2 tokens, ACS replication | not tested |

## Development

```bash
pip install -e '.[dev]'
pytest -q                                             # unit tests (no node needed)
scripts/local-canton.sh start                         # downloads Canton OSS (~285 MB), ~1.3 GB RAM
CDZ_E2E_DIR=tests/e2e/run pytest -q tests/e2e         # end-to-end against it
scripts/local-canton.sh stop
scripts/fetch-protos.sh && scripts/gen-protos.sh      # refresh protos (pinned canton tag)
```

Layout of `src/cdz`:

- `crypto` and `topology`: hashes, keys and mappings.
- `authz`: Canton authorization rules, offline.
- `bundle`: signing files.
- `tx_hash` and `prepared`: interactive-submission hashing and checks.
- `manage`: change planning.
- `ledger` and `admin`: API clients.
- `utilities`, `registry` and `registrar_cli`: DA Utilities.

References:

- Canton docs: external signing, the hashing algorithm, topology.
- Canton v3.5.19 sources: `TopologyMapping.scala`, `Signing.scala`,
  `TopologyTransactionSignature.scala`.
- DA Registry docs.
- BitSafe DecMan (`DECENTRALIZING_AN_EXTERNAL_PARTY.md`, `canton_hash` golden vectors).
