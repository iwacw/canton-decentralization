# Runbook: `rails-csol-dev` (DevNet)

Commands for the external party in `party.json`. Background and rules are in [README.md](README.md).

## Setup

| File | What |
|---|---|
| `.env` | Ledger/Admin endpoints, `CDZ_SYNCHRONIZER_ID`, DFNS credentials, local `CDZ_TX_KEY_*` |
| `own-a.env`, `own-b.env` | namespace owner keys (`CDZ_NS_KEY_*`), one file per owner |
| `party.json` | public party definition; must match the live topology |

```bash
. .venv/bin/activate
kubectl --context dev-a -n canton-validator port-forward svc/participant 5012:5002   # Admin API, own terminal
cdz party status                                  # serials, keys, thresholds; "drift": [] = party.json is in sync
DFNS_KEY=key-01k5f-q09hl-e8nqu47lgv0puphs         # DFNS id of dev-dns-party-signing-1
```

## 1. Transactions (interactive submission)

Prepare, sign up to the signing threshold, execute. Needs only the JSON Ledger API.

```bash
cdz tx prepare --exercise <template or interface id> --cid <cid> --choice <Choice> --args '{…}' -o tx.json
cdz dfns sign-bundle tx.json --key-id $DFNS_KEY -o tx.dfns.json   # waits for the DFNS approval
cdz bundle sign tx.json -o tx.local.json                          # only if a local CDZ_TX_KEY_* is a party key
cdz bundle merge tx.signed.json tx.dfns.json tx.local.json        # several signers; with one, execute its copy
cdz tx execute tx.signed.json
```

### Example: accept Canton Coin

```bash
python scripts/accept-cc.py --dry-run     # pending incoming CC transfers
python scripts/accept-cc.py --yes         # writes cc-accept/accept-<cid16>.json per transfer, signs with local keys,
                                          # executes if that meets the threshold, else "needs more signatures"
B=cc-accept/accept-<cid16>
cdz dfns sign-bundle $B.json --key-id $DFNS_KEY -o $B.signed.json   # keeps the local signatures already in $B.json
cdz tx execute $B.signed.json
```

Accept before the transfer's `executeBefore` (shown by `--dry-run`).

## 2. Topology transactions (Admin API)

Plan, each required key signs its own copy, merge, check, submit, update `party.json`.

| Change | Who signs |
|---|---|
| add a signing key | owners up to the namespace threshold + the new key |
| remove a signing key, signing threshold | owners up to the namespace threshold |
| add a namespace owner | current owners up to the threshold + the new owner |
| remove an owner, namespace threshold | current owners up to the threshold |

### 2a. Add a party signing key

```bash
cdz keys generate --role tx --name local-tx-1 --env-out .env --pub-out new.pub.json   # local key, or a DFNS key:
cdz dfns keys create --name dev-dns-party-signing-2 --pub-out new.pub.json           #   note its key-… id

cdz topology plan-party --add-key new.pub.json --signing-threshold 1 -o add-key.json
cdz --env own-a.env bundle sign add-key.json -o add-key.own-a.json --roles ns         # + own-b.env if threshold 2
cdz bundle sign add-key.json -o add-key.new.json --roles tx --key $(jq -r .fingerprint new.pub.json)
#   DFNS key instead: cdz dfns sign-bundle add-key.json --key-id <new key-…> -o add-key.new.json
cdz bundle merge add-key.signed.json add-key.own-a.json add-key.new.json
cdz bundle show add-key.signed.json --live        # READY, "base state matches the node", "fully signed"
cdz topology submit add-key.signed.json
jq --slurpfile k new.pub.json '.signing.keys += [$k[0] | del(.role)] | .signing.threshold = 1' party.json > p.json && mv p.json party.json
cdz party status                                  # new serial, "drift": []
```

Remove a key or change the signing threshold (owners only):

```bash
cdz topology plan-party --remove-key <fingerprint> --signing-threshold 1 -o rm-key.json
cdz --env own-a.env bundle sign rm-key.json -o rm-key.own-a.json --roles ns
cdz bundle merge rm-key.signed.json rm-key.own-a.json
cdz topology submit rm-key.signed.json
jq --arg fp <fingerprint> '.signing.keys |= map(select(.fingerprint != $fp)) | .signing.threshold = 1' party.json > p.json && mv p.json party.json
```

The Wallet Gateway sends one DFNS signature per transaction: keep the signing threshold at 1 while it signs.

### 2b. Add a namespace (topology) key

```bash
cdz --env own-c.env keys generate --role ns --name own-c --env-out own-c.env --pub-out own-c.pub.json

cdz topology plan-dns --add-owner own-c.pub.json --threshold 2 -o add-owner.json   # root delegation of own-c + DNS update
cdz --env own-a.env bundle sign add-owner.json -o add-owner.own-a.json --roles ns  # current owners up to the threshold
cdz --env own-c.env bundle sign add-owner.json -o add-owner.own-c.json --roles ns  # the new owner
cdz bundle merge add-owner.signed.json add-owner.own-a.json add-owner.own-c.json
cdz bundle show add-owner.signed.json --live --strict
cdz topology submit add-owner.signed.json
jq --slurpfile k own-c.pub.json '.namespace.owners += [$k[0] | del(.role)] | .namespace.threshold = 2' party.json > p.json && mv p.json party.json
cdz party status
```

The namespace id and the party id do not change.

Change the namespace threshold (signed by as many owners as the current threshold):

```bash
cdz topology plan-dns --threshold 1 -o dns-threshold.json
cdz --env own-a.env bundle sign dns-threshold.json -o dns-threshold.own-a.json --roles ns
cdz --env own-b.env bundle sign dns-threshold.json -o dns-threshold.own-b.json --roles ns
cdz bundle merge dns-threshold.signed.json dns-threshold.own-a.json dns-threshold.own-b.json
cdz topology submit dns-threshold.signed.json
jq '.namespace.threshold = 1' party.json > p.json && mv p.json party.json
```

## Errors

| Error | Fix |
|---|---|
| `the bundle's signing keys/threshold differ from party.json` | update `party.json` from `cdz party status` |
| `none of the local keys is needed by this bundle` with `--key` | keys are named after their variable (`CDZ_TX_KEY_LOCAL_TX_1` is `local_tx_1`); or pass the fingerprint |
| `not fully authorized yet` on submit | signatures missing: `cdz bundle show <bundle> --strict` |
| `INVALID_ARGUMENT: An error occurred…` from the Admin API | the node hides the reason: `kubectl --context dev-a -n canton-validator logs deploy/participant --since=5m \| grep -E 'TOPOLOGY_\|rejectionReason'` |
| `LIVE MISMATCH` or a serial conflict | the topology changed since planning: plan again |
| DFNS signature timeout | approve in DFNS, rerun `sign-bundle` with `--signature-id sig-…` |
