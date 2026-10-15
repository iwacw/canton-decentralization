"""JSON Ledger API v2 client (HTTP + bearer JWT). Shapes follow Canton 3.5 openapi.yaml."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cdz import crypto


class LedgerError(RuntimeError):
    def __init__(self, status: int, body: str, path: str):
        self.status, self.body, self.path = status, body, path
        try:
            j = json.loads(body)
            msg = f"{j.get('code', '')}: {j.get('cause', body)}"
        except ValueError:
            msg = body[:500]
        super().__init__(f"{path} -> HTTP {status} {msg}")


class TokenProvider:
    """Static token (CDZ_LEDGER_TOKEN) or OAuth2 client-credentials (CDZ_OAUTH_*)."""

    def __init__(self, env: dict, prefix: str = "CDZ_"):
        self.static = env.get(f"{prefix}LEDGER_TOKEN") or None
        self.url = env.get(f"{prefix}OAUTH_TOKEN_URL")
        self.form = {
            "grant_type": "client_credentials",
            "client_id": env.get(f"{prefix}OAUTH_CLIENT_ID", ""),
            "client_secret": env.get(f"{prefix}OAUTH_CLIENT_SECRET", ""),
            **({"audience": env[f"{prefix}OAUTH_AUDIENCE"]} if env.get(f"{prefix}OAUTH_AUDIENCE") else {}),
            **({"scope": env[f"{prefix}OAUTH_SCOPE"]} if env.get(f"{prefix}OAUTH_SCOPE") else {}),
        }
        self._token, self._exp = None, 0.0

    def __call__(self) -> str | None:
        if self.static:
            return self.static
        if not self.url:
            return None
        if self._token and time.time() < self._exp - 60:
            return self._token
        req = urllib.request.Request(self.url, data=urllib.parse.urlencode(self.form).encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=30) as r:
            j = json.loads(r.read())
        self._token, self._exp = j["access_token"], time.time() + float(j.get("expires_in", 300))
        return self._token


def sig_json(s: crypto.Sig) -> dict:
    j = s.to_json()
    return {"format": j["format"], "signature": j["signature"], "signedBy": j["signed_by"], "signingAlgorithmSpec": j["algorithm"]}


class LedgerClient:
    def __init__(self, base_url: str, token=None, user_id: str | None = None, timeout: float = 60.0):
        self.base = base_url.rstrip("/")
        self.token = token or (lambda: None)
        self.user_id = user_id
        self.timeout = timeout

    def _req(self, method: str, path: str, body=None, query: dict | None = None):
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        tok = self.token()
        if tok:
            req.add_header("Authorization", f"Bearer {tok}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise LedgerError(e.code, e.read().decode(errors="replace"), path) from None
        return json.loads(raw) if raw else {}

    # --- state ---------------------------------------------------------------------------

    def participant_id(self) -> str:
        return self._req("GET", "/v2/parties/participant-id")["participantId"]

    def connected_synchronizers(self, party: str | None = None) -> list[dict]:
        q = {"party": party} if party else None
        return self._req("GET", "/v2/state/connected-synchronizers", query=q).get("connectedSynchronizers", [])

    def synchronizer_id(self, expected: str | None = None) -> str:
        syncs = [s["synchronizerId"] for s in self.connected_synchronizers()]
        if expected:
            match = [s for s in syncs if s == expected or s.startswith(expected + "::")]
            if not match:
                raise RuntimeError(f"participant is not connected to {expected} (connected: {syncs})")
            return expected
        if len(syncs) != 1:
            raise RuntimeError(f"set CDZ_SYNCHRONIZER_ID; participant is connected to {syncs}")
        return syncs[0]

    def ledger_end(self) -> int:
        return int(self._req("GET", "/v2/state/ledger-end").get("offset", 0))

    def active_contracts(
        self, party: str, templates=(), interfaces=(), include_blob: bool = False, page_size: int = 500
    ) -> list[dict]:
        """Created events of active contracts visible to `party`, filtered by template/interface ids."""
        cum = [
            {"identifierFilter": {"TemplateFilter": {"value": {"templateId": t, "includeCreatedEventBlob": include_blob}}}}
            for t in templates
        ] + [
            {
                "identifierFilter": {
                    "InterfaceFilter": {
                        "value": {"interfaceId": i, "includeInterfaceView": True, "includeCreatedEventBlob": include_blob}
                    }
                }
            }
            for i in interfaces
        ]
        if not cum:
            cum = [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": include_blob}}}}]
        fmt = {"filtersByParty": {party: {"cumulative": cum}}, "verbose": True}
        out, token, offset = [], None, None
        while True:
            body = {"eventFormat": fmt, "maxPageSize": page_size}
            if token:
                body["pageToken"] = token
            if offset is not None:
                body["activeAtOffset"] = offset
            r = self._req("POST", "/v2/state/active-contracts-page", body)
            offset = r.get("activeAtOffset", offset)
            for entry in r.get("activeContracts", []):
                ac = (entry.get("contractEntry") or {}).get("JsActiveContract")
                if ac:
                    ev = ac["createdEvent"]
                    ev["synchronizerId"] = ac.get("synchronizerId")
                    out.append(ev)
            token = r.get("nextPageToken")
            if not token:
                return out

    # --- parties / users -----------------------------------------------------------------

    def allocate_external_party(
        self,
        synchronizer: str,
        txs: list[tuple[bytes, list[crypto.Sig]]],
        multi: list[crypto.Sig] = (),
        user_id: str | None = None,
        wait: bool = True,
    ) -> str:
        body = {
            "synchronizer": synchronizer,
            "onboardingTransactions": [
                {"transaction": crypto.b64(b), "signatures": [sig_json(s) for s in sigs]} for b, sigs in txs
            ],
            "multiHashSignatures": [sig_json(s) for s in multi],
            "waitForAllocation": wait,
        }
        if user_id:
            body["userId"] = user_id
        return self._req("POST", "/v2/parties/external/allocate", body)["partyId"]

    def party_details(self, party: str) -> list[dict]:
        return self._req("GET", f"/v2/parties/{urllib.parse.quote(party, safe='')}").get("partyDetails", [])

    def ensure_user(self, user: str) -> bool:
        """Create the ledger user if missing (needs participant/IDP admin). True if created."""
        try:
            self._req("GET", f"/v2/users/{urllib.parse.quote(user, safe='')}")
            return False
        except LedgerError as e:
            if e.status != 404:
                raise
        self._req("POST", "/v2/users", {"user": {"id": user, "isDeactivated": False, "identityProviderId": ""}, "rights": []})
        return True

    def grant_rights(self, user: str, act_as=(), read_as=(), execute_as=()) -> dict:
        rights = (
            [{"kind": {"CanActAs": {"value": {"party": p}}}} for p in act_as]
            + [{"kind": {"CanReadAs": {"value": {"party": p}}}} for p in read_as]
            + [{"kind": {"CanExecuteAs": {"value": {"party": p}}}} for p in execute_as]
        )
        return self._req("POST", f"/v2/users/{urllib.parse.quote(user, safe='')}/rights", {"userId": user, "rights": rights})

    # --- commands ------------------------------------------------------------------------

    def submit_and_wait(self, act_as: list[str], commands: list[dict], disclosed=(), synchronizer_id=None, read_as=()) -> dict:
        """Ordinary submission for LOCAL parties (used by test fixtures; never for the registrar)."""
        body = {
            "commands": commands,
            "commandId": str(uuid.uuid4()),
            "actAs": act_as,
            "readAs": list(read_as),
            "disclosedContracts": list(disclosed),
        }
        if self.user_id:
            body["userId"] = self.user_id
        if synchronizer_id:
            body["synchronizerId"] = synchronizer_id
        return self._req("POST", "/v2/commands/submit-and-wait-for-transaction", {"commands": body})

    def prepare(
        self,
        party: str,
        command: dict,
        synchronizer_id: str | None = None,
        disclosed=(),
        read_as=(),
        max_record_time: str | None = None,
        scheme: str = "HASHING_SCHEME_VERSION_V2",
        package_preference=(),
        command_id: str | None = None,
    ) -> dict:
        body = {
            "commandId": command_id or str(uuid.uuid4()),
            "commands": [command],
            "actAs": [party],
            "readAs": list(read_as),
            "disclosedContracts": list(disclosed),
            "packageIdSelectionPreference": list(package_preference),
            "verboseHashing": False,
            "hashingSchemeVersion": scheme,
        }
        if self.user_id:
            body["userId"] = self.user_id
        if synchronizer_id:
            body["synchronizerId"] = synchronizer_id
        if max_record_time:
            body["maxRecordTime"] = max_record_time
        return self._req("POST", "/v2/interactive-submission/prepare", body)

    def execute_and_wait(self, prepared_b64: str, party: str, sigs: list[crypto.Sig], scheme: str) -> dict:
        body = {
            "preparedTransaction": prepared_b64,
            "partySignatures": {"signatures": [{"party": party, "signatures": [sig_json(s) for s in sigs]}]},
            "submissionId": str(uuid.uuid4()),
            "hashingSchemeVersion": scheme,
            "deduplicationPeriod": {"Empty": {}},
        }
        if self.user_id:
            body["userId"] = self.user_id
        return self._req("POST", "/v2/interactive-submission/executeAndWait", body)
