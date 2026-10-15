"""DA Utilities off-ledger APIs: choice contexts + disclosed contracts for registrar choices.

Base URL per network (`[utilities].api`): https://api.utilities.digitalasset{,-staging,-dev}.com
- token standard (per admin): /api/token-standard/v0/registrars/<admin>/registry/...
- utilities backend:          /api/utilities/v0/...
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from cdz.utilities import strip_disclosed


class RegistryError(RuntimeError):
    pass


class RegistryClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 30.0):
        if not base_url:
            raise RegistryError("no utilities API base URL configured ([utilities].api in the network profile)")
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _req(self, method: str, path: str, body=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise RegistryError(f"{method} {path} -> HTTP {e.code}: {e.read().decode(errors='replace')[:500]}") from None
        return json.loads(raw) if raw else {}

    def _ts(self, admin: str) -> str:
        return f"/api/token-standard/v0/registrars/{urllib.parse.quote(admin, safe='')}/registry"

    # --- discovery ---------------------------------------------------------------------------

    def operator_party(self) -> str:
        r = self._req("GET", "/api/utilities/v0/operator")
        if isinstance(r, str):
            return r
        for k in ("operatorParty", "operator", "party", "partyId", "operatorPartyId"):
            if isinstance(r, dict) and isinstance(r.get(k), str):
                return r[k]
        raise RegistryError(f"unexpected operator response: {json.dumps(r)[:300]}")

    def info(self, admin: str) -> dict:
        return self._req("GET", self._ts(admin) + "/metadata/v1/info")

    def instruments(self, admin: str) -> list[dict]:
        out, token = [], None
        while True:
            q = "?pageSize=100" + (f"&pageToken={urllib.parse.quote(token)}" if token else "")
            r = self._req("GET", self._ts(admin) + "/metadata/v1/instruments" + q)
            out += r.get("instruments", [])
            token = r.get("nextPageToken")
            if not token:
                return out

    # --- choice contexts ---------------------------------------------------------------------

    @staticmethod
    def _ctx(r: dict) -> tuple[dict, list[dict]]:
        c = r.get("choiceContext", r)
        return c.get("choiceContextData") or {"values": {}}, strip_disclosed(c.get("disclosedContracts", []))

    def transfer_factory(self, admin: str, choice_args: dict) -> tuple[str, str, dict, list[dict]]:
        """-> (factoryId, transferKind, choiceContextData, disclosedContracts)."""
        r = self._req("POST", self._ts(admin) + "/transfer-instruction/v1/transfer-factory",
                      {"choiceArguments": choice_args, "excludeDebugFields": True})
        ctx, disclosed = self._ctx(r)
        return r["factoryId"], r.get("transferKind", ""), ctx, disclosed

    def transfer_instruction_context(self, admin: str, cid: str, action: str) -> tuple[dict, list[dict]]:
        if action not in ("accept", "reject", "withdraw"):
            raise RegistryError(action)
        r = self._req("POST", self._ts(admin) + f"/transfer-instruction/v1/{cid}/choice-contexts/{action}",
                      {"meta": {}, "excludeDebugFields": True})
        return self._ctx(r)

    def mint_request_accept_context(self, cid: str) -> tuple[dict, list[dict]]:
        r = self._req("POST", f"/api/utilities/v0/registry/mint/v0/request/{cid}/choice-contexts/accept",
                      {"meta": {}, "excludeDebugFields": True})
        return self._ctx(r)

    def mint_offer_factory(self, holder: str, admin: str, instrument: str) -> tuple[str, dict, list[dict]]:
        r = self._req("POST", "/api/utilities/v0/registry/mint/v0/offer",
                      {"holder": holder, "instrumentId": {"admin": admin, "id": instrument}})
        ctx, disclosed = self._ctx(r)
        return r["factoryId"], ctx, disclosed

    def burn_request_accept_context(self, cid: str) -> tuple[dict, list[dict]]:
        r = self._req("POST", f"/api/utilities/v0/registry/burn/v0/request/{cid}/choice-contexts/accept",
                      {"meta": {}, "excludeDebugFields": True})
        return self._ctx(r)
