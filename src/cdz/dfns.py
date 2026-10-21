"""Minimal DFNS API client: Keys API + User Action Signing (stdlib HTTP, `cryptography`).

Protocol as implemented by the official SDKs (@dfns/sdk 0.8.31 `utils/userActionFetch.js`,
@dfns/sdk-keysigner 0.8.31, dfns-sdk (Python) 1.0.3 `_internal/http_client.py`, `auth.py`) and
docs.dfns.co (api-reference/auth/signing-flows, create-user-action-challenge/-signature,
keys/{list-keys,get-key,create-key,generate-signature,get-signature}):

- every request: `Authorization: Bearer <token>`; GET needs nothing else;
- mutating request: POST /auth/action/init {userActionPayload: <exact JSON body string>,
  userActionHttpMethod, userActionHttpPath: <path without query>, userActionServerKind: "Api"}
  -> {challenge, challengeIdentifier, allowCredentials.key[].id};
  clientData = JSON {"type":"key.get","challenge":...} signed with the credential's private key
  (Ed25519 raw; ECDSA P-256/secp256k1 DER over SHA-256; RSA PKCS#1 v1.5 SHA-256);
  POST /auth/action {challengeIdentifier, firstFactor: {kind: "Key", credentialAssertion:
  {credId, clientData: b64url, signature: b64url}}} -> {userAction};
  then the request itself with `X-DFNS-USERACTION: <userAction>` and the same body bytes.

Secrets (auth token, user action tokens, credential private key) are never printed: errors
carry only the HTTP status, the request path and the server's message, with secrets redacted.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from cdz import __version__, crypto

DEFAULT_BASE_URL = "https://api.dfns.io"
SIGNED_STATES = ("Signed", "Confirmed")
PENDING_STATES = ("Pending", "Executing")
FAILED_STATES = ("Failed", "Rejected")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class DfnsError(RuntimeError):
    def __init__(self, status: int, message: str, path: str):
        self.status, self.path = status, path
        super().__init__(f"DFNS {path} -> HTTP {status}: {message}")


class DfnsConfigError(ValueError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _read_secret(value: str) -> str:
    if value.startswith("file:"):
        return Path(value[5:]).expanduser().read_text()
    return value


def token_scope(token: str) -> dict:
    """Unverified JWT payload claims DFNS puts in `https://custom/app_metadata` (orgId, ...)."""
    try:
        payload = json.loads(unb64url(token.split(".")[1]))
        meta = payload.get("https://custom/app_metadata") or {}
        return meta if isinstance(meta, dict) else {}
    except (IndexError, ValueError, UnicodeDecodeError):
        raise DfnsConfigError("CDZ_DFNS_AUTH_TOKEN is not a JWT") from None


# --- credential (service account) signer ----------------------------------------------------


class CredentialSigner:
    """Signs User Action challenges with a service-account / PAT credential key."""

    def __init__(self, cred_id: str, private_key_text: str, origin: str | None = None):
        self.cred_id = cred_id
        self.origin = origin or None
        self._key = load_private_key(private_key_text)

    def sign_bytes(self, data: bytes) -> bytes:
        k = self._key
        if isinstance(k, ed25519.Ed25519PrivateKey):
            return k.sign(data)
        if isinstance(k, ec.EllipticCurvePrivateKey):
            return k.sign(data, ec.ECDSA(hashes.SHA256()))
        if isinstance(k, rsa.RSAPrivateKey):
            return k.sign(data, padding.PKCS1v15(), hashes.SHA256())
        raise DfnsConfigError(f"unsupported credential key type {type(k).__name__}")

    def client_data(self, challenge: str) -> bytes:
        d: dict = {"type": "key.get", "challenge": challenge}
        if self.origin:  # Python SDK / docs variant; the TypeScript key signer sends no origin
            d.update(origin=self.origin, crossOrigin=False)
        return json.dumps(d, separators=(",", ":")).encode()

    def assertion(self, challenge: dict) -> dict:
        allowed = [c.get("id") for c in (challenge.get("allowCredentials") or {}).get("key") or []]
        if allowed and self.cred_id not in allowed:
            raise DfnsConfigError(f"CDZ_DFNS_CRED_ID {self.cred_id} is not among the allowed credentials {allowed}")
        cd = self.client_data(challenge["challenge"])
        return {
            "kind": "Key",
            "credentialAssertion": {"credId": self.cred_id, "clientData": b64url(cd), "signature": b64url(self.sign_bytes(cd))},
        }


def load_private_key(text: str):
    text = text.strip()
    if "\\n" in text and "\n" not in text:  # PEM squeezed into one env line
        text = text.replace("\\n", "\n")
    try:
        if text.startswith("-----BEGIN"):
            return serialization.load_pem_private_key(text.encode(), password=None)
        return serialization.load_der_private_key(base64.b64decode(text, validate=True), password=None)
    except (ValueError, TypeError) as e:
        # never echo the key material
        raise DfnsConfigError(f"CDZ_DFNS_PRIVATE_KEY is not a usable unencrypted PEM/PKCS#8 key ({type(e).__name__})") from None


# --- transport ------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would resend the bearer token to the new location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


Transport = Callable[[str, str, dict, "bytes | None", float], "tuple[int, bytes]"]


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# --- config + client ------------------------------------------------------------------------


@dataclass
class DfnsConfig:
    base_url: str = DEFAULT_BASE_URL
    auth_token: str = field(default="", repr=False)
    org_id: str | None = None
    cred_id: str | None = None
    private_key: str | None = field(default=None, repr=False)
    app_origin: str | None = None
    debug: bool = False

    @classmethod
    def from_env(cls, env=None) -> DfnsConfig:
        e = os.environ if env is None else env
        token = _read_secret(e.get("CDZ_DFNS_AUTH_TOKEN", "")).strip()
        pk = e.get("CDZ_DFNS_PRIVATE_KEY", "").strip()
        return cls(
            base_url=(e.get("CDZ_DFNS_BASE_URL") or DEFAULT_BASE_URL).strip(),
            auth_token=token,
            org_id=(e.get("CDZ_DFNS_ORG_ID") or "").strip() or None,
            cred_id=(e.get("CDZ_DFNS_CRED_ID") or "").strip() or None,
            private_key=_read_secret(pk) if pk else None,
            app_origin=(e.get("CDZ_DFNS_APP_ORIGIN") or "").strip() or None,
            debug=(e.get("CDZ_DFNS_DEBUG") or "").lower() in ("1", "true", "yes"),
        )

    def secrets(self) -> list[str]:
        return [s for s in (self.auth_token, self.private_key) if s]


def _check_base_url(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("https", "http") or not u.hostname or u.query or u.fragment or u.username or u.password:
        raise DfnsConfigError("CDZ_DFNS_BASE_URL must be an absolute https URL without query, fragment or credentials")
    if u.scheme == "http" and u.hostname not in _LOCAL_HOSTS:
        raise DfnsConfigError("CDZ_DFNS_BASE_URL must use https (plain http only for localhost)")
    return url.rstrip("/")


class DfnsClient:
    def __init__(self, cfg: DfnsConfig, transport: Transport | None = None, timeout: float = 30.0):
        if not cfg.auth_token:
            raise DfnsConfigError("CDZ_DFNS_AUTH_TOKEN is not set (service account token; value or file:/path)")
        self.cfg = cfg
        self.base = _check_base_url(cfg.base_url)
        self.transport = transport or urllib_transport
        self.timeout = timeout
        self.org_id = token_scope(cfg.auth_token).get("orgId")
        if cfg.org_id and self.org_id != cfg.org_id:
            raise DfnsConfigError(f"the auth token is not scoped to CDZ_DFNS_ORG_ID {cfg.org_id}")
        self._signer: CredentialSigner | None = None
        self._redact = list(cfg.secrets())

    # --- plumbing ---------------------------------------------------------------------------

    def signer(self) -> CredentialSigner:
        if self._signer is None:
            if not (self.cfg.cred_id and self.cfg.private_key):
                raise DfnsConfigError("mutating DFNS calls need CDZ_DFNS_CRED_ID and CDZ_DFNS_PRIVATE_KEY (User Action Signing)")
            self._signer = CredentialSigner(self.cfg.cred_id, self.cfg.private_key, self.cfg.app_origin)
        return self._signer

    def _scrub(self, text: str) -> str:
        for s in self._redact:
            if s and len(s) >= 8:
                text = text.replace(s, "<redacted>")
        return text

    def _send(self, method: str, path: str, payload: str | None, extra: dict | None = None) -> tuple[int, object]:
        headers = {
            "Authorization": f"Bearer {self.cfg.auth_token}",
            "Accept": "application/json",
            "User-Agent": f"cdz/{__version__}",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra or {})
        status, raw = self.transport(method, self.base + path, headers, payload.encode() if payload is not None else None, self.timeout)
        if self.cfg.debug:
            print(f"dfns: {method} {path.split('?')[0]} -> {status}", file=sys.stderr)
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {"message": raw[:300].decode(errors="replace")}
        if status >= 300:
            err = body.get("error") if isinstance(body, dict) else None
            err = err if isinstance(err, dict) else (body if isinstance(body, dict) else {})
            msg = str(err.get("message") or err.get("code") or "error")[:500]
            raise DfnsError(status, self._scrub(msg), path.split("?")[0])
        return status, body

    def get(self, path: str, query: dict | None = None):
        q = {k: v for k, v in (query or {}).items() if v is not None}
        return self._send("GET", path + ("?" + urllib.parse.urlencode(q) if q else ""), None)[1]

    def mutate(self, method: str, path: str, body: dict) -> tuple[int, dict]:
        """User Action Signing, then the request with exactly the signed body bytes."""
        payload = json.dumps(body, separators=(",", ":"))
        signer = self.signer()
        _, ch = self._send("POST", "/auth/action/init", json.dumps({
            "userActionPayload": payload,
            "userActionHttpMethod": method,
            "userActionHttpPath": path.split("?")[0],
            "userActionServerKind": "Api",
        }, separators=(",", ":")))
        if not isinstance(ch, dict) or "challenge" not in ch or "challengeIdentifier" not in ch:
            raise DfnsError(0, "unexpected /auth/action/init response", "/auth/action/init")
        _, ua = self._send("POST", "/auth/action", json.dumps({
            "challengeIdentifier": ch["challengeIdentifier"], "firstFactor": signer.assertion(ch),
        }, separators=(",", ":")))
        token = ua.get("userAction") if isinstance(ua, dict) else None
        if not token:
            raise DfnsError(0, "no userAction token in the /auth/action response", "/auth/action")
        self._redact.append(token)
        status, res = self._send(method, path, payload, {"X-DFNS-USERACTION": token})
        return status, res if isinstance(res, dict) else {}

    # --- keys -------------------------------------------------------------------------------

    def list_keys(self, page_size: int = 100) -> list[dict]:
        out, tok = [], None
        while True:
            r = self.get("/keys", {"limit": page_size, "paginationToken": tok})
            out += r.get("items", [])
            tok = r.get("nextPageToken")
            if not tok:
                return out

    def get_key(self, key_id: str) -> dict:
        return self.get(f"/keys/{_seg(key_id)}")

    def create_key(self, name: str) -> dict:
        status, k = self.mutate("POST", "/keys", {"scheme": "EdDSA", "curve": "ed25519", "name": name})
        if status == 202:
            raise DfnsError(202, f"key creation is pending a policy approval ({_approval(k)}); approve it, then `cdz dfns keys list`", "/keys")
        return k

    def generate_signature(self, key_id: str, message: bytes) -> dict:
        """`kind: Message` over the exact bytes (hex, no 0x, as the Wallet Gateway sends it)."""
        path = f"/keys/{_seg(key_id)}/signatures"
        status, r = self.mutate("POST", path, {"kind": "Message", "message": message.hex()})
        if not r.get("id"):
            raise DfnsError(status, f"signature request not created ({_approval(r)})", path)
        return r

    def get_signature(self, key_id: str, sig_id: str) -> dict:
        return self.get(f"/keys/{_seg(key_id)}/signatures/{_seg(sig_id)}")

    def wait_signature(self, key_id: str, req: dict, timeout: float, interval: float = 3.0,
                       on_pending: Callable[[dict], None] | None = None, sleep=time.sleep, clock=time.monotonic) -> dict:
        deadline = clock() + timeout
        notified = False
        while True:
            st = req.get("status")
            if st in SIGNED_STATES:
                return req
            if st in FAILED_STATES:
                raise DfnsError(0, f"signature {req.get('id')} {st}: {req.get('reason') or 'no reason given'}", f"/keys/{key_id}/signatures")
            if st not in PENDING_STATES:
                raise DfnsError(0, f"signature {req.get('id')} has unknown status {st!r}", f"/keys/{key_id}/signatures")
            if not notified and on_pending:
                on_pending(req)
                notified = True
            if clock() >= deadline:
                raise TimeoutError(f"DFNS signature {req.get('id')} still {st} after {timeout:.0f}s "
                                   f"(approval {req.get('approvalId') or '-'}); rerun with --signature-id {req.get('id')}")
            sleep(interval)
            req = self.get_signature(key_id, req["id"])


def _seg(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _approval(r) -> str:
    if isinstance(r, dict):
        for k in ("approvalId", "id"):
            if r.get(k):
                return f"{k} {r[k]}"
    return "no id returned"


# --- conversions ----------------------------------------------------------------------------


def _hex(s: str, what: str) -> bytes:
    s = s.strip()
    s = s[2:] if s[:2] in ("0x", "0X") else s
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"{what} is not hex") from None


def is_canton_key(k: dict) -> bool:
    """What the Wallet Gateway DFNS provider lists (core/signing-dfns/src/dfns.ts isCantonKey + Active)."""
    return k.get("scheme") == "EdDSA" and k.get("curve") == "ed25519" and k.get("status") == "Active"


def public_key(k: dict) -> crypto.PublicKey:
    """cdz/Canton public key of a DFNS EdDSA/ed25519 key (`publicKey` = hex of the raw 32 bytes)."""
    if k.get("scheme") != "EdDSA" or k.get("curve") != "ed25519":
        raise ValueError(f"DFNS key {k.get('id')} is {k.get('scheme')}/{k.get('curve')}, Canton needs EdDSA/ed25519")
    raw = _hex(str(k.get("publicKey") or ""), f"publicKey of {k.get('id')}")
    if len(raw) != 32:
        raise ValueError(f"publicKey of DFNS key {k.get('id')} has {len(raw)} bytes, expected 32 raw Ed25519 bytes (64 hex chars)")
    return crypto.PublicKey.from_crypto(ed25519.Ed25519PublicKey.from_public_bytes(raw))


def pub_json(k: dict, name: str | None = None) -> dict:
    """The cdz public-key JSON (`role: tx`) for a DFNS key, plus where it lives."""
    pk = public_key(k)
    return {"name": name or k.get("name") or k["id"], "role": "tx", **pk.to_json(),
            "dfns": {"key_id": k["id"], "public_key_hex": pk.spki[-32:].hex(), "gateway_public_key": crypto.b64(pk.spki[-32:])}}


def signature_candidates(sig: dict | None) -> list[bytes]:
    """64-byte r||s candidates from a DFNS signature object (`encoded`, else r+s), hex with optional 0x."""
    if not sig:
        return []
    out = []
    if sig.get("encoded"):
        out.append(_hex(sig["encoded"], "signature.encoded"))
    if sig.get("r") and sig.get("s"):
        r, s = _hex(sig["r"], "signature.r"), _hex(sig["s"], "signature.s")
        if len(r) <= 32 and len(s) <= 32:
            out.append(r.rjust(32, b"\0") + s.rjust(32, b"\0"))
    return [c for i, c in enumerate(out) if len(c) == 64 and c not in out[:i]]


def verified_signature(pk: crypto.PublicKey, data: bytes, req: dict) -> crypto.Sig:
    """The DFNS signature as a cdz Sig, only if it verifies over `data` with the key."""
    cands = signature_candidates(req.get("signature"))
    if not cands:
        raise ValueError(f"DFNS signature {req.get('id')} carries no 64-byte Ed25519 signature")
    for c in cands:
        if pk.verify(c, data):
            return crypto.Sig(c, pk.fingerprint, pk.spec.sig_format, pk.spec.algorithm)
    raise ValueError(f"DFNS signature {req.get('id')} does NOT verify against key {pk.fingerprint[:16]}… over {data.hex()[:16]}…; nothing written")


def signed_message(req: dict) -> bytes | None:
    rb = req.get("requestBody") or {}
    if rb.get("kind") != "Message" or not rb.get("message"):
        return None
    return _hex(rb["message"], "requestBody.message")
