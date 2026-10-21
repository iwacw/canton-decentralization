"""In-process fake of the DFNS API pieces cdz uses (no network beyond 127.0.0.1).

Enforces what the real API documents: bearer token on every call, User Action Signing for
mutations (challenge bound to method + path + exact payload, credential signature over the
clientData, single-use tokens), Keys API shapes. Keys are local Ed25519 keys acting as the
"DFNS-held" keys, so signatures are real and verifiable.
"""

from __future__ import annotations

import base64
import itertools
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(org_id: str) -> str:
    head = b64url(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode())
    body = b64url(json.dumps({"iss": "auth.dfns.io", "https://custom/app_metadata": {"orgId": org_id, "tokenKind": "Service"}}).encode())
    return f"{head}.{body}.{b64url(secrets.token_bytes(32))}"


class MockDfns:
    def __init__(self, sa_key=None):
        self.org_id = "or-30tnh-itmjs-9hfme3k8sbn8jd4u"
        self.cred_id = "cr-1hb8c-n5a1o-8q0dsfd1kd5l2ml4"
        self.token = make_token(self.org_id)
        self.sa_key = sa_key or ed25519.Ed25519PrivateKey.generate()
        self.keys: dict[str, dict] = {}
        self.privs: dict[str, ed25519.Ed25519PrivateKey] = {}
        self.sigs: dict[str, dict] = {}
        self.challenges: dict[str, dict] = {}
        self.actions: dict[str, dict] = {}
        self.requests: list[dict] = []
        self.ids = itertools.count(1)
        # behaviour knobs
        self.pending_polls = 0  # GETs that still answer Pending before the signature is Signed
        self.approve = True  # False: pending forever (until approve_all)
        self.reject = False
        self.tamper = False  # return a signature over different data
        self.encoding = "encoded"  # encoded | rs | 0x
        self.bad_public_key = False
        self.page = 2
        self.prefix = ""  # deployment path prefix of the base URL, stripped before routing
        self.pending_status = "Pending"  # or Executing
        self.fail = False  # signature ends Failed
        self.accept_202 = False  # POST /signatures answers 202 with an approval object
        self.lock = threading.Lock()

    # --- setup helpers ---------------------------------------------------------------------

    def _id(self, prefix: str) -> str:
        return f"{prefix}-{next(self.ids):05d}-mock0-{secrets.token_hex(7)}"

    def private_key_pem(self) -> str:
        return self.sa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()).decode()

    def env(self, base_url: str) -> dict:
        return {"CDZ_DFNS_BASE_URL": base_url, "CDZ_DFNS_ORG_ID": self.org_id, "CDZ_DFNS_AUTH_TOKEN": self.token,
                "CDZ_DFNS_CRED_ID": self.cred_id, "CDZ_DFNS_PRIVATE_KEY": self.private_key_pem().replace("\n", "\\n")}

    def add_key(self, name="k", scheme="EdDSA", curve="ed25519", status="Active", wallets=()) -> str:
        kid = self._id("key")
        if curve == "ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
            self.privs[kid] = priv
            pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        else:
            pub = "02" + secrets.token_hex(32)
        self.keys[kid] = {"id": kid, "scheme": scheme, "curve": curve, "publicKey": pub, "name": name, "status": status,
                          "custodial": True, "dateCreated": "2026-10-21T00:00:00.000Z", "masterKey": False,
                          "_wallets": [{"id": self._id("wa"), "network": n} for n in wallets]}
        return kid

    def approve_all(self):
        self.approve = True
        self.pending_polls = 0

    def sig_requests(self) -> list[dict]:
        return [r for r in self.requests if r["method"] == "POST" and r["path"].endswith("/signatures")]

    # --- API --------------------------------------------------------------------------------

    def public(self, k: dict) -> dict:
        return {x: v for x, v in k.items() if not x.startswith("_")}

    def handle(self, method: str, path: str, headers: dict, raw: bytes):
        with self.lock:
            return self._handle(method, path, headers, raw)

    def _handle(self, method, path, headers, raw):
        self.requests.append({"method": method, "path": path, "headers": dict(headers), "body": raw})
        if headers.get("authorization") != f"Bearer {self.token}":
            return 401, {"error": {"message": "Unauthorized"}}
        if not headers.get("user-agent"):
            return 400, {"error": {"message": "User-Agent must not be empty"}}
        if self.prefix:
            if not path.startswith(self.prefix + "/"):
                return 404, {"error": {"message": "wrong prefix"}}
            path = path[len(self.prefix):]
        route, _, query = path.partition("?")
        q = dict(p.split("=", 1) for p in query.split("&") if p)
        parts = route.strip("/").split("/")
        body = json.loads(raw) if raw else None
        if route == "/redirect-me":
            return 302, {"location": "http://127.0.0.1:1/stolen"}
        if route == "/auth/action/init" and method == "POST":
            need = {"userActionPayload", "userActionHttpMethod", "userActionHttpPath"}
            if set(body) != need | {"userActionServerKind"} or body["userActionServerKind"] != "Api":
                return 400, {"error": {"message": "bad init body"}}
            ch = b64url(secrets.token_bytes(32))
            cid = "eyJ" + secrets.token_hex(16)
            self.challenges[cid] = {"challenge": ch, **body, "used": False}
            return 200, {"challenge": ch, "challengeIdentifier": cid, "supportedCredentialKinds": [{"kind": "Key", "factor": "first", "requiresSecondFactor": False}],
                         "userVerification": "required", "attestation": "none", "externalAuthenticationUrl": "",
                         "allowCredentials": {"key": [{"type": "public-key", "id": self.cred_id}], "webauthn": []}}
        if route == "/auth/action" and method == "POST":
            c = self.challenges.get(body.get("challengeIdentifier"))
            ff = body.get("firstFactor") or {}
            if not c or c["used"]:
                return 401, {"error": {"message": "invalid challenge"}}
            c["used"] = True
            ca = ff.get("credentialAssertion") or {}
            if ff.get("kind") != "Key" or ca.get("credId") != self.cred_id:
                return 401, {"error": {"message": "unknown credential"}}
            cd = unb64url(ca["clientData"])
            j = json.loads(cd)
            if j.get("type") != "key.get" or j.get("challenge") != c["challenge"]:
                return 401, {"error": {"message": "client data mismatch"}}
            try:
                pub = self.sa_key.public_key()
                if isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(unb64url(ca["signature"]), cd, ec.ECDSA(hashes.SHA256()))
                else:
                    pub.verify(unb64url(ca["signature"]), cd)
            except InvalidSignature:
                return 401, {"error": {"message": "bad credential signature"}}
            tok = "ua." + secrets.token_hex(24)
            self.actions[tok] = {"method": c["userActionHttpMethod"], "path": c["userActionHttpPath"], "payload": c["userActionPayload"], "used": False}
            return 200, {"userAction": tok}
        if method != "GET":
            ua = self.actions.get(headers.get("x-dfns-useraction", ""))
            if not ua or ua["used"]:
                return 403, {"error": {"message": "User action signature is missing"}}
            ua["used"] = True
            if (ua["method"], ua["path"], ua["payload"]) != (method, route, raw.decode()):
                return 403, {"error": {"message": "user action does not match the request"}}
        if parts == ["keys"] and method == "GET":
            items = sorted(self.keys.values(), key=lambda k: k["id"])
            start = int(q.get("paginationToken", "0"))
            n = min(int(q.get("limit", 50)), self.page)
            page = items[start:start + n]
            r = {"items": [self.public(k) for k in page]}
            if start + n < len(items):
                r["nextPageToken"] = str(start + n)
            return 200, r
        if parts == ["keys"] and method == "POST":
            if body.get("scheme") != "EdDSA" or body.get("curve") != "ed25519":
                return 400, {"error": {"message": "unsupported"}}
            kid = self.add_key(body.get("name", ""))
            if self.bad_public_key:
                self.keys[kid]["publicKey"] = "00" + self.keys[kid]["publicKey"]
            return 200, self.public(self.keys[kid])
        if len(parts) == 2 and parts[0] == "keys" and method == "GET":
            k = self.keys.get(parts[1])
            if not k:
                return 404, {"error": {"message": "Key not found"}}
            return 200, {**self.public(k), "wallets": k["_wallets"], "store": {"id": "store-x", "kind": "Mpc", "keyId": k["id"]}}
        if len(parts) == 3 and parts[0] == "keys" and parts[2] == "signatures" and method == "POST":
            kid = parts[1]
            if kid not in self.keys:
                return 404, {"error": {"message": "Key not found"}}
            if body.get("kind") != "Message":
                return 400, {"error": {"message": "only Message in the mock"}}
            if self.accept_202:
                return 202, {"id": "ap-mock0-mock0-0000000000000001", "status": "Pending", "activityId": "x"}
            sid = self._id("sig")
            req = {"id": sid, "keyId": kid, "requester": {"userId": "us-x"}, "requestBody": body, "status": self.pending_status,
                   "dateRequested": "2026-10-21T00:00:00Z", "_polls": self.pending_polls}
            self.sigs[sid] = req
            self._progress(req, first=True)
            return 200, self.public(req)
        if len(parts) == 4 and parts[0] == "keys" and parts[2] == "signatures" and method == "GET":
            req = self.sigs.get(parts[3])
            if not req or req["keyId"] != parts[1]:
                return 404, {"error": {"message": "Signature not found"}}
            self._progress(req)
            return 200, self.public(req)
        return 404, {"error": {"message": f"no route {method} {route}"}}

    def _progress(self, req, first=False):
        if req["status"] not in ("Pending", "Executing"):
            return
        if self.fail:
            req.update(status="Failed", reason="signer unavailable")
            return
        if self.reject:
            req.update(status="Rejected", reason="policy rejected")
            return
        if not self.approve:
            req["approvalId"] = "ap-mock0-mock0-0000000000000000"
            return
        if req["_polls"] > 0:
            if not first:
                req["_polls"] -= 1
            req["approvalId"] = "ap-mock0-mock0-0000000000000000"
            return
        msg = bytes.fromhex(req["requestBody"]["message"].removeprefix("0x"))
        sig = self.privs[req["keyId"]].sign(msg + (b"x" if self.tamper else b""))
        r, s = sig[:32].hex(), sig[32:].hex()
        if self.encoding == "encoded":
            out = {"r": "0x" + r, "s": "0x" + s, "encoded": sig.hex()}
        elif self.encoding == "0x":
            out = {"r": "0x" + r, "s": "0x" + s, "encoded": "0x" + sig.hex()}
        else:
            out = {"r": r, "s": s}
        req.update(status="Signed", signature=out, dateSigned="2026-10-21T00:00:01Z")


class _Handler(BaseHTTPRequestHandler):
    mock: MockDfns

    def _do(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        status, body = self.mock.handle(self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, raw)
        data = json.dumps(body).encode()
        self.send_response(status)
        if status == 302:
            self.send_header("Location", body["location"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = _do

    def log_message(self, *a):
        pass


class MockServer:
    def __init__(self, mock: MockDfns | None = None):
        self.mock = mock or MockDfns()
        handler = type("H", (_Handler,), {"mock": self.mock})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
