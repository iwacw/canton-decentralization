"""Canton hashing, fingerprints, signing keys and signatures.

Sources: canton v3.5.19 `crypto/HashBuilder.scala`, `crypto/Signing.scala`,
`topology/transaction/TopologyTransactionSignature.scala`, `TopologyMapping.scala`.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from cdz._proto.com.digitalasset.canton.crypto.v30 import crypto_pb2 as cpb

# HashPurpose ids (canton crypto/HashPurpose.scala)
PURPOSE_TOPOLOGY_TX = 11
PURPOSE_FINGERPRINT = 12
PURPOSE_DECENTRALIZED_NAMESPACE = 37
PURPOSE_PREPARED_SUBMISSION = 48
PURPOSE_MULTI_TOPOLOGY_TX = 55

MULTIHASH_SHA256 = b"\x12\x20"


class HashBuilder:
    """Canton HashBuilderFromMessageDigest over SHA-256: purpose first, length-prefixed bytes."""

    def __init__(self, purpose: int):
        self._h = hashlib.sha256(struct.pack(">i", purpose))

    def add_raw(self, data: bytes) -> "HashBuilder":
        self._h.update(data)
        return self

    def add_int(self, value: int) -> "HashBuilder":
        return self.add_raw(struct.pack(">i", value))

    def add_bytes(self, data: bytes) -> "HashBuilder":
        return self.add_int(len(data)).add_raw(data)

    def add_string(self, value: str) -> "HashBuilder":
        return self.add_bytes(value.encode("utf-8"))

    def finish(self) -> bytes:
        """Multihash encoding (0x12 0x20 || sha256), as Hash.getCryptographicEvidence."""
        return MULTIHASH_SHA256 + self._h.digest()


def canton_hash(purpose: int, data: bytes) -> bytes:
    return HashBuilder(purpose).add_raw(data).finish()


def topology_tx_hash(serialized_versioned_tx: bytes) -> bytes:
    """Hash signed for a topology transaction (over the UntypedVersionedMessage bytes)."""
    return canton_hash(PURPOSE_TOPOLOGY_TX, serialized_versioned_tx)


def multi_tx_hash(tx_hashes: list[bytes]) -> bytes:
    """MultiTransactionSignature.computeCombinedHash: sorted by hex, count + length-prefixed hashes."""
    uniq = sorted(set(tx_hashes), key=lambda h: h.hex())
    b = HashBuilder(PURPOSE_MULTI_TOPOLOGY_TX).add_int(len(uniq))
    for h in uniq:
        b.add_bytes(h)
    return b.finish()


def dns_namespace(owner_namespaces: list[str] | set[str]) -> str:
    """DecentralizedNamespaceDefinition.computeNamespace (owners sorted by fingerprint string)."""
    b = HashBuilder(PURPOSE_DECENTRALIZED_NAMESPACE)
    for ns in sorted(set(owner_namespaces)):
        b.add_string(ns)
    return b.finish().hex()


# --- key specs ------------------------------------------------------------------------------


@dataclass(frozen=True)
class KeySpec:
    name: str
    key_spec: int  # crypto.v30.SigningKeySpec (same numbers in the Ledger API enum)
    algorithm: int  # SigningAlgorithmSpec
    sig_format: int  # SignatureFormat
    curve: type | None  # cryptography EC curve class, None for Ed25519
    digest: type | None


SPECS: dict[str, KeySpec] = {
    "ed25519": KeySpec(
        "ed25519",
        cpb.SIGNING_KEY_SPEC_EC_CURVE25519,
        cpb.SIGNING_ALGORITHM_SPEC_ED25519,
        cpb.SIGNATURE_FORMAT_CONCAT,
        None,
        None,
    ),
    "p256": KeySpec(
        "p256",
        cpb.SIGNING_KEY_SPEC_EC_P256,
        cpb.SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256,
        cpb.SIGNATURE_FORMAT_DER,
        ec.SECP256R1,
        hashes.SHA256,
    ),
    "secp256k1": KeySpec(
        "secp256k1",
        cpb.SIGNING_KEY_SPEC_EC_SECP256K1,
        cpb.SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256,
        cpb.SIGNATURE_FORMAT_DER,
        ec.SECP256K1,
        hashes.SHA256,
    ),
    "p384": KeySpec(
        "p384",
        cpb.SIGNING_KEY_SPEC_EC_P384,
        cpb.SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_384,
        cpb.SIGNATURE_FORMAT_DER,
        ec.SECP384R1,
        hashes.SHA384,
    ),
}
_SPEC_BY_PROTO = {s.key_spec: s for s in SPECS.values()}
_CURVE_TO_SPEC = {"secp256r1": "p256", "secp256k1": "secp256k1", "secp384r1": "p384"}


def spec_for_proto(key_spec: int) -> KeySpec:
    try:
        return _SPEC_BY_PROTO[key_spec]
    except KeyError:
        raise ValueError(f"unsupported signing key spec {key_spec}") from None


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text.strip(), validate=True)


# --- public / private keys ------------------------------------------------------------------


class PublicKey:
    """A signing public key as Canton sees it: X.509 SPKI DER + key spec."""

    def __init__(self, spki_der: bytes, spec: KeySpec):
        self.spki = spki_der
        self.spec = spec
        self._key = serialization.load_der_public_key(spki_der)
        if spec.curve is None:
            if not isinstance(self._key, ed25519.Ed25519PublicKey):
                raise ValueError("key is not Ed25519")
        elif not (isinstance(self._key, ec.EllipticCurvePublicKey) and isinstance(self._key.curve, spec.curve)):
            raise ValueError(f"key does not match spec {spec.name}")

    @classmethod
    def from_crypto(cls, key) -> "PublicKey":
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if isinstance(key, ed25519.Ed25519PublicKey):
            return cls(spki, SPECS["ed25519"])
        name = _CURVE_TO_SPEC.get(key.curve.name)
        if not name:
            raise ValueError(f"unsupported curve {key.curve.name}")
        return cls(spki, SPECS[name])

    @classmethod
    def from_spki(cls, spki_der: bytes) -> "PublicKey":
        return cls.from_crypto(serialization.load_der_public_key(spki_der))

    @classmethod
    def from_proto(cls, p: cpb.SigningPublicKey) -> "PublicKey":
        if p.format != cpb.CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO:
            raise ValueError(f"unsupported key format {p.format}")
        return cls(p.public_key, spec_for_proto(p.key_spec))

    @property
    def fingerprint(self) -> str:
        if self.spec.curve is None:  # Ed25519: hash the raw key (backwards compatibility rule)
            data = self._key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            data = self.spki
        return canton_hash(PURPOSE_FINGERPRINT, data).hex()

    def to_proto(self, usage: list[int]) -> cpb.SigningPublicKey:
        return cpb.SigningPublicKey(
            format=cpb.CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO,
            public_key=self.spki,
            usage=usage,
            key_spec=self.spec.key_spec,
        )

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            if self.spec.curve is None:
                self._key.verify(signature, data)
            else:
                self._key.verify(signature, data, ec.ECDSA(self.spec.digest()))
            return True
        except InvalidSignature:
            return False

    def to_json(self) -> dict:
        return {"spec": self.spec.name, "spki": b64(self.spki), "fingerprint": self.fingerprint}

    @classmethod
    def from_json(cls, d: dict) -> "PublicKey":
        pk = cls(unb64(d["spki"]), SPECS[d["spec"]])
        if d.get("fingerprint") and d["fingerprint"] != pk.fingerprint:
            raise ValueError(f"fingerprint mismatch for key {d['fingerprint']}")
        return pk

    def __eq__(self, other) -> bool:
        return isinstance(other, PublicKey) and self.spki == other.spki

    def __hash__(self) -> int:
        return hash(self.spki)

    def __repr__(self) -> str:
        return f"PublicKey({self.spec.name}, {self.fingerprint})"


class SigningKey:
    """Private signing key held by this process (loaded from the environment / a file)."""

    def __init__(self, private_key, name: str = ""):
        self._key = private_key
        self.public = PublicKey.from_crypto(private_key.public_key())
        self.name = name

    @classmethod
    def generate(cls, spec: str = "ed25519", name: str = "") -> "SigningKey":
        s = SPECS[spec]
        key = ed25519.Ed25519PrivateKey.generate() if s.curve is None else ec.generate_private_key(s.curve())
        return cls(key, name)

    @classmethod
    def from_pkcs8(cls, der: bytes, name: str = "") -> "SigningKey":
        return cls(serialization.load_der_private_key(der, password=None), name)

    @classmethod
    def from_ed25519_seed(cls, seed: bytes, name: str = "") -> "SigningKey":
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed), name)

    @classmethod
    def parse(cls, text: str, name: str = "") -> "SigningKey":
        """Accepts PEM, base64 PKCS#8 DER, or a base64/hex 32-byte Ed25519 seed."""
        text = text.strip()
        if text.startswith("-----BEGIN"):
            return cls(serialization.load_pem_private_key(text.encode(), password=None), name)
        raw: bytes | None = None
        if len(text) == 64:
            try:
                raw = bytes.fromhex(text)
            except ValueError:
                raw = None
        if raw is None:
            raw = unb64(text)
        if len(raw) == 32:
            return cls.from_ed25519_seed(raw, name)
        return cls.from_pkcs8(raw, name)

    def pkcs8_b64(self) -> str:
        return b64(
            self._key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )

    @property
    def fingerprint(self) -> str:
        return self.public.fingerprint

    def sign(self, data: bytes) -> bytes:
        if self.public.spec.curve is None:
            return self._key.sign(data)
        return self._key.sign(data, ec.ECDSA(self.public.spec.digest()))

    def signature(self, data: bytes) -> "Sig":
        s = self.public.spec
        return Sig(self.sign(data), self.fingerprint, s.sig_format, s.algorithm)


@dataclass(frozen=True)
class Sig:
    """Signature in Canton terms; the enum numbers are identical in the Admin and Ledger APIs."""

    signature: bytes
    signed_by: str
    format: int
    algorithm: int

    def to_canton(self) -> cpb.Signature:
        return cpb.Signature(
            format=self.format, signature=self.signature, signed_by=self.signed_by, signing_algorithm_spec=self.algorithm
        )

    @classmethod
    def from_canton(cls, s) -> "Sig":
        return cls(s.signature, s.signed_by, s.format, s.signing_algorithm_spec)

    def to_json(self) -> dict:
        return {
            "signed_by": self.signed_by,
            "format": cpb.SignatureFormat.Name(self.format),
            "algorithm": cpb.SigningAlgorithmSpec.Name(self.algorithm),
            "signature": b64(self.signature),
        }

    @classmethod
    def from_json(cls, d: dict) -> "Sig":
        return cls(
            unb64(d["signature"]),
            d["signed_by"],
            cpb.SignatureFormat.Value(d["format"]),
            cpb.SigningAlgorithmSpec.Value(d["algorithm"]),
        )
