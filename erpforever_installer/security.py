"""Signed entitlements and encrypted release verification. Contains public material only."""
import base64
import hashlib
import io
import json
import re
import tarfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_PAYLOAD = 100 * 1024 * 1024
MAX_UNPACKED = 300 * 1024 * 1024


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def normalize_site(site):
    site = str(site).strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", site) or ".." in site:
        raise ValueError("Use a hostname only, without scheme, port or path")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in site.split('.')):
        raise ValueError("Invalid hostname")
    return site


def verify_license(token, public_key, site=None, now=None):
    if len(token) > 8192:
        raise ValueError("Invalid token")
    prefix, payload, signature = token.strip().split(".")
    if prefix != "EF1":
        raise ValueError("Invalid token version")
    raw = unb64(payload)
    Ed25519PublicKey.from_public_bytes(public_key).verify(unb64(signature), raw)
    claims = json.loads(raw)
    if claims.get("format") != 1 or claims.get("issuer") != "ERPForever":
        raise ValueError("Invalid issuer")
    if claims["expires"] <= (now if now is not None else int(time.time())):
        raise ValueError("Official download entitlement has expired")
    if site and normalize_site(claims["site"]) != normalize_site(site):
        raise ValueError("Token belongs to another site")
    if len(unb64(claims["secret"])) != 32 or not re.fullmatch(r"[a-f0-9]{32}", claims["id"]):
        raise ValueError("Invalid entitlement")
    return claims


def recipient_id(claims):
    return hashlib.sha256(claims["id"].encode()).hexdigest()


def verify_manifest(document, public_key):
    body = document["manifest"]
    Ed25519PublicKey.from_public_bytes(public_key).verify(unb64(document["signature"]), canonical(body))
    if body.get("format") != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", body.get("version", "")):
        raise ValueError("Invalid release format")
    if type(body.get("sequence")) is not int or body["sequence"] < 1:
        raise ValueError("Invalid release sequence")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", body.get("sha256", "")):
        raise ValueError("Invalid release checksum")
    if not re.fullmatch(r"frappe/erpnext@sha256:[a-f0-9]{64}", body.get("erpnext_image", "")):
        raise ValueError("Only a pinned ERPNext image is allowed")
    validate_services(body.get("services", {}))
    return body


def validate_services(services):
    reserved = {"db", "backend", "frontend", "proxy", "redis-cache", "redis-queue", "scheduler", "websocket", "queue-long", "queue-short"}
    if not isinstance(services, dict) or len(services) > 12:
        raise ValueError("Invalid service set")
    allowed = {"image", "command", "environment", "volumes", "depends_on", "healthcheck", "mem_limit", "cpus"}
    for name, spec in services.items():
        if not re.fullmatch(r"addon-[a-z0-9-]{1,40}", name) or name in reserved or not isinstance(spec, dict):
            raise ValueError("Invalid service name")
        if set(spec) - allowed:
            raise ValueError("Unsafe service option")
        if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", spec.get("image", "")):
            raise ValueError("Addon images must be pinned by digest")
        for volume in spec.get("volumes", []):
            if not isinstance(volume, str) or not re.fullmatch(r"addon-[a-z0-9-]+:/[a-zA-Z0-9/_-]+(?::ro)?", volume):
                raise ValueError("Only isolated named volumes are allowed")


def decrypt_release(document, encrypted, claims, public_key):
    manifest = verify_manifest(document, public_key)
    if len(encrypted) > MAX_PAYLOAD:
        raise ValueError("Release too large")
    if "sha256:" + hashlib.sha256(encrypted).hexdigest() != manifest["sha256"]:
        raise ValueError("Release checksum mismatch")
    aad = f"ERPForever:{manifest['version']}:{manifest['sequence']}".encode()
    envelope = unb64(manifest["recipients"][recipient_id(claims)])
    key = AESGCM(unb64(claims["secret"])).decrypt(envelope[:12], envelope[12:], aad)
    archive = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], aad)
    return archive


def safe_extract(archive, target):
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > 20000 or sum(m.size for m in members) > MAX_UNPACKED:
            raise ValueError("Archive limits exceeded")
        for m in members:
            path = Path(m.name)
            if path.is_absolute() or ".." in path.parts or m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
                raise ValueError("Unsafe archive member")
            dest = (target / path).resolve()
            if target.resolve() not in dest.parents:
                raise ValueError("Archive escapes destination")
        tar.extractall(target, members=members, filter="data")
