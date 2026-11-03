import json
import urllib.request
from pathlib import Path

from erpforever_installer.security import MAX_PAYLOAD, verify_license, verify_manifest

REPOSITORY = "mojeer/erpforever-installer"
RELEASE_ROOT = f"https://github.com/{REPOSITORY}/releases/latest/download/"


def fetch(url, limit):
    request = urllib.request.Request(url, headers={"User-Agent": "ERPForever-Installer/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("HTTPS required")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Download exceeds size limit")
    return data


def public_key():
    return bytes.fromhex(Path(__file__).with_name("public-key.hex").read_text().strip())


def load_release(token, site, minimum_sequence=0):
    key = public_key()
    claims = verify_license(token, key, site)
    document = json.loads(fetch(RELEASE_ROOT + "manifest.json", 8 * 1024 * 1024))
    manifest = verify_manifest(document, key)
    if manifest["sequence"] < minimum_sequence:
        raise ValueError("Release downgrade rejected")
    # The immutable version URL avoids a latest-alias race between the two downloads.
    url = f"https://github.com/{REPOSITORY}/releases/download/v{manifest['version']}/erpforever.enc"
    return document, claims, url


def fetch_payload(url):
    return fetch(url, MAX_PAYLOAD)
