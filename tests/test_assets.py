"""Regression for an image that serves HTML but has lost its bundle manifest."""
import json
import subprocess
import sys

import pytest

from erpforever_installer.deployment import ASSET_CHECK


@pytest.mark.parametrize("damage", [None, "empty_manifest", "missing_file", "missing_rtl"])
def test_browser_readiness_requires_manifests_and_files(tmp_path, damage):
    assets = tmp_path / "sites/assets"
    assets.mkdir(parents=True)
    core = {name: "/assets/" + name for name in [
        "website.bundle.css", "login.bundle.css", "frappe-web.bundle.js", "desk.bundle.js"
    ]}
    rtl = {"rtl_desk.bundle.css": "/assets/rtl_desk.bundle.css"}
    for url in [*core.values(), *rtl.values()]:
        (tmp_path / ("sites" + url)).write_text("test bundle")
    if damage == "empty_manifest":
        core = {}
    if damage == "missing_rtl":
        rtl = {}
    if damage == "missing_file":
        (assets / "frappe-web.bundle.js").unlink()
    (assets / "assets.json").write_text(json.dumps(core))
    (assets / "assets-rtl.json").write_text(json.dumps(rtl))
    result = subprocess.run([sys.executable, "-c", ASSET_CHECK], cwd=tmp_path, capture_output=True)
    assert (result.returncode == 0) == (damage is None)
