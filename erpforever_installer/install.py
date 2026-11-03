import argparse
import getpass
import os
import shutil
import subprocess
from pathlib import Path

from erpforever_installer import deployment
from erpforever_installer.releases import fetch_payload, load_release, public_key
from erpforever_installer.security import decrypt_release, normalize_site, safe_extract


def main():
    parser = argparse.ArgumentParser(description="ERPForever managed installer (dedicated Ubuntu 24.04 host)")
    parser.add_argument("--site")
    parser.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run as root on a dedicated server")
    root = deployment.ROOT
    if root.exists():
        raise SystemExit("/opt/erpforever already exists; refusing to overwrite an installation")
    site = normalize_site(args.site or input("Site hostname (e.g. erp.example.com): "))
    token = args.token_file.read_text().strip() if args.token_file else getpass.getpass("ERPForever token (hidden): ")
    document, claims, url = load_release(token, site)
    archive = decrypt_release(document, fetch_payload(url), claims, public_key())
    print("Entitlement and release signature verified.")
    password = getpass.getpass("Choose the Administrator password (minimum 14 characters): ")
    if len(password) < 14 or password != getpass.getpass("Confirm Administrator password: "):
        raise SystemExit("Password must match and have at least 14 characters")
    if not shutil.which("docker"):
        # Official Docker apt repository, not an unaudited curl-to-shell installation.
        deployment.run(["apt-get", "install", "-y", "ca-certificates", "curl"], root=Path("/"))
        Path("/etc/apt/keyrings").mkdir(mode=0o755, exist_ok=True)
        deployment.run(["curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc"], root=Path("/"))
        os.chmod("/etc/apt/keyrings/docker.asc", 0o644)
        arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        Path("/etc/apt/sources.list.d/docker.sources").write_text(f"Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: noble\nComponents: stable\nArchitectures: {arch}\nSigned-By: /etc/apt/keyrings/docker.asc\n")
        deployment.run(["apt-get", "update", "-qq"], root=Path("/"))
        deployment.run(["apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"], root=Path("/"))
    root.mkdir(mode=0o755)
    os.umask(0o077)
    safe_extract(archive, root / "app")
    deployment.private_write(root / "license.token", token + "\n")
    control = root / "control"
    control.mkdir(mode=0o700)
    signed_agent = root / "app/deployment/erpforever_installer"
    if not signed_agent.is_dir() or (signed_agent / "public-key.hex").read_text().strip() != public_key().hex():
        raise ValueError("Signed update agent missing or signing identity changed")
    agent_location = control / "agents" / document["manifest"]["version"] / "erpforever_installer"
    agent_location.parent.mkdir(parents=True, mode=0o700)
    shutil.copytree(signed_agent, agent_location)
    (control / "erpforever_installer").symlink_to(agent_location.relative_to(control), target_is_directory=True)
    deployment.private_write(root / "agent-version", document["manifest"]["version"])
    deployment.run(["python3", "-m", "venv", str(control / "venv")], root=root)
    deployment.run([str(control / "venv/bin/pip"), "install", "cryptography>=44,<51"], root=root)
    (control / "docker").mkdir(mode=0o700)
    deployment.private_write(control / "docker/config.json", '{"auths":{}}\n')
    print("Building and provisioning ERPForever. This can take several minutes.")
    deployment.provision(root, site, document["manifest"], password)
    Path("/run/erpforever").mkdir(mode=0o750, exist_ok=True)
    os.chown("/run/erpforever", 0, 1000)
    service = f"""[Unit]
Description=ERPForever signed update service
After=docker.service network-online.target
Requires=docker.service
[Service]
WorkingDirectory={control}
ExecStart={control}/venv/bin/python -m erpforever_installer.agent
Restart=on-failure
UMask=0077
RuntimeDirectory=erpforever
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
Group=1000
Environment=DOCKER_CONFIG={control}/docker
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/erpforever /run/erpforever
[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/erpforever-update.service").write_text(service)
    deployment.run(["systemctl", "daemon-reload"], root=root)
    deployment.run(["systemctl", "enable", "--now", "erpforever-update.service"], root=root)
    print(f"Installed. Point the hostname at this server; HTTPS is issued automatically. Open https://{site}")
    print("Login: Administrator. The password is saved in /opt/erpforever/admin-password (root-only).")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Download/decryption errors may carry attacker-controlled text; only safe type metadata is printed.
        raise SystemExit(f"Installation stopped ({type(exc).__name__}). No token was printed. Inspect server state before retrying.") from None
