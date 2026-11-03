"""Single-tenant Docker deployment. Only signed image references enter generated configuration."""
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

ROOT = Path("/opt/erpforever")
MARIADB_IMAGE = "mariadb@sha256:c4124d1afa875e47f2892edf26b482fa54f796e2f342d3717a04ca091a22a9bd"
REDIS_IMAGE = "redis@sha256:8da19c7399dca900c6822a1cf30f9d2285585e2c4b457ff4095b0f4500054d3f"
CADDY_IMAGE = "caddy@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5"
# A successful SQL query does not establish that the browser can load Frappe.
# Run this in the bench directory both at image build and before ending maintenance.
ASSET_CHECK = (
    "import json; from pathlib import Path; p=Path('sites/assets'); "
    "d=json.loads((p/'assets.json').read_text()); d.update(json.loads((p/'assets-rtl.json').read_text())); "
    "keys=['website.bundle.css','login.bundle.css','frappe-web.bundle.js','desk.bundle.js','rtl_desk.bundle.css']; "
    "assert all(d.get(k,'').startswith('/assets/') and Path('sites'+d[k]).is_file() for k in keys), "
    "'Missing core browser bundles'"
)


def private_write(path, value):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing a symlink target")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=f".{path.name}.", delete=False) as file:
            temporary = Path(file.name)
            os.chmod(temporary, 0o600)
            file.write(value)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def run(args, root=ROOT, timeout=1800):
    # Never include tokens or passwords in command arguments or exception output.
    subprocess.run(args, cwd=root, check=True, timeout=timeout)


def compose(*args, root=ROOT):
    return run(["docker", "compose", "--project-name", "erpforever", "--env-file", ".env", *args], root)


def config(root, site, version, image, local_port=None, services=None):
    from erpforever_installer.security import validate_services
    addons = services or {}
    validate_services(addons)
    (root / ".dockerignore").write_text("*\n!Dockerfile\n!app/\n!app/**\napp/.git\napp/preview\napp/**/__pycache__\n")
    # image and version have already been verified with the owner's Ed25519 signature.
    (root / "Dockerfile").write_text(f'''FROM {image}
USER root
COPY --chown=1000:0 app /home/frappe/frappe-bench/apps/erpforever
USER frappe
WORKDIR /home/frappe/frappe-bench
RUN ./env/bin/pip install --no-deps -e apps/erpforever && printf '\\nerpforever\\n' >> sites/apps.txt && if [ ! -L sites/assets ]; then rm -rf sites/assets; ln -s ../assets sites/assets; fi && bench build --app erpforever && ./env/bin/python -c "{ASSET_CHECK}"
''')
    # JSON is valid YAML; generation through json.dumps prevents YAML injection.
    volumes = ["sites:/home/frappe/frappe-bench/sites", "logs:/home/frappe/frappe-bench/logs"]
    base = {"image": f"erpforever-local:{version}", "build": {"context": "."},
            "restart": "unless-stopped", "volumes": volumes,
            "depends_on": {"db": {"condition": "service_healthy"},
                           "redis-cache": {"condition": "service_started"},
                           "redis-queue": {"condition": "service_started"}}}
    def service(command=None, extra=None):
        result = dict(base)
        if command:
            result["command"] = command
        result.update(extra or {})
        return result
    services = {
        "db": {"image": MARIADB_IMAGE, "restart": "unless-stopped",
               "command": ["--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci"],
               "environment": {"MARIADB_ROOT_PASSWORD": "${DB_PASSWORD}"},
               "volumes": ["db:/var/lib/mysql"], "healthcheck": {
                   "test": ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"],
                   "interval": "10s", "timeout": "5s", "retries": 30}},
        "redis-cache": {"image": REDIS_IMAGE, "restart": "unless-stopped"},
        "redis-queue": {"image": REDIS_IMAGE, "restart": "unless-stopped",
                        "volumes": ["queue:/data"], "command": ["redis-server", "--appendonly", "yes"]},
        "backend": service(extra={"volumes": volumes + ["/run/erpforever:/run/erpforever"], "group_add": ["1000"]}),
        "websocket": service(["node", "/home/frappe/frappe-bench/apps/frappe/socketio.js"]),
        "queue-short": service(["bench", "worker", "--queue", "short,default"]),
        "queue-long": service(["bench", "worker", "--queue", "long,default,short"]),
        "scheduler": service(["bench", "schedule"]),
        "frontend": service(["nginx-entrypoint.sh"], {"environment": {
            "BACKEND": "backend:8000", "SOCKETIO": "websocket:9000", "FRAPPE_SITE_NAME_HEADER": site,
            "UPSTREAM_REAL_IP_ADDRESS": "127.0.0.1", "UPSTREAM_REAL_IP_HEADER": "X-Forwarded-For",
            "UPSTREAM_REAL_IP_RECURSIVE": "off", "PROXY_READ_TIMEOUT": "120", "CLIENT_MAX_BODY_SIZE": "50m"}}),
    }
    if local_port:
        services["frontend"]["ports"] = [f"127.0.0.1:{int(local_port)}:8080"]
    else:
        services["proxy"] = {"image": CADDY_IMAGE, "restart": "unless-stopped",
                             "ports": ["80:80", "443:443", "443:443/udp"],
                             "volumes": ["./Caddyfile:/etc/caddy/Caddyfile:ro", "caddy-data:/data", "caddy-config:/config"],
                             "depends_on": ["frontend"]}
        (root / "Caddyfile").write_text(f"{site} {{\n encode zstd gzip\n reverse_proxy frontend:8080\n}}\n")
    extra_volumes = set()
    for name, spec in addons.items():
        services[name] = {**spec, "restart": "unless-stopped", "security_opt": ["no-new-privileges:true"]}
        extra_volumes.update(v.split(':', 1)[0] for v in spec.get("volumes", []))
    (root / "compose.yaml").write_text(json.dumps({"services": services,
        "volumes": {name: {} for name in ["sites", "logs", "db", "queue", "caddy-data", "caddy-config", *sorted(extra_volumes)]}}, indent=2))


def provision(root, site, manifest, admin_password, local_port=None):
    private_write(root / ".env", "DB_PASSWORD=" + secrets.token_urlsafe(36) + "\n")
    private_write(root / "admin-password", admin_password + "\n")
    (root / "new-site.py").write_text('''import os
from pathlib import Path
import frappe
from frappe.installer import _new_site
os.chdir('/home/frappe/frappe-bench/sites')
frappe.init(os.environ['EF_SITE'], new_site=True)
_new_site(db_name=None, site=os.environ['EF_SITE'], db_root_username='root',
          db_root_password=Path('/run/secrets/db-password').read_text().strip(),
          admin_password=Path('/run/secrets/admin-password').read_text().strip(),
          db_host='db', mariadb_user_host_login_scope='%',
          install_apps=['erpnext','erpforever'])
frappe.init(os.environ['EF_SITE'])
frappe.connect()
frappe.db.set_value('User', 'Administrator', 'language', 'ar')
frappe.db.commit()
frappe.conf.host_name='https://' + os.environ['EF_SITE']
from frappe.installer import update_site_config
update_site_config('host_name', frappe.conf.host_name)
update_site_config('erpforever_managed_updates', True)
frappe.destroy()
''')
    # Secret files are mounted for the provisioning container only, never into the web services.
    (root / "provision.py").write_text('''import json, pathlib
p=pathlib.Path('/home/frappe/frappe-bench/sites/common_site_config.json')
d=json.loads(p.read_text()) if p.exists() else {}
d.update(db_host='db',db_port=3306,redis_cache='redis://redis-cache:6379',redis_queue='redis://redis-queue:6379',redis_socketio='redis://redis-queue:6379',socketio_port=9000)
p.write_text(json.dumps(d))
pathlib.Path('/home/frappe/frappe-bench/sites/apps.txt').write_text('frappe\\nerpnext\\nerpforever\\n')
''')
    config(root, site, manifest["version"], manifest["erpnext_image"], local_port, services=manifest.get("services", {}))
    compose("build", "backend", root=root)
    compose("up", "-d", "--wait", "db", "redis-cache", "redis-queue", root=root)
    compose("run", "--rm", "--no-deps", "-v", f"{root}/provision.py:/tmp/configure.py:ro",
            "backend", "./env/bin/python", "/tmp/configure.py", root=root)
    db_password = dict(line.split("=", 1) for line in (root / ".env").read_text().splitlines())["DB_PASSWORD"]
    private_write(root / "db-password", db_password)
    # frappe's UID is 1000; this one-off container runs as that UID, so give only its group temporary read access.
    for name in ("db-password", "admin-password"):
        os.chown(root / name, 0, 1000)
        os.chmod(root / name, 0o640)
    try:
        compose("run", "--rm", "--no-deps", "-e", f"EF_SITE={site}",
                "-v", f"{root}/new-site.py:/tmp/new-site.py:ro",
                "-v", f"{root}/db-password:/run/secrets/db-password:ro",
                "-v", f"{root}/admin-password:/run/secrets/admin-password:ro",
                "backend", "./env/bin/python", "/tmp/new-site.py", root=root)
    finally:
        (root / "db-password").unlink(missing_ok=True)
        os.chmod(root / "admin-password", 0o600)
    compose("run", "--rm", "--no-deps", "backend", "bench", "--site", site, "enable-scheduler", root=root)
    compose("up", "-d", root=root)
    private_write(root / "deployment.json", json.dumps({"site": site, "version": manifest["version"],
                                                       "sequence": manifest["sequence"], "local_port": local_port,
                                                       "image": manifest["erpnext_image"], "automatic": True}, indent=2))
