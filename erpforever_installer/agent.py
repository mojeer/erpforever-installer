"""Constrained Unix-socket service with hourly signed-release automatic updates."""
import concurrent.futures
import fcntl
import json
import os
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from erpforever_installer import deployment
from erpforever_installer.releases import fetch_payload, load_release, public_key
from erpforever_installer.security import decrypt_release, safe_extract

ROOT = deployment.ROOT
SOCKET = Path("/run/erpforever/agent.sock")
POOL = concurrent.futures.ThreadPoolExecutor(max_workers=1)
MUTEX = threading.Lock()


class Updater:
    def __init__(self, root=ROOT):
        self.root = root
        self.state_file = root / "update-state.json"
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {"events": []}
        if self.state.get("running"):
            self.state.update(running=False, message="توقفت خدمة التحديث أثناء العملية؛ راجع سجل الخادم قبل المتابعة.",
                              recovery_required=True)
        self.save()

    def save(self):
        deployment.private_write(self.state_file, json.dumps(self.state, ensure_ascii=False, indent=2))

    def event(self, message):
        self.state["events"] = (self.state.get("events", []) + [time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + " · " + message])[-100:]
        self.state["message"] = message
        self.save()

    def status(self):
        cfg = json.loads((self.root / "deployment.json").read_text())
        return {**self.state, "configured": True, "installed": cfg["version"], "automatic": cfg.get("automatic", True),
                "update_available": self.state.get("available_sequence", 0) > cfg["sequence"]}

    def check(self):
        cfg = json.loads((self.root / "deployment.json").read_text())
        document, _, _ = load_release((self.root / "license.token").read_text().strip(), cfg["site"], cfg["sequence"])
        manifest = document["manifest"]
        self.state.update(available=manifest["version"], available_sequence=manifest["sequence"],
                          checked_at=int(time.time()))
        self.save()
        return self.status()

    def command(self, *args):
        with (self.root / "update-diagnostics.log").open("ab") as log:
            subprocess.run(["docker", "compose", "--project-name", "erpforever", "--env-file", ".env", *args],
                           cwd=self.root, check=True, timeout=3600, stdout=log, stderr=log)

    def apply(self):
        # Cross-process lock survives service restarts; the in-process lock avoids duplicate queueing.
        with (self.root / "update.lock").open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.state["running"] = False
                self.save()
                MUTEX.release()
                return
            try:
                self._apply()
            finally:
                MUTEX.release()

    def _apply(self):
        cfg = json.loads((self.root / "deployment.json").read_text())
        if self.state.get("recovery_required"):
            return
        self.state.update(running=True)
        self.save()
        migration_started = False
        maintenance = False
        replaced = False
        previous = self.root / "previous-app"
        try:
            token = (self.root / "license.token").read_text().strip()
            document, claims, url = load_release(token, cfg["site"], cfg["sequence"])
            manifest = document["manifest"]
            if manifest["sequence"] <= cfg["sequence"]:
                self.event("النظام محدّث بالفعل.")
                return
            self.event("جارٍ تنزيل الإصدار والتحقق من التوقيع والتشفير.")
            archive = decrypt_release(document, fetch_payload(url), claims, public_key())
            with tempfile.TemporaryDirectory(prefix="release-", dir=self.root) as stage:
                stage = Path(stage)
                safe_extract(archive, stage / "app")
                agent_source = stage / "app/deployment/erpforever_installer"
                target = self.root / "control/erpforever_installer"
                agent_version = self.root / "agent-version"
                # Upgrade the deployment engine first, then re-verify/re-apply with that engine.
                # This ensures a release can introduce new deployment behavior in the SAME update.
                if target.is_dir() and agent_source.is_dir() and (
                    not agent_version.exists() or agent_version.read_text().strip() != manifest["version"]
                ):
                    if (agent_source / "public-key.hex").read_text().strip() != public_key().hex():
                        raise ValueError("Signing key rotation requires owner intervention")
                    if not target.is_symlink():
                        raise ValueError("Unexpected agent package layout")
                    next_agent = self.root / "control/agents" / manifest["version"] / "erpforever_installer"
                    next_agent.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    shutil.copytree(agent_source, next_agent, dirs_exist_ok=True)
                    next_link = self.root / "control/.agent-next"
                    next_link.unlink(missing_ok=True)
                    next_link.symlink_to(next_agent.relative_to(self.root / "control"), target_is_directory=True)
                    os.replace(next_link, target)
                    deployment.private_write(agent_version, manifest["version"])
                    self.event("تم تحديث خدمة التحديث الموقّعة؛ جارٍ إعادة تشغيلها لإكمال التطبيق.")
                    self.state["running"] = False
                    self.save()
                    os._exit(1)
                self.event("جارٍ تفعيل وضع الصيانة وإنشاء نسخة احتياطية لقاعدة البيانات والملفات.")
                self.command("exec", "-T", "backend", "bench", "--site", cfg["site"], "set-maintenance-mode", "on")
                maintenance = True
                # Stop asynchronous writers before backup. Web requests are now blocked by maintenance mode.
                self.command("stop", "scheduler", "queue-short", "queue-long")
                self.command("exec", "-T", "backend", "bench", "--site", cfg["site"], "backup", "--with-files")
                self.state["backup_completed_at"] = int(time.time())
                self.save()
                shutil.rmtree(previous, ignore_errors=True)
                shutil.copy2(self.root / "compose.yaml", self.root / "previous-compose.yaml")
                shutil.copy2(self.root / "Dockerfile", self.root / "previous-Dockerfile")
                (self.root / "app").rename(previous)
                shutil.move(str(stage / "app"), self.root / "app")
                replaced = True
                self.event("جارٍ بناء التطبيق والخدمات المعتمدة.")
                deployment.config(self.root, cfg["site"], manifest["version"], manifest["erpnext_image"], cfg.get("local_port"),
                                  services=manifest.get("services", {}))
                self.command("build", "backend")
                # Run migrations in a one-off container with the NEW code while all old writers are stopped.
                self.command("stop", "backend", "websocket", "frontend")
                migration_started = True
                self.event("جارٍ تحديث قاعدة البيانات وملفات اللغة والواجهة.")
                self.command("run", "--rm", "--no-deps", "backend", "bench", "--site", cfg["site"], "migrate")
                self.command("run", "--rm", "--no-deps", "backend", "bench", "build", "--app", "erpforever")
                self.command("up", "-d", "--remove-orphans")
                self.event("جارٍ فحص جاهزية النظام.")
                self.healthcheck(cfg["site"])
                self.command("exec", "-T", "backend", "bench", "--site", cfg["site"], "set-maintenance-mode", "off")
                maintenance = False
                cfg.update(version=manifest["version"], sequence=manifest["sequence"], image=manifest["erpnext_image"])
                deployment.private_write(self.root / "deployment.json", json.dumps(cfg, indent=2))
                self.event("اكتمل التحديث بنجاح. النسخة الاحتياطية محفوظة على الخادم.")
            self.state.update(available=manifest["version"], available_sequence=manifest["sequence"])
        except Exception as exc:
            if migration_started:
                # A database migration cannot be safely rolled back by restoring code alone.
                self.state["recovery_required"] = True
                self.event("توقف التحديث أثناء ترحيل البيانات. يبقى وضع الصيانة مفعّلًا لحماية البيانات؛ يلزم تدخل المالك.")
            else:
                if replaced and previous.exists():
                    shutil.rmtree(self.root / "app")
                    previous.rename(self.root / "app")
                    shutil.copy2(self.root / "previous-compose.yaml", self.root / "compose.yaml")
                    shutil.copy2(self.root / "previous-Dockerfile", self.root / "Dockerfile")
                if maintenance:
                    self.command("up", "-d")
                    self.command("exec", "-T", "backend", "bench", "--site", cfg["site"], "set-maintenance-mode", "off")
                self.event("تعذّر التحديث قبل ترحيل البيانات. يستمر العمل بالإصدار السابق.")
            self.state["error_type"] = type(exc).__name__
        finally:
            self.state["running"] = False
            self.save()

    def healthcheck(self, site):
        for _ in range(30):
            try:
                # Execute a read-only DB check through Frappe; HTTP health is checked after maintenance is disabled.
                self.command("exec", "-T", "backend", "bench", "--site", site, "execute", "frappe.db.sql",
                             "--args", '["select 1"]')
                return
            except (subprocess.SubprocessError, OSError):
                time.sleep(2)
        raise RuntimeError("Health check failed")

    def submit(self):
        if self.state.get("recovery_required") or not MUTEX.acquire(blocking=False):
            return self.status()
        self.state["running"] = True
        self.save()
        POOL.submit(self.apply)
        return self.status()


def main():
    os.umask(0o077)
    updater = Updater()
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(15)
            try:
                request = json.loads(self.rfile.readline(4096))
                op = request.get("operation")
                if op == "status":
                    result = updater.status()
                elif op == "check":
                    result = updater.check()
                elif op == "apply":
                    result = updater.submit()
                else:
                    result = {"error": "Unsupported operation"}
            except Exception as exc:
                result = {"error": type(exc).__name__, "message": "تعذّر التحقق من التحديث؛ راجع الاتصال وصلاحية الاشتراك."}
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode() + b"\n")
    def automatic():
        while True:
            try:
                if updater.status()["automatic"] and not updater.status().get("running"):
                    state = updater.check()
                    if state["update_available"]:
                        updater.submit()
            except Exception:
                # Quiet when no actionable state changes; no credential or server responses in the log.
                pass
            time.sleep(3600)
    SOCKET.parent.mkdir(mode=0o750, exist_ok=True)
    SOCKET.unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(str(SOCKET), Handler) as server:
        os.chown(SOCKET, 0, 1000)
        os.chmod(SOCKET, 0o660)
        threading.Thread(target=automatic, daemon=True).start()
        server.serve_forever()


if __name__ == "__main__":
    main()
