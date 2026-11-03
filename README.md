# ERPForever installer

Public bootstrap and managed update service for **ERPForever on ERPNext 16**. Product releases are encrypted; installation and official updates require an owner-issued, site-bound token. No private signing keys, product source or installation tokens belong in this repository.

## One-line install

Run on a **new dedicated Ubuntu 24.04 server**. Point the intended hostname at the server first; allow ports 80 and 443 for automatic HTTPS.

```bash
sudo bash -c 'bash <(curl --proto "=https" --tlsv1.2 -fsSL https://raw.githubusercontent.com/mojeer/erpforever-installer/main/install.sh)'
```

The installer asks for:

1. The site hostname.
2. Your ERPForever token in a hidden prompt.
3. A new Administrator password.

It verifies the token's Ed25519 signature, hostname and expiry; verifies the release signature and checksum; unwraps the customer-specific AES-GCM key; decrypts the release; then installs Docker if needed and provisions the stack. Tokens are never passed as command arguments or stored in Git. They remain root-only on the server. Do not paste tokens into GitHub, chat, URLs or screenshots.

For inspecting the bootstrap before running it, download `install.sh`, review it, and execute the local file. The one-line command trusts this owner's GitHub bootstrap; signed product payloads add a second verification layer after bootstrap.

### التثبيت

شغّل الأمر على خادم Ubuntu 24.04 جديد ومخصص للنظام. أدخل اسم النطاق ورمز التثبيت الذي يصدره المالك، ثم اختر كلمة مرور المدير. يتولى المُثبّت إعداد الخدمات واللغة العربية وخط Almarai وهوية ERPForever وشهادة HTTPS. لا تضع رمز التثبيت داخل الأمر أو الرابط.

## Automatic updates

The host service checks stable GitHub releases **hourly**. A newer owner-signed release is automatically downloaded, verified and applied. Application, translations, theme, pinned ERPNext/Frappe runtime, the update agent itself, and optional signed services can evolve through releases.

Before applying a release it blocks requests with maintenance mode, stops workers/scheduler, and backs up the database and public/private files. It then builds the new image, migrates, compiles translations, starts services, checks the database and required browser bundles, and exits maintenance. Image builds preserve the official runtime's hashed asset indexes and reject missing login/Desk/RTL bundles. History is visible in **ERPForever → التحديثات** to System Managers. A migration failure leaves maintenance enabled for owner recovery. Recovery does not silently overwrite business data. The previous source tree and database/file backups are retained on the server.

Automatic update access expires with the official-download entitlement; the already installed ERP continues operating. Revocation affects future packages, not copies already obtained. Backups stay in the site's private backup directory inside the persistent `sites` volume. They are on the same server: arrange encrypted offsite copies through your normal backup provider.

## Supported deployment

- ERPNext **16.53.0** + Frappe **16.55.0** in the initial pinned official image. Future versions are explicitly pinned in signed releases.
- Fresh, single-tenant Docker deployment with MariaDB 11.8, Redis, workers, scheduler, websocket, reverse proxy, and HTTPS.
- No in-place conversion of an existing arbitrary bench or Frappe Cloud installation is performed.
- Native Frappe permissions apply to all desktop data and forms.
- Full Arabic catalog review is being completed in Codex batches; inherited upstream translations are not presented as already reviewed.

Extra services use `addon-*` names, digest-pinned container images and isolated named volumes. Host mounts, privileged containers, host networking and externally published addon ports are rejected. This is a container-service extension mechanism; arbitrary extra Frappe applications may also require explicit app packaging and schema migrations.

## Owner-only maintenance

Only the owner has write/merge access. Outside pull requests are closed automatically; contributors are not invited. A public repository can still be viewed, forked or cloned. Official product distribution is controlled by encrypted releases and signing keys, not by hiding this public installer.

The ERPNext-derived product is GPLv3 compatible. Paid installation, hosting, support and official updates are supported; token-gated distribution does not remove recipients' rights to corresponding source, modification and redistribution. The decrypted release includes product source and notices. Frappe is MIT; Almarai is SIL OFL. ERPForever is independently maintained and is not affiliated with Frappe.

## Test

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest ruff
.venv/bin/python -m pytest tests
.venv/bin/ruff check erpforever_installer
bash -n install.sh
```

See [SECURITY.md](SECURITY.md) for the trust model and operational boundaries.
