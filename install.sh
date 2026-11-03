#!/usr/bin/env bash
set -euo pipefail
# Public bootstrap. Never pass an entitlement in shell arguments, history or environment.
if [[ "${EUID}" -ne 0 ]]; then
  echo 'Run this installer as root on a dedicated Ubuntu 24.04 server.' >&2
  exit 1
fi
if [[ ! -r /etc/os-release ]]; then echo 'Ubuntu 24.04 required.' >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then echo 'Ubuntu 24.04 required.' >&2; exit 1; fi
if [[ -e /opt/erpforever/deployment.json ]]; then echo 'Already installed. Use the ERPForever update screen.' >&2; exit 1; fi
apt-get update -qq
apt-get install -y -qq python3-venv ca-certificates curl git
umask 077
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://api.github.com/repos/mojeer/erpforever-installer/tarball/main -o "$stage/installer.tar.gz"
mkdir "$stage/source"
tar -xzf "$stage/installer.tar.gz" -C "$stage/source" --strip-components=1
python3 -m venv "$stage/venv"
"$stage/venv/bin/pip" --quiet install -r "$stage/source/requirements.txt"
cd "$stage/source"
"$stage/venv/bin/python" -m erpforever_installer.install "$@" </dev/tty
