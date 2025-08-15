#!/usr/bin/env bash
set -euo pipefail

BUCKET="${1:?usage: deploy.sh <bucket> <key>}"
KEY="${2:?usage: deploy.sh <bucket> <key>}"

APP_DIR="/opt/app"
RELEASES_DIR="${APP_DIR}/releases"
CURRENT_LINK="${APP_DIR}/current"
SYSTEMD_UNIT="app.service"
HEALTH_URL="http://127.0.0.1:8000/health"

log() { echo "[deploy] $(date -u +'%Y-%m-%dT%H:%M:%SZ') $*"; }

mkdir -p "$RELEASES_DIR"
TMPDIR="$(mktemp -d "${RELEASES_DIR}/new.XXXX")"

log "download s3://${BUCKET}/${KEY}"
aws s3 cp "s3://${BUCKET}/${KEY}" "${TMPDIR}/app.zip"

log "unpack artifact"
unzip -q "${TMPDIR}/app.zip" -d "${TMPDIR}"

# Optional: install Python deps if present
if [[ -f "${TMPDIR}/requirements.txt" ]]; then
  python3 -m pip install --upgrade pip
  python3 -m pip install -r "${TMPDIR}/requirements.txt"
fi

# Ensure systemd unit exists (create once if missing)
if ! systemctl cat "${SYSTEMD_UNIT}" >/dev/null 2>&1; then
  log "creating ${SYSTEMD_UNIT}"
  cat >/etc/systemd/system/${SYSTEMD_UNIT} <<'UNIT'
[Unit]
Description=Gunicorn Flask App
After=network.target

[Service]
User=root
WorkingDirectory=/opt/app/current
ExecStart=/usr/bin/python3 /usr/local/bin/gunicorn -b 0.0.0.0:8000 app:app --access-logfile /var/log/gunicorn/app.log
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "${SYSTEMD_UNIT}"
fi

# Atomic switch: symlink "current" to the new release
log "switch release symlink"
ln -sfn "${TMPDIR}" "${CURRENT_LINK}"

# (Re)start service
log "restart ${SYSTEMD_UNIT}"
systemctl restart "${SYSTEMD_UNIT}"

# Health check with small retry loop
for i in {1..10}; do
  if curl -fsS "${HEALTH_URL}" >/dev/null; then
    log "health check passed"
    exit 0
  fi
  log "health check not ready (attempt ${i})"
  sleep 2
done

log "ERROR: health check failed, see journalctl -u ${SYSTEMD_UNIT}"
journalctl -u "${SYSTEMD_UNIT}" -n 100 --no-pager || true
exit 1
