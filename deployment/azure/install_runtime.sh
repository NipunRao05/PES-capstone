#!/bin/bash
# Run only after independently checking archive checksum and extracting to /opt/honeypot.
set -euo pipefail
umask 077
cd /opt/honeypot
test "$(id -u)" = 0
mountpoint -q /opt/honeypot-data
test -f /opt/honeypot-data/secrets.env
test -f release/source-manifest.json
test ! -e .runtime || test -L .runtime
if test -L .runtime; then
  test "$(readlink -f .runtime)" = /opt/honeypot-data/runtime
else
  ln -s /opt/honeypot-data/runtime .runtime
fi
python3 - <<'PY'
import json,os,re
from pathlib import Path
c=json.loads(Path('/etc/honeypot-infrastructure.json').read_text())
env={'HONEYPOT_DEPLOYMENT_ID':c['deployment_id'],'HONEYPOT_RUN_ID':c['run_id'],
 'HONEYPOT_EXPERIMENT_ID':c['experiment_id'],'HONEYPOT_EXPERIMENT_VERSION':str(c['experiment_version']),
 'HONEYPOT_DATA_VOLUME_ID':c['data_volume_id']}
if any(not re.fullmatch(r'[A-Za-z0-9_./():-]+',value) for value in env.values()):raise ValueError('Invalid nonsecret deployment identity')
content=''.join(k+"='"+v+"'\n" for k,v in env.items())
path=Path('/etc/honeypot-runtime.env')
if path.exists() and path.read_text()!=content:
 raise ValueError('Existing runtime identity differs; explicit migration required')
path.write_text(content);os.chmod(path,0o600)
PY
set -a
. /etc/honeypot-runtime.env
set +a
export HONEYPOT_DEPLOYMENT_MODE=true HONEYPOT_SECRET_FILE=/opt/honeypot-data/secrets.env HONEYPOT_DOCKER_LOG_ROOT=/opt/honeypot-data/docker/containers
install -m 0644 deployment/docker-data-guard.conf /etc/systemd/system/docker.service.d/honeypot-data-guard.conf
install -m 0644 deployment/honeypot.service /etc/systemd/system/honeypot.service
install -d -m 0755 /etc/systemd/system/honeypot.service.d
printf '[Service]\nEnvironmentFile=/etc/honeypot-runtime.env\n' > /etc/systemd/system/honeypot.service.d/azure.conf
if test ! -f /opt/honeypot-data/.honeypot-data-volume.json; then
  python3 -B scripts/deployment_guard.py --initialize-marker
fi
python3 -B scripts/deployment_guard.py --offline
systemctl daemon-reload
systemctl unmask docker.service docker.socket containerd.service
systemctl enable docker.service
systemctl start docker.service
python3 -B scripts/deployment_guard.py
echo 'Docker ready. Build/pull reviewed images, then explicitly enable/start honeypot.service; no stack started here.'
