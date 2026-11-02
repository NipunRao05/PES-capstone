#!/bin/bash
# Provisioning only. No application secret, archive fetch or stack start.
set -euo pipefail
umask 077
systemctl mask docker.service docker.socket containerd.service
python3 /usr/local/sbin/honeypot-prepare-disk
install -d -m 0700 /opt/honeypot-data/runtime /opt/honeypot-data/backups /opt/honeypot-data/exports
install -d -m 0755 /opt/honeypot /etc/docker /etc/systemd/system/docker.service.d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable' > /etc/apt/sources.list.d/docker.list
apt-get update
# Select/update only at reviewed provisioning time; record dpkg versions before gate.
DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
cat > /etc/docker/daemon.json <<'EOF'
{"data-root":"/opt/honeypot-data/docker","log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"firewall-backend":"iptables","iptables":true,"ip6tables":true}
EOF
# New Docker releases may keep image content in containerd, outside DockerRootDir.
# Place that store on the same disk too; never accept an OS-disk image-store fallback.
install -d -m 0755 /etc/containerd /etc/systemd/system/containerd.service.d
cat > /etc/containerd/config.toml <<'EOF'
version = 2
root = "/opt/honeypot-data/containerd"
state = "/run/containerd"
EOF
cat > /etc/ssh/sshd_config.d/00-honeypot.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
AllowAgentForwarding no
EOF
sshd -t
systemctl reload ssh
cat > /etc/systemd/system/honeypot-firewall.service <<'EOF'
[Unit]
Description=Private honeypot host boundary
After=network-pre.target
Before=docker.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/honeypot-host-firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/docker.service.d/azure-preflight.conf <<'EOF'
[Unit]
Requires=honeypot-firewall.service
After=honeypot-firewall.service
[Service]
Environment=HONEYPOT_DEPLOYMENT_MODE=true
Environment=HONEYPOT_SECRET_FILE=/opt/honeypot-data/secrets.env
Environment=HONEYPOT_DOCKER_LOG_ROOT=/opt/honeypot-data/docker/containers
EnvironmentFile=/etc/honeypot-runtime.env
ExecStartPre=/usr/bin/python3 /opt/honeypot/scripts/deployment_guard.py --offline
EOF
cat > /etc/systemd/system/containerd.service.d/honeypot-data-guard.conf <<'EOF'
[Unit]
RequiresMountsFor=/opt/honeypot-data
ConditionPathIsMountPoint=/opt/honeypot-data
[Service]
Environment=HONEYPOT_DEPLOYMENT_MODE=true
Environment=HONEYPOT_SECRET_FILE=/opt/honeypot-data/secrets.env
EnvironmentFile=/etc/honeypot-runtime.env
ExecStartPre=/usr/bin/python3 /opt/honeypot/scripts/deployment_guard.py --offline
EOF
systemctl daemon-reload
systemctl enable honeypot-firewall.service
systemctl start honeypot-firewall.service
echo 'Bootstrap prepared. Docker remains MASKED until archive, secrets and marker are installed.'
