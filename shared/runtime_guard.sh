#!/bin/sh
# Runs only in the container namespace. Never changes the host firewall.
set -eu
: "${RUNTIME_ALLOWED_NETWORKS:?missing reviewed destination networks}"
: "${RUNTIME_ALLOWED_PORTS:?missing reviewed destination ports}"

# Fail closed if the required kernel/tool support is absent. Docker DNS resolves
# internal aliases; Compose sets its external forwarding resolver to loopback.
iptables -w 3 -P OUTPUT DROP
iptables -w 3 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 3 -A OUTPUT -o lo -j ACCEPT
iptables -w 3 -A OUTPUT -d 169.254.0.0/16 -j REJECT
for gateway in $(ip -4 route show default | awk '{print $3}'); do
  iptables -w 3 -A OUTPUT -d "$gateway/32" -j REJECT
done
for network in $RUNTIME_ALLOWED_NETWORKS; do
  iptables -w 3 -A OUTPUT -d "$network" -p tcp -m multiport --dports "$RUNTIME_ALLOWED_PORTS" -j ACCEPT
done
ip6tables -w 3 -P OUTPUT DROP
ip6tables -w 3 -A OUTPUT -o lo -j ACCEPT
ip6tables -w 3 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Clearing the bounding, permitted, effective and ambient capabilities prevents a
# compromised workload from changing these rules. Docker exec remains operator-only.
exec setpriv --reuid=65532 --regid=65532 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs "$@"
