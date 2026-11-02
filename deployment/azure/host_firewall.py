#!/usr/bin/python3
"""iptables-nft host boundary, without flushing Docker or host-wide tables."""
import ipaddress
import argparse
import json
from pathlib import Path
import subprocess


def rules(admin_cidr, provisioning=False):
    network = ipaddress.ip_network(admin_cidr, strict=True)
    if network.version != 4 or network.prefixlen < 24:
        raise ValueError('One restricted administrator IPv4 CIDR required')
    entries = [
        ('HONEYPOT-INPUT', ['-i', 'lo', '-j', 'ACCEPT']),
        ('HONEYPOT-INPUT', ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']),
        ('HONEYPOT-INPUT', ['-s', '172.28.0.0/16', '-j', 'DROP']),
        ('HONEYPOT-INPUT', ['-p','udp','-s','168.63.129.16/32','--sport','67','--dport','68','-j','ACCEPT']),
        ('HONEYPOT-INPUT', ['-p', 'tcp', '-s', str(network), '--dport', '22', '-j', 'ACCEPT']),
        ('HONEYPOT-INPUT', ['-j', 'DROP']),
        ('HONEYPOT-FORWARD', ['-s', '172.28.0.0/16', '-d', '169.254.0.0/16', '-j', 'DROP']),
        ('HONEYPOT-FORWARD', ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'RETURN']),
        ('HONEYPOT-FORWARD', ['-s', '172.28.0.0/16', '-d', '172.28.0.0/16', '-j', 'RETURN']),
        ('HONEYPOT-FORWARD', ['-s', '172.28.0.0/16', '-j', 'DROP']),
        # Private phase: all unsolicited host-to-container routed ingress denied.
        # Same-bridge flows returned above; established operator replies work.
        ('HONEYPOT-FORWARD', ['-j', 'DROP']),
    ]
    if provisioning:
        entries.insert(-1,('HONEYPOT-FORWARD',['-i','docker0','-j','RETURN']))
    return entries


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--provisioning',action='store_true')
    args=parser.parse_args()
    config = json.loads(Path('/etc/honeypot-infrastructure.json').read_text())
    entries = rules(config['admin_source_cidr'],args.provisioning)
    if config['enable_public_honeypot']:
        raise ValueError('Private host firewall refuses public mode; separate reviewed host release required')
    for chain in ('HONEYPOT-INPUT', 'HONEYPOT-FORWARD', 'DOCKER-USER'):
        subprocess.run(['iptables', '-w', '5', '-N', chain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Update only our own chains. Install while app is stopped; not an atomic
    # online firewall-upgrade mechanism. Existing SSH return traffic is preserved.
    for chain in ('HONEYPOT-INPUT', 'HONEYPOT-FORWARD'):
        subprocess.run(['iptables', '-w', '5', '-F', chain], check=True)
    for chain, rule in entries:
        subprocess.run(['iptables', '-w', '5', '-A', chain, *rule], check=True)
    for parent, target in (('INPUT', 'HONEYPOT-INPUT'), ('DOCKER-USER', 'HONEYPOT-FORWARD'), ('FORWARD', 'DOCKER-USER')):
        if subprocess.run(['iptables', '-w', '5', '-C', parent, '-j', target], capture_output=True).returncode:
            subprocess.run(['iptables', '-w', '5', '-I', parent, '1', '-j', target], check=True)
    subprocess.run(['ip6tables', '-w', '5', '-P', 'INPUT', 'DROP'], check=True)
    subprocess.run(['ip6tables', '-w', '5', '-P', 'FORWARD', 'DROP'], check=True)
    for rule in (['-i', 'lo', '-j', 'ACCEPT'], ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']):
        if subprocess.run(['ip6tables', '-w', '5', '-C', 'INPUT', *rule], capture_output=True).returncode:
            subprocess.run(['ip6tables', '-w', '5', '-I', 'INPUT', '1', *rule], check=True)
    print('Private host ingress/DOCKER-USER boundaries installed; host provisioning OUTPUT unchanged')


if __name__ == '__main__':
    main()
