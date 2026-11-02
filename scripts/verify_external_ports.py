"""Operator-invoked TCP checks from independent admin/non-admin vantage points."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import socket

MANAGEMENT = [3000,8000,8001,8003,8011,8012,9090,9091,9092,9095,9096,9100,9644,3100,6379,15432,13306]


def verify(host, vantage, public=False, connect=socket.create_connection):
    ipaddress.IPv4Address(host)
    expected = {22:vantage=='admin',5432:public,3306:public,**{p:False for p in MANAGEMENT}}
    results=[]
    for port,wanted in expected.items():
        try:
            with connect((host,port),timeout=2):reachable=True
        except OSError:reachable=False
        results.append({'port':port,'expected_reachable':wanted,'reachable':reachable,'passed':reachable==wanted})
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-ip',required=True)
    parser.add_argument('--deployment-id',required=True)
    parser.add_argument('--vantage',choices=['admin','other'],required=True)
    parser.add_argument('--expect-public',action='store_true',help='Observe future authorized mode; never enables ingress')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    rows=verify(args.public_ip,args.vantage,args.expect_public)
    report={'schema_version':1,'deployment_id':args.deployment_id,'checked_at':datetime.now(timezone.utc).isoformat(),
        'public_ip':args.public_ip,'vantage':args.vantage,'expected_public':args.expect_public,
        'status':'PASS' if all(r['passed'] for r in rows) else 'FAIL','checks':rows,
        'scope':'Fixed TCP probes only; unreachable does not independently prove an NSG rule or administrator source identity'}
    with args.output.open('x',encoding='utf-8') as out:json.dump(report,out,indent=2)
    print(json.dumps(report));return int(report['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
