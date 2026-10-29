#!/usr/bin/env python3
"""Check password revocation against warmed sockets in disposable fixtures."""
import argparse
import os
import time
from pathlib import Path
from run import Suite, redis_command
from pool_benchmark import POOL

parser=argparse.ArgumentParser()
parser.add_argument("--output",required=True)
parser.add_argument("--artifact",default="local/crowdsec-plugin:ops-160-v7")
args=parser.parse_args()
os.environ.pop("CROWDSEC_TEST_POOL",None)
passed=True
for pooled in (False, True):
    s=Suite(str(Path(args.output)/("pooled" if pooled else "unpooled")))
    s.artifact=args.artifact
    s.overrides=POOL if pooled else {}
    try:
        s.setup()
        s.start()
        s.check("warm-allow", all(s.request()[0]==200 for _ in range(10)))
        redis_command(s.redis_port,"ACL","SETUSER","crowdsec","resetpass",">replacement-fixture-password")
        responses=[s.request()[0] for _ in range(10)]
        s.check("revoked-password-stops-existing-configuration",all(status==403 for status in responses),statuses=responses,pooled=pooled)
        # Restore only synthetic fixture credentials for orderly cleanup.
        redis_command(s.redis_port,"ACL","SETUSER","crowdsec","resetpass",">fixture password%value")
        s.check("restored-identity-before-select-revocation",all(s.request()[0]==200 for _ in range(10)))
        redis_command(s.redis_port,"ACL","SETUSER","crowdsec","-select")
        responses=[s.request()[0] for _ in range(10)]
        s.check("revoked-select-stops-existing-configuration",all(status==403 for status in responses),statuses=responses,pooled=pooled)
        redis_command(s.redis_port,"ACL","SETUSER","crowdsec","+select")
        if pooled:
            s.check("restored-identity-warmed",all(s.request()[0]==200 for _ in range(10)))
            def ids():
                rows=redis_command(s.redis_port,"CLIENT","LIST").splitlines()
                return {line.split()[0] for line in rows if "user=crowdsec " in line}
            old=ids()
            s.check("old-sockets-observed-before-database-change",bool(old))
            redis_command(s.redis_port,"SET","crowdsec:192.0.2.1","t",database=12)
            redis_command(s.redis_port,"SET","crowdsec:192.0.2.5","f",database=12)
            s.overrides.update(redisCacheDatabase="12")
            s.config(token=700)
            deadline=time.monotonic()+5
            correct=False
            while time.monotonic()<deadline:
                correct=s.request()[0]==403 and s.request("192.0.2.5")[0]==200 and not (old & ids())
                if correct:break
                time.sleep(0.05)
            s.check("database-change-retires-old-sockets",correct)
            redis_command(s.redis_port,"ACL","SETUSER","crowdsec","resetpass",">rotated-fixture-password")
            old=ids()
            s.overrides.update(redisCachePassword="rotated-fixture-password")
            s.config(token=701)
            deadline=time.monotonic()+5
            correct=False
            while time.monotonic()<deadline:
                correct=s.request("192.0.2.5")[0]==200 and not (old & ids())
                if correct:break
                time.sleep(0.05)
            s.check("password-change-retires-old-sockets",correct)
            old=ids()
            s.check("old-sockets-observed-before-username-change",bool(old))
            redis_command(s.redis_port,"ACL","SETUSER","crowdsec-rotated","on",">rotated-user-fixture-password","~crowdsec:*","+get","+set","+del","+select","+eval")
            s.overrides.update(redisCacheUsername="crowdsec-rotated",redisCachePassword="rotated-user-fixture-password")
            s.config(token=702)
            deadline=time.monotonic()+5
            correct=False
            while time.monotonic()<deadline:
                correct=s.request("192.0.2.5")[0]==200 and not (old & ids())
                if correct:break
                time.sleep(0.05)
            s.check("username-change-retires-old-sockets",correct)
        s.stop()
        s.completed=True
    finally:
        s.cleanup()
    passed=not s.failures and passed
raise SystemExit(0 if passed else 1)
