#!/usr/bin/env python3
"""Fail over a direct Redis DNS endpoint on an isolated Docker network."""
import argparse
import time
from run import Suite, REDIS, command, redis_command
from pool_benchmark import POOL

parser=argparse.ArgumentParser()
parser.add_argument("--output",required=True)
args=parser.parse_args()
s=Suite(args.output)
s.overrides=dict(POOL,redisCacheHost="redis:6379",redisCacheReadHosts=["redis:6379"])
try:
    s.setup()
    s.start(mode="stream")
    s.check("old-endpoint-warmed",all(s.request()[0]==200 and s.request("192.0.2.2")[0]==403 for _ in range(10)))
    old=s.redis
    promoted=s.run("redis-promoted",REDIS,"redis-server","/fixture/redis.conf",options=(
        "--platform","linux/amd64","--network-alias","redis",
        "--mount",f"type=bind,src={s.temp},dst=/fixture,readonly","-p","127.0.0.1::6379"))
    port=s.published(promoted,6379)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        try:
            if redis_command(port,"PING")=="PONG":break
        except OSError:pass
        time.sleep(0.05)
    else:raise RuntimeError("promoted Redis did not start")
    # Invert decisions so successful reads from the wrong backend cannot pass.
    redis_command(port,"SET","crowdsec:192.0.2.1","t")
    redis_command(port,"SET","crowdsec:192.0.2.2","f")
    old_ip=command("docker","inspect",old,"--format",'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
    new_ip=command("docker","inspect",promoted,"--format",'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
    s.check("distinct-endpoint-addresses",old_ip!=new_ip,old=old_ip,new=new_ip)
    command("docker","network","disconnect",s.name,old)
    s.redis,s.redis_port=promoted,port
    started=time.monotonic()
    results=[s.request() for _ in range(10)]
    s.check("failover-never-allows-new-ban",all(code==403 and duration<=2 for code,duration,_ in results),statuses=[r[0]for r in results],maximum=max(r[1]for r in results))
    deadline=started+10
    recovered=False
    while time.monotonic()<deadline:
        if s.request()[0]==403 and s.request("192.0.2.2")[0]==200:
            recovered=True;break
        time.sleep(0.05)
    s.check("dns-failover-recovers-with-new-decisions",recovered,seconds=time.monotonic()-started)
    s.stop()
    s.completed=True
finally:
    s.cleanup()
raise SystemExit(bool(s.failures))
