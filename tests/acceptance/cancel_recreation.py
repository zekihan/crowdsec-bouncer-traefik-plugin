"""Exercise retirement during a delayed snapshot with changed and reused prefixes."""
import argparse
import json
import time
import urllib.request
from run import Suite, redis_command
from refresh import snapshot, wait_for

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
s = Suite(parser.parse_args().output)
try:
    s.setup()
    s.overrides = {"streamStartupBlock": False, "httpTimeoutSeconds": 10, "updateIntervalSeconds": 10}
    s.start()
    for i, reuse in enumerate((False, True)):
        old = f"crowdsec:cancel:{i}:old:"
        active = old if reuse else f"crowdsec:cancel:{i}:active:"
        retired_ip, active_ip = f"192.0.2.{210+i}", f"192.0.2.{220+i}"
        snapshot(s, [retired_ip], delay=5)
        s.overrides.update(redisCacheKeyPrefix=old)
        s.config(token=300+i*2)
        def inflight():
            state = json.load(urllib.request.urlopen(f"http://127.0.0.1:{s.fixture_port}/state", timeout=3))
            return state.get("inflight", 0) > 0
        if not wait_for(inflight, 15):
            s.check("delayed-refresh-started", False, reuse=reuse)
            continue
        snapshot(s, [active_ip])
        s.overrides.update(redisCacheKeyPrefix=active)
        s.config(token=301+i*2)
        good = wait_for(lambda: redis_command(s.redis_port, "GET", active+active_ip) == "t", 15)
        time.sleep(6)
        s.check("retired-snapshot-not-published", good and redis_command(s.redis_port, "GET", old+retired_ip) is None and (reuse or redis_command(s.redis_port, "GET", old+"updated") is None), reuse=reuse)
    s.stop()
    s.completed = True
finally:
    s.cleanup()
raise SystemExit(bool(s.failures))
