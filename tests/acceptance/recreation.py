import argparse
import time
from run import Suite, redis_command

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
args = parser.parse_args()
s = Suite(args.output)
try:
    s.setup()
    s.start()
    before = s.metrics()
    for n in range(10):
        prefix = f"crowdsec:recreation:{n}:"
        s.overrides = {"redisCacheKeyPrefix": prefix}
        s.config(token=200 + n)
        started = time.monotonic()
        good = False
        while time.monotonic() - started < 30:
            if (
                redis_command(s.redis_port, "GET", prefix + "updated") is not None
                and redis_command(s.redis_port, "GET", prefix + "192.0.2.200") == "t"
                and s.request("192.0.2.200", "/stream")[0] == 403
            ):
                good = True
                break
            time.sleep(0.1)
        s.check(
            "prefix-recreation-refresh",
            good,
            cycle=n,
            seconds=time.monotonic() - started,
        )
        if not good:
            break
    time.sleep(60)
    after = s.metrics()
    retired = ["crowdsec:updated"] + [
        f"crowdsec:recreation:{n}:updated" for n in range(9)
    ]
    s.check(
        "retired-prefixes-stop-refreshing",
        all(redis_command(s.redis_port, "GET", key) is None for key in retired),
    )
    s.check(
        "recreation-goroutine-cleanup",
        after["go_goroutines"] <= before["go_goroutines"] + 10,
        before=before,
        after=after,
    )
    s.stop()
    s.completed = True
finally:
    s.cleanup()
