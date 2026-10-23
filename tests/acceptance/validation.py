"""Snapshot shape and uncached-request contention regressions."""

import json
import time
import urllib.request
from run import Suite, redis_command
from refresh import snapshot, wait_for


def raw_snapshot(s, value):
    urllib.request.urlopen(
        urllib.request.Request(
            f"http://127.0.0.1:{s.fixture_port}/snapshot",
            json.dumps({"snapshot": value}).encode(),
            {"Content-Type": "application/json"},
        ),
        timeout=3,
    ).read()


def checks(s):
    snapshot(s, ["192.0.2.200"])
    s.start(mode="stream")

    def uncached():
        return s.request("192.0.2.199", "/stream")[0]

    s.check("warmed-uncached-allow", wait_for(lambda: uncached() == 200))
    redis_command(
        s.redis_port, "SET", "crowdsec:refresh:lease", "fixture-owner", "EX", 10
    )
    redis_command(s.redis_port, "DEL", "crowdsec:updated")
    time.sleep(2.2)
    s.check(
        "contention-keeps-warmed-uncached-requests-allowed",
        all(uncached() == 200 for _ in range(100)),
    )
    # Model a failing owner retaining/reacquiring the lease at every follower tick.
    # Busy must preserve short-lived health, but cannot extend the freshness budget.
    raw_snapshot(s, {})
    started = time.monotonic()
    while time.monotonic() - started < 34:
        redis_command(
            s.redis_port, "SET", "crowdsec:refresh:lease", "fixture-owner", "EX", 30
        )
        urllib.request.urlopen(
            f"http://127.0.0.1:{s.fixture_port}/v1/decisions/stream?startup=true",
            timeout=3,
        ).read()
        if uncached() == 403:
            break
        time.sleep(0.5)
    s.check("stale-busy-follower-fails-closed", uncached() == 403)
    s.check(
        "busy-owner-published-no-success",
        redis_command(s.redis_port, "GET", "crowdsec:updated") is None,
    )
    snapshot(s, ["192.0.2.200"])
    redis_command(s.redis_port, "DEL", "crowdsec:refresh:lease")
    s.check(
        "stale-follower-recovers-after-success", wait_for(lambda: uncached() == 200)
    )
    redis_command(
        s.redis_port, "SET", "crowdsec:refresh:lease", "fixture-owner", "EX", 10
    )
    redis_command(s.redis_port, "DEL", "crowdsec:updated")
    # Recreate middleware while another owner holds the lease: it must remain cold.
    s.config(mode="stream", token=777)
    s.check(
        "cold-contention-blocks-uncached-requests",
        wait_for(lambda: uncached() == 403, seconds=3),
    )
    s.check("cold-contention-stays-blocked", all(uncached() == 403 for _ in range(100)))
    redis_command(s.redis_port, "DEL", "crowdsec:refresh:lease")
    s.check("cold-instance-recovers-after-success", wait_for(lambda: uncached() == 200))
    for value in [
        None,
        {},
        {"message": "wrong endpoint"},
        [],
        {"new": []},
        {"new": {}, "deleted": []},
    ]:
        raw_snapshot(s, value)
        redis_command(s.redis_port, "DEL", "crowdsec:updated")
        time.sleep(2.2)
        s.check(
            "invalid-shape-preserves-ban",
            redis_command(s.redis_port, "GET", "crowdsec:192.0.2.200") == "t",
            response=value,
        )
        s.check(
            "invalid-shape-no-success",
            redis_command(s.redis_port, "GET", "crowdsec:updated") is None,
            response=value,
        )
        snapshot(s, ["192.0.2.200"])
        s.check("valid-snapshot-recovers", wait_for(lambda: uncached() == 200))
    for empty in [{"new": [], "deleted": []}, {"new": None, "deleted": None}]:
        raw_snapshot(s, empty)
        redis_command(s.redis_port, "DEL", "crowdsec:updated")
        s.check(
            "valid-empty-clears-tracked-ban",
            wait_for(
                lambda: (
                    redis_command(s.redis_port, "GET", "crowdsec:192.0.2.200") is None
                    and redis_command(s.redis_port, "GET", "crowdsec:updated")
                    is not None
                )
            ),
            response=empty,
        )
        snapshot(s, ["192.0.2.200"])
        redis_command(s.redis_port, "DEL", "crowdsec:updated")
        s.check(
            "repopulate-after-empty",
            wait_for(
                lambda: (
                    redis_command(s.redis_port, "GET", "crowdsec:192.0.2.200") == "t"
                )
            ),
        )
    s.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    suite = Suite(parser.parse_args().output)
    try:
        suite.setup()
        checks(suite)
        suite.completed = True
    except Exception as exc:
        suite.check("harness", False, error=str(exc))
        raise
    finally:
        suite.cleanup()
    raise SystemExit(bool(suite.failures))
