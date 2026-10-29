"""Short refresh regressions using the packaged plugin and real Redis ACLs."""

import json
import os
import time
import urllib.request
from run import Suite, redis_command, command, TRAEFIK, MODULE


def snapshot(s, addresses, delay=0):
    body = {
        "snapshot": {
            "new": [{"type": "ban", "value": ip, "duration": "1m"} for ip in addresses],
            "deleted": [],
        },
        "delay": delay,
    }
    urllib.request.urlopen(
        urllib.request.Request(
            f"http://127.0.0.1:{s.fixture_port}/snapshot",
            json.dumps(body).encode(),
            {"Content-Type": "application/json"},
        ),
        timeout=3,
    ).read()


def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def regressions(s):
    env = dict(
        os.environ,
        REDIS_REFRESH_FIXTURE=f"127.0.0.1:{s.redis_port}",
        GOCACHE=str(s.temp / "go-cache"),
    )
    result = command(
        "go",
        "test",
        "-race",
        "./pkg/cache",
        "-run",
        "TestRedisRefreshRegression",
        "-count=1",
        env=env,
    )
    (s.output / "redis-ownership-native.log").write_text(result)
    s.check("100-redis-ownership-and-reconciliation-cycles", True)
    snapshot(s, ["192.0.2.200"])
    s.start(mode="stream")
    s.check(
        "initial-snapshot",
        wait_for(
            lambda: redis_command(s.redis_port, "GET", "crowdsec:192.0.2.200") == "t"
        ),
    )
    cases = [
        (
            "decision-set",
            ["~crowdsec:refresh:*", "~crowdsec:updated", "~crowdsec:192.0.2.200"],
        ),
        (
            "decision-delete",
            [
                "~crowdsec:refresh:*",
                "~crowdsec:updated",
                "%R~crowdsec:192.0.2.200",
                "~crowdsec:192.0.2.202",
            ],
        ),
        (
            "success-marker",
            ["~crowdsec:refresh:*", "%R~crowdsec:updated", "~crowdsec:192.0.2.*"],
        ),
    ]
    for cycle, permissions in cases:
        old, new = "192.0.2.200", "192.0.2.202"
        redis_command(
            s.redis_port, "ACL", "SETUSER", "crowdsec", "resetkeys", *permissions
        )
        snapshot(s, [new])
        redis_command(s.redis_port, "DEL", "crowdsec:updated")
        time.sleep(2.2)
        s.check(
            "denied-batch-no-partial-delete",
            redis_command(s.redis_port, "GET", "crowdsec:" + old) == "t",
            cycle=cycle,
        )
        s.check(
            "denied-batch-no-success",
            redis_command(s.redis_port, "GET", "crowdsec:updated") is None,
            cycle=cycle,
        )
        redis_command(
            s.redis_port, "ACL", "SETUSER", "crowdsec", "resetkeys", "~crowdsec:*"
        )
        s.check(
            "fresh-snapshot-recovers-consumed-delta",
            wait_for(
                lambda: (
                    redis_command(s.redis_port, "GET", "crowdsec:" + new) == "t"
                    and redis_command(s.redis_port, "GET", "crowdsec:" + old) is None
                )
            ),
            cycle=cycle,
        )
        snapshot(s, [old])
        redis_command(s.redis_port, "DEL", "crowdsec:updated")
        s.check(
            "next-snapshot-removes-stale-ban",
            wait_for(
                lambda: (
                    redis_command(s.redis_port, "GET", "crowdsec:" + old) == "t"
                    and redis_command(s.redis_port, "GET", "crowdsec:" + new) is None
                )
            ),
            cycle=cycle,
        )
    # A second Traefik process shares the Redis namespace and delayed LAPI.
    snapshot(s, ["192.0.2.200"], delay=0.3)
    peer = s.run(
        "traefik-peer",
        TRAEFIK,
        "--configfile=/fixture/traefik.json",
        options=(
            "--platform",
            "linux/amd64",
            "--cpus",
            "2",
            "--memory",
            "512m",
            "--read-only",
            "--cap-drop=ALL",
            "--user",
            "65532:65532",
            "-p",
            "127.0.0.1::8000",
            "--mount",
            f"type=volume,src={s.volume},dst=/plugins-local/src/{MODULE},readonly",
            "--mount",
            f"type=bind,src={s.temp},dst=/fixture,readonly",
        ),
    )
    primary_port = s.port
    s.port = s.published(peer, 8000)
    s.check(
        "peer-protected-requests",
        wait_for(
            lambda: (
                s.request("192.0.2.200", "/stream")[0] == 403 and s.request()[0] == 200
            )
        ),
    )
    s.port = primary_port
    time.sleep(5)
    state = json.load(
        urllib.request.urlopen(f"http://127.0.0.1:{s.fixture_port}/state", timeout=3)
    )
    s.check(
        "separate-traefik-processes-serialize-lapi",
        state.get("max_inflight") == 1,
        maximum=state.get("max_inflight"),
    )
    logs = command("docker", "logs", peer)
    s.check(
        "peer-no-interpreter-error",
        "panic" not in logs.lower() and "failed to create plugin" not in logs.lower(),
    )
    s.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    suite = Suite(parser.parse_args().output)
    try:
        suite.setup()
        regressions(suite)
        suite.completed = True
    except Exception as exc:
        suite.check("harness", False, error=str(exc))
        raise
    finally:
        suite.cleanup()
    raise SystemExit(bool(suite.failures))
