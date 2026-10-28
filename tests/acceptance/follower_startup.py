"""Reproduce aligned 300s followers and verify the rendered readiness route in Traefik."""

import argparse
import http.client
import json
import time
import urllib.request

from run import Suite, redis_command
from refresh import wait_for


def get(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request("GET", path)
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


def checks(s):
    # A fixture owner spans container startup; this does not test lease expiry.
    redis_command(
        s.redis_port, "SET", "crowdsec:refresh:lease", "fixture-owner", "EX", 120
    )
    redis_command(s.redis_port, "DEL", "crowdsec:updated")
    s.overrides = {"updateIntervalSeconds": 300, "updateMaxFailure": -1}
    s.static_overrides = {
        "ping": {"entryPoint": "crowdsec-health"},
        "entryPoints": {
            "web": {"address": ":8000", "forwardedHeaders": {"insecure": True}},
            "traefik": {"address": ":8080"},
            "crowdsec-health": {"address": ":8082"},
        },
    }
    s.extra_ports = ("-p", "127.0.0.1::8082")
    s.extra_routers = {
        "crowdsec-readiness": {
            "entryPoints": ["crowdsec-health"],
            "rule": "Path(`/crowdsec-ready`)",
            "priority": 10000,
            "middlewares": ["refresh"],
            "service": "ping@internal",
        }
    }
    s.start(mode="stream")
    health_port = s.published(s.traefik, 8082)
    s.check("native-ping-healthy-during-cold-block", get(health_port, "/ping") == 200)
    s.check("cold-readiness-fails-closed", get(health_port, "/crowdsec-ready") == 403)
    s.check("cold-requests-fail-closed", s.request("192.0.2.199", "/stream")[0] == 403)
    redis_command(s.redis_port, "SET", "crowdsec:192.0.2.200", "t", "EX", 60)
    redis_command(s.redis_port, "SET", "crowdsec:2001:db8::200", "t", "EX", 60)
    # Publish success only after the synthetic owner's decisions are installed.
    redis_command(s.redis_port, "SET", "crowdsec:updated", "f", "EX", 299)
    redis_command(s.redis_port, "DEL", "crowdsec:refresh:lease")
    started = time.monotonic()
    s.check(
        "readiness-adopts-committed-marker-before-next-300s-poll",
        wait_for(lambda: get(health_port, "/crowdsec-ready") == 200, seconds=3),
    )
    s.check(
        "independent-followers-adopt-committed-marker",
        all(s.request("192.0.2.199", path)[0] == 200 for path in ("/live", "/stream")),
        elapsed=time.monotonic() - started,
    )
    for address in ("192.0.2.200", "2001:db8::200"):
        s.check(
            "published-bans-still-enforced",
            s.request(address, "/stream")[0] == 403,
            family="IPv6" if ":" in address else "IPv4",
        )
    state = json.load(
        urllib.request.urlopen(f"http://127.0.0.1:{s.fixture_port}/state", timeout=3)
    )
    s.check(
        "recovery-needs-no-extra-lapi-poll", state["calls"] == 0, calls=state["calls"]
    )
    s.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    suite = Suite(parser.parse_args().output)
    try:
        suite.setup()
        checks(suite)
        suite.completed = True
    finally:
        suite.cleanup()
    raise SystemExit(bool(suite.failures))
