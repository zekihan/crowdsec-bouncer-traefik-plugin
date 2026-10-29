#!/usr/bin/env python3
"""Compare the accepted artifact with opt-in pooling in disposable fixtures.

This synthetic experiment does not replace the full paired release suite or
30-minute fault soak. Defaults: three alternating pairs, two Traefik processes,
two middleware instances per process, 100/s steady then 250/s burst.
"""
import argparse
import itertools
import json
import os
from pathlib import Path
import time
import urllib.request
from run import Suite, command, redis_command, TRAEFIK, MODULE, PYTHON, ROOT
from load import drive

BASELINE = "docker.io/zekihan/crowdsec-traefik-local-plugin@sha256:d3b7eba05cc8db2cc567ce7dac8f7422e7ac2f9f37775784afd9977dea336ffc"
POOL = dict(redisCachePoolMaxActive=4, redisCachePoolMaxIdle=4,
            redisCachePoolMaxWaiters=16, redisCachePoolIdleTimeoutSeconds=5,
            redisCachePoolMaxLifetimeSeconds=30)


def info(port, section):
    raw = redis_command(port, "INFO", section)
    return dict(line.split(":", 1) for line in raw.splitlines() if ":" in line and not line.startswith("#"))


def peers(s, count):
    ports, diagnostics = [s.port], []
    for index in range(1, count):
        peer = s.run(f"traefik-peer-{index}", TRAEFIK,
                     "--configfile=/fixture/traefik.json", options=(
                         "--platform", "linux/amd64", "--cpus", "2", "--memory", "512m",
                         "--read-only", "--cap-drop=ALL", "--user", "65532:65532",
                         "-p", "127.0.0.1::8000", "-p", "127.0.0.1::8080",
                         "--mount", f"type=volume,src={s.volume},dst=/plugins-local/src/{MODULE},readonly",
                         "--mount", f"type=bind,src={s.temp},dst=/fixture,readonly"))
        ports.append(s.published(peer, 8000))
        diagnostics.append(s.published(peer, 8080))
    s.request_ports = itertools.cycle(ports)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if all(s.request()[0] == 200 for _ in ports):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("peer startup failed")
    original_request=s.request
    paths=itertools.cycle([path for path in ("/live","/stream") for _ in ports])
    def request(ip="192.0.2.1", path="/live", method="GET", data=None):
        return original_request(ip,next(paths),method,data)
    s.request=request
    original = s.metrics
    def metrics():
        values = original()
        for port in diagnostics:
            raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3).read().decode()
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0] in values and parts[0] != "redis_connections":
                    values[parts[0]] += float(parts[1])
        stats, commands = info(s.redis_port, "stats"), info(s.redis_port, "commandstats")
        values["total_connections_received"] = int(stats["total_connections_received"])
        for name in ("auth", "select", "get"):
            values[name + "_calls"] = int(dict(item.split("=", 1) for item in commands.get("cmdstat_"+name, "calls=0").split(","))["calls"])
        redis_cpu, redis_memory = info(s.redis_port,"cpu"), info(s.redis_port,"memory")
        values["redis_cpu_seconds_total"] = float(redis_cpu["used_cpu_sys"])+float(redis_cpu["used_cpu_user"])
        values["redis_used_memory_bytes"] = int(redis_memory["used_memory"])
        values["redis_rss_bytes"] = int(redis_memory["used_memory_rss"])
        return values
    s.metrics = metrics


def dns(s):
    captures = []
    for index, container in enumerate([s.traefik] + [c for c in s.containers if "traefik-peer-" in c]):
        name = f"{s.name}-dns-{index}"
        s.containers.append(name)
        command("docker", "run", "-d", "--name", name, "--network", "container:"+container,
                "--cap-drop=ALL", "--cap-add=NET_RAW", "--mount",
                f"type=bind,src={ROOT / 'tests/acceptance'},dst=/fixture,readonly",
                PYTHON, "python", "/fixture/dns_capture.py")
        captures.append(name)
    return captures


def run(args, pair, candidate):
    label = f"pair-{pair}-" + ("pool" if candidate else "unpooled")
    s = Suite(str(Path(args.output) / label))
    s.artifact = args.candidate if candidate else (args.baseline or args.candidate)
    # Explicit overrides make this independent of CROWDSEC_TEST_POOL.
    s.overrides = POOL if candidate else {}
    try:
        s.setup()
        s.start(mode="stream")
        peers(s, args.processes)
        captures = dns(s)
        drive(s, args.warmup, "warmup", rate=100)
        results = []
        for phase, rate in (("steady",args.steady_rate), ("burst",args.burst_rate)):
            result = drive(s, args.seconds, phase, rate=rate)
            samples = result["samples"]
            elapsed = samples[-1]["elapsed"]-samples[0]["elapsed"]
            result["rates"] = {key:(samples[-1][key]-samples[0][key])/elapsed
                               for key in ("total_connections_received","auth_calls","select_calls","get_calls")}
            result["redis_cpu_cores"] = (samples[-1]["redis_cpu_seconds_total"]-samples[0]["redis_cpu_seconds_total"])/elapsed
            result["redis_peak_rss_bytes"] = max(row["redis_rss_bytes"] for row in samples)
            result["redis_peak_used_memory_bytes"] = max(row["redis_used_memory_bytes"] for row in samples)
            result["rate_measurement_note"] = "Includes five admin AUTH/SELECT connections per metrics sample."
            results.append(result)
        before = s.metrics()
        time.sleep(10)
        after = s.metrics()
        # Refresh continues during idle; cleanup is bounded rather than zero.
        s.check("idle-bounds", after["redis_connections"] <= args.processes*2*2*POOL["redisCachePoolMaxActive"], before=before, after=after)
        for name in captures:
            logs = command("docker", "logs", name)
            (s.output/(name+".jsonl")).write_text(logs+"\n")
            s.check("dns-capture", any("queries" in line for line in logs.splitlines()))
        (s.output/"comparison.json").write_text(json.dumps(results,indent=2))
        for peer in [c for c in s.containers if "traefik-peer-" in c]:
            logs=command("docker","logs",peer)
            (s.output/(peer+".log")).write_text(logs)
            s.check("peer-interpreter-log",not any(word in logs.lower() for word in ("panic","failed to load plugin","unable to create plugin")))
        s.stop()
        s.completed = True
    finally:
        s.cleanup()
    return not s.failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--candidate", default="local/crowdsec-plugin:ops-160-v7")
    parser.add_argument("--baseline", help="default: same candidate artifact with pooling disabled")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--start-pair",type=int,default=0,help="odd indices run the pooled artifact first")
    parser.add_argument("--processes", type=int, default=2)
    parser.add_argument("--steady-rate",type=int,default=100)
    parser.add_argument("--burst-rate",type=int,default=250)
    args=parser.parse_args()
    if min(args.seconds,args.warmup,args.pairs,args.processes,args.steady_rate,args.burst_rate)<1 or args.seconds<10 or args.warmup<10 or args.start_pair<0:
        parser.error("positive inputs and at least ten warm-up and measured seconds required")
    os.environ.pop("CROWDSEC_TEST_POOL", None)
    passed = True
    for pair in range(args.start_pair,args.start_pair+args.pairs):
        for candidate in ((False, True) if pair%2==0 else (True, False)):
            passed = run(args,pair,candidate) and passed
    return 0 if passed else 1

if __name__ == "__main__":
    raise SystemExit(main())
