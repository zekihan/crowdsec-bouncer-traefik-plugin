#!/usr/bin/env python3
"""Release budgets; no shortened run is a passing release result."""

import concurrent.futures
import json
import math
import statistics
import threading
import time
from run import Suite, redis_command, command


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def expected_response(code, duration, expected, started, finished, faults):
    if duration > 3:
        return False
    if code == expected:
        return True
    # Requests already in flight can encounter the next scheduled outage.
    fault_exposure = finished >= math.floor(started / 60) * 60 + 50
    return faults and expected == 200 and code == 403 and fault_exposure


def drive(suite, seconds, label, faults=False, rate=100):
    start = time.monotonic()
    offset = getattr(suite, "corpus_offset", 0)
    samples = []
    durations = []
    unexpected = []
    missed = 0
    outstanding = threading.BoundedSemaphore(50)
    lock = threading.Lock()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=50)
    sample_at = start
    status_at = start + 60
    outage = False
    count = 0
    maximum = 0

    def work(index):
        nonlocal maximum
        category = index % 10
        ip = (
            "192.0.2.1"
            if category < 7
            else (
                "192.0.2.2"
                if category < 9
                else f"198.{18 + ((offset + index) // 65536) % 2}.{((offset + index) // 256) % 256}.{(offset + index) % 256}"
            )
        )
        expected = 403 if category in (7, 8) else 200
        request_started = time.monotonic() - start
        code, duration, _ = suite.request(ip)
        request_finished = time.monotonic() - start
        with lock:
            durations.append(duration)
            maximum = max(maximum, duration)
            if not expected_response(
                code, duration, expected, request_started, request_finished, faults
            ):
                unexpected.append(
                    {
                        "index": index,
                        "code": code,
                        "duration": duration,
                        "expected": expected,
                        "started": request_started,
                        "finished": request_finished,
                    }
                )
        outstanding.release()

    try:
        while time.monotonic() - start < seconds:
            now = time.monotonic()
            elapsed = now - start
            phase = elapsed % 60
            wanted_outage = faults and 50 <= phase < 55
            if wanted_outage != outage:
                suite.control("disconnect" if wanted_outage else "", "ALL")
                outage = wanted_outage
            if now >= sample_at:
                samples.append(dict(elapsed=elapsed, **suite.metrics()))
                sample_at += 5
            if now >= status_at:
                suite.emit(
                    "load-progress",
                    label=label,
                    elapsed=elapsed,
                    completed=len(durations),
                    missed=missed,
                    unexpected=len(unexpected),
                )
                status_at += 60
            target = start + count / rate
            if now < target:
                time.sleep(target - now)
            elif now - target > 0.1:
                missed += 1
            if outstanding.acquire(blocking=False):
                pool.submit(work, count)
            else:
                missed += 1
            count += 1
    finally:
        pool.shutdown(wait=True)
        suite.control()
    suite.corpus_offset = offset + count
    result = {
        "label": label,
        "seconds": seconds,
        "arrivals": count,
        "completed": len(durations),
        "missed": missed,
        "unexpected_count": len(unexpected),
        "examples": unexpected[:10],
        "max": maximum,
        "p50": percentile(durations, 0.5),
        "p95": percentile(durations, 0.95),
        "p99": percentile(durations, 0.99),
        "samples": samples,
    }
    cpu = (
        samples[-1]["process_cpu_seconds_total"]
        - samples[0]["process_cpu_seconds_total"]
    ) / (samples[-1]["elapsed"] - samples[0]["elapsed"])
    result.update(
        cpu=cpu,
        rss95=percentile([s["process_resident_memory_bytes"] for s in samples], 0.95),
    )
    (suite.output / (label + ".json")).write_text(json.dumps(result, indent=2))
    suite.check(
        label + "-correctness",
        not missed and not unexpected and len(durations) == count,
        arrivals=count,
        completed=len(durations),
        missed=missed,
        unexpected=len(unexpected),
        maximum=maximum,
    )
    return result


def environment(suite):
    containers = command("docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Image}}")
    unrelated = sorted(
        line for line in containers.splitlines() if suite.name not in line
    )
    limits = command(
        "docker", "info", "--format", "{{.NCPU}} {{.MemTotal}} {{.ServerVersion}}"
    )
    return {"other_containers": unrelated, "engine": limits}


def paired(suite):
    for pair in range(3):
        before = environment(suite)
        runs = []
        for baseline in (True, False):
            suite.start(baseline=baseline)
            label = f"pair-{pair}-" + ("upstream" if baseline else "derivative")
            drive(suite, 300, label + "-warmup")
            runs.append(drive(suite, 600, label))
            suite.stop()
        after = environment(suite)
        suite.check(
            f"pair-{pair}-environment", before == after, before=before, after=after
        )
        upstream, derivative = runs
        suite.check(
            f"pair-{pair}-latency",
            derivative["p95"] <= 0.05
            and derivative["p99"] <= 0.1
            and derivative["p95"] <= max(upstream["p95"] * 1.2, upstream["p95"] + 0.005)
            and derivative["p99"]
            <= max(upstream["p99"] * 1.2, upstream["p99"] + 0.005),
            baseline_p95=upstream["p95"],
            baseline_p99=upstream["p99"],
            p95=derivative["p95"],
            p99=derivative["p99"],
        )
        suite.check(
            f"pair-{pair}-resources",
            derivative["cpu"] <= max(upstream["cpu"] * 1.2, upstream["cpu"] + 0.05)
            and derivative["rss95"]
            <= max(upstream["rss95"] * 1.2, upstream["rss95"] + 32 * 1024**2),
            baseline_cpu=upstream["cpu"],
            cpu=derivative["cpu"],
            baseline_rss=upstream["rss95"],
            rss=derivative["rss95"],
        )


def recovery(suite):
    suite.start(mode="stream")
    for cycle in range(20):
        command("docker", "stop", "-t", "1", suite.redis)
        time.sleep(5)
        command("docker", "start", suite.redis)
        suite.redis_port = suite.published(suite.redis, 6379)
        readiness_deadline = time.monotonic() + 10
        while True:
            if time.monotonic() > readiness_deadline:
                raise RuntimeError(
                    "disposable Redis did not restart within ten seconds"
                )
            try:
                if redis_command(suite.redis_port, "PING") == "PONG":
                    break
            except OSError:
                time.sleep(0.05)
        started = time.monotonic()
        good = False
        while time.monotonic() - started < 10:
            if (
                suite.request("192.0.2.200", "/stream")[0] == 403
                and redis_command(suite.redis_port, "GET", "crowdsec:updated")
                is not None
            ):
                good = True
                break
            time.sleep(0.05)
        suite.check("recovery", good, cycle=cycle, seconds=time.monotonic() - started)
    suite.stop()


def soak(suite):
    suite.start()
    drive(suite, 60, "soak-warmup")
    idle = suite.metrics()
    result = drive(suite, 1800, "soak", faults=True)
    time.sleep(60)
    final = suite.metrics()
    for key, tolerance in [
        ("go_goroutines", 10),
        ("process_open_fds", 5),
        ("redis_connections", 5),
    ]:
        suite.check(
            "cleanup-" + key,
            final[key] <= idle[key] + tolerance,
            before=idle[key],
            after=final[key],
        )
        early = [s[key] for s in result["samples"] if 300 <= s["elapsed"] <= 600]
        late = [s[key] for s in result["samples"] if 1500 <= s["elapsed"] <= 1800]
        suite.check(
            "growth-" + key,
            statistics.median(late) <= statistics.median(early) + tolerance,
        )
    key = "process_resident_memory_bytes"
    suite.check(
        "cleanup-rss",
        final[key] <= idle[key] + max(idle[key] * 0.2, 32 * 1024**2),
        before=idle[key],
        after=final[key],
    )
    early = statistics.median(
        [s[key] for s in result["samples"] if 300 <= s["elapsed"] <= 600]
    )
    late = statistics.median(
        [s[key] for s in result["samples"] if 1500 <= s["elapsed"] <= 1800]
    )
    suite.check(
        "growth-rss",
        late <= early + max(early * 0.1, 16 * 1024**2),
        before=early,
        after=late,
    )
    suite.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--mode", choices=["paired", "soak", "recovery", "all"], default="all"
    )
    args = parser.parse_args()
    suite = Suite(args.output)
    try:
        suite.setup()
        if args.mode in ("all", "paired"):
            paired(suite)
        if args.mode in ("all", "recovery"):
            recovery(suite)
        if args.mode in ("all", "soak"):
            soak(suite)
        suite.completed = True
    except Exception as exc:
        suite.check("harness", False, error=str(exc))
        raise
    finally:
        suite.cleanup()
    raise SystemExit(bool(suite.failures))
