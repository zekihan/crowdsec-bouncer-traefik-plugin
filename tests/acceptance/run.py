#!/usr/bin/env python3
"""Run only disposable Docker fixtures; never accesses Kubernetes or real credentials."""

import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
TRAEFIK = "docker.io/traefik@sha256:575fa15b135078fe5e50aa847987d96dbddd7b093c172429618404df73f3fa7c"
REDIS = "ecr-public.aws.com/docker/library/redis@sha256:0bf6577d7774e592b29d093e3ac9390eb91e13d72c21e506afce736de5e0eeb0"
PYTHON = (
    "python@sha256:c50ccfb66e5cc97a610dcd0b9597de6ef5b52c96280b51997b353a0fc87a8361"
)
BUSYBOX = (
    "busybox@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092"
)
MODULE = "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
UPSTREAM_REVISION = "f9c85b1472d618e9188a025c9b2308d0b27e5321"


def command(*args, **kw):
    return subprocess.check_output(
        args, text=True, stderr=subprocess.STDOUT, **kw
    ).strip()


def redis_command(port, *args):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as conn:
        conn.settimeout(4)
        reader = conn.makefile("rb")
        result = None
        for values in [("AUTH", "admin", "fixture-admin"), ("SELECT", "11"), args]:
            encoded = [str(a).encode() for a in values]
            conn.sendall(
                b"*%d\r\n" % len(encoded)
                + b"".join(b"$%d\r\n" % len(a) + a + b"\r\n" for a in encoded)
            )
            line = reader.readline()
            if not line:
                raise ConnectionError("Redis closed the fixture connection")
            if line.startswith(b"-"):
                raise RuntimeError(line.decode())
            if line.startswith(b"$"):
                size = int(line[1:])
                result = reader.read(size + 2)[:-2].decode() if size >= 0 else None
            else:
                result = line[1:].strip().decode()
        return result


class Suite:
    def __init__(self, output):
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.events = open(self.output / "events.jsonl", "a", buffering=1)
        self.name = "redis-acl-" + uuid.uuid4().hex[:10]
        self.temp = Path(tempfile.mkdtemp(prefix="redis-acl-acceptance-"))
        self.containers = []
        self.volumes = []
        self.port = self.diag = 0
        self.threadlocal = threading.local()
        self.failures = []
        self.completed = False
        self.emit(
            "environment",
            traefik=TRAEFIK,
            redis=REDIS,
            pid=os.getpid(),
            target="linux/amd64",
            host=command("docker", "info", "--format", "{{.Architecture}}"),
            cpu_limit=2,
            memory_limit="512m",
        )

    def emit(self, event, **data):
        row = dict(time=time.time(), event=event, **data)
        self.events.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)

    def check(self, name, passed, **data):
        self.emit("check", name=name, passed=bool(passed), **data)
        if not passed:
            self.failures.append(name)

    def run(self, name, image, *args, options=()):
        container = self.name + "-" + name
        self.containers.append(container)
        command(
            "docker",
            "run",
            "-d",
            "--name",
            container,
            "--network",
            self.name,
            "--network-alias",
            name,
            *options,
            image,
            *args,
        )
        return container

    def published(self, container, port):
        return int(command("docker", "port", container, str(port)).rsplit(":", 1)[1])

    def request(self, ip="192.0.2.1", path="/live", method="GET", data=None):
        started = time.monotonic()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request(
                method,
                path,
                data,
                {
                    "X-Forwarded-For": ip,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            response = conn.getresponse()
            body = response.read()
            result = response.status, time.monotonic() - started, body
            conn.close()
            return result
        except Exception as exc:
            return 0, time.monotonic() - started, str(exc).encode()

    def control(self, fault="", cmd="GET"):
        urllib.request.urlopen(
            f"http://127.0.0.1:{self.fixture_port}/control?fault={fault}&command={cmd}",
            timeout=4,
        ).read()

    def setup(self):
        command("docker", "network", "create", self.name)
        config = (
            'bind 0.0.0.0\nsave ""\nappendonly no\nuser default on >fixture-legacy ~* &* +@all\n'
            "user admin on >fixture-admin ~* &* +@all\n"
            'user crowdsec on ">fixture password%value" ~crowdsec:* +get +set +del +select +eval\n'
        )
        (self.temp / "redis.conf").write_text(config)
        self.redis = self.run(
            "redis",
            REDIS,
            "redis-server",
            "/fixture/redis.conf",
            options=(
                "--platform",
                "linux/amd64",
                "--mount",
                f"type=bind,src={self.temp},dst=/fixture,readonly",
                "-p",
                "127.0.0.1::6379",
            ),
        )
        self.redis_port = self.published(self.redis, 6379)
        self.fixture = self.run(
            "fixture",
            PYTHON,
            "python",
            "/fixture/fixture.py",
            options=(
                "--mount",
                f"type=bind,src={ROOT / 'tests/acceptance'},dst=/fixture,readonly",
                "-p",
                "127.0.0.1::8080",
            ),
        )
        self.fixture_port = self.published(self.fixture, 8080)
        for _ in range(100):
            try:
                redis_command(self.redis_port, "PING")
                self.control()
                break
            except Exception:
                time.sleep(0.1)
        for prefix in ("", "crowdsec:"):
            redis_command(
                self.redis_port, "SET", prefix + "192.0.2.1", "f", "EX", 14400
            )
            redis_command(
                self.redis_port, "SET", prefix + "192.0.2.2", "t", "EX", 14400
            )
            redis_command(
                self.redis_port, "SET", prefix + "192.0.2.3", "c", "EX", 14400
            )
        redis_command(self.redis_port, "SET", "other:sentinel", "unchanged")
        volume = self.name + "-source"
        self.volumes.append(volume)
        command("docker", "volume", "create", volume)
        command(
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            volume + ":/destination",
            BUSYBOX,
            "sh",
            "-c",
            "chown 0:65532 /destination && chmod 0770 /destination",
        )
        command(
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--read-only",
            "--cap-drop=ALL",
            "--memory",
            "32m",
            "--cpus",
            "0.1",
            "-v",
            volume + ":/destination",
            "local/crowdsec-plugin:redis-acl",
        )
        self.volume = volume
        archive = subprocess.check_output(
            ["git", "archive", UPSTREAM_REVISION], cwd=ROOT
        )
        (self.temp / "upstream.tar").write_bytes(archive)
        upstream = self.temp / "upstream"
        upstream.mkdir()
        with tarfile.open(self.temp / "upstream.tar") as tar:
            tar.extractall(upstream, filter="data")
        self.emit(
            "artifact",
            image=command(
                "docker",
                "image",
                "inspect",
                "local/crowdsec-plugin:redis-acl",
                "--format",
                "{{json .Descriptor}}",
            ),
        )

    def config(self, baseline=False, mode="live", block=True, token=0):
        plugin = dict(
            enabled=True,
            logLevel="ERROR",
            crowdsecMode=mode,
            crowdsecLapiScheme="http",
            crowdsecLapiHost="fixture:8080",
            crowdsecLapiKey="fixture",
            redisCacheEnabled=True,
            redisCacheHost="fixture:6380",
            redisCacheReadHosts=["fixture:6381"],
            redisCacheDatabase="11",
            redisCachePassword="fixture-legacy"
            if baseline
            else "fixture password%value",
            redisCacheUnreachableBlock=block,
            updateIntervalSeconds=1,
            updateMaxFailure=0,
            httpTimeoutSeconds=1,
            defaultDecisionSeconds=300,
            metricsUpdateIntervalSeconds=0,
            streamStartupBlock=True,
            forwardedHeadersTrustedIps=["172.16.0.0/12", "127.0.0.1/32"],
            captchaFilePath="/plugins-local/src/" + MODULE + "/captcha.html",
            captchaProvider="custom",
            captchaCustomResponse="token",
            captchaCustomKey="fixture",
            captchaCustomJsURL="http://fixture:8080/script.js",
            captchaSiteKey="fixture",
            captchaSecretKey="fixture",
            captchaCustomValidateURL="http://fixture:8080/captcha",
            captchaGracePeriodSeconds=60,
        )
        if not baseline:
            plugin.update(
                redisCacheUsername="crowdsec", redisCacheKeyPrefix="crowdsec:"
            )
        plugin.update(getattr(self, "overrides", {}))
        # Changed header ensures provider watches recreate the middleware.
        plugin["remediationHeadersCustomName"] = "X-Remediation-" + str(token)
        stream = dict(
            plugin,
            crowdsecMode="stream",
            updateIntervalSeconds=1 if mode == "stream" else 10,
        )
        dynamic = {
            "http": {
                "routers": {
                    "live": {
                        "rule": "PathPrefix(`/live`)",
                        "entryPoints": ["web"],
                        "service": "backend",
                        "middlewares": ["bouncer"],
                    },
                    "stream": {
                        "rule": "PathPrefix(`/stream`)",
                        "entryPoints": ["web"],
                        "service": "backend",
                        "middlewares": ["refresh"],
                    },
                },
                "services": {
                    "backend": {
                        "loadBalancer": {"servers": [{"url": "http://fixture:8080"}]}
                    }
                },
                "middlewares": {
                    "bouncer": {"plugin": {"bouncer": plugin}},
                    "refresh": {"plugin": {"bouncer": stream}},
                },
            }
        }
        path = self.temp / "dynamic.yaml"
        pending = self.temp / "dynamic.new"
        pending.write_text(json.dumps(dynamic))
        pending.replace(path)

    def start(self, baseline=False, mode="live", block=True):
        for prefix in ("", "crowdsec:"):
            for ip, value in (
                ("192.0.2.1", "f"),
                ("192.0.2.2", "t"),
                ("192.0.2.3", "c"),
            ):
                redis_command(self.redis_port, "SET", prefix + ip, value, "EX", 14400)
        self.config(baseline, mode, block)
        static = dict(
            entryPoints={
                "web": {"address": ":8000", "forwardedHeaders": {"insecure": True}},
                "traefik": {"address": ":8080"},
            },
            api={"insecure": True, "debug": True},
            metrics={"prometheus": {}},
            log={"level": "ERROR"},
            providers={
                "file": {"filename": "/fixture/dynamic.yaml", "watch": True},
                "providersThrottleDuration": "100ms",
            },
            experimental={
                "abortOnPluginFailure": True,
                "localPlugins": {"bouncer": {"moduleName": MODULE}},
            },
        )
        (self.temp / "traefik.json").write_text(json.dumps(static))
        source = (
            f"type=bind,src={self.temp / 'upstream'},dst=/plugins-local/src/{MODULE},readonly"
            if baseline
            else f"type=volume,src={self.volume},dst=/plugins-local/src/{MODULE},readonly"
        )
        started = time.monotonic()
        self.traefik = self.run(
            "traefik",
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
                "--mount",
                source,
                "--mount",
                f"type=bind,src={self.temp},dst=/fixture,readonly",
                "-p",
                "127.0.0.1::8000",
                "-p",
                "127.0.0.1::8080",
            ),
        )
        self.port, self.diag = (
            self.published(self.traefik, 8000),
            self.published(self.traefik, 8080),
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.request("192.0.2.2")[0] == 403 and self.request()[0] == 200:
                self.check(
                    "startup",
                    True,
                    baseline=baseline,
                    seconds=time.monotonic() - started,
                )
                return
            time.sleep(0.1)
        self.check(
            "startup",
            False,
            baseline=baseline,
            seconds=time.monotonic() - started,
            allow=str(self.request()),
            ban=str(self.request("192.0.2.2")),
        )
        raise RuntimeError(command("docker", "logs", self.traefik))

    def stop(self):
        logs = command("docker", "logs", self.traefik)
        (self.output / (self.traefik + "-" + str(time.time_ns()) + ".log")).write_text(
            logs
        )
        self.check(
            "interpreter-log",
            not any(
                s in logs.lower()
                for s in ("panic", "failed to load plugin", "unable to create plugin")
            ),
        )
        command("docker", "rm", "-f", self.traefik)
        self.containers.remove(self.traefik)

    def metrics(self):
        raw = (
            urllib.request.urlopen(f"http://127.0.0.1:{self.diag}/metrics", timeout=3)
            .read()
            .decode()
        )
        wanted = (
            "go_goroutines",
            "process_open_fds",
            "process_resident_memory_bytes",
            "process_cpu_seconds_total",
        )
        values = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in wanted:
                values[parts[0]] = float(parts[1])
        clients = redis_command(self.redis_port, "CLIENT", "LIST")
        values["redis_connections"] = sum(
            "user=crowdsec " in line or "user=default " in line
            for line in clients.splitlines()
        )
        if len(values) != 5:
            raise RuntimeError("missing required metrics: " + str(values))
        return values

    def functional(self, block=True):
        self.start(block=block)
        for ip, expected in [("192.0.2.1", 200), ("192.0.2.2", 403)]:
            results = [self.request(ip) for _ in range(100)]
            self.check("cached-" + ip, all(x[0] == expected for x in results))
        for fault in (
            "noperm",
            "auth",
            "malformed",
            "truncated",
            "disconnect",
            "stall",
            "slow",
        ):
            for cmd in ("AUTH", "SELECT", "GET", "SET"):
                if fault not in ("stall", "noperm") and cmd != "GET":
                    continue
                self.control(fault, cmd)
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    results = list(
                        pool.map(lambda _: self.request("198.19.0.1"), range(100))
                    )
                self.check(
                    "http-fault-" + fault + "-" + cmd,
                    all(x[0] == 403 and x[1] <= 3 for x in results),
                    maximum=max(x[1] for x in results),
                    statuses=sorted(set(x[0] for x in results)),
                )
                self.control()
                redis_command(self.redis_port, "DEL", "crowdsec:198.19.0.1")
        self.check(
            "foreign-sentinel",
            redis_command(self.redis_port, "GET", "other:sentinel") == "unchanged",
        )
        self.stop()
        for _ in range(9):
            self.start()
            self.stop()
        self.start()
        for n in range(10):
            started = time.monotonic()
            self.config(token=n + 1)
            # Provider throttle plus an observable header on a banned request.
            deadline = started + 30
            observed = False
            while time.monotonic() < deadline:
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
                    conn.request(
                        "GET", "/live", headers={"X-Forwarded-For": "192.0.2.2"}
                    )
                    response = conn.getresponse()
                    observed = (
                        response.status == 403
                        and response.getheader("X-Remediation-" + str(n + 1))
                        is not None
                    )
                    response.read()
                    conn.close()
                    if observed:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            self.check(
                "recreation", observed, cycle=n, seconds=time.monotonic() - started
            )
        self.stop()

    def cleanup(self):
        for name in reversed(self.containers):
            subprocess.run(
                ["docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        for name in self.volumes:
            subprocess.run(
                ["docker", "volume", "rm", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        subprocess.run(
            ["docker", "network", "rm", self.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        shutil.rmtree(self.temp)
        self.emit("result", completed=self.completed, failures=self.failures)
        self.events.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=["functional"], default="functional")
    parser.add_argument("--fail-open", action="store_true")
    args = parser.parse_args()
    suite = Suite(args.output)
    try:
        suite.setup()
        suite.functional(block=not args.fail_open)
        suite.completed = True
    except Exception as exc:
        suite.check("harness", False, error=str(exc))
        raise
    finally:
        suite.cleanup()
    raise SystemExit(bool(suite.failures))


if __name__ == "__main__":
    main()
