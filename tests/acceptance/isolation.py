#!/usr/bin/env python3
import socket
import time
from run import Suite, redis_command


def app_command(port, *args, username="crowdsec", password="fixture password%value"):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.settimeout(3)
        reader = conn.makefile("rb")
        result = b""
        for values in [("AUTH", username, password), ("SELECT", "11"), args]:
            encoded = [str(a).encode() for a in values]
            conn.sendall(
                b"*%d\r\n" % len(encoded)
                + b"".join(b"$%d\r\n" % len(a) + a + b"\r\n" for a in encoded)
            )
            result = reader.readline()
            if result.startswith(b"-"):
                break
            if result.startswith(b"$") and int(result[1:]) >= 0:
                result = reader.read(int(result[1:]) + 2)
        return result


def isolation(s):
    s.start()
    for cmd in [
        ("GET", "other:sentinel"),
        ("SET", "other:sentinel", "corrupt"),
        ("DEL", "other:sentinel"),
        ("EVAL", "return redis.call('GET', KEYS[1])", "1", "other:sentinel"),
    ]:
        outcomes = [app_command(s.redis_port, *cmd) for _ in range(100)]
        s.check(
            "foreign-key-" + cmd[0], all(v.startswith(b"-NOPERM") for v in outcomes)
        )
    for user, password in [
        ("missing-user", "fixture password%value"),
        ("crowdsec", "wrong-password"),
    ]:
        outcomes = [
            app_command(
                s.redis_port,
                "GET",
                "crowdsec:192.0.2.1",
                username=user,
                password=password,
            )
            for _ in range(100)
        ]
        s.check(
            "wrong-auth-" + user, all(v.startswith(b"-WRONGPASS") for v in outcomes)
        )
    s.control("null", "AUTH")
    s.check(
        "null-auth-is-not-a-stream-cache-miss",
        all(s.request(path="/stream")[0] == 403 for _ in range(100)),
    )
    s.control()
    for ip in ("2001:db8::1", "192.0.2.100"):
        good = True
        for _ in range(100):
            redis_command(s.redis_port, "DEL", "crowdsec:" + ip)
            code, elapsed, _ = s.request(ip)
            good &= (
                code == 200
                and elapsed <= 3
                and redis_command(s.redis_port, "GET", "crowdsec:" + ip) == "f"
            )
            good &= 0 < int(redis_command(s.redis_port, "TTL", "crowdsec:" + ip)) <= 300
            good &= redis_command(s.redis_port, "GET", ip) is None
        s.check("namespaced-miss-ttl-" + ip, good)
    good = True
    for _ in range(100):
        redis_command(s.redis_port, "DEL", "crowdsec:192.0.2.3_captcha")
        code, elapsed, _ = s.request("192.0.2.3", method="POST", data="token=valid")
        good &= code == 302 and elapsed <= 3
        good &= redis_command(s.redis_port, "GET", "crowdsec:192.0.2.3_captcha") == "d"
        good &= (
            0
            < int(redis_command(s.redis_port, "TTL", "crowdsec:192.0.2.3_captcha"))
            <= 60
        )
    s.check("captcha-prefix-ttl", good)
    redis_command(s.redis_port, "DEL", "crowdsec:192.0.2.3_captcha")
    s.control("noperm", "SET")
    good = all(
        s.request("192.0.2.3", method="POST", data="token=valid")[0] == 503
        for _ in range(100)
    )
    s.check(
        "captcha-write-denial",
        good
        and redis_command(s.redis_port, "GET", "crowdsec:192.0.2.3_captcha") is None,
    )
    s.control()
    for blocked in (False, True):
        s.overrides = {
            "redisCacheHost": "fixture:6399",
            "redisCacheReadHosts": ["fixture:6399"],
        }
        s.config(block=blocked, token=100 + int(blocked))
        time.sleep(0.5)
        results = [s.request() for _ in range(100)]
        s.check(
            "unreachable-block-" + str(blocked),
            all(r[0] == (403 if blocked else 200) and r[1] <= 3 for r in results),
            statuses=sorted(set(r[0] for r in results)),
        )
    s.overrides = {}
    s.config(token=103)
    time.sleep(0.5)
    s.check(
        "foreign-sentinel",
        redis_command(s.redis_port, "GET", "other:sentinel") == "unchanged",
    )
    s.stop()
    s.overrides = {
        "redisCacheUsername": "",
        "redisCachePassword": "fixture-legacy",
        "redisCacheKeyPrefix": "",
    }
    s.start()
    s.check(
        "legacy-auth-empty-prefix",
        all(
            s.request()[0] == 200 and s.request("192.0.2.2")[0] == 403
            for _ in range(100)
        ),
    )
    s.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    suite = Suite(args.output)
    try:
        suite.setup()
        isolation(suite)
        suite.completed = True
    except Exception as exc:
        suite.check("harness", False, error=str(exc))
        raise
    finally:
        suite.cleanup()
    raise SystemExit(bool(suite.failures))
