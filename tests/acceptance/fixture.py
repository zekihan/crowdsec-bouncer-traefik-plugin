"""Disposable LAPI/backend/CAPTCHA and fault-injecting Redis proxy."""

import http.server
import copy
import json
import socket
import socketserver
import threading
import time
import urllib.parse

state = {"fault": "", "command": "GET", "calls": 0}
lock = threading.Lock()


class HTTP(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        route = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(route.query)
        if route.path == "/control":
            with lock:
                state.update(
                    fault=query.get("fault", [""])[0],
                    command=query.get("command", ["GET"])[0],
                )
            body = b"ok"
        elif route.path == "/v1/decisions/stream":
            with lock:
                state["calls"] += 1
                snapshot = copy.deepcopy(state.get("snapshot"))
                snapshot_set = "snapshot" in state
                delay = state.get("delay", 0)
                state["inflight"] = state.get("inflight", 0) + 1
                state["max_inflight"] = max(
                    state.get("max_inflight", 0), state["inflight"]
                )
            time.sleep(delay)
            with lock:
                state["inflight"] -= 1
            body = json.dumps(
                {
                    "deleted": [{"value": "192.0.2.201"}],
                    "new": [{"type": "ban", "value": "192.0.2.200", "duration": "30s"}],
                }
            ).encode()
            if snapshot_set:
                if query.get("startup") != ["true"]:
                    snapshot = {"new": [], "deleted": []}
                body = json.dumps(snapshot).encode()
        elif route.path == "/v1/decisions":
            body = b"null"
        elif route.path == "/state":
            with lock:
                body = json.dumps(state).encode()
        else:
            body = b"fixture-backend"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        payload = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/snapshot":
            update = json.loads(payload)
            with lock:
                state["snapshot"] = update["snapshot"]
                state["delay"] = update.get("delay", 0)
                state["max_inflight"] = 0
        body = b'{"success":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def read_command(reader):
    first = reader.readline(4096)
    if not first:
        return None, None
    if not first.strip():
        return read_command(reader)
    if not first.startswith(b"*"):
        return first, first.strip().split()
    raw, args = first, []
    for _ in range(int(first[1:])):
        line = reader.readline(4096)
        size = int(line[1:])
        value = reader.read(size + 2)
        raw += line + value
        args.append(value[:-2])
    return raw, args


def reply(reader):
    line = reader.readline(4096)
    if line.startswith(b"$") and int(line[1:]) >= 0:
        return line + reader.read(int(line[1:]) + 2)
    return line


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        upstream = None
        try:
            reader = self.request.makefile("rb")
            while True:
                raw, args = read_command(reader)
                if raw is None:
                    break
                with lock:
                    fault, command = state["fault"], state["command"]
                if (command == "ALL" or args[0].decode().upper() == command) and fault:
                    if fault == "stall":
                        time.sleep(3)
                        break
                    if fault == "disconnect":
                        break
                    if fault == "slow":
                        for _ in range(30):
                            self.request.sendall(b"+")
                            time.sleep(0.1)
                        break
                    responses = {
                        "noperm": b"-NOPERM fixture denied\r\n",
                        "null": b"$-1\r\n",
                        "auth": b"-WRONGPASS fixture\r\n",
                        "malformed": b"?invalid\r\n",
                        "truncated": b"$8\r\nx",
                    }
                    self.request.sendall(responses[fault])
                    break
                if upstream is None:
                    upstream = socket.create_connection(("redis", 6379), timeout=3)
                    upstream_reader = upstream.makefile("rb")
                upstream.sendall(raw)
                self.request.sendall(reply(upstream_reader))
        except (OSError, ValueError):
            pass
        finally:
            if upstream:
                upstream.close()


class TCP(socketserver.ThreadingTCPServer):
    request_queue_size = 128
    allow_reuse_address = True
    daemon_threads = True


for port in (6380, 6381):
    server = TCP(("0.0.0.0", port), Proxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()


class HTTPServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128


HTTPServer(("0.0.0.0", 8080), HTTP).serve_forever()
