"""Count synthetic DNS query packets inside a disposable Traefik network namespace.

Requires only NET_RAW in the isolated sidecar. Logs query counts and names, never
application payloads. Loopback/outgoing packet copies are excluded.
"""
import collections
import json
import socket
import struct
import time

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.settimeout(0.2)
counts = collections.Counter()
last = time.monotonic()
print(json.dumps({"ready": True}), flush=True)
while True:
    try:
        frame, address = sock.recvfrom(65535)
        if address[2] == socket.PACKET_OUTGOING or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        offset = (ip[0] & 15) * 4
        if ip[9] != 17 or len(ip) < offset + 20:
            continue
        source, destination = struct.unpack("!HH", ip[offset:offset+4])
        # Docker's embedded resolver may DNAT loopback queries to another port.
        if destination != 53 and ip[16:20] != socket.inet_aton("127.0.0.11"):
            continue
        payload = ip[offset+8:]
        if len(payload) < 12 or payload[2] & 128:
            continue
        labels, index = [], 12
        while index < len(payload) and payload[index]:
            length = payload[index]
            if length > 63 or index + length + 1 > len(payload):
                break
            labels.append(payload[index+1:index+1+length].decode("ascii", errors="replace"))
            index += length + 1
        else:
            counts[".".join(labels)] += 1
    except socket.timeout:
        pass
    if time.monotonic() - last >= 1:
        print(json.dumps({"queries": sum(counts.values()), "names": counts}), flush=True)
        last = time.monotonic()
