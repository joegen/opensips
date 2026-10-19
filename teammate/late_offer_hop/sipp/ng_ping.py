#!/usr/bin/env python3
import os
import socket
import sys
import time


def ping(host, port, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cookie = os.urandom(6).hex()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        try:
            sock.sendto(f"{cookie} d7:command4:pinge".encode(), (host, port))
            data, _ = sock.recvfrom(4096)
            if data.startswith(cookie.encode()) and b"pong" in data:
                return True
        except OSError:
            pass
        finally:
            sock.close()
        time.sleep(0.2)
    return False


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22222
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0
    if ping(host, port, timeout):
        print("pong")
        return 0
    print(f"no pong from {host}:{port} within {timeout}s", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
