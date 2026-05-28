"""Sentinel ZTNA — Policy Enforcement Point (PEP).

A lightweight HTTP forward proxy that gates every request on a policy
decision from the backend. This is the component that, in production,
would replace a VPN concentrator: instead of granting blanket network
reachability post-authentication, every individual request is
re-authorised.

Flow
----
    client (curl -x …) ──► PEP :9090
                              │
                              ▼
                 POST /api/access  ──► PDP :8000
                              │
                              ▼ ALLOW / MONITOR / BLOCK
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
        forward to                          403 Forbidden
        target service                      (with reason)

Environment variables
---------------------
    ZTNA_PDP_URL    backend access endpoint  (default http://localhost:8000/api/access)
    ZTNA_LISTEN     "host:port"              (default 0.0.0.0:9090)
"""

from __future__ import annotations

import os
import socket
import sys
import threading
from datetime import datetime, timezone

try:
    import requests as req_lib
except ImportError:
    print("[FATAL] 'requests' not installed: pip install requests", file=sys.stderr)
    raise

# ─── configuration ────────────────────────────────────────────────────────────

PDP_URL = os.environ.get("ZTNA_PDP_URL", "http://localhost:8000/api/access")
LISTEN = os.environ.get("ZTNA_LISTEN", "0.0.0.0:9090")
PROXY_HOST, PROXY_PORT = LISTEN.split(":") if ":" in LISTEN else (LISTEN, "9090")
PROXY_PORT = int(PROXY_PORT)
BUFFER_SIZE = 8192
DEFAULT_HTTP_PORT = 80
PDP_TIMEOUT = 3.0

# ANSI colours for the demo TTY
C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_GREEN = "\033[38;5;46m"
C_YELLOW = "\033[38;5;220m"
C_RED = "\033[38;5;196m"
C_CYAN = "\033[38;5;51m"


def log(client_ip: str, host: str, path: str, decision: str, risk: int | None) -> None:
    colour = {"ALLOW": C_GREEN, "MONITOR": C_YELLOW, "BLOCK": C_RED}.get(decision, C_RESET)
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    risk_str = f"r={risk:>3}" if risk is not None else "r=  -"
    print(
        f"{C_DIM}{ts}{C_RESET} {C_CYAN}{client_ip:<15}{C_RESET} "
        f"{host:<28} {path:<32} {colour}{decision}{C_RESET} {risk_str}",
        flush=True,
    )


# ─── HTTP request parsing ─────────────────────────────────────────────────────

def parse_http_request(raw: bytes) -> dict | None:
    try:
        if b"\r\n\r\n" in raw:
            head, body = raw.split(b"\r\n\r\n", 1)
        else:
            head, body = raw, b""

        lines = head.decode("utf-8", errors="replace").split("\r\n")
        if not lines or not lines[0].strip():
            return None

        parts = lines[0].split(" ")
        if len(parts) < 2:
            return None
        method, raw_uri = parts[0].upper(), parts[1]
        version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

        uri_host_override = None
        if raw_uri.startswith(("http://", "https://")):
            without_scheme = raw_uri.split("://", 1)[1]
            slash = without_scheme.find("/")
            uri_host_override = without_scheme if slash == -1 else without_scheme[:slash]
            path = "/" if slash == -1 else without_scheme[slash:]
        else:
            path = raw_uri

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        raw_host = uri_host_override or headers.get("host", "")
        if ":" in raw_host:
            host, port_str = raw_host.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = DEFAULT_HTTP_PORT
        else:
            host, port = raw_host, DEFAULT_HTTP_PORT

        session_id = headers.get("x-session-id") or _query_param(path, "session_id")
        return {
            "method": method, "path": path, "version": version,
            "headers": headers, "body": body, "host": host, "port": port,
            "session_id": session_id, "user_agent": headers.get("user-agent", ""),
        }
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] parse error: {e}", flush=True)
        return None


def _query_param(path: str, key: str) -> str | None:
    if "?" not in path:
        return None
    qs = path.split("?", 1)[1]
    for p in qs.split("&"):
        if "=" in p:
            k, _, v = p.partition("=")
            if k.strip() == key:
                return v.strip()
    return None


# ─── PDP call ─────────────────────────────────────────────────────────────────

def query_pdp(session_id: str, client_ip: str, host: str, method: str,
              path: str, ua: str) -> tuple[str, int | None, list[str]]:
    try:
        r = req_lib.post(
            PDP_URL,
            json={
                "session_id": session_id,
                "ip_address": client_ip,
                "target_service": host,
                "method": method,
                "path": path,
                "user_agent": ua,
            },
            timeout=PDP_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        decision = (data.get("decision") or "BLOCK").upper()
        if decision not in ("ALLOW", "MONITOR", "BLOCK"):
            decision = "BLOCK"
        return decision, data.get("risk_score"), data.get("reasons") or []
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] PDP error: {e} — fail-closed BLOCK", flush=True)
        return "BLOCK", None, ["pdp_unreachable"]


# ─── HTTP responses ───────────────────────────────────────────────────────────

def http_response(code: int, reason: str, body: str,
                  extra_headers: dict[str, str] | None = None) -> bytes:
    b = body.encode("utf-8")
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": str(len(b)),
        "Connection": "close",
        "X-ZTNA-Gateway": "Sentinel/1.0",
    }
    if extra_headers:
        headers.update(extra_headers)
    head = f"HTTP/1.1 {code} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return (head + "\r\n").encode() + b


# ─── forwarding ───────────────────────────────────────────────────────────────

def forward_request(parsed: dict) -> bytes:
    host, port = parsed["host"], parsed["port"]
    path = parsed["path"] if parsed["path"].startswith("/") else "/" + parsed["path"]
    method = parsed["method"]

    headers = dict(parsed["headers"])
    headers.pop("proxy-connection", None)
    headers["host"] = host
    headers["connection"] = "close"
    headers.pop("x-session-id", None)

    head_lines = [f"{method} {path} HTTP/1.1"]
    head_lines.extend(f"{k.title()}: {v}" for k, v in headers.items())
    request_bytes = ("\r\n".join(head_lines) + "\r\n\r\n").encode() + parsed["body"]

    try:
        with socket.create_connection((host, port), timeout=8) as s:
            s.sendall(request_bytes)
            chunks: list[bytes] = []
            s.settimeout(8)
            while True:
                try:
                    data = s.recv(BUFFER_SIZE)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
        if not chunks:
            return http_response(502, "Bad Gateway", f"Empty response from {host}:{port}")
        return b"".join(chunks)
    except socket.timeout:
        return http_response(504, "Gateway Timeout", f"Target {host}:{port} timed out")
    except ConnectionRefusedError:
        return http_response(502, "Bad Gateway", f"Could not connect to {host}:{port}")
    except Exception as e:  # noqa: BLE001
        return http_response(502, "Bad Gateway", f"Forward error: {e}")


# ─── connection handler ───────────────────────────────────────────────────────

def handle_client(sock: socket.socket, addr) -> None:
    client_ip = addr[0]
    try:
        sock.settimeout(5)
        raw = b""
        try:
            while b"\r\n\r\n" not in raw:
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                raw += chunk
        except socket.timeout:
            pass

        if not raw:
            return

        parsed = parse_http_request(raw)
        if not parsed:
            sock.sendall(http_response(400, "Bad Request", "Could not parse HTTP request"))
            return

        host, path = parsed["host"] or "unknown", parsed["path"]

        if not parsed["session_id"]:
            log(client_ip, host, path, "BLOCK", None)
            sock.sendall(http_response(
                403, "Forbidden",
                "Sentinel ZTNA: missing X-Session-ID header (run the simulator to issue one).",
                {"X-ZTNA-Reason": "no_session_id"},
            ))
            return

        decision, risk, reasons = query_pdp(
            parsed["session_id"], client_ip, host,
            parsed["method"], path, parsed["user_agent"],
        )
        log(client_ip, host, path, decision, risk)

        if decision == "BLOCK":
            sock.sendall(http_response(
                403, "Forbidden",
                f"Sentinel ZTNA blocked this request.\n"
                f"risk={risk} reasons={', '.join(reasons)}",
                {"X-ZTNA-Reason": ",".join(reasons)[:200]},
            ))
            return

        # ALLOW / MONITOR → forward, but tag MONITORed requests in headers
        response = forward_request(parsed)
        if decision == "MONITOR":
            try:
                head, _, body = response.partition(b"\r\n\r\n")
                head += b"\r\nX-ZTNA-Mode: MONITOR"
                response = head + b"\r\n\r\n" + body
            except Exception:
                pass
        sock.sendall(response)
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] {client_ip}: {e}", flush=True)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(64)
    print(f"\n  {C_CYAN}Sentinel ZTNA — PEP{C_RESET}")
    print(f"  listen     {PROXY_HOST}:{PROXY_PORT}")
    print(f"  PDP        {PDP_URL}")
    print(f"  fail-mode  closed (BLOCK on PDP error)\n")
    print(f"  {C_DIM}time     client_ip       host                         path                             decision risk{C_RESET}")
    try:
        while True:
            client_sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[ZTNA] shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
