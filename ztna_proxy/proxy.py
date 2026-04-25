"""
ZTNA Gateway - Policy Enforcement Point (PEP)
=============================================
Architecture:
    Client → [This Proxy :9090] → [Backend /access :8000] → Target Server
                                        ↓
                               ALLOW / MONITOR / BLOCK

v4 changes:
- forward_request() rewritten with explicit path extraction,
  correct HTTP/1.1 formatting, and Connection: close
- Debug print shows exact request line being forwarded
"""

import socket
import threading
import datetime

try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARN] 'requests' not installed. sudo apt install python3-requests")
    print("[WARN] All traffic will BLOCK until requests is available.\n")

# ─── Configuration ────────────────────────────────────────────────────────────

PROXY_HOST        = "0.0.0.0"
PROXY_PORT        = 9090
BACKEND_URL       = "http://10.127.11.94:8000/access"
BUFFER_SIZE       = 4096
DEFAULT_HTTP_PORT = 80

# ─── Logging ──────────────────────────────────────────────────────────────────

def log(client_ip, host, path, decision):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[LOG] {now} | {client_ip} | {host} | {path} | {decision}", flush=True)

# ─── HTTP Parsing ─────────────────────────────────────────────────────────────

def parse_http_request(raw_data: bytes):
    """
    Parse a raw HTTP request. Handles both:
      Direct:  GET /path HTTP/1.1
      Proxy:   GET http://host/path HTTP/1.1  (what curl -x sends)
    Returns a dict or None on failure.
    """
    try:
        if b"\r\n\r\n" in raw_data:
            head_bytes, body = raw_data.split(b"\r\n\r\n", 1)
        else:
            head_bytes, body = raw_data, b""

        lines = head_bytes.decode("utf-8", errors="replace").split("\r\n")
        if not lines or not lines[0].strip():
            return None

        parts = lines[0].split(" ")
        if len(parts) < 2:
            return None

        method  = parts[0].upper()
        raw_uri = parts[1]
        version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

        # Handle absolute URI (curl -x sends: GET http://httpbin.org/get HTTP/1.1)
        uri_host_override = None
        if raw_uri.startswith("http://") or raw_uri.startswith("https://"):
            without_scheme = raw_uri.split("://", 1)[1]
            slash_pos = without_scheme.find("/")
            if slash_pos == -1:
                uri_host_override = without_scheme
                path = "/"
            else:
                uri_host_override = without_scheme[:slash_pos]
                path = without_scheme[slash_pos:]
        else:
            path = raw_uri

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        # Resolve host and port
        raw_host = uri_host_override or headers.get("host", "")
        if ":" in raw_host:
            host, port_str = raw_host.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = DEFAULT_HTTP_PORT
        else:
            host = raw_host
            port = DEFAULT_HTTP_PORT

        # Extract session_id
        session_id = headers.get("x-session-id")
        if not session_id and "?" in path:
            qs = path.split("?", 1)[1]
            for param in qs.split("&"):
                if "=" in param:
                    k, _, v = param.partition("=")
                    if k.strip() == "session_id":
                        session_id = v.strip()
                        break

        return {
            "method":     method,
            "path":       path,
            "version":    version,
            "headers":    headers,
            "body":       body,
            "host":       host,
            "port":       port,
            "session_id": session_id,
        }

    except Exception as e:
        print(f"[WARN] parse error: {e}")
        return None

# ─── Backend Decision Engine ──────────────────────────────────────────────────

def query_backend(session_id: str, client_ip: str, host: str = "") -> str:
    """POST to decision engine. Fail-closed → BLOCK on any error."""
    if not REQUESTS_AVAILABLE:
        return "BLOCK"
    try:
        resp = req_lib.post(
            BACKEND_URL,
            json={
                "session_id":     session_id,
                "ip_address":     client_ip,
                "target_service": host,
            },
            timeout=3,
        )
        resp.raise_for_status()
        decision = resp.json().get("decision", "BLOCK").upper()
        return decision if decision in ("ALLOW", "MONITOR", "BLOCK") else "BLOCK"
    except Exception as e:
        print(f"[WARN] Backend error: {e} — defaulting to BLOCK")
        return "BLOCK"

# ─── HTTP Response Helpers ────────────────────────────────────────────────────

def make_error_response(code: int, reason: str, body: str) -> bytes:
    b = body.encode("utf-8")
    return (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {len(b)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8") + b

# ─── Request Forwarding ───────────────────────────────────────────────────────

def forward_request(parsed: dict) -> bytes:
    """
    Forwards the HTTP request to the real target server.

    Fixes applied:
      ✔ path extraction  — /get extracted from http://httpbin.org/get
      ✔ request format   — GET /get HTTP/1.1 + Host + Connection: close
      ✔ response loop    — recv until server closes connection
    """
    host = parsed["host"]
    port = parsed["port"]

    # ✔ PATH EXTRACTION
    # parse_http_request() already extracted the relative path.
    # We ensure it starts with / and never send the full absolute URL.
    path = parsed["path"]
    if not path.startswith("/"):
        path = "/" + path

    # ✔ BUILD CORRECT HTTP REQUEST
    # Exactly the format the target server expects:
    #   GET /get HTTP/1.1
    #   Host: httpbin.org
    #   Connection: close
    forward_req  = f"GET {path} HTTP/1.1\r\n"
    forward_req += f"Host: {host}\r\n"
    forward_req += "Connection: close\r\n"
    forward_req += "\r\n"

    print(f"[DEBUG] Target  → {host}:{port}")
    print(f"[DEBUG] Request → {forward_req.splitlines()[0]}")

    try:
        # Connect to target server
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.settimeout(5)
        target_socket.connect((host, port))

        # Send the correctly formatted request
        target_socket.sendall(forward_req.encode())

        # ✔ RECEIVE FULL RESPONSE
        # Connection: close means server closes after response — loop until empty
        response = b""
        while True:
            try:
                data = target_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                response += data
            except socket.timeout:
                break

        target_socket.close()

        if not response:
            return make_error_response(502, "Bad Gateway",
                                       f"Empty response from {host}:{port}.")
        return response

    except socket.timeout:
        return make_error_response(504, "Gateway Timeout",
                                   f"Target {host}:{port} timed out.")
    except ConnectionRefusedError:
        return make_error_response(502, "Bad Gateway",
                                   f"Could not connect to {host}:{port}.")
    except Exception as e:
        return make_error_response(502, "Bad Gateway", f"Forward error: {e}")

# ─── Per-Connection Handler ───────────────────────────────────────────────────

def handle_client(client_sock: socket.socket, client_addr):
    client_ip = client_addr[0]
    try:
        # Read until full HTTP head received
        raw_data = b""
        client_sock.settimeout(5)
        try:
            while b"\r\n\r\n" not in raw_data:
                chunk = client_sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                raw_data += chunk
        except socket.timeout:
            pass

        if not raw_data:
            return

        parsed = parse_http_request(raw_data)
        if not parsed:
            client_sock.sendall(make_error_response(400, "Bad Request",
                                                    "Could not parse HTTP request."))
            return

        host = parsed["host"] or "unknown"
        path = parsed["path"]

        # Gate 1: session_id required
        if not parsed["session_id"]:
            log(client_ip, host, path, "BLOCK (no session_id)")
            client_sock.sendall(make_error_response(
                403, "Forbidden",
                "Access denied: missing X-Session-ID header or ?session_id= param."
            ))
            return

        # Gate 2: backend policy decision
        decision = query_backend(parsed["session_id"], client_ip, host)
        log(client_ip, host, path, decision)

        if decision == "BLOCK":
            client_sock.sendall(make_error_response(
                403, "Forbidden", "Access denied by Zero Trust policy."
            ))
            return

        # ALLOW or MONITOR → forward to real target
        response = forward_request(parsed)
        client_sock.sendall(response)

    except Exception as e:
        print(f"[ERROR] {client_ip}: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

# ─── Main ─────────────────────────────────────────────────────────────────────

def run_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(50)
    print(f"[ZTNA] Proxy listening on {PROXY_HOST}:{PROXY_PORT}")
    print(f"[ZTNA] Decision engine  → {BACKEND_URL}")
    print("[ZTNA] Press Ctrl+C to stop.\n")
    try:
        while True:
            client_sock, client_addr = server.accept()
            threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[ZTNA] Shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    run_proxy()
