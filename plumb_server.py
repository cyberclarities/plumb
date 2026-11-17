#!/usr/bin/env python3
"""
Plumb container entrypoint.

    serve               run the collector every INTERVAL_HOURS and serve the dashboard (default)
    run-once            run the collector now, then exit
    check SITE          pull one site and print the result
    new-secret SITE     generate a secret for a site and print where it goes
    demo                like serve, but with fake data (no sites.json or secrets needed)

The dashboard is served over HTTPS on PLUMB_PORT (default 6443) behind HTTP Basic
authentication. Nothing else is served: "/", "/data/latest.json", and "/healthz".
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import http.server
import json
import logging
import os
import pathlib
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

APP = pathlib.Path(__file__).resolve().parent
COLLECTOR = APP / "collector.py"
log = logging.getLogger("plumb.server")


# --------------------------------------------------------------------------- settings
def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


class Settings:
    def __init__(self, demo: bool = False) -> None:
        self.demo = demo or env("PLUMB_DEMO").lower() in ("1", "true", "yes")
        self.port = int(env("PLUMB_PORT", "6443"))
        self.bind = env("PLUMB_BIND", "0.0.0.0")
        self.config_dir = pathlib.Path(env("PLUMB_CONFIG", "/config"))
        self.data_dir = pathlib.Path(env("PLUMB_DATA", "/data"))
        self.output_dir = pathlib.Path(env("OUTPUT_DIR", str(self.data_dir / "output")))
        os.environ["OUTPUT_DIR"] = str(self.output_dir)
        os.environ.setdefault("SITES_FILE", str(self.config_dir / "sites.json"))
        self.interval_h = float(env("INTERVAL_HOURS", "12"))
        self.retry_min = float(env("RETRY_MINUTES", "30"))
        self.run_timeout = int(env("RUN_TIMEOUT_MINUTES", "60")) * 60
        self.auth = env("PLUMB_DASHBOARD_AUTH", "on").lower() not in ("off", "false", "0", "no")
        self.user = env("PLUMB_DASHBOARD_USER", "plumb")
        self.password = os.environ.get("PLUMB_DASHBOARD_PASSWORD", "").rstrip("\r\n")  # tolerate Windows line endings
        self.hostnames = [h.strip() for h in env("PLUMB_HOSTNAMES").split(",") if h.strip()]

    def validate(self) -> None:
        if self.auth and len(self.password) < 12:
            sys.exit("PLUMB_DASHBOARD_PASSWORD must be set to at least 12 characters "
                     "(or set PLUMB_DASHBOARD_AUTH=off, which isn't recommended).")
        if not self.demo and not pathlib.Path(os.environ["SITES_FILE"]).exists():
            sys.exit(f"{os.environ['SITES_FILE']} not found. Copy config/sites.example.json to config/sites.json "
                     "and list your sites, or start in demo mode (PLUMB_DEMO=1) to preview the dashboard.")


# --------------------------------------------------------------------------- TLS
def _wanted_names(s: Settings) -> list[str]:
    return list(dict.fromkeys(["localhost", *s.hostnames, "127.0.0.1"]))


def _selfsigned_is_current(cert_path: pathlib.Path, wanted: list[str]) -> bool:
    """True if the existing self-signed certificate covers exactly these names and isn't near expiry."""
    from cryptography import x509
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have = {str(v) for v in san.get_values_for_type(x509.DNSName)} | \
               {str(v) for v in san.get_values_for_type(x509.IPAddress)}
        expires = cert.not_valid_after_utc
    except Exception:
        return False
    return have == set(wanted) and expires - dt.datetime.now(dt.timezone.utc) > dt.timedelta(days=30)


def ensure_certificate(s: Settings) -> tuple[pathlib.Path, pathlib.Path, bool]:
    """Use the operator's certificate if present; otherwise keep a self-signed one that matches PLUMB_HOSTNAMES."""
    user_cert, user_key = s.config_dir / "tls" / "cert.pem", s.config_dir / "tls" / "key.pem"
    if user_cert.exists() and user_key.exists():
        return user_cert, user_key, True
    tls_dir = s.data_dir / "tls"
    cert, key = tls_dir / "selfsigned-cert.pem", tls_dir / "selfsigned-key.pem"
    wanted = _wanted_names(s)
    if cert.exists() and key.exists():
        if _selfsigned_is_current(cert, wanted):
            return cert, key, False
        log.info("PLUMB_HOSTNAMES changed or the certificate is near expiry; making a new self-signed certificate")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import ipaddress

    tls_dir.mkdir(parents=True, exist_ok=True)
    pkey = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for n in wanted:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, s.hostnames[0] if s.hostnames else "plumb")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(pkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(pkey, hashes.SHA256())
    )
    key.write_bytes(pkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    os.chmod(key, 0o600)
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    log.info("created a self-signed certificate for: %s", ", ".join(wanted))
    return cert, key, False


def fingerprint(cert_path: pathlib.Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# --------------------------------------------------------------------------- scheduler
class Scheduler(threading.Thread):
    """Runs the collector on schedule, and right away when the dashboard is missing,
    shows the wrong mode (demo vs. live), or sites.json has changed since the last run."""

    def __init__(self, s: Settings):
        super().__init__(daemon=True, name="scheduler")
        self.s = s
        self.stop = threading.Event()
        self.state = {"last_attempt": None, "last_ok": None, "last_error": None, "running": False}
        self._snap: tuple[float, tuple[float | None, bool | None]] | None = None

    def snapshot(self) -> tuple[float | None, bool | None]:
        """(generated_at, demo) of the current dashboard data; re-read only when the file changes."""
        p = self.s.output_dir / "data" / "latest.json"
        try:
            mtime = p.stat().st_mtime
        except OSError:
            return None, None
        if self._snap and self._snap[0] == mtime:
            return self._snap[1]
        try:
            d = json.loads(p.read_text())
            val = (dt.datetime.fromisoformat(d["generated_at"]).timestamp(), bool(d.get("demo")))
        except Exception:
            val = (None, None)
        self._snap = (mtime, val)
        return val

    def last_generated(self) -> float | None:
        return self.snapshot()[0]

    @staticmethod
    def sites_mtime() -> float | None:
        try:
            return pathlib.Path(os.environ["SITES_FILE"]).stat().st_mtime
        except OSError:
            return None

    def reason_to_run(self, now: float) -> str | None:
        last, was_demo = self.snapshot()
        if last is None:
            return "no dashboard yet"
        if was_demo != self.s.demo:
            return "switching to demo data" if self.s.demo else "switching from demo to live data"
        if not self.s.demo and (self.sites_mtime() or 0) > last:
            return "sites.json changed"
        if now >= last + self.s.interval_h * 3600:
            return "scheduled"
        return None

    def run_collector(self, reason: str) -> bool:
        cmd = [sys.executable, str(COLLECTOR)] + (["--demo"] if self.s.demo else [])
        self.state.update(running=True, last_attempt=time.time())
        log.info("collector run starting (%s)%s", reason, ", demo data" if self.s.demo else "")
        try:
            proc = subprocess.run(cmd, timeout=self.s.run_timeout, capture_output=True, text=True)
            for line in (proc.stdout + proc.stderr).splitlines():
                log.info("collector: %s", line)
            # exit 2 = every site unreachable; the dashboard was still written and shows why
            ok = proc.returncode in (0, 2)
            self.state["last_error"] = None if ok else f"collector exited {proc.returncode}"
        except subprocess.TimeoutExpired:
            ok, self.state["last_error"] = False, f"collector ran longer than {self.s.run_timeout // 60} minutes"
        finally:
            self.state["running"] = False
        if ok:
            self.state["last_ok"] = time.time()
        log.info("collector run %s", "finished" if ok else f"FAILED: {self.state['last_error']}")
        return ok

    def run(self) -> None:
        retry_at = 0.0       # after a failed run, don't try again before this
        announced = None     # last "next run" time logged, so the log isn't repeated every minute
        while not self.stop.is_set():
            now = time.time()
            # A fixed sites.json shouldn't wait out the retry delay.
            if retry_at and (self.sites_mtime() or 0) > (self.state["last_attempt"] or 0):
                retry_at = 0.0
            reason = self.reason_to_run(now)
            if reason and now >= retry_at:
                ok = self.run_collector(reason)
                if ok and self.reason_to_run(time.time()):
                    # Reported success but the dashboard didn't change; don't spin re-running it.
                    log.warning("collector finished but the dashboard wasn't updated; check OUTPUT_DIR")
                    ok = False
                retry_at = 0.0 if ok else time.time() + self.s.retry_min * 60
                continue
            last = self.last_generated()
            due = retry_at if retry_at else (last + self.s.interval_h * 3600 if last else now)
            if due != announced:
                log.info("next collector run %s at %s", "retry" if retry_at else "scheduled",
                         dt.datetime.fromtimestamp(due, dt.timezone.utc).isoformat(timespec="minutes"))
                announced = due
            # Wake every minute so an edited sites.json or a manual run-once is noticed promptly.
            self.stop.wait(max(1.0, min(due - time.time(), 60)))


# --------------------------------------------------------------------------- HTTP
PENDING_PAGE = b"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="30">
<title>Plumb</title><style>body{font:15px system-ui,sans-serif;margin:15vh auto;max-width:520px;color:#222;padding:0 20px}
@media(prefers-color-scheme:dark){body{background:#1a1a19;color:#eee}}</style></head><body>
<h1>Plumb</h1><p>The first check of your sites is running. This page refreshes on its own every 30 seconds.</p>
<p>If it's still here after 15 minutes, ask your Plumb administrator to look at the container's logs.</p></body></html>"""

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                               "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

FAIL_LIMIT, FAIL_WINDOW = 10, 900


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Plumb"
    sys_version = ""
    timeout = 30  # drop clients that stall mid-request
    protocol_version = "HTTP/1.1"

    # set on the class by serve()
    settings: Settings = None  # type: ignore
    scheduler: Scheduler = None  # type: ignore
    hsts = False
    failures: dict[str, list[float]] = {}
    lock = threading.Lock()

    def log_message(self, fmt, *args):  # never logs headers, so credentials never reach the log
        log.info("%s %s", self.client_address[0], fmt % args)

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: dict | None = None):
        self.send_response(code)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        if self.hsts:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _locked_out(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            recent = [t for t in self.failures.get(ip, []) if now - t < FAIL_WINDOW]
            self.failures[ip] = recent
            return len(recent) >= FAIL_LIMIT

    def _record_failure(self, ip: str) -> None:
        now = time.time()
        with self.lock:
            self.failures.setdefault(ip, []).append(now)
            if len(self.failures) > 1000:  # forget addresses with no recent failures
                for k in [k for k, v in self.failures.items() if not v or now - v[-1] > FAIL_WINDOW]:
                    del self.failures[k]

    def _authorized(self) -> bool:
        s = self.settings
        if not s.auth:
            return True
        ip = self.client_address[0]
        if self._locked_out(ip):
            self._send(429, b"Too many failed sign-in attempts. Try again in 15 minutes.\n", "text/plain; charset=utf-8",
                       {"Retry-After": str(FAIL_WINDOW)})
            return False
        header = self.headers.get("Authorization", "")
        ok = False
        if header.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(header[6:], validate=True).decode("utf-8").partition(":")
                # evaluate both comparisons every time
                ok = hmac.compare_digest(user.encode(), s.user.encode()) & hmac.compare_digest(pw.encode(), s.password.encode())
            except Exception:
                ok = False
        if not ok:
            if header:
                self._record_failure(ip)
                log.warning("%s failed sign-in", ip)
            self._send(401, b"Sign in to view the Plumb dashboard.\n", "text/plain; charset=utf-8",
                       {"WWW-Authenticate": 'Basic realm="Plumb", charset="UTF-8"'})
        return ok

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            return self._health()
        if not self._authorized():
            return
        out = self.settings.output_dir
        if path in ("/", "/index.html"):
            page = out / "index.html"
            return self._send(200, page.read_bytes() if page.exists() else PENDING_PAGE)
        if path == "/data/latest.json":
            p = out / "data" / "latest.json"
            if p.exists():
                return self._send(200, p.read_bytes(), "application/json")
        self._send(404, b"Not found.\n", "text/plain; charset=utf-8")

    do_HEAD = do_GET

    def _not_allowed(self):
        self._send(405, b"Method not allowed.\n", "text/plain; charset=utf-8", {"Allow": "GET, HEAD"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed

    def _health(self):
        st = self.scheduler.state
        last = self.scheduler.last_generated()
        limit = (self.settings.interval_h + 1) * 3600
        if last is None:
            status, code = ("starting", 200) if time.time() - START < 3600 else ("no-data", 503)
        elif time.time() - last > limit:
            status, code = "stale", 503
        else:
            status, code = "ok", 200
        body = {"status": status, "running": st["running"],
                "last_run": dt.datetime.fromtimestamp(last, dt.timezone.utc).isoformat(timespec="seconds") if last else None}
        self._send(code, json.dumps(body).encode(), "application/json")


HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$")


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    ssl_ctx: ssl.SSLContext = None  # type: ignore

    def finish_request(self, request, client_address):
        """Runs in the request's own thread: a slow or silent client can't hold up anyone else."""
        request.settimeout(15)
        first = request.recv(1, socket.MSG_PEEK)
        if not first:
            return
        if first != b"\x16":  # not a TLS handshake: someone typed http:// instead of https://
            return self._redirect_to_https(request, client_address)
        tls = self.ssl_ctx.wrap_socket(request, server_side=True)
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            tls.close()

    def _redirect_to_https(self, sock, client_address):
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
        lines = data.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        path = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else "/"
        host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
        if not HOST_RE.match(host):
            host = f"localhost:{self.server_address[1]}"
        location = f"https://{host}{path}"
        body = (f"Plumb only answers over HTTPS. Go to {location}\n").encode()
        sock.sendall(b"HTTP/1.1 301 Moved Permanently\r\nLocation: " + location.encode("latin-1", "replace") +
                     b"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " + str(len(body)).encode() +
                     b"\r\nConnection: close\r\n\r\n" + body)
        log.info("%s plain HTTP request; redirected to HTTPS", client_address[0])

    def handle_error(self, request, client_address):
        # Port scanners, failed handshakes and dropped connections end up here. One line, no traceback.
        exc = sys.exc_info()[1]
        log.info("%s connection closed: %s", client_address[0], exc.__class__.__name__ if exc else "error")


START = time.time()


def serve(demo: bool = False) -> int:
    s = Settings(demo=demo)
    s.validate()
    s.output_dir.mkdir(parents=True, exist_ok=True)
    cert, key, user_supplied = ensure_certificate(s)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)

    sched = Scheduler(s)
    Handler.settings, Handler.scheduler, Handler.hsts = s, sched, user_supplied
    Server.ssl_ctx = ctx
    httpd = Server((s.bind, s.port), Handler)

    def shutdown(signum, _frame):
        log.info("received signal %s, shutting down", signum)
        sched.stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("Plumb dashboard: https://<this host>:%d/  (%s)", s.port,
             "your certificate" if user_supplied else "self-signed certificate")
    log.info("certificate SHA-256 fingerprint: %s", fingerprint(cert))
    if not s.auth:
        log.warning("dashboard sign-in is OFF (PLUMB_DASHBOARD_AUTH=off). Anyone who can reach this port can read it.")
    if s.demo:
        log.warning("DEMO MODE: the dashboard shows fake data")
    sched.start()
    httpd.serve_forever(poll_interval=1)
    httpd.server_close()
    return 0


def run_collector(*args: str) -> int:
    Settings()  # applies OUTPUT_DIR / SITES_FILE defaults
    return subprocess.call([sys.executable, str(COLLECTOR), *args])


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    args = sys.argv[1:] or ["serve"]
    cmd = args[0]
    if cmd == "serve":
        return serve()
    if cmd == "demo":
        return serve(demo=True)
    if cmd == "run-once":
        return run_collector()
    if cmd == "check" and len(args) == 2:
        return run_collector("--check", args[1])
    if cmd == "new-secret" and len(args) == 2:
        return run_collector("--new-secret", args[1])
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main())
