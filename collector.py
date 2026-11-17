#!/usr/bin/env python3
"""
Plumb: WordPress version monitor (collector).

Pulls a signed report from the Plumb Agent plugin on each site listed in
sites.json, verifies the signature on the response, compares core, plugin, and
theme versions against what's published on WordPress.org (or by the vendor's own
updater, for premium components), and writes a self-contained HTML dashboard
plus JSON snapshots.

Works on any host: WP Engine, GoDaddy, a VPS, anything that serves WordPress.

Usually run inside the Docker container (see README). Directly:

    python3 collector.py --env-file config/plumb.env                   # normal run
    python3 collector.py --demo                                        # fake data, no network
    python3 collector.py --new-secret acmecorp                         # make a site secret
    python3 collector.py --env-file config/plumb.env --check acmecorp  # pull one site, print the result
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import pathlib
import random
import re
import secrets
import sys
import threading
import time
from urllib.parse import urlsplit

try:
    import requests
except ImportError:  # demo mode and --new-secret still work without it
    requests = None

WPORG_CORE = "https://api.wordpress.org/core/version-check/1.7/"
WPORG_PLUGIN = "https://api.wordpress.org/plugins/info/1.2/"
WPORG_THEME = "https://api.wordpress.org/themes/info/1.2/"
AGENT_ROUTE = "/plumb/v1/report"
AGENT_LATEST = "1.0.0"  # bump when you ship a new agent; older agents get flagged
USER_AGENT = "plumb/1.0"
SITE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HERE = pathlib.Path(__file__).resolve().parent
log = logging.getLogger("plumb")


# --------------------------------------------------------------------------- config
def load_env_file(path: str | None) -> None:
    """Minimal KEY=VALUE loader so we don't need python-dotenv."""
    if not path:
        return
    p = pathlib.Path(path)
    if not p.exists():
        sys.exit(f"env file not found: {path}")
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self) -> None:
        self.sites_file = pathlib.Path(os.path.expanduser(os.environ.get("SITES_FILE", str(HERE / "config" / "sites.json"))))
        self.output_dir = pathlib.Path(os.path.expanduser(os.environ.get("OUTPUT_DIR", str(HERE / "output"))))
        self.workers = int(os.environ.get("WORKERS", "8"))
        self.timeout = int(os.environ.get("REQUEST_TIMEOUT", "30"))
        self.interval_hours = int(os.environ.get("INTERVAL_HOURS", "12"))
        self.history_keep = int(os.environ.get("HISTORY_KEEP", "60"))  # 60 x 12h = 30 days
        self.unverified_is_review = env_bool("UNVERIFIED_IS_REVIEW", True)
        self.stale_update_check_days = int(os.environ.get("STALE_UPDATE_CHECK_DAYS", "3"))


def load_sites(cfg: Config) -> list[dict]:
    if not cfg.sites_file.exists():
        sys.exit(f"sites file not found: {cfg.sites_file} (copy config/sites.example.json to config/sites.json)")
    raw = json.loads(cfg.sites_file.read_text(encoding="utf-8-sig"))  # utf-8-sig: Windows editors may add a BOM
    sites, seen = [], set()
    for i, s in enumerate(raw.get("sites", [])):
        name = s.get("name", "")
        if not SITE_NAME_RE.match(name):
            sys.exit(f"sites[{i}]: invalid or missing name {name!r}")
        if name in seen:
            sys.exit(f"sites[{i}]: duplicate name {name!r}")
        seen.add(name)
        url = (s.get("url") or "").rstrip("/")
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            sys.exit(f"site {name}: url must be a full URL like https://www.example.org")
        if parts.scheme == "http" and not s.get("allow_insecure"):
            sys.exit(f"site {name}: url is http://. Use https://, or set \"allow_insecure\": true for a lab site.")
        if s.get("secret"):
            sys.exit(f"site {name}: put the secret in .env and reference it with secret_env, not in sites.json")
        sites.append({
            "name": name,
            "url": url,
            "group": s.get("group") or "Ungrouped",
            "environment": s.get("environment") or "production",
            "secret_env": s.get("secret_env") or f"PLUMB_SECRET_{re.sub(r'[^A-Za-z0-9]', '_', name).upper()}",
            "endpoint": s.get("endpoint"),
            "allow_insecure": bool(s.get("allow_insecure")),
        })
    if not sites:
        sys.exit(f"no sites defined in {cfg.sites_file}")
    return sites


# --------------------------------------------------------------------------- versions
def vparse(v: str | None) -> tuple[int, ...] | None:
    """Leading dotted-numeric part of a version string, e.g. '6.8.1-RC1' -> (6, 8, 1)."""
    if not v:
        return None
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", str(v))
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def vcmp(a: str | None, b: str | None) -> int | None:
    """-1 if a<b, 0 if equal, 1 if a>b, None if either can't be parsed."""
    pa, pb = vparse(a), vparse(b)
    if pa is None or pb is None:
        return None
    n = max(len(pa), len(pb))
    pa, pb = pa + (0,) * (n - len(pa)), pb + (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


# --------------------------------------------------------------------------- HTTP helpers
def http_session():
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def get_json(session, url, params=None, ok_404=False, timeout=30):
    """GET with retry on 429/5xx. Honors Retry-After."""
    for attempt in range(5):
        try:
            r = session.get(url, params=params, timeout=timeout)
        except requests.RequestException as e:
            if attempt == 4:
                raise
            log.warning("request error %s (%s), retrying", url, e)
            time.sleep(2 ** attempt)
            continue
        if ok_404 and r.status_code == 404:
            return None
        if r.status_code == 429 or r.status_code >= 500:
            ra = r.headers.get("Retry-After", "")
            wait = int(ra) if ra.isdigit() else min(60, 2 ** attempt * 3)
            log.warning("HTTP %s from %s, waiting %ss", r.status_code, url, wait)
            time.sleep(wait)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError(f"giving up on {url} after retries")


# --------------------------------------------------------------------------- signed pull
def sign_request(secret: str, ts: str, nonce: str) -> str:
    msg = f"PLUMB1\nGET\n{AGENT_ROUTE}\n{ts}\n{nonce}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_response(secret: str, nonce: str, payload: dict) -> dict:
    if payload.get("v") != 1 or not isinstance(payload.get("report"), str):
        raise RuntimeError("unexpected response format (is the Plumb Agent installed?)")
    if not hmac.compare_digest(str(payload.get("nonce", "")), nonce):
        raise RuntimeError("response nonce doesn't match the request: possibly a cached or replayed response")
    expected = hmac.new(secret.encode(), f"PLUMB1-RESP\n{nonce}\n{payload['report']}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(payload.get("sig", ""))):
        raise RuntimeError("response signature is invalid: the report can't be trusted")
    return json.loads(payload["report"])


def pull_site(session, site: dict, secret: str, timeout: int) -> dict:
    base = site["url"]
    candidates = [site["endpoint"]] if site.get("endpoint") else [
        f"{base}/wp-json{AGENT_ROUTE}",
        f"{base}/?rest_route={AGENT_ROUTE}",  # sites without pretty permalinks
    ]
    last_err = None
    for url in candidates:
        nonce = secrets.token_hex(16)
        ts = str(int(time.time()))
        headers = {
            "X-Plumb-Timestamp": ts,
            "X-Plumb-Nonce": nonce,
            "X-Plumb-Signature": sign_request(secret, ts, nonce),
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        }
        # The nonce in the query string also stops any page cache from serving an old response.
        try:
            r = session.get(url, params={"_plumb": nonce}, headers=headers, timeout=timeout, allow_redirects=False)
        except requests.exceptions.SSLError as e:
            raise RuntimeError(f"TLS certificate problem: {e}") from None
        except requests.RequestException as e:
            raise RuntimeError(f"connection failed: {e.__class__.__name__}: {e}") from None
        if r.is_redirect:
            raise RuntimeError(f"redirected to {r.headers.get('Location')}; set this site's url to the final address")
        if r.status_code == 404:
            last_err = ("404: agent not installed, or it refused the request. The agent answers 404 on purpose; "
                        "check its Recent activity in wp-admin > Settings > Plumb Agent for the real reason.")
            continue
        if r.status_code in (401, 403):
            raise RuntimeError(f"HTTP {r.status_code}: something in front of WordPress (WAF or security plugin) blocked the request")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} from {url}")
        try:
            payload = r.json()
        except ValueError:
            raise RuntimeError("response wasn't JSON (a WAF challenge page or a PHP error?)") from None
        return verify_response(secret, nonce, payload)
    raise RuntimeError(last_err or "no endpoint answered")


# --------------------------------------------------------------------------- WordPress.org
_WPORG_FIELDS_OFF = ("sections", "description", "short_description", "screenshots", "banners", "icons",
                     "contributors", "ratings", "versions", "reviews", "tags", "compatibility")


class WpOrg:
    def __init__(self, session):
        self.s = session
        self._cache: dict[tuple[str, str], dict | None] = {}
        self._lock = threading.Lock()

    def core_latest(self) -> str:
        data = get_json(self.s, WPORG_CORE)
        return data["offers"][0]["current"]

    def lookup(self, kind: str, slug: str) -> dict | None:
        key = (kind, slug)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        url = WPORG_PLUGIN if kind == "plugin" else WPORG_THEME
        params = {"action": f"{kind}_information", "request[slug]": slug}
        params.update({f"request[fields][{f}]": "0" for f in _WPORG_FIELDS_OFF})
        try:
            data = get_json(self.s, url, params, ok_404=True)
        except Exception as e:  # one failed lookup shouldn't sink the run
            log.warning("wordpress.org lookup failed for %s %s: %s", kind, slug, e)
            data = None
        info = None
        if isinstance(data, dict) and not data.get("error") and data.get("version"):
            info = {"version": data["version"]}
        with self._lock:
            self._cache[key] = info
        return info


# --------------------------------------------------------------------------- evaluation
ACTIVE_STATUSES = {"active", "network-active", "parent"}  # a parent theme's code runs too


def evaluate_component(kind: str, c: dict, wporg_info: dict | None) -> dict:
    installed = c.get("version") or ""
    vendor = c.get("update_version")
    latest, source = None, None
    if wporg_info:
        latest, source = wporg_info["version"], "wordpress.org"
    elif vendor:
        latest, source = vendor, "vendor updater"

    cmp = vcmp(installed, latest) if latest else None
    if cmp is None:
        state = "unverified"
    elif cmp < 0:
        state = "outdated"
    else:
        state = "current"

    # The site's own update check wins if it reports something newer (covers premium
    # components that happen to share a slug with a free wordpress.org listing).
    if vendor and state != "outdated" and vcmp(installed, vendor) == -1:
        state, latest, source = "outdated", vendor, "vendor updater"

    return {
        "kind": kind,
        "slug": c.get("slug"),
        "title": c.get("name") or c.get("slug"),
        "status": c.get("status"),
        "active": c.get("status") in ACTIVE_STATUSES,
        "installed": installed,
        "latest": latest,
        "source": source,
        "state": state,
        "auto_update": bool(c.get("auto_update")),
    }


def new_site_record(site: dict) -> dict:
    return {
        "id": site["name"],
        "name": site["name"],
        "url": site["url"],
        "group": site["group"],
        "environment": site["environment"],
        "primary_domain": urlsplit(site["url"]).netloc,
    }


def evaluate_site(rec: dict, report: dict | None, core_latest: str, wporg, cfg: Config) -> dict:
    if report is None:
        rec.update(status="unreachable", components=[], core_state="unknown", counts={}, notes=[])
        return rec

    env = report.get("environment") or {}
    rec.update(
        core_version=(report.get("core") or {}).get("version"),
        core_latest=core_latest,
        php_version=env.get("php_version"),
        db_server=env.get("db_server"),
        is_multisite=env.get("multisite"),
        site_count=env.get("site_count"),
        agent_version=report.get("agent_version"),
        flags=report.get("flags") or {},
        mu_plugins=report.get("mu_plugins") or [],
        reported_home_url=report.get("home_url"),
    )

    comps = []
    for p in report.get("plugins") or []:
        comps.append(evaluate_component("plugin", p, wporg.lookup("plugin", p.get("slug", ""))))
    for t in report.get("themes") or []:
        comps.append(evaluate_component("theme", t, wporg.lookup("theme", t.get("slug", ""))))
    order = {"outdated": 0, "unverified": 1, "current": 2}
    comps.sort(key=lambda x: (order[x["state"]], not x["active"], x["kind"], (x["title"] or "").lower()))
    rec["components"] = comps

    c = vcmp(rec["core_version"], core_latest)
    rec["core_state"] = "unknown" if c is None else ("behind" if c < 0 else "current")

    def count(state, active):
        return sum(1 for x in comps if x["state"] == state and x["active"] == active)

    rec["counts"] = {
        "plugins": sum(1 for x in comps if x["kind"] == "plugin"),
        "themes": sum(1 for x in comps if x["kind"] == "theme"),
        "inactive": sum(1 for x in comps if not x["active"]),
        "outdated_active": count("outdated", True),
        "outdated_inactive": count("outdated", False),
        "unverified_active": count("unverified", True),
        "unverified_inactive": count("unverified", False),
    }

    notes = []
    agent_old = vcmp(rec["agent_version"], AGENT_LATEST) == -1
    if agent_old:
        notes.append(f"Plumb Agent {rec['agent_version']} is older than {AGENT_LATEST}; update it.")
    checks = report.get("update_checks") or {}
    pc = checks.get("plugins")
    if pc and time.time() - pc > cfg.stale_update_check_days * 86400:
        days = int((time.time() - pc) // 86400)
        notes.append(f"The site's own plugin update check last ran {days} days ago, so vendor-updater versions may be stale. "
                     "wp-cron may not be running.")
    elif not pc:
        notes.append("The site has never run its own plugin update check; vendor-updater versions are unavailable.")
    home = report.get("home_url")
    if home and urlsplit(home).netloc.lower() != rec["primary_domain"].lower():
        notes.append(f"The site reports its home URL as {home}, which doesn't match the URL in sites.json.")
    rec["notes"] = notes

    counts = rec["counts"]
    if rec["core_state"] == "behind" or counts["outdated_active"]:
        status = "action"
    elif (counts["outdated_inactive"] or rec["core_state"] == "unknown" or agent_old
          or (cfg.unverified_is_review and counts["unverified_active"])):
        status = "review"
    else:
        status = "current"
    rec["status"] = status
    return rec


# --------------------------------------------------------------------------- live run
def collect_one(session, site: dict, cfg: Config) -> tuple[dict, dict | None]:
    rec = new_site_record(site)
    secret = os.environ.get(site["secret_env"], "").strip()  # tolerate Windows line endings
    t0 = time.time()
    report = None
    if len(secret) < 32:
        rec["error"] = f"no secret: set {site['secret_env']} in .env (at least 32 characters)"
    else:
        try:
            report = pull_site(session, site, secret, cfg.timeout)
            rec["error"] = None
        except Exception as e:
            rec["error"] = str(e)[:400]
    if rec["error"]:
        log.warning("%s: %s", site["name"], rec["error"])
    rec["collect_seconds"] = round(time.time() - t0, 1)
    return rec, report


def run_live(cfg: Config, only: str | None = None):
    if requests is None:
        sys.exit("The 'requests' package is required: pip install requests")
    sites = load_sites(cfg)
    if only:
        sites = [s for s in sites if s["name"] == only]
        if not sites:
            sys.exit(f"no site named {only!r} in {cfg.sites_file}")
    wporg = WpOrg(http_session())
    core_latest = wporg.core_latest()
    log.info("latest WordPress core on wordpress.org: %s", core_latest)
    log.info("pulling %d sites with %d workers", len(sites), cfg.workers)
    session = http_session()
    results = []
    with cf.ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        for f in cf.as_completed([pool.submit(collect_one, session, s, cfg) for s in sites]):
            results.append(f.result())
    return results, core_latest, wporg


# --------------------------------------------------------------------------- demo data
class FakeWpOrg:
    def __init__(self, plugins, themes):
        self.t = {"plugin": plugins, "theme": themes}

    def lookup(self, kind, slug):
        v = self.t[kind].get(slug)
        return {"version": v} if v else None


def run_demo(cfg: Config):
    rnd = random.Random(7)
    core_latest = "6.9.1"
    catalog = {
        "akismet": ("Akismet Anti-spam", "5.5"), "wordpress-seo": ("Yoast SEO", "26.4"),
        "contact-form-7": ("Contact Form 7", "6.1.3"), "woocommerce": ("WooCommerce", "10.3.5"),
        "elementor": ("Elementor", "3.33.1"), "wordfence": ("Wordfence Security", "8.1.1"),
        "updraftplus": ("UpdraftPlus", "1.25.9"), "redirection": ("Redirection", "5.5.2"),
        "classic-editor": ("Classic Editor", "1.6.7"), "wp-mail-smtp": ("WP Mail SMTP", "4.7.0"),
    }
    premium = {"gravityforms": ("Gravity Forms", "2.9.21"), "advanced-custom-fields-pro": ("Advanced Custom Fields PRO", "6.6.2")}
    themes = {"twentytwentyfive": ("Twenty Twenty-Five", "1.3"), "twentytwentyfour": ("Twenty Twenty-Four", "1.4"),
              "astra": ("Astra", "4.11.15")}
    roster = [
        ("acmecorp", "Acme Corp", "production"), ("acmecorp-stg", "Acme Corp", "staging"),
        ("bluefinch", "Blue Finch Studio", "production"), ("harborchurch", "Harbor Church", "production"),
        ("harborchurch-stg", "Harbor Church", "staging"), ("lakeview", "Lakeview Academy", "production"),
        ("northwind", "Northwind Foods", "production"), ("pinecrest", "Pinecrest Clinic", "production"),
        ("redoakbank", "Red Oak Bank", "production"), ("redoak-dev", "Red Oak Bank", "development"),
        ("summitcl", "Summit Legal", "production"), ("tallgrass", "Tallgrass Ministries", "production"),
    ]

    def older(v):
        p = list(vparse(v))
        i = rnd.choice([j for j in range(len(p)) if p[j] > 0])
        p[i] -= 1
        return ".".join(map(str, p))

    def comp(slug, name, latest, outdated, status="active", vendor_feed=True, wporg=True):
        ver = older(latest) if outdated else latest
        return {"slug": slug, "name": name, "version": ver, "status": status,
                "update_version": latest if (outdated and vendor_feed) else None,
                "auto_update": rnd.random() > 0.7}

    out = []
    now = int(time.time())
    for idx, (name, group, envname) in enumerate(roster):
        site = {"name": name, "url": f"https://{'www.' if envname == 'production' else ''}{name}.org",
                "group": group, "environment": envname}
        rec = new_site_record(site)
        rec["collect_seconds"] = round(rnd.uniform(0.4, 2.5), 1)
        if name == "summitcl":
            rec["error"] = ("404: agent not installed, or it refused the request. The agent answers 404 on purpose; "
                            "check its Recent activity in wp-admin > Settings > Plumb Agent for the real reason.")
            out.append((rec, None))
            continue
        rec["error"] = None
        plugins = [comp(s, *catalog[s], outdated=rnd.random() < 0.12,
                        status="active" if rnd.random() > 0.2 else "inactive")
                   for s in rnd.sample(list(catalog), rnd.randint(4, 8))]
        for s, (n, v) in premium.items():
            if rnd.random() > 0.5:
                plugins.append(comp(s, n, v, outdated=rnd.random() < 0.4, vendor_feed=rnd.random() > 0.3))
        theme_slug = rnd.choice(list(themes))
        tlist = [comp(theme_slug, *themes[theme_slug], outdated=rnd.random() < 0.15)]
        for s in themes:
            if s != theme_slug and rnd.random() > 0.5:
                tlist.append(comp(s, *themes[s], outdated=rnd.random() < 0.3, status="inactive"))
        report = {
            "agent_version": "1.0.0" if name != "tallgrass" else "0.9.0",
            "home_url": site["url"],
            "core": {"version": core_latest if rnd.random() > 0.25 else "6.8.3"},
            "environment": {"php_version": rnd.choice(["8.2.29", "8.3.24", "8.3.24", "8.4.11"]),
                            "db_server": "8.0.39", "multisite": False, "site_count": 1},
            "flags": {"file_editing_disabled": rnd.random() > 0.4, "wp_debug": rnd.random() < 0.1,
                      "wp_debug_display": False},
            "update_checks": {"plugins": now - (rnd.randint(1, 20) * 3600 if name != "lakeview" else 9 * 86400)},
            "plugins": plugins, "themes": tlist,
            "mu_plugins": [{"file": "plumb-agent.php", "name": "Plumb Agent", "version": "1.0.0"}],
        }
        if idx == 2:  # one fully current site
            report["core"]["version"] = core_latest
            for c in report["plugins"] + report["themes"]:
                src = {**catalog, **premium, **themes}[c["slug"]]
                c["version"], c["update_version"] = src[1], None
                c["status"] = "active" if c in report["plugins"] else c["status"]
        out.append((rec, report))
    wp_plugins = {k: v[1] for k, v in catalog.items()}
    wp_themes = {k: v[1] for k, v in themes.items()}
    return out, core_latest, FakeWpOrg(wp_plugins, wp_themes)


# --------------------------------------------------------------------------- output
def atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def write_outputs(sites, core_latest, cfg: Config, started: dt.datetime, demo: bool) -> pathlib.Path:
    finished = dt.datetime.now(dt.timezone.utc)
    sev = {"action": 0, "unreachable": 1, "review": 2, "current": 3}
    sites.sort(key=lambda s: (sev[s["status"]], s["group"].lower(), s["name"]))
    summary = {k: sum(1 for s in sites if s["status"] == k) for k in sev}
    summary["sites"] = len(sites)
    summary["outdated"] = sum(s["counts"].get("outdated_active", 0) + s["counts"].get("outdated_inactive", 0) for s in sites)
    summary["unverified"] = sum(s["counts"].get("unverified_active", 0) + s["counts"].get("unverified_inactive", 0) for s in sites)
    payload = {
        "generated_at": finished.isoformat(timespec="seconds"),
        "started_at": started.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 1),
        "interval_hours": cfg.interval_hours,
        "core_latest": core_latest,
        "agent_latest": AGENT_LATEST,
        "unverified_is_review": cfg.unverified_is_review,
        "demo": demo,
        "summary": summary,
        "sites": sites,
    }
    data_json = json.dumps(payload, indent=2)
    out = cfg.output_dir
    atomic_write(out / "data" / "latest.json", data_json)
    stamp = finished.strftime("%Y%m%dT%H%M%SZ")
    atomic_write(out / "data" / "history" / f"{stamp}.json", data_json)
    hist = sorted((out / "data" / "history").glob("*.json"))
    for old in hist[: max(0, len(hist) - cfg.history_keep)]:
        old.unlink()

    template = (HERE / "dashboard_template.html").read_text(encoding="utf-8")
    embedded = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    atomic_write(out / "index.html", template.replace("/*__PLUMB_DATA__*/null", embedded))
    return out / "index.html"


# --------------------------------------------------------------------------- main
def cmd_new_secret(name: str) -> int:
    if not SITE_NAME_RE.match(name):
        sys.exit(f"invalid site name {name!r}")
    secret = secrets.token_hex(32)
    var = f"PLUMB_SECRET_{re.sub(r'[^A-Za-z0-9]', '_', name).upper()}"
    print(f"\nSecret for site '{name}' (256-bit). Store it in two places, nowhere else:\n")
    print(f"1) Plumb's .env:\n   {var}={secret}\n")
    print(f"2) The site's wp-config.php, above \"That's all, stop editing\":\n   define( 'PLUMB_AGENT_SECRET', '{secret}' );\n")
    print(f"sites.json can leave secret_env out; it defaults to {var}.\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file", help="path to a KEY=VALUE config file (e.g. .env)")
    ap.add_argument("--demo", action="store_true", help="generate a dashboard from fake data, no network")
    ap.add_argument("--new-secret", metavar="SITE", help="generate a secret for a site and print where it goes")
    ap.add_argument("--check", metavar="SITE", help="pull one site and print its evaluated result; writes nothing")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.new_secret:
        return cmd_new_secret(args.new_secret)
    load_env_file(args.env_file)
    cfg = Config()
    started = dt.datetime.now(dt.timezone.utc)

    if args.demo:
        pairs, core_latest, wporg = run_demo(cfg)
    else:
        pairs, core_latest, wporg = run_live(cfg, only=args.check)

    sites = [evaluate_site(rec, report, core_latest, wporg, cfg) for rec, report in pairs]

    if args.check:
        print(json.dumps(sites[0], indent=2))
        return 0 if sites[0]["status"] != "unreachable" else 1

    path = write_outputs(sites, core_latest, cfg, started, args.demo)
    failed = sum(1 for s in sites if s["status"] == "unreachable")
    log.info("dashboard written to %s (%d sites, %d unreachable)", path, len(sites), failed)
    # Non-zero exit if every site failed, so the scheduler surfaces a broken run.
    return 2 if sites and failed == len(sites) else 0


if __name__ == "__main__":
    sys.exit(main())
