# Plumb

*WordPress version monitor.* A plumb line shows whether something is actually true, not just whether it looks true from where you stand.

> **Not technical?** Start with the [Plumb User Guide](docs/USER_GUIDE.md). It covers reading the dashboard and checking the Plumb Agent on a WordPress site, in plain language. This README is for whoever sets Plumb up.

Every 12 hours Plumb pulls a signed report from each WordPress site you list, checks core, plugin and theme versions against what's currently published, and shows a status for each site on a single dashboard page. It works on any host: WP Engine, shared hosting, a VPS, anything that serves WordPress.

Plumb runs as one Docker container on macOS, Windows or Linux. It serves the dashboard at **`https://<this computer>:6443/`**.

## How it works

```
 Plumb container (every 12 h)                   Each WordPress site
 ────────────────────────────                   ───────────────────
 config/sites.json + per-site secret
        │  GET /wp-json/plumb/v1/report
        │  signed: HMAC(secret, timestamp + nonce)
        └──────────────────────────────────────▶  Plumb Agent (must-use plugin)
                                                  1. HTTPS?  2. IP on allowlist?
                                                  3. rate limit  4. signature + 5-min window
                                                  5. nonce never seen before
        ┌──────────────────────────────────────  signed report, bound to that nonce
        │                                         (anything else: a plain 404)
 verify signature ─▶ compare with wordpress.org / vendor feed ─▶ dashboard
                                                                  https://<host>:6443/  (sign-in required)
```

| Part | Where it runs | Files |
|---|---|---|
| **Plumb Agent** | On each WordPress site, as a must-use plugin | `agent/plumb-agent.php` |
| **Plumb container** | On one computer you control: collector, scheduler and dashboard | `Dockerfile`, `compose.yaml`, `plumb_server.py`, `collector.py`, `dashboard_template.html` |
| **Your configuration** | The `config` folder, read by the container | `config/sites.json`, `config/plumb.env`, optional `config/tls/` |

## Security model

The goal is least privilege: Plumb needs read access to version numbers and nothing more.

**On each site**

- **Read-only agent.** It has one GET route with no inputs that change what it does. It can't modify the site; the only things it writes are its own replay, rate-limit and activity records.
- **A unique secret per site.** Each request is signed with HMAC-SHA256 over a timestamp and a one-time nonce. A leaked secret exposes one site's version list, not the fleet.
- **The secret lives outside the database.** `PLUMB_AGENT_SECRET` goes in `wp-config.php`, or in an environment variable. A SQL injection in some other plugin can't read it. Storing it in the database is a fallback that the settings page warns about.
- **Replay protection.** Requests older than 5 minutes are refused, and so is any nonce that's already been used.
- **Puller IP allowlist,** configured in wp-admin under **Settings > Plumb Agent**. It's checked before the signature, and accepts IPv4, IPv6 and CIDR ranges.
- **Silent failure.** Every refusal returns the same 404 WordPress gives for a route that doesn't exist, and the route is hidden from the public `/wp-json` index. The real reason is recorded in the agent's **Recent activity** log, and only there.
- **Rate limiting.** After 10 refused requests in 15 minutes, an IP is ignored, even if it then sends a valid request.
- **Signed responses.** The agent signs its report and binds it to the request's nonce. Plumb rejects a report that's been altered, replayed, or served from a cache.

**In the container**

- **HTTPS only, TLS 1.2 or newer,** on port 6443. A self-signed certificate is created on first start, or you can supply your own.
- **Sign-in required.** The container refuses to start without a dashboard password of at least 12 characters. After 10 failed sign-ins in 15 minutes, that address is locked out for 15 minutes. Credentials are never logged.
- **Serves three paths and nothing else:** the dashboard, `/data/latest.json`, and `/healthz`. `/healthz` needs no sign-in and reports only status and the last run time.
- **Strict browser headers:** a Content-Security-Policy, no framing, no referrer, and no caching.
- **Locked-down container.** It runs as an unprivileged user with a read-only filesystem and no Linux capabilities, and can't gain privileges. Only `/data` and `/tmp` are writable.
- **Secrets stay out of the image.** `config/plumb.env` is read by Docker when the container starts, and `.dockerignore` keeps everything except code out of the build.

If the Plumb container is compromised, the attacker gets the version inventory of your sites. That's reconnaissance, not access: nothing Plumb holds can log in to, write to, or run code on a site.

**What this doesn't protect against:** the agent runs on the site it reports on. A site that's already compromised can report whatever an attacker wants it to. Plumb detects drift; it isn't an integrity monitor.

## Setup

### 1. Install Docker

| Host | What to install |
|---|---|
| **macOS** (Intel or Apple Silicon) | [Docker Desktop for Mac](https://docs.docker.com/desktop/setup/install/mac-install/) |
| **Windows 10/11** | [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/), using the WSL 2 backend it recommends |
| **Linux** | [Docker Engine](https://docs.docker.com/engine/install/) and the Compose plugin |

On any of them, `docker compose version` must report **2.24 or newer**; `compose.yaml` uses a form of `env_file` that older versions reject.

**Licensing:**

- **Docker Desktop** (macOS and Windows) is free for organizations with fewer than 250 employees *and* less than $10 million in annual revenue, and for personal and educational use.
- **Paid subscription required:** larger organizations and government entities. Docker's terms don't exempt nonprofits by name, so a larger nonprofit should check. See [Docker's license page](https://docs.docker.com/subscription/desktop-license/).
- **Docker Engine** on Linux is open source and has no such requirement.

### 2. Put Plumb in a folder and create your config

Put the project folder somewhere permanent, such as `~/plumb` on macOS or Linux, or `C:\Users\<you>\plumb` on Windows. Then, from that folder:

**macOS / Linux**

```bash
cp config/plumb.env.example config/plumb.env
cp config/sites.example.json config/sites.json
chmod 600 config/plumb.env
```

**Windows (PowerShell)**

```powershell
Copy-Item config\plumb.env.example config\plumb.env
Copy-Item config\sites.example.json config\sites.json
```

Then edit `config/plumb.env`:

- **`PLUMB_DASHBOARD_PASSWORD`:** set a password of at least 12 characters. This is required.
- **`PLUMB_HOSTNAMES`:** the name or IP address people will use to reach the dashboard, such as `plumb.example.org,192.168.1.50`. This goes into the self-signed certificate.
- **`TZ`:** your time zone, for log timestamps.

On Windows, Notepad is fine. If your editor asks, save with **LF** (Unix) line endings; Plumb tolerates Windows line endings, but LF avoids surprises.

### 3. Preview it with fake data

In `config/plumb.env`, set `PLUMB_DEMO=1`. Then run:

```bash
docker compose up -d --build
```

Open **`https://localhost:6443/`** and sign in with the username and password from `plumb.env`.

Your browser will warn that the certificate isn't trusted. That's expected for a self-signed certificate (see [Certificates](#certificates)). To confirm you're connected to your own container, compare the certificate's SHA-256 fingerprint in the browser with the one in the logs:

```bash
docker compose logs plumb | grep fingerprint
```

When you're done looking, set `PLUMB_DEMO=0` and run `docker compose up -d`. Plumb notices the switch and replaces the demo data with a real check right away.

### 4. Find the address your sites will see

Every site's allowlist needs the **public outbound IP address** of the computer running Plumb:

```bash
docker compose exec plumb python -c "import urllib.request;print(urllib.request.urlopen('https://ifconfig.me/ip').read().decode())"
```

On a laptop that moves between networks, this address changes, and the sites will refuse Plumb until their allowlist is updated. For anything beyond a trial, run Plumb on a machine with a fixed address: an office server, a VM, or a small cloud host.

### 5. Add each site

**a. Generate the site's secret:**

```bash
docker compose run --rm plumb new-secret acmecorp
```

This prints two lines:
- one for `config/plumb.env`
- one `define( 'PLUMB_AGENT_SECRET', '...' );` line for the site's `wp-config.php`

Put each in its place and nowhere else.

**b. Install the agent.** Copy `agent/plumb-agent.php` to the site's `wp-content/mu-plugins/` folder, creating the folder if needed. Must-use plugins load automatically and can't be deactivated from wp-admin.

- **WP Engine:** use SFTP, git push, or the File Manager.
- **Other hosts:** use SFTP or the host's file manager.

**c. Configure it** in wp-admin under **Settings > Plumb Agent** (or **Network Admin > Settings** on multisite):

- **Allowed puller IP addresses:** the address from step 4.
- **Read the client IP from:** leave this on `REMOTE_ADDR` unless the site is behind a proxy or CDN. The table on that page shows what the site sees for *your* browser's request. If `REMOTE_ADDR` shows a proxy address rather than yours, pick the header that shows your real IP, and only one your host or CDN sets. A header the client can set itself can be faked.
- **Require HTTPS:** leave it on.

**d. Add the site to `config/sites.json`.**

**e. Apply and test:**

```bash
docker compose up -d                                   # picks up the new secret in plumb.env
docker compose exec plumb python /app/plumb_server.py check acmecorp
```

`check` pulls one site and prints the result without changing the dashboard. If it fails with a 404, open the agent's **Recent activity** section, which records the real reason.

- **Changes to `sites.json`** are noticed within a minute, and Plumb runs a fresh check on its own.
- **Changes to `plumb.env`** need `docker compose up -d`. Docker only reads that file when it creates the container, and it recreates the container automatically when the file changes.

### 6. Let it run

The container starts with the computer (via `restart: unless-stopped`) and checks every site every 12 hours. If a run fails outright, it retries after 30 minutes. A restart doesn't trigger an extra run; Plumb picks up the schedule where it left off. It does run right away when there's no dashboard yet, when you switch between demo and live data, or when `sites.json` changes.

**Opening port 6443 to other computers:**

- **macOS:** allow Docker when the firewall asks.
- **Windows:** allow Docker Desktop when Windows Defender Firewall asks.
- **Linux with ufw:** `sudo ufw allow 6443/tcp`.

To keep the dashboard on the Plumb computer only, change the port line in `compose.yaml` to `"127.0.0.1:6443:6443"`.

## Day-to-day commands

Run these from the project folder.

| Task | Command |
|---|---|
| Start or apply changes | `docker compose up -d` |
| Stop | `docker compose down` |
| See the logs | `docker compose logs -f plumb` |
| Run a check of every site now | `docker compose exec plumb python /app/plumb_server.py run-once` |
| Check one site | `docker compose exec plumb python /app/plumb_server.py check SITE` |
| New secret for a site | `docker compose run --rm plumb new-secret SITE` |
| Health | `docker compose ps` shows `healthy` when the dashboard answers and the data is fresh |
| Update Plumb after changing its code | `docker compose up -d --build` |

### What lives where

| Location | Contents | Back it up? |
|---|---|---|
| `config/` (your folder) | `sites.json`, `plumb.env` (secrets), optional `tls/` certificate | **Yes**, and treat `plumb.env` as a password file |
| `plumb-data` Docker volume | Dashboard, 30 days of history snapshots, the self-signed certificate | Optional; it rebuilds itself on the next run |

To start completely fresh, run `docker compose down -v`. This deletes the `plumb-data` volume and its history.

## Certificates

**Self-signed (default).** Created on first start for `localhost`, `127.0.0.1` and the names in `PLUMB_HOSTNAMES`, and valid for 825 days. Browsers warn about it.

- **One person:** accept the warning once, after checking the fingerprint against the logs.
- **A team:** the warning trains people to click through warnings. Use your own certificate instead.

If you change `PLUMB_HOSTNAMES` later, run `docker compose up -d`. Plumb notices the names changed and makes a new certificate, so the fingerprint changes too. It also renews the certificate on its own 30 days before it expires.

**Your own certificate.** This can come from your internal certificate authority, or from a public one if Plumb has a real DNS name.

1. Save the certificate (with its chain) as `config/tls/cert.pem`, and the private key as `config/tls/key.pem`.
2. **On Linux only,** let the container's user read the key:
   ```bash
   sudo chown 10001 config/tls/key.pem
   chmod 600 config/tls/key.pem
   ```
3. Run `docker compose restart`.

Plumb uses your certificate whenever both files exist, and then also sends HSTS.

## Reading the dashboard

| Status | Meaning |
|---|---|
| **Action needed** | Core is behind the latest release, or an **active** plugin or theme (including a parent theme) is behind |
| **Review** | Only **inactive** components are behind, an active one couldn't be verified, or the agent is out of date |
| **Current** | Core and every plugin and theme were checked and confirmed current |
| **Unreachable** | The pull failed or the agent refused it; expand the row to see why |

- **Unverified** means neither wordpress.org nor the vendor's own updater reported a published version. Plumb doesn't count it as current.
- **Configuration flags** appear in the detail row: the wp-admin file editor being enabled, and `WP_DEBUG` being on in production.
- **Notes** in the detail row cover a stale site update check (wp-cron not running), a home URL that doesn't match `sites.json`, and an outdated agent.
- **Stale data:** if the collector stops running, a banner appears once the last run is more than 13 hours old, and `/healthz` reports `stale`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Container exits right away | Read `docker compose logs plumb`. Usually the dashboard password is missing or shorter than 12 characters, or `config/sites.json` doesn't exist (set `PLUMB_DEMO=1` to preview without it) |
| `env file ... not found` | `config/plumb.env` hasn't been created yet; copy it from `plumb.env.example` |
| Browser says the connection isn't secure | Expected with the self-signed certificate. Check the fingerprint, or install your own certificate (see [Certificates](#certificates)) |
| Browser can't connect at all | Include `:6443` in the address. (If you type `http://`, Plumb redirects you to `https://`.) From another computer, check the host firewall. On a Mac with Docker Desktop's Kubernetes turned on, Kubernetes already uses port 6443; turn it off, or change the port line in `compose.yaml` to `"6444:6443"` |
| "Too many failed sign-in attempts" | That address had 10 failed sign-ins. Wait 15 minutes, or run `docker compose restart` to clear the lockout. On macOS and Windows, Docker Desktop can make every visitor appear to come from the same address, so one person's mistyped password can lock out everyone for 15 minutes |
| `404: agent not installed, or it refused the request` | Check the agent's **Recent activity**. "IP not on allowlist": the site sees a different IP (see "Read the client IP from" and step 4). "timestamp outside 5-minute window": see the next row. "bad signature": the secrets don't match. "not HTTPS": the host isn't telling WordPress the request was HTTPS |
| "timestamp outside 5-minute window" | The clock on the Plumb computer is off. Docker uses the host's clock, so fix the host's time sync. On a Mac or Windows laptop, Docker Desktop's clock can drift after sleep; restarting Docker Desktop fixes it |
| `HTTP 403` / `401` from a site | A WAF or security plugin (Cloudflare, Wordfence, Sucuri) blocked the request before WordPress saw it. Allowlist the Plumb IP there too |
| `redirected to ...` | The `url` in `sites.json` isn't the site's final address (`www` vs. no `www`, `http` vs. `https`). Use the final one |
| `response wasn't JSON` | Usually a WAF challenge page, or a PHP fatal error on the site |
| Note: "update check last ran N days ago" | wp-cron isn't firing, so premium-plugin versions from vendor feeds may be stale. Set up a real cron or your host's equivalent |

## Rotating a secret

1. Run `docker compose run --rm plumb new-secret SITE`.
2. Update the site's `wp-config.php`.
3. Update `config/plumb.env`, then run `docker compose up -d`.

The site is unreachable for any pull that happens between steps 2 and 3. To rotate the dashboard password, change it in `plumb.env` and run `docker compose up -d`.

## Updating the agent

1. Bump `Version` and `VERSION` in `plumb-agent.php`.
2. Bump `AGENT_LATEST` in `collector.py`, then run `docker compose up -d --build`.
3. Redeploy the file to each site.

Until a site is updated, the dashboard flags it as running an old agent.

## Running without Docker (development)

For working on Plumb itself, it runs directly with Python 3.10 or newer:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python collector.py --demo                            # writes output/index.html with fake data
.venv/bin/python collector.py --env-file config/plumb.env       # a real run
```

For anything people rely on, use the container: it adds the schedule, HTTPS, sign-in and the hardening described above.

## Known gaps

- **Version drift isn't exposure.** Plumb shows that something is behind, not whether that version has a known vulnerability. Adding a vulnerability feed (Wordfence Intelligence, WPScan or Patchstack) is the natural next step.
- **Must-use plugins and drop-ins** are listed by the agent but not version-checked.
- **Core is compared against the single latest release.** Sites deliberately held on an older supported branch will show as behind.
- **The image hasn't been published to a registry.** Each host builds it locally with `--build`.
