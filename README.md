# Plumb

*WordPress version monitor.* A plumb line shows whether something is actually true, not just whether it looks true from where you stand.

> **Not technical?** Start with the [Plumb User Guide](docs/USER_GUIDE.md). It covers reading the dashboard and checking the Plumb Agent on a WordPress site, in plain language. This README is for whoever sets Plumb up.

Every 12 hours Plumb pulls a signed report from each WordPress site you list, checks core, plugin and theme versions against what's currently published, and shows a status for each site on a single dashboard page. It works on any host: WP Engine, shared hosting, a VPS, anything that serves WordPress.

## How it works

```
 Plumb server (every 12 h)                      Each WordPress site
 ─────────────────────────                      ───────────────────
 sites.json + per-site secret
        │  GET /wp-json/plumb/v1/report
        │  signed: HMAC(secret, timestamp + nonce)
        └──────────────────────────────────────▶  Plumb Agent (must-use plugin)
                                                  1. HTTPS?  2. IP on allowlist?
                                                  3. rate limit  4. signature + 5-min window
                                                  5. nonce never seen before
        ┌──────────────────────────────────────  signed report, bound to that nonce
        │                                         (anything else: a plain 404)
 verify signature ─▶ compare with wordpress.org / vendor feed ─▶ output/index.html
```

There are two parts:

| Part | Where it runs | Files |
|---|---|---|
| **Plumb Agent** | On each WordPress site, as a must-use plugin | `agent/plumb-agent.php` |
| **Plumb collector + dashboard** | On one server or workstation you control | `collector.py`, `dashboard_template.html`, `sites.json`, `.env` |

## Security model

The goal is least privilege: Plumb needs read access to version numbers and nothing more.

- **Read-only agent.** It has one GET route with no inputs that change what it does. It can't modify the site; the only things it writes are its own replay, rate-limit and activity records.
- **A unique secret per site.** Each request is signed with HMAC-SHA256 over a timestamp and a one-time nonce. A leaked secret exposes one site's version list, not the fleet.
- **The secret lives outside the database.** `PLUMB_AGENT_SECRET` goes in `wp-config.php`, or in an environment variable. A SQL injection in some other plugin can't read it. Storing it in the database is a fallback that the settings page warns about.
- **Replay protection.** Requests older than 5 minutes are refused, and so is any nonce that's already been used.
- **Puller IP allowlist,** configured in wp-admin under **Settings > Plumb Agent**. It's checked before the signature, and accepts IPv4, IPv6 and CIDR ranges.
- **Silent failure.** Every refusal returns the same 404 WordPress gives for a route that doesn't exist, and the route is hidden from the public `/wp-json` index. The real reason is recorded in the agent's **Recent activity** log, and only there.
- **Rate limiting.** After 10 refused requests in 15 minutes, an IP is ignored, even if it then sends a valid request.
- **Signed responses.** The agent signs its report and binds it to the request's nonce. Plumb rejects a report that's been altered, replayed, or served from a cache.

If the Plumb server is compromised, the attacker gets the version inventory of your sites. That's reconnaissance, not access: nothing Plumb holds can log in to, write to, or run code on a site.

**What this doesn't protect against:** the agent runs on the site it reports on. A site that's already compromised can report whatever an attacker wants it to. Plumb detects drift; it isn't an integrity monitor.

## Setup

### 1. Plumb server

```bash
sudo mkdir -p /opt/plumb && cd /opt/plumb      # copy the project files here
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env && chmod 600 .env
cp sites.example.json sites.json
.venv/bin/python collector.py --demo             # preview: open output/index.html
```

The server's clock must be accurate (NTP), because signatures expire after 5 minutes.

### 2. Each site

**a. Generate the site's secret** on the Plumb server:

```bash
.venv/bin/python collector.py --new-secret acmecorp
```

This prints two lines:
- one for Plumb's `.env`
- one `define( 'PLUMB_AGENT_SECRET', '...' );` line for the site's `wp-config.php`

Put each in its place and nowhere else.

**b. Install the agent** as a must-use plugin. Copy `agent/plumb-agent.php` to `wp-content/mu-plugins/plumb-agent.php`; create the folder if it doesn't exist. Must-use plugins load automatically and can't be deactivated from wp-admin.

- **WP Engine:** use SFTP, git push, or the File Manager.
- **Other hosts:** use SFTP or the host's file manager.

**c. Configure it** in wp-admin under **Settings > Plumb Agent** (or **Network Admin > Settings** on multisite):

- **Allowed puller IP addresses:** your Plumb server's public outbound IP. Find it with `curl https://ifconfig.me` from that server.
- **Read the client IP from:** leave this on `REMOTE_ADDR` unless the site is behind a proxy or CDN. The table on that page shows what the site sees for *your* browser's request. If `REMOTE_ADDR` shows a proxy address rather than yours, pick the header that shows your real IP, and only one your host or CDN sets. A header the client can set itself can be faked.
- **Require HTTPS:** leave it on.

**d. Add the site to `sites.json`** and test it on its own:

```bash
.venv/bin/python collector.py --env-file .env --check acmecorp
```

`--check` pulls one site and prints the result without changing the dashboard. If it fails with a 404, open the agent's **Recent activity** section, which records the real reason.

### 3. Schedule it every 12 hours

**Linux with systemd (recommended).** Runs at 05:15 and 17:15, and catches up after downtime:

```bash
sudo useradd --system --no-create-home plumb
sudo chown -R plumb: /opt/plumb
sudo cp deploy/plumb.service deploy/plumb.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now plumb.timer
systemctl list-timers plumb.timer          # next run
journalctl -u plumb.service -n 100         # last run
```

**Linux / macOS with cron.**

```cron
15 5,17 * * * cd /opt/plumb && .venv/bin/python collector.py --env-file .env >> output/collector.log 2>&1
```

**Windows Task Scheduler.**

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\plumb\.venv\Scripts\python.exe" `
           -Argument "collector.py --env-file .env" -WorkingDirectory "C:\plumb"
$trigger = New-ScheduledTaskTrigger -Once -At 5:15am -RepetitionInterval (New-TimeSpan -Hours 12)
Register-ScheduledTask -TaskName "Plumb" -Action $action -Trigger $trigger
```

### 4. Serve the dashboard

`output/index.html` is a single static file. **Keep it behind authentication** (an internal web server, VPN, or SSO in front of nginx/IIS), or just open it locally. It's a list of which sites run out-of-date software, which is exactly the list an attacker would want.

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
- **Stale data:** if the collector stops running, a banner appears once the last run is more than 13 hours old.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `404: agent not installed, or it refused the request` | Check the agent's **Recent activity**. "IP not on allowlist": the site sees a different IP (see "Read the client IP from"). "timestamp outside 5-minute window": fix the clock (NTP). "bad signature": the secrets don't match. "not HTTPS": the host isn't telling WordPress the request was HTTPS |
| `HTTP 403` / `401` | A WAF or security plugin (Cloudflare, Wordfence, Sucuri) blocked the request before WordPress saw it. Allowlist the Plumb server's IP there too |
| `redirected to ...` | The `url` in `sites.json` isn't the site's final address (`www` vs. no `www`, `http` vs. `https`). Use the final one |
| `response wasn't JSON` | Usually a WAF challenge page, or a PHP fatal error on the site |
| Note: "update check last ran N days ago" | wp-cron isn't firing, so premium-plugin versions from vendor feeds may be stale. Set up a real cron or your host's equivalent |

## Rotating a secret

1. Run `collector.py --new-secret SITE`.
2. Update the site's `wp-config.php`, then Plumb's `.env`.

The site is unreachable for any pull that happens between those two steps.

## Updating the agent

1. Bump `Version` and `VERSION` in `plumb-agent.php`.
2. Bump `AGENT_LATEST` in `collector.py`.
3. Redeploy the file to each site.

Until a site is updated, the dashboard flags it as running an old agent.

## Known gaps

- **Version drift isn't exposure.** Plumb shows that something is behind, not whether that version has a known vulnerability. Adding a vulnerability feed (Wordfence Intelligence, WPScan or Patchstack) is the natural next step.
- **Must-use plugins and drop-ins** are listed by the agent but not version-checked.
- **Core is compared against the single latest release.** Sites deliberately held on an older supported branch will show as behind.
