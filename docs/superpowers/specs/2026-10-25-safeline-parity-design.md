# SafeLine Parity: Design

Date: 2026-10-25
Status: user opted out of questions ("make it identical like SafeLine and talk
to me again"). Every decision below is my call, made for the user to review.

## Intent

The engine (Caddy + Coraza + `hi_*` modules) and the manager API exist. The
user wants the product to feel like SafeLine
(<https://github.com/chaitin/SafeLine>, live demo at
`demo.waf.chaitin.com:9443`, v9.4):

- a web console
- one-command Docker install
- the same menus and features

It should be deployed on the dev server `10.1.1.2` (AlmaLinux 10.2,
Docker 29).

## Non-goals

- **Copying SafeLine's code or branding.** SafeLine is GPL-3.0. We match the
  features and the UX, not the code, logo or name. The console is
  "HostingInside WAF".
- **SafeLine's semantic detection engine.** It is closed-source. Detection
  stays Coraza + OWASP CRS. SafeLine's own benchmark shows ModSecurity/CRS
  level 1 at a 17.58% false-positive rate against its 0.07%. Closing that gap
  is the false-positive test's job, not this work's.
- **Dynamic HTML/JS encryption and anti-replay.** These break sites more
  than they protect them.
- **Multi-node, alerting webhooks, SSO.**

## Console menu (mirrors SafeLine v9.4)

| Menu | Content |
|---|---|
| **Statistics** | Requests, PV, UV, unique IPs, blocked, blocked IPs, 4xx and 5xx with their rates, QPS, request and blocked time series, geo (countries), user clients (OS and browser), response status, referrers, popular apps and pages. Filters: application, 24h/7d/30d. |
| **Applications** | Cards showing mode (Defense/Audit/Disabled), requests and blocks today, domain, ports, and quick toggles (HTTP Flood, Bot Protect, Auth, Attacks). Add/Edit dialog with domains, listening ports (HTTP/HTTPS), SSL cert, type (Reverse Proxy / Static Files / Redirect), upstreams, name and description. Detail page tabs: Overview, Protection, HTTP Flood, Anti-Bot, Auth, Waiting Room, Allow & Deny, Advanced. |
| **Attacks** | Events tab (grouped by IP + app) and Logs tab. Each log's detail shows matched rules, payload (Coraza `data`), attack type and the request. |
| **Allow & Deny** | Events and logs of access blocks and allows, plus the **Custom Rules** tab: global rules with a name, an enabled flag, allow/deny, scope (all or selected apps) and conditions. |
| **HTTP Flood** | Rate Limiting (the three limits per app, plus current bans with unban), and Waiting Room (per app). |
| **Anti-Bot** | Challenge per app (on/off, difficulty) and challenge logs. |
| **Auth** | Password gate per app (users list) and auth logs. |
| **Settings** | Certificates, IP Groups, account (password, TOTP), API tokens, system (version, engine status). |

## Backend additions

1. **Access log → traffic stats.**
   - Caddy access logs (per-host `logger_names` = site ID) go to
     `access.log`.
   - Our modules add `hi_action` and `hi_type` to the access log through
     `caddyhttp.ExtraLogFields`.
   - A second tailer stores rows in `requests`, which are kept for
     `retention_days` (default 7). The GeoIP country is filled at ingest.
2. **Event enrichment.** Coraza match lines add `tx_id`, `data` (payload),
   `severity` and the attack type (protection key from the rule ID).
   `waf_block` carries `tx_id`, so a log's detail can join all its matches.
3. **Console auth.**
   - Users with bcrypt passwords and optional TOTP (RFC 6238).
   - Sessions in an HttpOnly, SameSite=Strict cookie. Mutating requests
     also need the header `X-Requested-With: hiwaf`.
   - Login lockout after 5 failures in 15 minutes.
   - On first start an `admin` user is created with a random password,
     logged and written to `<data>/initial-admin.txt`.
   - `manager -resetadmin` prints a new password.
   - API keys from config, plus tokens created in the UI, still work as
     Bearer tokens.
4. **One HTTPS listener (`:9443`)** serves both the console and the API.
   The self-signed certificate is generated into the data directory on first
   start.
5. **Site model additions.** All are optional, and the old documents stay
   valid:

   | Field | Meaning |
   |---|---|
   | `description` | Free text |
   | `ports` | `[{port, https}]`. Default: the global HTTP and HTTPS ports. |
   | `type` | `proxy` / `static` / `redirect`. Static sites serve `<static_dir>/<site_id>` (zip upload). Redirect sites use `redirect: {url, code}`. |
   | `lb_policy` | `round_robin` / `ip_hash` / `least_conn` |
   | `advanced` | `{hsts, gzip, http_redirect, keep_host}` |
   | `tls.cert_id` | A global certificate |
   | `access.allow_groups`, `access.block_groups` | IP groups |
   | `auth` | `{enabled, users:[{username, password_hash}], session_ttl_sec}` |
   | `waiting_room` | `{enabled, max_active, session_ttl_sec}` |
6. **Global objects:** `certificates`, `ip_groups` and `global_rules`
   tables, each with CRUD endpoints. A change to any of them re-applies the
   config.
7. **New engine modules:**
   - `hi_auth`: login page, bcrypt check, signed session cookie. A failed
     login returns 401, which counts as an error.
   - `hi_waitroom`: in-memory active-session cap with a queue page that
     auto-refreshes.

   The chain becomes
   `hi_access → hi_ratelimit → hi_auth → hi_waitroom → hi_challenge → waf → upstream`.

## Packaging

- **Image:** one multi-stage `Dockerfile`: node builds the console, Go builds
  both binaries (`CGO_ENABLED=0`), and the runtime is debian-slim. The
  console is embedded in the manager with `go:embed`.
- **`compose.yaml`:** services `hiwaf-engine` and `hiwaf-manager`, both
  `network_mode: host` (no Docker NAT, as decided for testing), sharing
  `/data/hiwaf`.
- **`scripts/install.sh`:**
  1. Checks Docker.
  2. Writes the config.
  3. Downloads the DB-IP Country Lite mmdb (CC-BY, no license key).
  4. Builds and starts the containers.
  5. Prints the console URL and the admin password.
