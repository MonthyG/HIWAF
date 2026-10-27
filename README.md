# HostingInside WAF

A web application firewall for HostingInside customer sites, built on
[Caddy](https://caddyserver.com) and [Coraza](https://coraza.io) with the
OWASP Core Rule Set. It has two binaries:

- **`hi-waf`**: the engine. This is Caddy with coraza-caddy and our own
  modules compiled in:
  - `hi_access`: IP, country and custom rules
  - `hi_ratelimit`: access, attack and error limits, plus bans
  - `hi_auth`: a password gate
  - `hi_waitroom`: a waiting room
  - `hi_challenge`: a JS proof-of-work bot challenge
  - admin endpoints for bans and waiting-room counts
- **`manager`**: the control plane. It serves the web console and the REST
  API on one HTTPS port (9443), and keeps sites, certificates, IP groups,
  custom rules and console users in SQLite. It compiles everything into one
  Caddy JSON config, pushes it to the engine's admin API, and reads the
  engine's security events and access log for the statistics and logs.

The console mirrors SafeLine's menus:

- **Statistics**
- **Applications**
- **Attacks**
- **Allow & Deny**
- **HTTP Flood**: Rate Limiting and Waiting Room
- **Anti-Bot**
- **Auth**
- **Settings**: certificates, IP groups, account with TOTP 2FA, API tokens

Detection is the OWASP Core Rule Set, not SafeLine's closed-source semantic
engine. See `docs/superpowers/specs/2026-10-25-safeline-parity-design.md`.

## Install with Docker (recommended)

On a Linux host with Docker and the Compose plugin, from a checkout of this
repository:

```sh
sudo ./scripts/install.sh --open-firewall              # Let's Encrypt for site certificates
sudo ./scripts/install.sh --acme-internal --open-firewall   # lab: the WAF's own CA
```

The script:

- checks that ports 80, 443 and 9443 are free
- writes `/data/hiwaf/manager.json`
- downloads the DB-IP Country Lite database for geo features
- builds the image and starts the containers `hiwaf-engine` and
  `hiwaf-manager`, both on the host network
- prints the console URL `https://<server>:9443` and the generated `admin`
  password

Run the script again to upgrade; data in `/data/hiwaf` is kept.

To reset the console password:

```sh
docker exec hiwaf-manager manager -config /data/manager.json -resetadmin
```

Logs: `docker compose logs -f manager` and `docker compose logs -f engine`.

> **Status:** `go vet ./...` and `go test ./...` pass, including the
> end-to-end engine tests in `integration/`, which start an in-process Caddy
> on ports 9080 and 2999 (`go test -short ./...` skips them).

## Prerequisites

- **Go 1.26 or later.** coraza-caddy's `go.mod` requires 1.26.0. You don't
  need xcaddy, because `cmd/hi-waf` is our own Caddy main.
- **For geo blocking only:** a MaxMind `GeoLite2-Country.mmdb`. Set its path
  in `geoip_db` in the manager config. If you leave it empty, any site that
  uses `allow_countries`, `block_countries` or a `country` rule match is
  rejected.

## Build

| OS | Command | Output |
|---|---|---|
| Windows (PowerShell) | `powershell -ExecutionPolicy Bypass -File build\build.ps1` | `bin\hi-waf.exe` and `bin\manager.exe` |
| Linux | `./build/build.sh` | `bin/hi-waf` and `bin/manager` |

Both scripts run `go mod tidy` first, then `go build` for `./cmd/hi-waf` and
`./cmd/manager`.

If `go mod tidy` fails with TLS or certificate errors, a network filter is
probably intercepting `proxy.golang.org`. Point Go at another module proxy
and build again, for example in PowerShell:

```powershell
$env:GOPROXY = "https://goproxy.io,direct"
$env:GOSUMDB = "sum.golang.org https://sum.golang.google.cn"
```

`GOSUMDB` points at Google's official mirror of the checksum database, for
networks that also block `sum.golang.org`; every module is still verified
against it. In a POSIX shell, use
`export GOPROXY=https://goproxy.io,direct GOSUMDB="sum.golang.org https://sum.golang.google.cn"`.

## Run

Start the engine first, then the manager:

```sh
bin/hi-waf run --resume
bin/manager -config examples/manager.json
```

In PowerShell on Windows, from the repository root:

```powershell
.\bin\hi-waf.exe run --resume
.\bin\manager.exe -config examples\manager.json
```

- `--resume` makes the engine start from the last config it was given, so
  sites keep working if the manager is down.
- On startup the manager pushes the full config compiled from its database.
  If the engine can't be reached, the API still starts, but any change
  returns `503` and is rolled back.

In `examples/manager.json`:

- The API listens on `127.0.0.1:9000` only, and the key
  `change-me-dev-key` authenticates as
  `Authorization: Bearer change-me-dev-key`. The manager refuses to start if
  that example key is configured while `listen` is not a loopback address
  (`127.0.0.1`, `::1` or `localhost`). Replace the key before you expose the
  API, for example with `"listen": ":9000"`.
- The engine admin API is `http://127.0.0.1:2019`.
- Sites are served on HTTP port `8080` and HTTPS port `8443`.
- `acme_internal` is `true`, so certificates come from Caddy's local CA
  instead of Let's Encrypt.

For production:

- Set `http_port` to `80`, `https_port` to `443` and `acme_internal` to
  `false`.
- Set `trusted_proxies` if the engine sits behind a load balancer. The
  compiled config also sets Caddy's `trusted_proxies_strict`, so the client
  IP is read from `X-Forwarded-For` right to left, skipping trusted hops,
  and a client can't spoof an `allow_ips` address in that header.

## Walkthrough with curl

These commands use bash syntax. In PowerShell, use `curl.exe` and adjust the
quoting.

```sh
API=http://localhost:9000/api/v1
AUTH="Authorization: Bearer change-me-dev-key"

# 1. Create a site from the example document. The response includes the
#    site's "id" (s_ + 12 hex) and the fully resolved settings.
curl -s -H "$AUTH" -H "Content-Type: application/json" \
     --data @examples/site-shop.json $API/sites
SITE=s_xxxxxxxxxxxx   # paste the id from the response

# 2. Send an SQL injection. The WAF answers 403 with the site's block page.
#    -k: the certificate is from Caddy's internal CA. --resolve points the
#    domain at the local engine.
curl -sk -o /dev/null -w '%{http_code}\n' \
     --resolve shop.example.com:8443:127.0.0.1 \
     "https://shop.example.com:8443/?id=1%27%20OR%20%271%27=%271"
#    -> 403. (A clean request gets 502 here, because the example upstream
#    10.0.0.5:8080 doesn't exist. The WAF blocks before the proxy is tried.)

# 3. List the events. You should see "waf_block" with rule_id 942xxx.
curl -s -H "$AUTH" "$API/events?site=$SITE"
curl -s -H "$AUTH" "$API/events?site=$SITE&type=waf_block"
curl -s -H "$AUTH" "$API/stats?site=$SITE&window=1h"

# 4. Get banned. The default attack limit is 10 WAF blocks in 60 s, which
#    bans the IP for 1800 s. Banned requests get 429 with Retry-After.
for i in $(seq 1 11); do
  curl -sk -o /dev/null -w '%{http_code} ' --resolve shop.example.com:8443:127.0.0.1 \
       "https://shop.example.com:8443/?id=1%27%20OR%20%271%27=%271"
done; echo

# 5. List the bans, then lift one.
curl -s -H "$AUTH" "$API/bans?site=$SITE"
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE -H "$AUTH" \
     "$API/bans?site=$SITE&ip=127.0.0.1"
#    -> 204, or 404 if the IP isn't banned.
```

The other endpoints are:

- `GET /sites` and `GET /sites/{id}` read sites.
- `PUT /sites/{id}` replaces a site's whole document.
- `DELETE /sites/{id}` removes a site.
- `GET /protections` returns the checkbox list for a UI.

## Site document

Only `domains` and `upstreams` are required. For every other field:

- If you leave it out, it gets its default.
- If you set it to `null`, that feature is off. This applies to the rate
  limits.

See `examples/site-shop.json` for a full example.

### Protection checkboxes (`waf.protections`)

The keys you set are merged over the defaults, so a key you leave out keeps
its default.

| Key | Protection | CRS rule IDs | Default |
|---|---|---|---|
| `sqli` | SQL injection | 942000-942999 | on |
| `xss` | Cross-site scripting | 941000-941999 | on |
| `rce` | Command injection | 932000-932999 | on |
| `lfi` | Path traversal / local file | 930000-930999 | on |
| `rfi` | Remote file inclusion | 931000-931999 | on |
| `php` | PHP injection | 933000-933999 | on |
| `nodejs` | Node.js injection | 934000-934999 | on |
| `java` | Java / deserialization | 944000-944999 | on |
| `session_fixation` | Session fixation | 943000-943999 | on |
| `scanner` | Scanner / bad-bot detection | 913000-913999 | on |
| `protocol` | Protocol attacks + enforcement | 920000-922999 | on |
| `data_leak` | Response data leakage (needs response body inspection) | 950000-956999 | **off** |

### Other settings

- **`waf`**
  - `mode`: `block` (the default), `detect` (log only) or `off`.
  - `paranoia`: 1-4, default 1.
  - `anomaly_threshold`: default 5.
- **`rate_limit`**: each limit is `{requests, window_sec, ban_sec}`.
  - `attack` counts WAF blocks. Default `{10, 60, 1800}`.
  - `error` counts 4xx and 5xx responses, except the WAF's own 403s.
    Default `{50, 60, 600}`.
  - `access` counts every request. It is **off** unless you set it.
- **`access`**
  - `allow_ips` and `block_ips` take IPs or CIDRs.
  - `allow_countries` and `block_countries` take ISO codes and need
    `geoip_db`.
  - `block_ips_file` is described in the next section.
  - `rules` are custom rules, evaluated in order. The first match wins.
    - A `block` rule returns 403.
    - An `allow` rule skips the rate limits, the challenge and the WAF.
      For that reason it must include an `ip`, `path_exact` or `path_prefix`
      condition, and every request it lets through is logged as
      `allowed_by_rule`.
      An `allow` rule never matches a request path that contains `;` or a
      `..` segment, because backends disagree about what such paths mean.
- **`bot_challenge`**: `{enabled, difficulty}`. Difficulty is 1-6, default 4.
- **`block_page`**: `{title, message}` for the 403 page.

### IP blocklist feeds (`feeds_dir` + `block_ips_file`)

To block a large or frequently updated IP list, set `feeds_dir` in the
manager config to a directory, for example `"feeds_dir": "feeds"`. Put plain
text files in it with one IP or CIDR per line.

In the site, set `"access": {"block_ips_file": "bad-ips.txt"}`:

- It must be a bare file name. The engine reads
  `<feeds_dir>/bad-ips.txt`.
- A site that sets `block_ips_file` is rejected while `feeds_dir` is empty.

The engine reads the file only when it loads a config. Caddy ignores a load
whose config hasn't changed, so re-PUTting an unchanged site doesn't pick up
a new file. An updated file takes effect at the next real config change or
the next engine restart.

### Uploaded certificates

A site with `tls.mode` set to `uploaded` can't be saved until its
certificate exists. Use this order:

```sh
# 1. Create the site with TLS off. It uses a new domain, because
#    shop.example.com exists from the walkthrough above and a duplicate
#    domain gets 400.
curl -s -H "$AUTH" -H "Content-Type: application/json" $API/sites \
     -d '{"domains":["secure.example.com"],"upstreams":["10.0.0.5:8080"],"tls":{"mode":"off"}}'
SITE=s_xxxxxxxxxxxx   # paste the id from the response

# 2. Upload the certificate and key (PEM) for that site.
jq -n --rawfile c cert.pem --rawfile k key.pem '{cert_pem:$c, key_pem:$k}' |
  curl -s -H "$AUTH" -H "Content-Type: application/json" --data @- \
       $API/sites/$SITE/certificate

# 3. Switch the site to the uploaded certificate. PUT replaces the whole
#    document.
curl -s -X PUT -H "$AUTH" -H "Content-Type: application/json" $API/sites/$SITE \
     -d '{"domains":["secure.example.com"],"upstreams":["10.0.0.5:8080"],"tls":{"mode":"uploaded"}}'
```

### The JS challenge blocks non-browser clients

With `bot_challenge.enabled`, a GET or HEAD request that accepts `text/html`
and has no clearance cookie gets a proof-of-work page. Every other request
without the cookie gets **403**. This includes API clients, webhooks, mobile
apps and `curl`.

The challenge is off by default. Turn it on only for sites that browsers
use. You can exempt machine paths with an `allow` rule such as
`{"action":"allow","match":{"path_prefix":"/api/"}}`, but remember that an
`allow` rule also skips the WAF.

## Operating it

Everything below is also in the console under **Settings > System**.

**Rule set updates.** The engine has CRS 4.25.0 built in. To run a newer
release, install it on the server; the script only installs a release that
the CRS project's signing key (fingerprint pinned in the script) signed:

```bash
bash scripts/crs-install.sh 4.30.0      # unpacks into /data/hiwaf/rulesets/4.30.0
```

Then pick it in the console, or `PUT /api/v1/rulesets/active` with
`{"version":"4.30.0"}` (`""` = built-in). The switch is a config reload, so
no connection is dropped. If the engine can't load the rules, the switch is
refused and the current rules keep running. It needs at least one site with
the WAF on, because only then does the engine parse the rules. Upgrading the
engine binary itself still needs a container restart (a second or two of
downtime on a single node).

**Backups.** The manager copies its database to `/data/hiwaf/backups` a
minute after it starts, then every `backup_hours` (default 24; -1 turns the
schedule off), and keeps the newest `backup_keep` (default 7). A backup holds
the sites, rules, certificates with their keys, users and security events,
but not the access log. The files are mode 0600; treat downloaded copies as
secrets. To restore one:

```bash
docker compose -f /opt/hiwaf/compose.yaml stop manager
docker compose -f /opt/hiwaf/compose.yaml run --rm manager manager -config /data/manager.json -restore /data/backups/waf-20261027-030000.db
docker compose -f /opt/hiwaf/compose.yaml start manager
```

The current database is kept beside the restored one as
`waf.db.before-restore-<time>`.

**Alerts.** Set a webhook (Slack, Discord or any JSON endpoint) to hear when
the engine stops answering for a minute, when it is back, and when a
scheduled backup fails. The manager runs on the same host, so it can't report
that the whole host is down: for that, set a heartbeat URL from an outside
monitor (Healthchecks.io, Uptime Kuma). The manager pings it every 30 s while
the engine is healthy, and the monitor alerts when the pings stop.

**Console exposure.** The console listens on `:9443` on every interface.
Sign-in is limited to 5 failures per address (per /64 for IPv6) and 50 per
account in 15 minutes. Turn on two-step sign-in, and if you can, allow
`9443` only from your office or VPN in the firewall.

## Known limits

- **Detection is the OWASP CRS at paranoia 1 by default.** It misses some
  attacks SafeLine's semantic engine catches (for example `;cat /etc/passwd`
  in a query parameter) and has more false positives. Raise the detection
  level per application, and measure false positives before production.
- **Memory per site.** Each site gets its own Coraza instance with the full
  CRS loaded. Measure memory per site before you put many tenants on one
  node.
- **Single node, in-memory state.** Rate-limit counters and bans live in the
  engine process. They survive config reloads but not a restart, and they
  aren't shared between nodes.
- **coraza-caddy error-string coupling.** `hi_ratelimit` recognises a WAF
  block by parsing the error text coraza-caddy returns. A test pins this
  format, but a coraza-caddy upgrade can break it.
- **`data_leak` buffers response bodies.** This costs memory and latency,
  which is why it is off by default.
- **The JS challenge blocks non-browser clients** (see above).
- **No Caddyfile support.** The engine is configured only through JSON from
  the manager.
- **Statistics come from the access log.** Rows are kept 7 days
  (`retention_days`) and events 30 days (`event_retention_days`) in SQLite,
  which suits one node and modest traffic.

## Layout

```
cmd/hi-waf/     engine main (Caddy + coraza-caddy + hi_* modules)
cmd/manager/    manager main
engine/         Caddy modules: access, auth, challenge, ratelimit, waitroom, events, clientip
manager/        api, store (SQLite), compile (site -> Caddy JSON), caddyclient, ingest, console (embedded UI)
console/        web console source (React + MUI; npm run build -> manager/console/dist)
scripts/        install.sh (Docker install), crs-install.sh (signed CRS releases)
integration/    end-to-end engine tests (in-process Caddy)
examples/       manager.json, site-shop.json
build/          build.sh, build.ps1
docs/           design spec and implementation plan
```
