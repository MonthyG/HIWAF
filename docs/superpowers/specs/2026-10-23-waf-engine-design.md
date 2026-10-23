# HostingInside WAF Engine: Design

Date: 2026-10-23
Status: draft, awaiting approval

## 1. Intent

HostingInside wants a WAF engine that is **as easy to use as SafeLine**, built on
**Caddy + OWASP Coraza** (`github.com/corazawaf/coraza-caddy/v2`). It will
later become a paid WAF add-on for the HostingInside OpenStack cloud. That
later work covers the cloud integration, the customer-facing API and billing,
all parked for now.

This phase builds **only the engine**: a WAF that runs on one machine, protects
one or more websites, and is configured with SafeLine-style simple settings
instead of raw ModSecurity rules.

"SafeLine-simple" means an operator says *what* they want, and the engine
works out *how*:

- website `shop.example.com` → upstream `10.0.0.5:8080`
- protections: ☑ SQL injection ☑ XSS ☐ Java attacks …
- mode: block / detect only / off
- rate limit: `100` requests per `10` seconds → ban for `5` minutes

## 2. Goals

1. A custom Caddy binary (built with `xcaddy`) containing coraza-caddy plus
   HostingInside modules for the SafeLine-like features in §4.
2. A small **management API** (REST/JSON) that takes simple site settings,
   stores them, compiles them into Caddy JSON config, and applies them live
   through Caddy's admin API, with no restart.
3. Attack logs and basic statistics, queryable through the management API.
4. A clean split between the **engine** (Caddy + modules, the data plane) and
   the **manager** (API + storage, the control plane). That split lets the
   cloud version later run one manager and many engine nodes.

## 3. Non-goals (this phase)

- OpenStack integration (Neutron, security-group origin lockdown, Keystone auth).
- Billing and metering.
- Multi-node clustering and shared rate-limit state across engines.
- A web dashboard UI. The API comes first, and a UI can be added on top later.
- A password gate in front of a site (SafeLine "auth"). Dropped by the user
  for now. It would slot in after `hi_ratelimit` later.
- Writing a new detection engine. Detection is Coraza + OWASP CRS. We do not
  copy SafeLine's proprietary semantic engine.

**Anti-goals** (failure even if it works):

- The customer has to write or understand SecRule syntax to get protection.
- A config change drops live traffic or needs a process restart.
- One site's settings leak into another site (wrong rules, wrong limits).

## 4. Feature map (SafeLine → our engine)

| SafeLine feature | Edition | Our implementation | Where |
|---|---|---|---|
| Site/app reverse proxy (domain → upstream) | free | Caddy `reverse_proxy`, one route per site | Caddy core |
| HTTPS: auto cert or upload | free | Caddy automatic HTTPS (ACME), or an uploaded cert/key pair | Caddy core |
| Attack detection by category | free | Coraza + embedded CRS. Each checkbox enables or disables one CRS rule family (§5) | coraza-caddy |
| Protection mode: block / observe / off | free | `SecRuleEngine On` / `DetectionOnly` / module not attached | coraza-caddy |
| Detection strictness | free | CRS paranoia level 1–4 + anomaly threshold | coraza-caddy |
| Rate limit: access frequency | free | `hi_ratelimit`: N requests per T seconds per client IP → ban B | **new module** |
| Rate limit: attack frequency | free | `hi_ratelimit`: N WAF blocks per T → ban B | **new module** |
| Rate limit: error frequency | free | `hi_ratelimit`: N 4xx/5xx responses per T → ban B (scanner and brute-force signal) | **new module** |
| IP allowlist / blocklist (single IP + CIDR) | free | `hi_access`: allowlisted IPs skip WAF and limits, blocklisted IPs get 403 | **new module** |
| Custom rules (match path/header/method/query → allow/block) | free | `hi_access` rules, a simple JSON condition list | **new module** |
| Auth gate (password before reaching site) | free | **Not built this phase** (user decision) | n/a |
| Custom block page | free / pro | Caddy `handle_errors` + HTML template with event ID | Caddy core |
| Attack logs + statistics | free | Engine writes JSON events, manager ingests into SQLite | engine + manager |
| Bot protection (JS challenge) | partly pro | `hi_challenge`: JS proof-of-work page + signed clearance cookie | **new module** |
| Geo/country blocking | pro | `hi_access` geo rules using a MaxMind GeoLite2 `.mmdb` file the operator supplies | **new module** |
| Dynamic HTML/JS obfuscation | pro | **Not built.** Low security value, high breakage risk | n/a |
| Threat-intel IP reputation feeds | pro | **Not built now.** `hi_access` blocklists can load a file, and feeds come later | n/a |

## 5. Protection checkboxes → CRS

Each checkbox maps to CRS rule-ID ranges. An unticked box emits
`SecRuleRemoveById <range>` after the CRS include.

| Checkbox key | Label | CRS files / IDs |
|---|---|---|
| `sqli` | SQL injection | 942xxx |
| `xss` | Cross-site scripting | 941xxx |
| `rce` | Command injection | 932xxx |
| `lfi` | Path traversal / local file | 930xxx |
| `rfi` | Remote file inclusion | 931xxx |
| `php` | PHP injection | 933xxx |
| `nodejs` | Node.js injection | 934xxx |
| `java` | Java / deserialization | 944xxx |
| `session_fixation` | Session fixation | 943xxx |
| `scanner` | Scanner / bad-bot detection | 913xxx |
| `protocol` | Protocol attacks + enforcement | 920xxx, 921xxx |
| `data_leak` | Response data leakage (needs response body inspection) | 950xxx–955xxx |

Defaults: everything on except `data_leak`, which costs memory and latency
because it buffers response bodies. Default paranoia is 1 and the default
inbound anomaly threshold is 5, both CRS defaults.

The exact ID ranges must be checked against the CRS version embedded in the
pinned coraza-caddy release. If a range doesn't match, the checkbox keeps
its **meaning** and the mapping follows the real CRS files. For example,
`protocol` also covers 922xxx (multipart attacks) where that file exists.

## 6. Architecture

```
               ┌───────────────────────── manager (Go, :9000) ─────────────────────────┐
 operator ───► │ REST API ─► validate ─► SQLite (sites, rules, events) ─► compiler      │
  (API key)    │                                    ▲                       │           │
               └────────────────────────────────────┼───────────────────────┼───────────┘
                                                    │ events (tail JSON log)│ POST /load (Caddy JSON)
                                                    │                       ▼
 internet ──► :80/:443 ──► Caddy engine (localhost admin :2019) ──────────────────────────
                route per host:
                 hi_access → hi_ratelimit → hi_challenge → coraza_waf → reverse_proxy ─► upstream
                handle_errors → block page
```

**Handler order per site, and why:**

1. `hi_access`: cheapest check, IP/geo/custom rules. Allowlisted requests
   skip everything below except the proxy.
2. `hi_ratelimit`: checks bans and counts the request first, so floods of
   challenge pages get banned too. It wraps the rest of the chain so it sees
   the result (WAF block or error status) for the attack and error counters.
3. `hi_challenge`: bots fail before they cost CRS CPU.
4. `coraza_waf`: CRS inspection.
5. `reverse_proxy`.

**State across config reloads:** every config load from the manager
re-creates Caddy modules. Bans and counters live in package-level shared
state keyed by site ID (Caddy `UsagePool`), so they **survive site edits and
reloads**. They are lost only when the process restarts.

**Restart and failure behaviour:**

- Caddy runs with `--resume`, so after a restart it reloads its last applied
  config by itself, and sites are served even if the manager is down.
- On startup the manager pushes the full config from SQLite, so SQLite is the
  source of truth.
- If the manager can't reach Caddy, writes fail with `503` and the database
  change is rolled back. Nothing is queued.

**Detect mode and events:** in detect mode Coraza doesn't interrupt, so
`hi_ratelimit` sees no error. Detections are still recorded. coraza-caddy
already logs each matched rule (rule ID, message, client, hostname, URI)
through its Caddy logger `http.handlers.waf`. The compiled Caddy logging
config sends that logger and our `hi_*` module loggers to one JSON events
file, and the manager parses it. That is one ingest path and needs no fork. In detect
mode events are logged but **don't count toward attack bans**. In block mode
they do.

**Engine modules** live in one Go package set under `engine/` and are compiled
into Caddy with `xcaddy build --with github.com/corazawaf/coraza-caddy/v2 --with hostinginside/waf/engine=./engine`.
Each module is a standard `caddyhttp.MiddlewareHandler` with JSON config and
Caddyfile support. Caddyfile support is for manual testing only; the manager
uses JSON.

**Rate-limit state** lives in memory per engine process: sliding-window
counters keyed by `(site, client IP)`, with periodic cleanup. State is lost on
restart, which is acceptable for a single node in dev. A Redis-backed store is
a later swap behind a `Store` interface.

**Client IP**: the TCP peer address by default. `X-Forwarded-For` is honoured
only when the peer is in a configured trusted-proxy list, using Caddy's
`trusted_proxies` and `client_ip`. Without this, attackers dodge every
per-IP limit by sending a fake header.

**Detecting a WAF block from the rate limiter**: coraza-caddy returns a Caddy
`HandlerError` whose message is `interruption triggered by rule <id> (<action>)`.
`hi_ratelimit` checks the returned error for that pattern to count attacks.
This string is a fragile dependency, so a unit test pins it. The fallback is a
small fork or wrapper module.

**Manager** (`manager/`): a separate Go binary.

- Storage: SQLite (pure-Go driver `modernc.org/sqlite`, no CGO, which keeps
  Windows/Linux builds easy).
- Auth: static API keys from a config file, sent as `Authorization: Bearer`.
  Keystone/tenant auth comes later.
- On every write: compile all sites into a complete Caddy JSON config and
  `POST http://127.0.0.1:2019/load`. If Caddy rejects it, the API returns
  the error and the database change is rolled back, so stored config and live
  config never diverge.
- Events: the engine's `hi_events` log writer appends one JSON line per
  security event to a file. The manager tails it into SQLite.

## 7. Management API (v1)

```
POST   /api/v1/sites                 create site
GET    /api/v1/sites                 list
GET    /api/v1/sites/{id}            get
PUT    /api/v1/sites/{id}            replace settings
DELETE /api/v1/sites/{id}            delete
POST   /api/v1/sites/{id}/certificate   upload cert+key (PEM)
GET    /api/v1/events?site=&since=&type=&ip=   attack/limit/ban events
GET    /api/v1/stats?site=&window=24h          totals by type, top IPs, top rules
GET    /api/v1/bans?site=            current bans (read from engine)
DELETE /api/v1/bans?site=&ip=        unban (via engine admin endpoint)
GET    /api/v1/protections           list of checkbox keys + labels (for a UI)
```

Site document (everything except `domains` and `upstreams` is optional, and
defaults are shown):

```json
{
  "name": "shop",
  "domains": ["shop.example.com"],
  "upstreams": ["10.0.0.5:8080"],
  "tls": { "mode": "auto" },                     // auto | uploaded | off
  "waf": {
    "mode": "block",                             // block | detect | off
    "paranoia": 1,
    "protections": { "sqli": true, "xss": true, "data_leak": false }
  },
  "rate_limit": {
    "access": { "requests": 100, "window_sec": 10, "ban_sec": 300 },
    "attack": { "requests": 10,  "window_sec": 60, "ban_sec": 1800 },
    "error":  { "requests": 50,  "window_sec": 60, "ban_sec": 600 }
  },
  "access": {
    "allow_ips": [], "block_ips": [],
    "block_countries": [], "allow_countries": [],
    "rules": [ { "action": "block", "match": { "path_prefix": "/admin", "not_ip": ["1.2.3.4"] } } ]
  },
  "bot_challenge": { "enabled": false, "difficulty": 4 },
  "block_page": { "title": "Blocked", "message": "…" }
}
```

**Defaulting rules:**

- An omitted field gets its default. An explicit `null` turns that feature
  off.
- `protections` is **merged** over the defaults: a key you leave out keeps
  its default.
- Rate-limit defaults: `attack` and `error` are on with the values shown.
  `access` is **off by default**, because the customer types the number (the
  SafeLine flow) and a guessed limit would ban real users behind a shared
  NAT.
- `waf.anomaly_threshold` (default 5) is exposed alongside `paranoia`.

**Custom rules (`access.rules`):** evaluated in order, first match wins.

- Match fields: `ip` (IPs/CIDRs), `not_ip`, `country`, `method`,
  `path_exact`, `path_prefix`, `path_regex`, `header` (`{name, contains|regex}`),
  `query` (`{name, contains|regex}`), `host`.
- All fields in one rule must match (AND). Use several rules for OR.
- Actions:
  - `block` returns 403.
  - `allow` skips the rest of `hi_access`, the rate limits, the challenge
    and the WAF, which is SafeLine whitelist behaviour.
  - Because `allow` turns off protection, the API rejects an `allow` rule
    unless it has an `ip`, `path_exact` or `path_prefix` condition, and every
    request it lets through is logged as an `allowed_by_rule` event.

## 8. Repository layout

```
D:\Timothy\Coraza\
  engine/           Caddy modules: access, challenge, ratelimit, events
  manager/          REST API, store, compiler, Caddy client, event ingester
  cmd/manager/      manager main
  build/            xcaddy build script (sh + ps1), base Caddy JSON
  examples/         sample site JSON, demo upstream
  docs/
  go.mod            single module: hostinginside/waf
```

## 9. Testing

- Unit tests per module: limiter window math, ban expiry, CIDR matching,
  cookie signing, PoW verification, custom-rule matching.
- Compiler golden tests: site JSON → expected Caddy JSON.
- Integration test: run Caddy in-process with the modules plus coraza-caddy
  against an `httptest` upstream, then fire SQLi/XSS payloads, a request flood
  and blocklisted IPs, and assert 403/429 plus the emitted events.

## 10. Constraints and known risks

- **Go is not installed on the development machine yet.** Code cannot be
  compiled or tested here until Go **1.26+** is installed (coraza-caddy's
  go.mod requires 1.26.0). xcaddy isn't needed: the plan builds our own Caddy
  main. The user will say when to run.
- **Memory per site**: each site gets its own Coraza WAF instance with CRS
  loaded. Pattern memoization shares regexes across sites, but memory per
  site must be measured before multi-tenant use.
- **coraza-caddy error-string coupling** (§6). Fixable, pinned by a test.
- **Response inspection (`data_leak`)** buffers bodies. Off by default.
- **JS challenge** blocks non-browser API clients. It is per-site and off by
  default, and the docs warn about it.

## 11. Decisions made without the user (please check)

1. API only this phase, no web dashboard.
2. Single engine node, in-memory rate-limit state.
3. Manager is a separate binary using SQLite and static API keys.
4. Premium features built: JS bot challenge, geo blocking (operator supplies
   the GeoLite2 DB). Skipped: HTML/JS obfuscation, threat-intel feeds.
5. Error-frequency limiter counts 4xx and 5xx responses except 403s produced
   by the WAF itself, which go to the attack counter instead.
6. Single Go module `hostinginside/waf`.

## 12. Left to the builder

Internal naming, sliding-window algorithm choice, cookie format, PoW scheme
details, log rotation, and exact HTTP error formats, as long as the behavior
in §4–§7 holds.
