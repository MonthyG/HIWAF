# HostingInside WAF Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A SafeLine-style WAF on Caddy + Coraza. It has a custom Caddy
binary with HostingInside modules (access rules, rate limits with bans, a JS
bot challenge, geo blocking, events), and a management API that compiles
simple site settings into live Caddy config.

**Architecture:** The engine is `cmd/hi-waf`, a Caddy main that imports
coraza-caddy and the `engine/*` modules. The manager is `cmd/manager`, a REST
API backed by SQLite. Each write compiles *all* sites into one Caddy JSON
config and `POST`s it to the Caddy admin `/load`. If that fails, the DB
transaction rolls back. The engine logs security events as JSON lines to one
file, and the manager tails that file into SQLite.

**Tech Stack:** Go 1.26, Caddy v2.11, `github.com/corazawaf/coraza-caddy/v2`
(embedded OWASP CRS v4), `modernc.org/sqlite`,
`github.com/oschwald/geoip2-golang` (v1), `go.uber.org/zap`.

**Spec:** `docs/superpowers/specs/2026-10-23-waf-engine-design.md`

## Global Constraints

- Go module path `hostinginside/waf`, a single module at the repo root. `go 1.26` (coraza-caddy's go.mod requires 1.26.0).
- **Go is not installed on the dev machine yet.** When a "Run" step can't execute, write the code and tests anyway and record the step as `NOT RUN (no Go toolchain)` in the task report. Never claim a test passed if it didn't run. Dependencies get resolved with `go mod tidy` on first run, so go.sum isn't hand-written.
- Engine binary: our own `cmd/hi-waf/main.go` calling `caddycmd.Main()`, which replaces xcaddy (same result, plain `go build`). Modules are JSON-configured only, with no Caddyfile support. The manager speaks JSON, and manual tests use `examples/*.json`.
- Module IDs: `http.handlers.hi_access`, `http.handlers.hi_ratelimit`, `http.handlers.hi_challenge`, `admin.api.hi_bans`. Coraza's ID is `http.handlers.waf`.
- Event log line message: exactly `"hi_event"`, with field `event` = type. Types: `waf_block`, `waf_match`, `rate_limit_ban`, `ip_block`, `geo_block`, `rule_block`, `allowed_by_rule`, `challenge_passed`, `challenge_failed`.
- Allow-skip var: `hi_skip` = `"true"`. Coraza tx header: `X-Hi-Waf-Tx`, value `<siteID>-<16 hex>`. Site IDs are `s_` + 12 lowercase hex, never containing `-`.
- Challenge: verify path `/.hi-waf/verify`, cookie `hi_clr`, token TTL 120 s, default difficulty 4 (range 1–6), default clearance TTL 3600 s.
- Defaults (spec §5, §7): WAF mode `block`, paranoia `1`, anomaly threshold `5`, every protection on except `data_leak`. Rate limits: `attack {10, 60, 1800}`, `error {50, 60, 600}`, and `access` **off**. TLS mode `auto`.
- Responses: blocks → 403, rate-limited or banned → 429 with `Retry-After` (seconds).
- Manager defaults: listen `:9000`, Caddy admin `http://127.0.0.1:2019`, Bearer API keys from config with constant-time compare.
- Caddy is run with `caddy run --resume`. The manager pushes the full config on startup. If Caddy is unreachable, writes return 503 and roll back.

## Review Focus

1. **Spoofed `X-Forwarded-For` with no trusted proxies.** Limits and IP rules must use the TCP peer. Test: `TestClientIPIgnoresXFFWithoutTrustedProxy` (Task 1).
2. **IPv6 and IPv4-mapped addresses** (`::ffff:203.0.113.7` vs a `203.0.113.0/24` rule, `2001:db8::/32`). Matching must normalize. Test: `TestIPSetIPv6AndMapped` (Task 4).
3. **Site edited while a client is banned.** The ban must survive the config reload. Test: `TestPoolStateSurvivesReload` (Task 3), plus the integration reload test (Task 11).
4. **Challenge return-path open redirect** (`//evil.com`, `/\evil.com`, `https://evil.com`). Must redirect to `/`. Test: `TestSafeReturn` (Task 5).
5. **Same domain on two sites, or differing only in case** (`Shop.Example.com` vs `shop.example.com`). Must be rejected. Test: `TestValidateAllDuplicateDomainsCaseInsensitive` (Task 6).

---

## File map

```
go.mod
cmd/hi-waf/main.go                 Caddy main + module imports
cmd/manager/main.go                manager main
engine/events/events.go            Event type + Emit
engine/clientip/clientip.go        client IP helper
engine/ratelimit/limiter.go        sliding window + ban State (pure)
engine/ratelimit/pool.go           shared State across reloads
engine/ratelimit/module.go         hi_ratelimit handler
engine/ratelimit/admin.go          admin.api.hi_bans
engine/access/ipset.go             IP/CIDR sets
engine/access/rules.go             custom rule model + matcher
engine/access/module.go            hi_access handler (+ geo)
engine/challenge/token.go          PoW token, clearance cookie, safeReturn
engine/challenge/module.go         hi_challenge handler
engine/challenge/page.html         challenge page (embedded)
manager/site/doc.go                API document types, Optional[T]
manager/site/protections.go        checkbox catalog
manager/site/resolve.go            defaults → Resolved
manager/site/validate.go           validation
manager/compile/directives.go      CRS directives per site
manager/compile/config.go          full Caddy JSON
manager/store/store.go             SQLite
manager/caddyclient/client.go      Caddy admin client
manager/ingest/ingest.go           event-log tailer + parser
manager/api/api.go                 REST handlers
integration/engine_test.go         end-to-end in-process Caddy
examples/manager.json, examples/site-shop.json
build/build.sh, build/build.ps1, README.md
```

---

### Task 1: Scaffold, events, client IP

**Files:**
- Create: `go.mod`, `.gitignore`, `cmd/hi-waf/main.go`, `engine/events/events.go`, `engine/clientip/clientip.go`
- Test: `engine/events/events_test.go`, `engine/clientip/clientip_test.go`

**Interfaces:**
- Produces:
  - `events.Event{Type, SiteID, ClientIP, Host, Method, URI, RuleID, Msg string; Until time.Time}`
  - the type constants from Global Constraints (`events.TypeWAFBlock` …)
  - `const events.LogMessage = "hi_event"`
  - `func events.Emit(l *zap.Logger, e Event)`, which logs at Info and omits empty fields. Field keys: `event, site_id, client_ip, host, method, uri, rule_id, msg, until` (RFC3339).
  - `func events.FromRequest(r *http.Request, typ, siteID string) Event`
  - `func clientip.Get(r *http.Request) string` returns the Caddy var `caddyhttp.ClientIPVarKey` if set, else the host of `r.RemoteAddr`. In both cases the IP is unmapped (`netip.Addr.Unmap`).

- [ ] **Step 1:** `git init`, `.gitignore` (`/bin/`, `*.db`, `*.log`, `*.mmdb`). `go.mod` declares `module hostinginside/waf` and `go 1.26`, with requires for caddy v2.11.4, coraza-caddy/v2, zap, modernc.org/sqlite, geoip2-golang v1.
- [ ] **Step 2: Write failing tests**

```go
func TestEmitOmitsEmptyFields(t *testing.T) {
    core, logs := observer.New(zap.InfoLevel)
    events.Emit(zap.New(core), events.Event{Type: events.TypeIPBlock, SiteID: "s_aaaaaaaaaaaa", ClientIP: "1.2.3.4"})
    e := logs.All()[0]
    assert.Equal(t, "hi_event", e.Message)
    m := e.ContextMap()
    assert.Equal(t, "ip_block", m["event"]); assert.Equal(t, "1.2.3.4", m["client_ip"])
    _, has := m["rule_id"]; assert.False(t, has)
}
func TestClientIPIgnoresXFFWithoutTrustedProxy(t *testing.T) {
    r := httptest.NewRequest("GET", "/", nil)
    r.RemoteAddr = "198.51.100.9:5555"
    r.Header.Set("X-Forwarded-For", "6.6.6.6")
    assert.Equal(t, "198.51.100.9", clientip.Get(r))
}
func TestClientIPUnmapsAndPrefersCaddyVar(t *testing.T) {
    r := httptest.NewRequest("GET", "/", nil)
    r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: "::ffff:203.0.113.7"}))
    assert.Equal(t, "203.0.113.7", clientip.Get(r))
}
```
- [ ] **Step 3: Run** `go test ./engine/events/ ./engine/clientip/`. Expected: FAIL (undefined).
- [ ] **Step 4: Implement** both packages. `cmd/hi-waf/main.go` blank-imports `caddy/v2/modules/standard`, `coraza-caddy/v2`, and `hostinginside/waf/engine/{access,ratelimit,challenge}` (those packages come in Tasks 2–5, so add each import as its package lands), then calls `caddycmd.Main()`.
- [ ] **Step 5: Run** the same tests. Expected: PASS.
- [ ] **Step 6: Commit** `feat: scaffold module, events and client IP helpers`.

### Task 2: Rate-limit core (sliding window + bans)

**Files:**
- Create: `engine/ratelimit/limiter.go`
- Test: `engine/ratelimit/limiter_test.go`

**Interfaces:**
- Produces:
  - `type Limit struct{ Requests int \`json:"requests"\`; WindowSec int \`json:"window_sec"\`; BanSec int \`json:"ban_sec"\` }`
  - `type Kind int` with `KindAccess, KindAttack, KindError`
  - `func NewState() *State`. It is pure, with no goroutines.
  - `func (s *State) BannedUntil(ip string, now time.Time) (time.Time, bool)`
  - `func (s *State) Record(k Kind, ip string, lim Limit, now time.Time) (until time.Time, newlyBanned bool)`
  - `func (s *State) Unban(ip string) bool`
  - `func (s *State) Bans(now time.Time) map[string]time.Time`, which returns only unexpired bans
  - `func (s *State) Sweep(now time.Time)`, which drops expired bans and idle windows
  - `State` is goroutine-safe (one mutex).

Sliding-window estimate per `(kind, ip)`. This is the algorithm the tests pin:

```go
// window start = now truncated to lim.WindowSec; on rollover: prev = cur if exactly one window passed, else 0; cur = 0
// estimate = cur+1 + prev * (1 - elapsedInCurrent/windowLen)
// if estimate > lim.Requests → ban until now+BanSec (newlyBanned=true unless already banned), reset that window
```

- [ ] **Step 1: Write failing tests**

```go
func TestRecordBansAfterLimit(t *testing.T) {
    s := NewState(); now := time.Unix(1000, 0); lim := Limit{Requests: 3, WindowSec: 10, BanSec: 60}
    for i := 0; i < 3; i++ { _, b := s.Record(KindAccess, "1.1.1.1", lim, now); assert.False(t, b) }
    until, b := s.Record(KindAccess, "1.1.1.1", lim, now)
    assert.True(t, b); assert.Equal(t, now.Add(60*time.Second), until)
    _, banned := s.BannedUntil("1.1.1.1", now.Add(59*time.Second)); assert.True(t, banned)
    _, banned = s.BannedUntil("1.1.1.1", now.Add(61*time.Second)); assert.False(t, banned)
}
func TestKindsAndIPsAreIndependent(t *testing.T) { /* 3 access hits on A + 3 attack hits on A + 3 access on B: no ban */ }
func TestPreviousWindowWeighting(t *testing.T) {
    s := NewState(); lim := Limit{Requests: 4, WindowSec: 10, BanSec: 60}; t0 := time.Unix(1000, 0)
    for i := 0; i < 4; i++ { s.Record(KindAccess, "x", lim, t0) }
    _, b := s.Record(KindAccess, "x", lim, t0.Add(11*time.Second)) // 4*0.9+1 = 4.6 > 4
    assert.True(t, b)
}
func TestUnbanAndBansList(t *testing.T) { /* ban, Bans() has ip, Unban → true, Bans() empty, Unban again → false */ }
func TestSweepDropsExpired(t *testing.T) { /* ban then Sweep(after expiry) → Bans empty */ }
```
- [ ] **Step 2: Run** `go test ./engine/ratelimit/ -run 'Record|Kinds|Previous|Unban|Sweep'`. Expected: FAIL.
- [ ] **Step 3: Implement** `limiter.go`.
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ratelimit): sliding-window limiter with bans`.

### Task 3: `hi_ratelimit` handler, shared pool, bans admin API

**Files:**
- Create: `engine/ratelimit/pool.go`, `engine/ratelimit/module.go`, `engine/ratelimit/admin.go`
- Test: `engine/ratelimit/module_test.go`

**Interfaces:**
- Consumes: Task 1 `events`, `clientip`. Task 2 `State`, `Limit`.
- Produces:
  - `type RateLimit struct{ SiteID string \`json:"site_id"\`; Access, Attack, Error *Limit \`json:"...,omitempty"\` }`, registered as `http.handlers.hi_ratelimit`
  - `const TxHeader = "X-Hi-Waf-Tx"`
  - `func isWAFInterruption(err error) (ruleID string, ok bool)`
  - admin `GET /hi/bans[?site=]` → `{"<siteID>":[{"ip":"…","until":"RFC3339"}]}`
  - admin `DELETE /hi/bans?site=&ip=` → 204, or 404 if not banned

Behaviour:
- `pool.go`: package var `caddy.NewUsagePool()`. `acquire(siteID) (*State, error)` calls `LoadOrNew`, whose constructor makes a `State` and starts a 30 s sweeper that stops on `Destruct`. `release(siteID)` calls `Delete`. `lookup(siteID)` uses `Range`. Provision calls acquire, and Cleanup calls release. Because the new config provisions before the old one cleans up, state survives reloads.
- `ServeHTTP`, in this order:
  1. If the IP is banned → 429.
  2. If `Access` is set, record it, and if that bans → emit `rate_limit_ban` and return 429.
  3. Overwrite `TxHeader` with `<SiteID>-<16 hex>`.
  4. Call next with a status-capturing writer that embeds `*caddyhttp.ResponseWriterWrapper` and overrides `WriteHeader`.
  5. If the returned error is a WAF interruption → emit `waf_block` with the rule ID, record `Attack`, and on a new ban emit `rate_limit_ban`.
  6. Otherwise, status = the `caddyhttp.HandlerError.StatusCode` from the error if present, else the captured status. If it's ≥ 400 and `Error` is set, record `Error`, emitting `rate_limit_ban` on a new ban.
  7. Return next's error unchanged.
- 429 responses: `caddyhttp.Error(429, err)` with `Retry-After` set to the ceiling of the remaining ban in seconds.
- `isWAFInterruption` uses `errors.As` into `caddyhttp.HandlerError` and the regexp `^interruption triggered by rule (\d+) ` on `.Err.Error()`. This is the coraza-caddy format.
- `Validate`: `SiteID` is non-empty, and every set Limit has all fields > 0.

- [ ] **Step 1: Write failing tests** (call `ServeHTTP` directly with a stub `caddyhttp.HandlerFunc` as next; `Provision` with `caddy.Context{Context: context.Background()}` via `caddy.NewContext(caddy.Context{Context: context.Background()})`)

```go
func TestIsWAFInterruptionPinsCorazaFormat(t *testing.T) {
    err := caddyhttp.HandlerError{StatusCode: 403, Err: fmt.Errorf("interruption triggered by rule %d (%s)", 949110, "deny")}
    id, ok := isWAFInterruption(err); assert.True(t, ok); assert.Equal(t, "949110", id)
    _, ok = isWAFInterruption(caddyhttp.Error(502, errors.New("dial tcp: refused"))); assert.False(t, ok)
}
func TestAccessLimit429WithRetryAfter(t *testing.T)   // Access{2,10,60}: req1,2 → next called; req3 → HandlerError 429, header Retry-After "60"
func TestAttackCountsOnlyWAFErrors(t *testing.T)     // Attack{1,60,600}, next returns interruption error twice → 2nd call banned; then next never called
func TestErrorCountsUpstream404NotWAF403(t *testing.T) // Error{1,60,60}: next writes 404 twice → banned; separate site where next returns WAF interruption twice → not banned by Error limit
func TestTxHeaderOverwritten(t *testing.T)           // client sends X-Hi-Waf-Tx: evil → next sees prefix "s_aaaaaaaaaaaa-" and 16 hex
func TestPoolStateSurvivesReload(t *testing.T)       // acquire(id) → ban ip → acquire(id) again → release(id) once → lookup(id) still has ban; release again → lookup false
func TestNoLimitsStillEmitsWAFBlock(t *testing.T)    // all limits nil, next returns interruption → observer log has event=waf_block rule_id=949110
```
- [ ] **Step 2: Run** `go test ./engine/ratelimit/`. Expected: FAIL.
- [ ] **Step 3: Implement** `pool.go`, `module.go` (`init` registers the module + `admin.go`'s `BanAdmin`, which implements `caddy.AdminRouter`), and a test for the admin GET/DELETE using `httptest` against `BanAdmin{}.Routes()[0].Handler`.
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5:** Add the blank import to `cmd/hi-waf/main.go`. Commit `feat(ratelimit): hi_ratelimit handler and bans admin API`.

### Task 4: `hi_access` (IP lists, geo, custom rules)

**Files:**
- Create: `engine/access/ipset.go`, `engine/access/rules.go`, `engine/access/module.go`
- Test: `engine/access/ipset_test.go`, `engine/access/rules_test.go`, `engine/access/module_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `func ParseIPSet(entries []string) (IPSet, error)`, which accepts both bare IPs and CIDRs
  - `func (s IPSet) Contains(a netip.Addr) bool`, which unmaps first
  - `type Rule struct{ Action string \`json:"action"\`; Match Match \`json:"match"\` }`, where Action is `"block"` or `"allow"`
  - `type Match struct{ IP, NotIP, Country, Method []string; PathExact, PathPrefix, PathRegex, Host string; Header, Query *KV }`, with JSON tags `ip, not_ip, country, method, path_exact, path_prefix, path_regex, host, header, query`
  - `type KV struct{ Name, Contains, Regex string }`
  - `func (r Rule) Validate() error` (exported, so the manager reuses it). Its checks:
    - the action is valid
    - at least one condition is set
    - regexes compile
    - IPs parse
    - `allow` rules have `IP`, `PathExact` or `PathPrefix`
  - `type Access struct{ SiteID string; AllowIPs, BlockIPs, AllowCountries, BlockCountries []string; BlockIPsFile, GeoIPDB string; Rules []Rule }`, with JSON tags `site_id, allow_ips, block_ips, allow_countries, block_countries, block_ips_file, geoip_db, rules`, registered as `http.handlers.hi_access`. `block_ips_file` is read at Provision (one IP/CIDR per line; blank lines and `#` comments are ignored) and merged into `BlockIPs`. This is the spec §4 hook for future threat-intel feeds.
  - `const SkipVar = "hi_skip"`

Behaviour:
- Conditions within one rule are ANDed.
- Method matching is case-insensitive.
- Host matching is case-insensitive and exact.
- `Country` matches the ISO code, upper-cased.
- Header and query values match on `Contains` (substring) or `Regex`.

Evaluation order in `ServeHTTP`:
1. `allow_ips` → set `SkipVar`, then next.
2. `block_ips` → `ip_block` + 403.
3. Geo:
   - If `allow_countries` is non-empty and the country is known but not in the list → `geo_block` + 403.
   - If the country is in `block_countries` → `geo_block` + 403.
   - An unknown country (private IP, or not in the DB) passes.
4. Rules, first match wins:
   - `block` → `rule_block` + 403.
   - `allow` → `allowed_by_rule` + `SkipVar` + next.
5. Otherwise, next.

GeoIP: opened in Provision with `geoip2.Open` and closed in Cleanup. `Validate` fails if any country is configured, either in the lists or in a rule, while `GeoIPDB` is empty.

- [ ] **Step 1: Write failing tests**

```go
func TestIPSetIPv6AndMapped(t *testing.T) {
    s, err := ParseIPSet([]string{"203.0.113.0/24", "2001:db8::/32", "198.51.100.7"}); require.NoError(t, err)
    assert.True(t, s.Contains(netip.MustParseAddr("::ffff:203.0.113.7")))
    assert.True(t, s.Contains(netip.MustParseAddr("2001:db8::1")))
    assert.True(t, s.Contains(netip.MustParseAddr("198.51.100.7")))
    assert.False(t, s.Contains(netip.MustParseAddr("198.51.100.8")))
    _, err = ParseIPSet([]string{"not-an-ip"}); assert.Error(t, err)
}
func TestRuleANDSemantics(t *testing.T)        // path_prefix "/admin" + not_ip ["1.2.3.4"]: /admin from 5.5.5.5 matches; /admin from 1.2.3.4 no; /shop from 5.5.5.5 no
func TestRuleHeaderQueryMethod(t *testing.T)   // header {Name:"User-Agent",Contains:"sqlmap"}, query {Name:"debug",Regex:"^1$"}, method ["post"] vs POST
func TestAllowRuleValidationRequiresAnchor(t *testing.T) // allow + only method → error; allow + path_prefix → ok; block + nothing → error; bad regex → error
func TestModuleOrder(t *testing.T)             // ip both in allow_ips and block_ips → allowed (SkipVar set, next called); block_ips → 403 + event ip_block; rule block → 403 rule_block; rule allow → SkipVar "true"
func TestCountryWithoutDBInvalid(t *testing.T) // Access{SiteID:"s_x", BlockCountries:["CN"]}.Validate() → error
func TestBlockIPsFile(t *testing.T)            // temp file "# feed\n203.0.113.0/24\n\n" → after Provision, 203.0.113.9 gets 403 ip_block; bad line → Provision error naming the line number
```
- [ ] **Step 2: Run** `go test ./engine/access/`. Expected: FAIL.
- [ ] **Step 3: Implement.** Use a `countryOf(addr) string` func field on the module, so tests stub geo without an `.mmdb`.
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5:** Add the blank import to main. Commit `feat(access): IP lists, geo blocking and custom rules`.

### Task 5: `hi_challenge` (JS proof-of-work bot challenge)

**Files:**
- Create: `engine/challenge/token.go`, `engine/challenge/module.go`, `engine/challenge/page.html`
- Test: `engine/challenge/token_test.go`, `engine/challenge/module_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `type Challenge struct{ SiteID string \`json:"site_id"\`; Secret string \`json:"secret"\`; Difficulty int \`json:"difficulty,omitempty"\`; ClearanceTTLSec int \`json:"clearance_ttl_sec,omitempty"\` }`, registered as `http.handlers.hi_challenge`. `Secret` is std base64 of ≥ 32 bytes.
  - `func issueToken(key []byte, siteID, ip string, now time.Time) string`
  - `func checkToken(key []byte, tok, siteID, ip string, now time.Time) error`, where the TTL is 120 s
  - `func validPoW(tok, nonce string, difficulty int) bool`, true when `hex(sha256(tok+":"+nonce))` has `difficulty` leading `'0'`
  - `func makeClearance(key []byte, siteID, ip string, exp time.Time) string`, producing `"<unix exp>.<b64url HMAC-SHA256(siteID|ip|exp)>"`
  - `func checkClearance(key []byte, v, siteID, ip string, now time.Time) bool`
  - `func safeReturn(p string) string`

Behaviour:
- A token is `b64url(siteID|exp|16 random hex).b64url(HMAC(siteID|ip|exp|rand))`, so the IP is bound but not revealed.
- All MAC comparisons use `hmac.Equal`.
- `ServeHTTP`, in this order:
  1. If the path is `VerifyPath` → read `c`, `n`, `r`. If `checkToken` and `validPoW` both pass → set cookie `hi_clr` (HttpOnly, `SameSite=Lax`, `Path=/`, `Secure` when `r.TLS != nil`), emit `challenge_passed`, and 302 to `safeReturn(r)`. Otherwise emit `challenge_failed` and return 403.
  2. If there's a valid `hi_clr` cookie → next.
  3. If the method is GET or HEAD and `Accept` contains `text/html` → 200 with the challenge page and `Cache-Control: no-store`.
  4. Otherwise → 403.
- `page.html` is an `html/template` with `{{.Token}}`, `{{.Difficulty}}`, `{{.Return}}`. Its JS:
  - brute-forces the nonce
  - uses `crypto.subtle` when available, and otherwise an inline pure-JS SHA-256, because `crypto.subtle` is missing on plain-HTTP pages
  - then navigates to `/.hi-waf/verify?c=…&n=…&r=…`
  - shows a `<noscript>` message
- `Provision` applies the defaults (difficulty 4, TTL 3600). `Validate`: difficulty is 1–6, and the secret decodes to ≥ 32 bytes.

- [ ] **Step 1: Write failing tests**

```go
func TestSafeReturn(t *testing.T) {
    for in, want := range map[string]string{"/shop?a=1": "/shop?a=1", "": "/", "//evil.com": "/", "/\\evil.com": "/", "https://evil.com": "/", "shop": "/"} {
        assert.Equal(t, want, safeReturn(in), in)
    }
}
func TestTokenBoundToIPAndExpires(t *testing.T) // issue for 1.1.1.1 at t0: check ok at t0+119s; error for 2.2.2.2; error at t0+121s; tampered token error
func TestValidPoW(t *testing.T)                 // brute force nonce for difficulty 2 in test, assert true; same nonce difficulty 6 almost surely false → instead assert a nonce whose hash lacks prefix returns false
func TestClearanceBoundToSiteAndIP(t *testing.T)
func TestModuleFlow(t *testing.T)               // GET Accept text/html no cookie → 200 page containing token; API GET Accept application/json → 403; verify with solved nonce → 302 Location "/" and Set-Cookie hi_clr; request with that cookie → next called
```
- [ ] **Step 2: Run** `go test ./engine/challenge/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5:** Add the blank import to main, then `go build ./cmd/hi-waf`. Expected: builds. Commit `feat(challenge): JS proof-of-work bot challenge`.

### Task 6: Site document, defaults, validation

**Files:**
- Create: `manager/site/doc.go`, `manager/site/protections.go`, `manager/site/resolve.go`, `manager/site/validate.go`
- Test: `manager/site/site_test.go`

**Interfaces:**
- Consumes: `ratelimit.Limit` (Task 2), `access.Rule` + `Rule.Validate` (Task 4), `access.ParseIPSet`.
- Produces:
  - `type Optional[T any] struct{ Set, Null bool; Value T }`. `UnmarshalJSON` sets `Set`, and a literal `null` sets `Null`. `MarshalJSON` round-trips. `func (o Optional[T]) Resolve(def *T) *T` returns `nil` if `Null`, `&Value` if `Set`, else `def`.
  - `Doc`: `Name`, `Domains`, `Upstreams []string`; `TLS *TLSDoc{Mode}`; `WAF *WAFDoc{Mode string; Paranoia, AnomalyThreshold int; Protections map[string]bool}` with JSON `anomaly_threshold`; `RateLimit *RateLimitDoc{Access, Attack, Error Optional[ratelimit.Limit]}`; `Access *AccessDoc{AllowIPs, BlockIPs, AllowCountries, BlockCountries []string; BlockIPsFile string; Rules []access.Rule}` (`Resolved` carries `BlockIPsFile` too, and the compiler passes it to `hi_access.block_ips_file`); `BotChallenge *ChallengeDoc{Enabled bool; Difficulty int}`; `BlockPage *BlockPageDoc{Title, Message string}`. JSON keys follow spec §7.
  - `type Protection struct{ Key, Label string; IDRanges []string; Default bool }`, `var Protections []Protection` with the 12 keys of spec §5 in that order (`protocol` = `920000-920999`, `921000-921999`, `922000-922999`; `data_leak` = `950000-955999`, Default false)
  - `Resolved{ID, Name string; Domains, Upstreams []string; TLSMode, WAFMode string; Paranoia, AnomalyThreshold int; Protections map[string]bool; Access, Attack, Error *ratelimit.Limit; AllowIPs, BlockIPs, AllowCountries, BlockCountries []string; Rules []access.Rule; Challenge bool; ChallengeDifficulty int; BlockTitle, BlockMessage string}`
  - `func Resolve(id string, d Doc) Resolved`, which lowercases domains and upper-cases countries
  - `type Cert struct{ CertPEM, KeyPEM string }`
  - `type ValidationError struct{ Field, Msg string }`, which implements `error`
  - `func Validate(d Doc, geoEnabled bool) error`
  - `func ValidateAll(sites []Resolved) error`
  - `func NewID() string`, returning `s_` + 12 hex

Validation (each failure returns a `*ValidationError` naming the JSON path, e.g. `access.rules[0].match.path_regex`):
- domains: non-empty, valid hostnames (wildcard `*.` prefix allowed)
- upstreams: non-empty, `host:port` or `http(s)://host:port`, all the same scheme
- `tls.mode` ∈ {auto, uploaded, off}; `waf.mode` ∈ {block, detect, off}; paranoia 1–4; threshold ≥ 1
- unknown protection key
- any set limit field ≤ 0
- bad IP
- country not two letters
- any country when `!geoEnabled`
- `Rule.Validate`
- challenge difficulty 0 (meaning default) or 1–6
- name ≤ 64 chars

- [ ] **Step 1: Write failing tests**

```go
func TestOmittedVsNullRateLimit(t *testing.T) {
    var d Doc
    require.NoError(t, json.Unmarshal([]byte(`{"domains":["a.com"],"upstreams":["10.0.0.5:80"],"rate_limit":{"error":null}}`), &d))
    r := Resolve("s_aaaaaaaaaaaa", d)
    assert.Nil(t, r.Access)                                       // access off by default
    assert.Equal(t, &ratelimit.Limit{Requests: 10, WindowSec: 60, BanSec: 1800}, r.Attack) // attack default (keyed: go vet rejects unkeyed imported structs)
    assert.Nil(t, r.Error)                                        // explicit null → off
}
func TestDefaults(t *testing.T) // minimal doc → TLSMode auto, WAFMode block, Paranoia 1, Threshold 5, Protections all true except data_leak false, Error {50,60,600}
func TestProtectionsMerge(t *testing.T) // {"waf":{"protections":{"xss":false}}} → xss false, sqli true
func TestValidateErrorsNameField(t *testing.T) // table: bad upstream → "upstreams[0]"; paranoia 5 → "waf.paranoia"; unknown key "foo" → "waf.protections.foo"; country with geo off → "access.block_countries"; allow rule w/o anchor → "access.rules[0]"
func TestValidateAllDuplicateDomainsCaseInsensitive(t *testing.T) {
    a := Resolve("s_a", Doc{Domains: []string{"Shop.Example.com"}, Upstreams: []string{"1.1.1.1:80"}})
    b := Resolve("s_b", Doc{Domains: []string{"shop.example.com"}, Upstreams: []string{"1.1.1.1:80"}})
    assert.Error(t, ValidateAll([]Resolved{a, b}))
}
```
- [ ] **Step 2: Run** `go test ./manager/site/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(manager): site document, defaults and validation`.

### Task 7: Compiler (CRS directives + Caddy JSON)

**Files:**
- Create: `manager/compile/directives.go`, `manager/compile/config.go`, `manager/compile/testdata/*.golden.json`
- Test: `manager/compile/compile_test.go`

**Interfaces:**
- Consumes: Task 6 `site.Resolved`, `site.Cert`, `site.Protections`. Module JSON field names from Tasks 3–5.
- Produces:
  - `type Options struct{ AdminListen string; HTTPPort, HTTPSPort int; EventLog, ChallengeSecret, GeoIPDB string; TrustedProxies []string; ACMEInternal bool }`
  - `func Directives(s site.Resolved) string`
  - `func Config(sites []site.Resolved, certs map[string]site.Cert, opt Options) (map[string]any, error)`, which errors when a site has `TLSMode == "uploaded"` and no cert

`Directives` output, in this exact order:

```
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=<P>"
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=<T>,setvar:tx.outbound_anomaly_score_threshold=4"
Include @owasp_crs/*.conf
SecRuleEngine On            (detect → DetectionOnly)
SecResponseBodyAccess Off   (On when data_leak)
SecRuleRemoveById <range>   (one line per range of each disabled protection, catalog order)
```

Config shape:
- `admin.listen` = `opt.AdminListen`
- `logging.logs`:
  - `default.exclude` = the 4 engine logger names (`http.handlers.waf`, `http.handlers.hi_access`, `http.handlers.hi_ratelimit`, `http.handlers.hi_challenge`)
  - `hi_events` = file writer at `opt.EventLog`, `roll_size_mb: 100`, json encoder, `include` = same 4 names
- `apps.http.http_port`/`https_port` from `opt`
- servers:
  - `"waf"` listens on `:HTTPSPort` and holds every site whose TLS isn't off. `automatic_https.skip_certificates` lists the domains of uploaded-cert sites.
  - `"plain"` listens on `:HTTPPort` and holds the TLS-off sites.
  - Omit a server when it has no sites.
  - `trusted_proxies {"source":"static","ranges":…}` when set.
  - A final fallback route returns `static_response 404 "unknown site"`.
- Per-site route: `match [{host: domains}]`, `terminal: true`, and a handler `subroute` with these routes:
  1. `hi_access` (only when the site has any access config)
  2. a route matched by `{"vars":{"{http.vars.hi_skip}":["true"]}}` → `reverse_proxy`, terminal
  3. the main route: `hi_ratelimit` (always), then `hi_challenge` (if enabled), then `waf` (`load_owasp_crs: true`, `directives`, `tx_id_req_header: "X-Hi-Waf-Tx"`; omitted when mode is off), then `reverse_proxy`
- `reverse_proxy`: `upstreams[].dial`. For an `https://` scheme, add `transport {"protocol":"http","tls":{}}`. Request header delete `X-Hi-Waf-Tx`.
- `errors.routes` per site: match host → `static_response` with `status_code: "{http.error.status_code}"`, `Content-Type: text/html; charset=utf-8`, and a body built from `html.EscapeString` of the title and message. The default title is `Request blocked` and the default message is `Your request was blocked by the web application firewall.`. The body includes `Event ID: {http.error.id}`.
- `apps.tls`:
  - `certificates.load_pem` for uploaded certs, tagged with the site ID
  - when `ACMEInternal` → `automation.policies [{"issuers":[{"module":"internal"}]}]`
- `hi_access.geoip_db` = `opt.GeoIPDB`
- `hi_challenge.secret` = `opt.ChallengeSecret`

- [ ] **Step 1: Write failing tests**

```go
func TestDirectivesDetectAndDisabled(t *testing.T) {
    r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
        WAF: &site.WAFDoc{Mode: "detect", Paranoia: 2, Protections: map[string]bool{"java": false}}})
    d := Directives(r)
    assert.Contains(t, d, "SecRuleEngine DetectionOnly")
    assert.Contains(t, d, "tx.blocking_paranoia_level=2")
    assert.Contains(t, d, "SecRuleRemoveById 944000-944999")
    assert.Contains(t, d, "SecRuleRemoveById 950000-955999") // data_leak default off
    assert.Less(t, strings.Index(d, "id:900000"), strings.Index(d, "@owasp_crs/*.conf"))
}
// Import coreruleset.FS from the exact path coraza-caddy's coraza.go imports (check its source at the pinned version; not verified here).
func TestProtectionRangesExistInEmbeddedCRS(t *testing.T) // for each Protection, for each range prefix NNN, fs.Glob(coreruleset.FS, "@owasp_crs/*-"+NNN+"-*.conf") (or REQUEST-/RESPONSE-) non-empty — guards spec §5 against the pinned CRS
func TestConfigGolden(t *testing.T)    // fixtures: minimal auto-TLS site; tls off + access rules + challenge; uploaded cert; waf off. Compare json.MarshalIndent to testdata/<name>.golden.json; -update flag rewrites
func TestUploadedWithoutCertErrors(t *testing.T)
func TestBlockPageEscapesHTML(t *testing.T) // title "<script>" → body contains "&lt;script&gt;"
```
- [ ] **Step 2: Run** `go test ./manager/compile/`. Expected: FAIL.
- [ ] **Step 3: Implement** with `map[string]any`. Generate the goldens with `-update`, then **read each golden by eye** against the shape above before committing.
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(manager): compile sites to Caddy JSON and CRS directives`.

### Task 8: SQLite store

**Files:**
- Create: `manager/store/store.go`
- Test: `manager/store/store_test.go`

**Interfaces:**
- Consumes: `site.Doc`, `site.Cert`.
- Produces:
  - `func Open(path string) (*Store, error)`, which uses driver `modernc.org/sqlite`, sets `PRAGMA journal_mode=WAL; busy_timeout=5000`, and migrates on open
  - `(*Store) Close() error`
  - `type SiteRecord struct{ ID string; Doc site.Doc; Created, Updated time.Time }`
  - `(*Store) Tx(ctx context.Context, fn func(*Tx) error) error`, which commits only when fn returns nil
  - `*Tx` methods: `ListSites() ([]SiteRecord, error)` (ordered by created), `GetSite(id string) (SiteRecord, bool, error)`, `PutSite(SiteRecord) error` (upsert), `DeleteSite(id string) (bool, error)` (also deletes the cert), `PutCert(siteID string, c site.Cert) error`, `Certs() (map[string]site.Cert, error)`
  - `(*Store) ListSites(ctx) ([]SiteRecord, error)`, `(*Store) Certs(ctx)`
  - `(*Store) Setting(ctx, key string) (string, bool, error)`, `(*Store) SetSetting(ctx, key, val string) error`
  - `type Event struct{ ID int64; TS time.Time; SiteID, Type, ClientIP, Host, Method, URI, RuleID, Msg string }`
  - `(*Store) InsertEvents(ctx, []Event) error`, done in one transaction
  - `type EventFilter struct{ SiteID, Type, IP string; Since time.Time; Limit int }`, where `Limit` defaults to 100 with max 1000
  - `(*Store) QueryEvents(ctx, EventFilter) ([]Event, error)`, newest first
  - `type Stats struct{ ByType map[string]int; TopIPs, TopRules []Count }`, `type Count struct{ Key string; N int }`
  - `(*Store) Stats(ctx, siteID string, since time.Time) (Stats, error)`, with top 10 each. `TopRules` counts `waf_match` events.

Tables:
- `sites(id PK, doc TEXT json, created, updated)`
- `certs(site_id PK, cert_pem, key_pem)`
- `settings(key PK, value)`
- `events(id INTEGER PK AUTOINCREMENT, ts INTEGER unix-ms, site_id, type, client_ip, host, method, uri, rule_id, msg)`, indexed on `(site_id, ts)`

- [ ] **Step 1: Write failing tests** (use `t.TempDir()`)

```go
func TestTxRollbackOnError(t *testing.T) // PutSite inside Tx returning errors.New("x") → ListSites empty
func TestSiteRoundTripPreservesNull(t *testing.T) // doc with rate_limit.error null → reload → Doc.RateLimit.Error.Null true
func TestEventsFilterAndStats(t *testing.T) // insert 3 waf_match (rule 942100 x2, 941100), 1 ip_block; QueryEvents{Type:"waf_match"} len 3 newest first; Stats TopRules[0] = {942100,2}
func TestDeleteSiteRemovesCert(t *testing.T)
```
- [ ] **Step 2: Run** `go test ./manager/store/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(manager): SQLite store`.

### Task 9: Caddy admin client + event ingester

**Files:**
- Create: `manager/caddyclient/client.go`, `manager/ingest/ingest.go`, `manager/ingest/testdata/events.log`
- Test: `manager/caddyclient/client_test.go`, `manager/ingest/ingest_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Event`.
- Produces:
  - `type Client struct{ BaseURL string; HTTP *http.Client }`
  - `var ErrUnreachable = errors.New("caddy admin unreachable")`
  - `type LoadError struct{ Status int; Body string }`, which implements `error`
  - `(*Client) Load(ctx, cfg any) error` does `POST /load` with `Content-Type: application/json`. A transport failure wraps `ErrUnreachable`, and a non-2xx response returns `*LoadError`.
  - `type Ban struct{ IP string \`json:"ip"\`; Until time.Time \`json:"until"\` }`
  - `(*Client) Bans(ctx, siteID string) (map[string][]Ban, error)`
  - `(*Client) Unban(ctx, siteID, ip string) (bool, error)`
  - `func ParseLine(line []byte) (store.Event, bool)`
  - `type Tailer struct{ Path string; Store *store.Store; Interval time.Duration; Logger *slog.Logger }`
  - `(*Tailer) Once(ctx) error`
  - `(*Tailer) Run(ctx) error`

Parsing:
- Each line is Caddy JSON: `ts` is float unix seconds, plus `logger` and `msg`.
- If `msg == "hi_event"` → map the fields to an Event one to one, with `Type` taken from `event`.
- Else if `logger == "http.handlers.waf"` and some string value (check `msg` first, then the others) contains `[id "` → a `waf_match` event. Pull `id`, `msg`, `client`, `uri`, `unique_id` with ``\[(\w+) "((?:[^"\\]|\\.)*)"\]``. `SiteID` is the part of `unique_id` before the first `-`.
- Ignore all other lines, including coraza's `WAF rule violation detected`, because `waf_block` covers it.

Tailer:
- The offset lives in setting `ingest_offset`. If the file is smaller than the offset, it was rotated, so restart at 0.
- Read only complete lines, insert in batches of ≤ 500, then save the offset after the insert.

- [ ] **Step 1: Write failing tests**

```go
func TestParseHiEvent(t *testing.T) // {"ts":1761200000.5,"logger":"http.handlers.hi_access","msg":"hi_event","event":"ip_block","site_id":"s_aaaaaaaaaaaa","client_ip":"1.2.3.4"} → Type ip_block, TS 2025-10-23T06:13:20.5Z
func TestParseCorazaMatch(t *testing.T) // msg `[client "1.2.3.4"] Coraza: Warning. SQL Injection Attack Detected [file "x"] [line "1"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [uri "/?id=1"] [unique_id "s_aaaaaaaaaaaa-0123456789abcdef"]` → waf_match, RuleID 942100, SiteID s_aaaaaaaaaaaa, ClientIP 1.2.3.4
func TestParseIgnoresOther(t *testing.T) // access log line; "WAF rule violation detected"; invalid JSON → false
func TestTailerOffsetAndRotation(t *testing.T) // write 2 lines → Once → 2 events; append partial line → Once → still 2; finish line → 3; truncate file and write 1 → Once → 4
func TestLoadErrors(t *testing.T) // httptest 400 body "bad" → *LoadError{400,"bad"}; closed server → errors.Is(err, ErrUnreachable)
```
- [ ] **Step 2: Run** `go test ./manager/caddyclient/ ./manager/ingest/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(manager): caddy admin client and event ingester`.

### Task 10: REST API + manager main

**Files:**
- Create: `manager/api/api.go`, `cmd/manager/main.go`, `examples/manager.json`
- Test: `manager/api/api_test.go`

**Interfaces:**
- Consumes: Tasks 6–9.
- Produces:
  - `type Loader interface{ Load(ctx context.Context, cfg any) error; Bans(ctx context.Context, siteID string) (map[string][]caddyclient.Ban, error); Unban(ctx context.Context, siteID, ip string) (bool, error) }`
  - `func New(st *store.Store, cl Loader, opt compile.Options, apiKeys []string) *API`
  - `(*API) Handler() http.Handler`
  - `(*API) Sync(ctx) error`, which compiles from the DB and loads
- Manager config file (JSON): `listen, db_path, caddy_admin, event_log, api_keys, http_port, https_port, geoip_db, trusted_proxies, acme_internal`

Behaviour:
- Routes are spec §7 exactly, using Go 1.22 `ServeMux` patterns.
- Every route needs `Authorization: Bearer <key>` (`subtle.ConstantTimeCompare`), else 401.
- Request bodies are capped at 1 MiB.
- `site.Validate(doc, opt.GeoIPDB != "")` runs on every POST/PUT body.
- Mutations run through `func (a *API) apply(ctx, fn func(*store.Tx) error) error`, which runs inside `store.Tx`:
  1. run `fn`
  2. list sites and certs
  3. `site.Resolve` each one
  4. `site.ValidateAll`
  5. `compile.Config`
  6. `Loader.Load`
  Any error rolls back.
- Error mapping: `*site.ValidationError` → 400 `{"error","field"}`, `ErrUnreachable` → 503, `*LoadError` → 502 with Caddy's message, not found → 404.
- `POST /sites` returns 201 with `{"id", ...doc}`.
- `GET` returns the stored doc, not the resolved one, plus a `"resolved"` field holding the effective settings so the user can see the defaults.
- Certificate upload: JSON `{"cert_pem","key_pem"}`. Validate with `tls.X509KeyPair`. The response never echoes the key.
- `GET /protections` returns the catalog `[{key,label,default}]`.
- Events and stats query params follow spec §7. `since` is RFC3339 and `window` is a Go duration.

`cmd/manager/main.go`:
1. Load the config.
2. Open the store.
3. Read setting `challenge_secret`. If it's absent, generate 32 random bytes, store them, and reuse them forever.
4. Call `Sync`. If it fails, log a warning and continue, so the API comes up while Caddy is down.
5. Start the `Tailer` goroutine.
6. Serve.

- [ ] **Step 1: Write failing tests** (use a fake `Loader` that records configs and can be set to fail)

```go
func TestAuthRequired(t *testing.T)                // no/wrong bearer → 401
func TestCreateSiteAppliesAndPersists(t *testing.T) // POST minimal doc → 201, fake got 1 config containing host "shop.example.com", GET list len 1
func TestRollbackWhenCaddyRejects(t *testing.T)    // fake returns &caddyclient.LoadError{400,"bad"} → 502, list still empty
func TestUnreachableIs503(t *testing.T)            // fake returns fmt.Errorf("%w", caddyclient.ErrUnreachable) → 503, nothing stored
func TestValidationErrorHasField(t *testing.T)     // waf.paranoia 9 → 400 {"field":"waf.paranoia"}
func TestDuplicateDomainRejected(t *testing.T)     // second site same domain → 400
func TestGetShowsResolvedDefaults(t *testing.T)    // resolved.rate_limit.attack == {10,60,1800}, resolved.rate_limit.access == null
func TestCertUploadRejectsMismatch(t *testing.T)   // mismatched key → 400
```
- [ ] **Step 2: Run** `go test ./manager/api/`. Expected: FAIL.
- [ ] **Step 3: Implement** `api.go` and `cmd/manager/main.go`. In `examples/manager.json`, use dev ports `8080`/`8443`, `acme_internal: true`, and the placeholder key `"change-me-dev-key"`.
- [ ] **Step 4: Run** `go test ./manager/... && go build ./...`. Expected: PASS and builds.
- [ ] **Step 5: Commit** `feat(manager): REST API and manager binary`.

### Task 11: End-to-end test, build scripts, README

**Files:**
- Create: `integration/engine_test.go`, `examples/site-shop.json`, `build/build.sh`, `build/build.ps1`, `README.md`

**Interfaces:**
- Consumes: everything. The engine runs in-process via `github.com/caddyserver/caddy/v2/caddytest` with `compile.Config` output (`AdminListen: "localhost:2999"`, as caddytest expects; HTTP port 9080; all sites `tls: off`) and an `httptest` upstream.

- [ ] **Step 1: Write the tests.** They're skipped under `-short`. Blank-import the coraza and engine modules.

```go
func TestE2E_SQLiBlockedAndEventLogged(t *testing.T) // GET http://localhost:9080/?id=1%27%20OR%20%271%27=%271 Host a.test → 403; event log file contains "waf_block" and a coraza line with [id "942
func TestE2E_DetectModePassesButLogs(t *testing.T)   // waf.mode detect → 200 from upstream; event log has [id "942 and no waf_block
func TestE2E_AccessLimitBansAndSurvivesReload(t *testing.T) // rate_limit.access {3,60,60}: 3x 200, 4th 429; InitServer again with same config → still 429
func TestE2E_RuleBlockAndAllowSkipsWAF(t *testing.T) // rule block path_prefix /admin → 403; rule allow path_prefix /webhook → SQLi payload to /webhook returns 200
func TestE2E_ChallengeServedToBrowser(t *testing.T)  // bot_challenge on, Accept text/html → 200 body contains "/.hi-waf/verify"
```
- [ ] **Step 2: Run** `go test ./integration/ -v`. Expected: PASS. A failure here most likely means a Caddy or coraza-caddy API assumption from the earlier tasks was wrong, so fix it at the source.
- [ ] **Step 3: Write the scripts and README.**
  - `build/build.ps1` and `build.sh` run `go mod tidy`, then `go build -o bin/hi-waf ./cmd/hi-waf` and `go build -o bin/manager ./cmd/manager`.
  - The README covers:
    - prerequisites: Go 1.26+, plus a GeoLite2-Country.mmdb if you want geo blocking
    - run order: `bin/hi-waf run --resume`, then `bin/manager -config examples/manager.json`
    - a curl walkthrough: create a site from `examples/site-shop.json`, send an SQLi to get 403, list events, list and delete bans
    - the checkbox list
    - known limits from spec §10
- [ ] **Step 4: Run** `go vet ./... && go test ./...`. Expected: clean.
- [ ] **Step 5: Commit** `test: end-to-end engine tests; docs: build and run guide`.

---

## Spec coverage notes (deviations, for the reviewer)

- **Spec §6 xcaddy → own `cmd/hi-waf` main.** This is the same binary pattern xcaddy generates, and it needs no extra tool.
- **Spec §6 "Caddyfile support for manual testing" → JSON examples instead.** The manager only emits JSON, so Caddyfile parsers would be untested code.
- **Spec §6 "Coraza error callback set from our wrapper" → no wrapper.** coraza-caddy already routes its error callback into its zap logger (`http.handlers.waf`). We send that logger to the events file, and tie each line to its site with the `X-Hi-Waf-Tx` → `tx_id_req_header` → `unique_id` chain. Coraza stays unmodified.
- **`hi_ratelimit` is always in the chain,** even with all limits off, because it emits `waf_block` and sets the tx header.
