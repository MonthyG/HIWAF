package compile

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/site"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func baseOptions() Options {
	return Options{
		AdminListen:     "127.0.0.1:2019",
		HTTPPort:        80,
		HTTPSPort:       443,
		EventLog:        "/var/log/hi-waf/events.log",
		ChallengeSecret: "c2VjcmV0",
		GeoIPDB:         "/var/lib/hi-waf/GeoLite2-Country.mmdb",
	}
}

// marshal is how goldens are written: two-space indent, no HTML escaping
// (so "<" stays readable), trailing newline.
func marshal(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	return b.String()
}

func TestDirectivesDetectAndDisabled(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		WAF: &site.WAFDoc{Mode: "detect", Paranoia: 2, Protections: map[string]bool{"java": false}}})
	d := Directives(r)
	assert.Contains(t, d, "SecRuleEngine DetectionOnly")
	assert.Contains(t, d, "tx.blocking_paranoia_level=2")
	assert.Contains(t, d, "SecRuleRemoveById 944000-944999")
	assert.Contains(t, d, "SecRuleRemoveById 950000-956999") // data_leak default off
	assert.Contains(t, d, "SecResponseBodyAccess Off")
	assert.Less(t, strings.Index(d, "id:900000"), strings.Index(d, "@owasp_crs/*.conf"))
	assert.Less(t, strings.Index(d, "@owasp_crs/*.conf"), strings.Index(d, "SecRuleRemoveById"))
}

func TestDirectivesDataLeakOn(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		WAF: &site.WAFDoc{Protections: map[string]bool{"data_leak": true}}})
	d := Directives(r)
	assert.Contains(t, d, "SecRuleEngine On")
	assert.Contains(t, d, "SecResponseBodyAccess On")
	assert.NotContains(t, d, "SecRuleRemoveById")
}

// Guards spec §5 against the CRS embedded in the pinned coraza-caddy: every
// 3-digit file number covered by a protection range must exist as
// @owasp_crs/REQUEST-NNN-*.conf or RESPONSE-NNN-*.conf.
func TestProtectionRangesExistInEmbeddedCRS(t *testing.T) {
	for _, p := range site.Protections {
		for _, r := range p.IDRanges {
			lo, hi, ok := strings.Cut(r, "-")
			require.True(t, ok, r)
			from, err := strconv.Atoi(lo)
			require.NoError(t, err)
			to, err := strconv.Atoi(hi)
			require.NoError(t, err)
			for n := from / 1000; n <= to/1000; n++ {
				m, err := fs.Glob(coreruleset.FS, fmt.Sprintf("@owasp_crs/*-%d-*.conf", n))
				require.NoError(t, err)
				assert.NotEmpty(t, m, "%s: no CRS file for %d", p.Key, n)
			}
		}
	}
}

func TestConfigGolden(t *testing.T) {
	cases := []struct {
		name  string
		sites []site.Resolved
		certs map[string]site.Cert
		opt   func(*Options)
	}{
		{
			name:  "auto_tls",
			sites: []site.Resolved{site.Resolve("s_aaaaaaaaaaaa", site.Doc{
				Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.1:80"},
			})},
		},
		{
			name:  "plain_access_challenge",
			sites: []site.Resolved{site.Resolve("s_bbbbbbbbbbbb", site.Doc{
				Domains:   []string{"b.com"},
				Upstreams: []string{"https://10.0.0.2:443"},
				TLS:       &site.TLSDoc{Mode: "off"},
				Access:    &site.AccessDoc{
					BlockIPs: []string{"1.2.3.4"},
					Rules:    []access.Rule{{Action: "block", Match: access.Match{PathPrefix: "/admin"}}},
				},
				BotChallenge: &site.ChallengeDoc{Enabled: true, Difficulty: 5},
			})},
			opt: func(o *Options) { o.TrustedProxies = []string{"10.0.0.0/8"} },
		},
		{
			name:  "uploaded_cert",
			sites: []site.Resolved{site.Resolve("s_cccccccccccc", site.Doc{
				Domains: []string{"c.com"}, Upstreams: []string{"10.0.0.3:80"},
				TLS: &site.TLSDoc{Mode: "uploaded"},
			})},
			certs: map[string]site.Cert{"s_cccccccccccc": {CertPEM: "CERT", KeyPEM: "KEY"}},
			opt:   func(o *Options) { o.ACMEInternal = true },
		},
		{
			name:  "waf_off",
			sites: []site.Resolved{site.Resolve("s_dddddddddddd", site.Doc{
				Domains: []string{"d.com"}, Upstreams: []string{"10.0.0.4:80"},
				WAF:       &site.WAFDoc{Mode: "off"},
				RateLimit: &site.RateLimitDoc{Error: site.Optional[ratelimit.Limit]{Set: true, Null: true}},
			})},
		},
		{
			name: "mixed_tls_plain",
			sites: []site.Resolved{
				site.Resolve("s_eeeeeeeeeeee", site.Doc{Domains: []string{"e.com"}, Upstreams: []string{"10.0.0.5:80"}}),
				site.Resolve("s_ffffffffffff", site.Doc{Domains: []string{"f.com"}, Upstreams: []string{"10.0.0.6:80"},
					TLS: &site.TLSDoc{Mode: "off"}}),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := baseOptions()
			if c.opt != nil {
				c.opt(&o)
			}
			cfg, err := Config(c.sites, c.certs, o)
			require.NoError(t, err)
			got := marshal(t, cfg)
			path := filepath.Join("testdata", c.name+".golden.json")
			if *update {
				require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, strings.ReplaceAll(string(want), "\r", ""), got)
		})
	}
}

func TestUploadedWithoutCertErrors(t *testing.T) {
	r := site.Resolve("s_cccccccccccc", site.Doc{Domains: []string{"c.com"}, Upstreams: []string{"10.0.0.3:80"},
		TLS: &site.TLSDoc{Mode: "uploaded"}})
	_, err := Config([]site.Resolved{r}, nil, baseOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s_cccccccccccc")
}

func TestBlockPageEscapesHTML(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		BlockPage: &site.BlockPageDoc{Title: "<script>", Message: "a & {env.SECRET}"}})
	h := blockPage(r)
	body := h["body"].(string)
	assert.Contains(t, body, "&lt;script&gt;")
	assert.NotContains(t, body, "<script>")
	assert.Contains(t, body, "a &amp; &#123;env.SECRET&#125;")
	assert.NotContains(t, body, "{env.SECRET}")
	assert.Contains(t, body, "Event ID: {http.error.id}")
	assert.Equal(t, "{http.error.status_code}", h["status_code"])
}

func TestBlockPageDefaults(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"}})
	body := blockPage(r)["body"].(string)
	assert.Contains(t, body, "<h1>Request blocked</h1>")
	assert.Contains(t, body, "<p>Your request was blocked by the web application firewall.</p>")
}

// routeHosts lists each route's host matcher (nil for the fallback route).
func routeHosts(routes []any) [][]string {
	var out [][]string
	for _, r := range routes {
		m, ok := r.(map[string]any)["match"]
		if !ok {
			out = append(out, nil)
			continue
		}
		out = append(out, m.([]any)[0].(map[string]any)["host"].([]string))
	}
	return out
}

func servers(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	return cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
}

// Ruling R11: exact-domain routes come before wildcard-domain routes, so
// x.a.com reaches its own site even when *.a.com's site is listed first.
func TestExactDomainsBeforeWildcards(t *testing.T) {
	wild := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"*.a.com", "a.com"}, Upstreams: []string{"10.0.0.1:80"}})
	exact := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	cfg, err := Config([]site.Resolved{wild, exact}, nil, baseOptions())
	require.NoError(t, err)
	srv := servers(t, cfg)["waf"].(map[string]any)
	assert.Equal(t, [][]string{{"a.com"}, {"x.a.com"}, {"*.a.com"}, nil}, routeHosts(srv["routes"].([]any)))
	assert.Equal(t, [][]string{{"a.com"}, {"x.a.com"}, {"*.a.com"}},
		routeHosts(srv["errors"].(map[string]any)["routes"].([]any)))
}

// Ruling R13: the plain server redirects TLS domains itself, ordered with the
// plain sites, so a plain *.a.com can't capture a TLS x.a.com on port 80.
func TestPlainServerRedirectsBeforeWildcards(t *testing.T) {
	plain := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"*.a.com"}, Upstreams: []string{"10.0.0.1:80"},
		TLS: &site.TLSDoc{Mode: "off"}})
	secure := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	cfg, err := Config([]site.Resolved{plain, secure}, nil, baseOptions())
	require.NoError(t, err)
	srvs := servers(t, cfg)
	routes := srvs["plain"].(map[string]any)["routes"].([]any)
	assert.Equal(t, [][]string{{"x.a.com"}, {"*.a.com"}, nil}, routeHosts(routes))
	redir := routes[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	assert.Equal(t, 308, redir["status_code"])
	assert.Equal(t, []string{"https://{http.request.host}{http.request.uri}"},
		redir["headers"].(map[string]any)["Location"])
	assert.Equal(t, true, srvs["waf"].(map[string]any)["automatic_https"].(map[string]any)["disable_redirects"])
}

func TestRedirectKeepsNonDefaultHTTPSPort(t *testing.T) {
	secure := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	o := baseOptions()
	o.HTTPSPort = 8443
	cfg, err := Config([]site.Resolved{secure}, nil, o)
	require.NoError(t, err)
	routes := servers(t, cfg)["plain"].(map[string]any)["routes"].([]any)
	redir := routes[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	assert.Equal(t, []string{"https://{http.request.host}:8443{http.request.uri}"},
		redir["headers"].(map[string]any)["Location"])
}

// Ruling R14: block_ips_file is a name inside FeedsDir, never a free path.
func TestBlockIPsFileInFeedsDir(t *testing.T) {
	r := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.1:80"},
		Access: &site.AccessDoc{BlockIPsFile: "drop.txt"}})
	_, err := Config([]site.Resolved{r}, nil, baseOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s_aaaaaaaaaaaa")

	o := baseOptions()
	o.FeedsDir = "/var/lib/hi-waf/feeds"
	cfg, err := Config([]site.Resolved{r}, nil, o)
	require.NoError(t, err)
	siteRoute := servers(t, cfg)["waf"].(map[string]any)["routes"].([]any)[0].(map[string]any)
	sub := siteRoute["handle"].([]any)[0].(map[string]any)["routes"].([]any)
	acc := sub[0].(map[string]any)["handle"].([]any)[0].(accessHandler)
	assert.Equal(t, "hi_access", acc.Handler)
	assert.Equal(t, filepath.Join("/var/lib/hi-waf/feeds", "drop.txt"), acc.BlockIPsFile)
}
