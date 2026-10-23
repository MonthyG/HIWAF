package compile

import (
	"fmt"
	"html"
	"strings"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/challenge"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/site"
)

// Options are the engine-wide settings that aren't part of any site.
type Options struct {
	AdminListen                        string
	HTTPPort, HTTPSPort                int
	EventLog, ChallengeSecret, GeoIPDB string
	TrustedProxies                     []string
	ACMEInternal                       bool
}

// engineLoggers are the Caddy loggers whose lines go to the events file.
var engineLoggers = []string{
	"http.handlers.waf",
	"http.handlers.hi_access",
	"http.handlers.hi_ratelimit",
	"http.handlers.hi_challenge",
}

// Handler JSON: the module's own config with Caddy's "handler" key in front.
type accessHandler struct {
	Handler string `json:"handler"`
	access.Access
}

type rateLimitHandler struct {
	Handler string `json:"handler"`
	ratelimit.RateLimit
}

type challengeHandler struct {
	Handler string `json:"handler"`
	challenge.Challenge
}

// Config compiles every site into one complete Caddy config. certs is keyed
// by site ID; a site with TLS mode "uploaded" and no cert is an error.
func Config(sites []site.Resolved, certs map[string]site.Cert, opt Options) (map[string]any, error) {
	var tlsSites, plainSites []site.Resolved
	var skipCerts []string
	var pems []any
	for _, s := range sites {
		switch s.TLSMode {
		case "off":
			plainSites = append(plainSites, s)
			continue
		case "uploaded":
			c, ok := certs[s.ID]
			if !ok || c.CertPEM == "" || c.KeyPEM == "" {
				return nil, fmt.Errorf("site %s: tls mode is uploaded but no certificate is stored", s.ID)
			}
			skipCerts = append(skipCerts, s.Domains...)
			pems = append(pems, map[string]any{"certificate": c.CertPEM, "key": c.KeyPEM, "tags": []string{s.ID}})
		}
		tlsSites = append(tlsSites, s)
	}

	servers := map[string]any{}
	if len(tlsSites) > 0 {
		srv := server(tlsSites, opt.HTTPSPort, opt)
		if len(skipCerts) > 0 {
			srv["automatic_https"] = map[string]any{"skip_certificates": skipCerts}
		}
		servers["waf"] = srv
	}
	if len(plainSites) > 0 {
		servers["plain"] = server(plainSites, opt.HTTPPort, opt)
	}
	httpApp := map[string]any{"http_port": opt.HTTPPort, "https_port": opt.HTTPSPort}
	if len(servers) > 0 {
		httpApp["servers"] = servers
	}
	apps := map[string]any{"http": httpApp}

	tlsApp := map[string]any{}
	if len(pems) > 0 {
		tlsApp["certificates"] = map[string]any{"load_pem": pems}
	}
	if opt.ACMEInternal {
		tlsApp["automation"] = map[string]any{"policies": []any{
			map[string]any{"issuers": []any{map[string]any{"module": "internal"}}},
		}}
	}
	if len(tlsApp) > 0 {
		apps["tls"] = tlsApp
	}

	return map[string]any{
		"admin": map[string]any{"listen": opt.AdminListen},
		"logging": map[string]any{"logs": map[string]any{
			"default": map[string]any{"exclude": engineLoggers},
			"hi_events": map[string]any{
				"writer":  map[string]any{"output": "file", "filename": opt.EventLog, "roll_size_mb": 100},
				"encoder": map[string]any{"format": "json"},
				"include": engineLoggers,
			},
		}},
		"apps": apps,
	}, nil
}

// server builds one HTTP server. Routes for exact domains come before routes
// for wildcard domains, so x.a.com wins over *.a.com whatever the site order.
func server(sites []site.Resolved, port int, opt Options) map[string]any {
	var routes, errRoutes []any
	for _, wildcard := range []bool{false, true} {
		for _, s := range sites {
			var hosts []string
			for _, d := range s.Domains {
				if strings.HasPrefix(d, "*.") == wildcard {
					hosts = append(hosts, d)
				}
			}
			if len(hosts) == 0 {
				continue
			}
			match := []any{map[string]any{"host": hosts}}
			routes = append(routes, map[string]any{
				"match":    match,
				"handle":   []any{map[string]any{"handler": "subroute", "routes": siteRoutes(s, opt)}},
				"terminal": true,
			})
			errRoutes = append(errRoutes, map[string]any{
				"match":  match,
				"handle": []any{blockPage(s)},
			})
		}
	}
	routes = append(routes, map[string]any{
		"handle": []any{map[string]any{"handler": "static_response", "status_code": 404, "body": "unknown site"}},
	})
	srv := map[string]any{
		"listen": []string{fmt.Sprintf(":%d", port)},
		"routes": routes,
		"errors": map[string]any{"routes": errRoutes},
	}
	if len(opt.TrustedProxies) > 0 {
		srv["trusted_proxies"] = map[string]any{"source": "static", "ranges": opt.TrustedProxies}
	}
	return srv
}

// siteRoutes is the site's handler chain: access, then an allowlist bypass
// straight to the proxy, then rate limit, challenge, WAF and proxy.
func siteRoutes(s site.Resolved, opt Options) []any {
	proxy := reverseProxy(s.Upstreams)
	var routes []any
	if hasAccess(s) {
		routes = append(routes, map[string]any{"handle": []any{accessHandler{
			Handler: "hi_access",
			Access: access.Access{
				SiteID:         s.ID,
				AllowIPs:       s.AllowIPs,
				BlockIPs:       s.BlockIPs,
				AllowCountries: s.AllowCountries,
				BlockCountries: s.BlockCountries,
				BlockIPsFile:   s.BlockIPsFile,
				GeoIPDB:        opt.GeoIPDB,
				Rules:          s.Rules,
			},
		}}})
	}
	routes = append(routes, map[string]any{
		"match":    []any{map[string]any{"vars": map[string]any{"{http.vars." + access.SkipVar + "}": []string{"true"}}}},
		"handle":   []any{proxy},
		"terminal": true,
	})
	main := []any{rateLimitHandler{
		Handler:   "hi_ratelimit",
		RateLimit: ratelimit.RateLimit{SiteID: s.ID, Access: s.Access, Attack: s.Attack, Error: s.Error},
	}}
	if s.Challenge {
		main = append(main, challengeHandler{
			Handler:   "hi_challenge",
			Challenge: challenge.Challenge{SiteID: s.ID, Secret: opt.ChallengeSecret, Difficulty: s.ChallengeDifficulty},
		})
	}
	if s.WAFMode != "off" {
		main = append(main, map[string]any{
			"handler":          "waf",
			"load_owasp_crs":   true,
			"directives":       Directives(s),
			"tx_id_req_header": ratelimit.TxHeader,
		})
	}
	main = append(main, proxy)
	return append(routes, map[string]any{"handle": main})
}

func hasAccess(s site.Resolved) bool {
	return len(s.AllowIPs) > 0 || len(s.BlockIPs) > 0 || len(s.AllowCountries) > 0 ||
		len(s.BlockCountries) > 0 || s.BlockIPsFile != "" || len(s.Rules) > 0
}

// reverseProxy dials each upstream without its scheme; https upstreams (the
// validator keeps all upstreams on one scheme) get a TLS transport.
func reverseProxy(upstreams []string) map[string]any {
	var list []any
	useTLS := false
	for _, u := range upstreams {
		if rest, ok := strings.CutPrefix(u, "https://"); ok {
			useTLS, u = true, rest
		} else {
			u = strings.TrimPrefix(u, "http://")
		}
		list = append(list, map[string]any{"dial": u})
	}
	h := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": list,
		"headers":   map[string]any{"request": map[string]any{"delete": []string{ratelimit.TxHeader}}},
	}
	if useTLS {
		h["transport"] = map[string]any{"protocol": "http", "tls": map[string]any{}}
	}
	return h
}

// blockPage is the error handler for the site: a small HTML page with the
// site's title and message and the Caddy error ID as the event ID.
func blockPage(s site.Resolved) map[string]any {
	title, msg := pageText(s.BlockTitle), pageText(s.BlockMessage)
	body := "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + title +
		"</title></head><body><h1>" + title + "</h1><p>" + msg +
		"</p><p>Event ID: {http.error.id}</p></body></html>"
	return map[string]any{
		"handler":     "static_response",
		"status_code": "{http.error.status_code}",
		"headers":     map[string]any{"Content-Type": []string{"text/html; charset=utf-8"}},
		"body":        body,
	}
}

// pageText HTML-escapes customer text and turns braces into entities so Caddy
// doesn't expand placeholders like {env.SECRET} inside it.
func pageText(s string) string {
	return strings.NewReplacer("{", "&#123;", "}", "&#125;").Replace(html.EscapeString(s))
}
