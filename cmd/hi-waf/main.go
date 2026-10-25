// Command hi-waf is the HostingInside WAF engine: Caddy plus Coraza and the
// hi_* modules, built with plain `go build` instead of xcaddy.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Caddy standard modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	// Coraza WAF handler (http.handlers.waf).
	_ "github.com/corazawaf/coraza-caddy/v2"

	// HostingInside modules: http.handlers.hi_ratelimit, admin.api.hi_bans,
	// http.handlers.hi_access.
	_ "hostinginside/waf/engine/access"
	_ "hostinginside/waf/engine/challenge"
	_ "hostinginside/waf/engine/ratelimit"
)

func main() {
	caddycmd.Main()
}
