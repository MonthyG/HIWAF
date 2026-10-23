// Command hi-waf is the HostingInside WAF engine: Caddy plus Coraza and the
// hi_* modules, built with plain `go build` instead of xcaddy.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Caddy standard modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	// Coraza WAF handler (http.handlers.waf).
	_ "github.com/corazawaf/coraza-caddy/v2"

	// HostingInside modules: http.handlers.hi_ratelimit, admin.api.hi_bans.
	_ "hostinginside/waf/engine/ratelimit"
	// The hi_access and hi_challenge imports are added as their
	// packages land (Tasks 4-5).
)

func main() {
	caddycmd.Main()
}
