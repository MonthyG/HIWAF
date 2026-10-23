// Package compile turns resolved sites into OWASP CRS directives for
// coraza-caddy and into one complete Caddy JSON config.
package compile

import (
	"fmt"
	"strings"

	"hostinginside/waf/manager/site"
)

// Directives returns the Coraza directives for s: the recommended config and
// CRS setup, the site's paranoia and anomaly thresholds, the CRS rules, the
// engine mode, and one SecRuleRemoveById per range of each disabled protection.
func Directives(s site.Resolved) string {
	var b strings.Builder
	line := func(format string, a ...any) {
		fmt.Fprintf(&b, format, a...)
		b.WriteByte('\n')
	}
	line("Include @coraza.conf-recommended")
	line("Include @crs-setup.conf.example")
	line(`SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d"`, s.Paranoia)
	line(`SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"`, s.AnomalyThreshold)
	line("Include @owasp_crs/*.conf")
	if s.WAFMode == "detect" {
		line("SecRuleEngine DetectionOnly")
	} else {
		line("SecRuleEngine On")
	}
	if s.Protections["data_leak"] {
		line("SecResponseBodyAccess On")
	} else {
		line("SecResponseBodyAccess Off")
	}
	for _, p := range site.Protections {
		if s.Protections[p.Key] {
			continue
		}
		for _, r := range p.IDRanges {
			line("SecRuleRemoveById %s", r)
		}
	}
	return b.String()
}
