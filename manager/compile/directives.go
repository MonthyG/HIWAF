// Package compile turns resolved sites into OWASP CRS directives for
// coraza-caddy and into one complete Caddy JSON config.
package compile

import (
	"fmt"
	"strings"

	"hostinginside/waf/manager/crsplugins"
	"hostinginside/waf/manager/site"
)

// exclusionBaseID numbers the per-path exception rules, one per exception,
// in the 1-99,999 range left for local rules.
const exclusionBaseID = 10100

// extraRules close gaps the CRS leaves at paranoia 1, found by attack tests
// (local-demo/wafbench). They load before the CRS rules so they score before
// its blocking check (949110), and their IDs sit in the CRS ranges of their
// protection, so turning that protection off removes them too.
//
//   - 921990 XXE: Coraza's XML parser keeps an entity it doesn't know (&xxe;)
//     as text and resolves the standard ones, so a leftover &name; means the
//     request declared its own entity.
//     shortcut: Coraza doesn't expose the raw XML body, so a blind XXE that only
//     uses %parameter; entities inside the DOCTYPE is missed; inspect the raw
//     body in a middleware if XML APIs become common.
//   - 932990 a recon command right after a shell operator ("| id", "`id`",
//     "; whoami -a"). CRS leaves short commands like these to paranoia 2, which
//     also blocks searches such as "cat food". Requiring the operator, and the
//     command to end there or take a flag, keeps "Q&A; id card" and "sort=id" out.
const extraRules = `SecRule XML:/* "@rx &[A-Za-z_][A-Za-z0-9_.-]*;" "id:921990,phase:2,block,capture,t:none,msg:'XML entity the request declared itself (XXE)',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',tag:'attack-protocol',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS "@rx (?:[;|&\x60\n]|\$\()\s*(?:id|whoami|uname|ifconfig|ipconfig|hostname|netstat|printenv)(?:\s*$|\s*[;|&\x60)]|\s+-)" "id:932990,phase:2,block,capture,t:none,msg:'Command injection: a shell command after a shell operator',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',tag:'attack-rce',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`

// AllowedMethods widens CRS's GET HEAD POST OPTIONS so REST APIs work.
const AllowedMethods = "GET HEAD POST OPTIONS PUT PATCH DELETE"

// AllowedContentTypes is CRS's list plus text/plain (sendBeacon, analytics)
// and the common +json types. Bodies with no parser of their own are parsed
// as form data (tx.enforce_bodyproc_urlencoded) and +json as JSON, so the
// attack rules still see what's in them.
const AllowedContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| " +
	"|text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain| " +
	"|application/merge-patch+json| |application/json-patch+json| |application/vnd.api+json| " +
	"|application/cloudevents+json| |application/cloudevents-batch+json|"

// Directives returns the Coraza directives for s: the recommended config and
// CRS setup, the site's paranoia and anomaly thresholds, the allowed methods
// and content types, the site's rule exceptions, the CRS rules, the engine
// mode, and one SecRuleRemoveById per range of each disabled protection.
// The CRS files come from crsDir (an unpacked release, see the rulesets API)
// or, when it is empty, from the copy built into the engine. The site's app
// profiles are CRS plugins under pluginsDir/<app>/, loaded around the rules
// in CRS's plugin order: config, before, the rules, after.
func Directives(s site.Resolved, crsDir, pluginsDir string) string {
	var b strings.Builder
	line := func(format string, a ...any) {
		fmt.Fprintf(&b, format, a...)
		b.WriteByte('\n')
	}
	line("Include @coraza.conf-recommended")
	setup, rules := "@crs-setup.conf.example", "@owasp_crs/*.conf"
	if crsDir != "" {
		setup, rules = crsDir+"/crs-setup.conf.example", crsDir+"/rules/*.conf"
	}
	line("Include %s", setup)
	line(`SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d"`, s.Paranoia)
	line(`SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"`, s.AnomalyThreshold)
	line(`SecAction "id:900010,phase:1,pass,nolog,setvar:tx.enforce_bodyproc_urlencoded=1"`)
	line(`SecAction "id:900200,phase:1,pass,nolog,setvar:'tx.allowed_methods=%s'"`, AllowedMethods)
	line(`SecAction "id:900220,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type=%s'"`, AllowedContentTypes)
	line(`SecRule REQUEST_HEADERS:Content-Type "@rx ^application/[a-z0-9.-]+\+json(?:\s*;|$)" "id:10010,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`)
	plugins := func(stage func(crsplugins.Stages) []string) {
		if pluginsDir == "" {
			return
		}
		for _, app := range s.Apps {
			for _, f := range stage(crsplugins.Files(app)) {
				line("Include %s/%s/%s", pluginsDir, app, f)
			}
		}
	}
	plugins(func(st crsplugins.Stages) []string { return st.Config })
	plugins(func(st crsplugins.Stages) []string { return st.Before })
	// Exceptions limited to a path act per request, so they run first.
	for i, e := range s.Exclusions {
		path, op := e.PathExact, "@streq"
		if e.PathPrefix != "" {
			path, op = e.PathPrefix, "@beginsWith"
		}
		if path == "" {
			continue
		}
		ctl := fmt.Sprintf("ctl:ruleRemoveById=%d", e.RuleID)
		if e.Field != "" {
			ctl = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", e.RuleID, e.Field)
		}
		line(`SecRule REQUEST_FILENAME "%s %s" "id:%d,phase:1,t:none,pass,nolog,%s"`, op, path, exclusionBaseID+i, ctl)
	}
	b.WriteString(extraRules)
	line("Include %s", rules)
	plugins(func(st crsplugins.Stages) []string { return st.After })
	// Site-wide exceptions change the loaded rules, so they follow them.
	for _, e := range s.Exclusions {
		switch {
		case e.PathExact != "" || e.PathPrefix != "":
		case e.Field != "":
			line(`SecRuleUpdateTargetById %d "!%s"`, e.RuleID, e.Field)
		default:
			line("SecRuleRemoveById %d", e.RuleID)
		}
	}
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
