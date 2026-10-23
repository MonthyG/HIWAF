// Package events defines the structured security events the engine logs.
package events

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"hostinginside/waf/engine/clientip"
)

// LogMessage is the exact log message of every event line.
const LogMessage = "hi_event"

// Event types.
const (
	TypeWAFBlock        = "waf_block"
	TypeWAFMatch        = "waf_match"
	TypeRateLimitBan    = "rate_limit_ban"
	TypeIPBlock         = "ip_block"
	TypeGeoBlock        = "geo_block"
	TypeRuleBlock       = "rule_block"
	TypeAllowedByRule   = "allowed_by_rule"
	TypeChallengePassed = "challenge_passed"
	TypeChallengeFailed = "challenge_failed"
)

// Event is one security event. Empty fields are omitted when logged.
type Event struct {
	Type     string
	SiteID   string
	ClientIP string
	Host     string
	Method   string
	URI      string
	RuleID   string
	Msg      string
	Until    time.Time
}

// Emit logs e at Info level with message LogMessage.
func Emit(l *zap.Logger, e Event) {
	fields := make([]zap.Field, 0, 9)
	add := func(key, val string) {
		if val != "" {
			fields = append(fields, zap.String(key, val))
		}
	}
	add("event", e.Type)
	add("site_id", e.SiteID)
	add("client_ip", e.ClientIP)
	add("host", e.Host)
	add("method", e.Method)
	add("uri", e.URI)
	add("rule_id", e.RuleID)
	add("msg", e.Msg)
	if !e.Until.IsZero() {
		fields = append(fields, zap.String("until", e.Until.UTC().Format(time.RFC3339)))
	}
	l.Info(LogMessage, fields...)
}

// FromRequest builds an Event of type typ for site siteID from r.
func FromRequest(r *http.Request, typ, siteID string) Event {
	return Event{
		Type:     typ,
		SiteID:   siteID,
		ClientIP: clientip.Get(r),
		Host:     r.Host,
		Method:   r.Method,
		URI:      r.URL.RequestURI(),
	}
}
