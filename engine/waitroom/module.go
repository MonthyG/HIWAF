// Package waitroom is the http.handlers.hi_waitroom middleware: when more
// than MaxActive visitors are active on a site, new visitors wait in a FIFO
// queue on an auto-refreshing page until a slot frees up.
package waitroom

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"hostinginside/waf/engine/events"
)

const (
	// CookieName holds the visitor's signed ID.
	CookieName = "hi_wr"

	defaultTTL     = 60
	refreshSec     = 5
	queueStaleness = 4 * refreshSec * time.Second
)

//go:embed page.html
var pageSrc string

var pageTmpl = template.Must(template.New("wait").Parse(pageSrc))

func init() {
	caddy.RegisterModule(WaitRoom{})
}

// WaitRoom is the http.handlers.hi_waitroom middleware.
type WaitRoom struct {
	SiteID        string `json:"site_id"`
	Secret        string `json:"secret"` // std base64 of >= 32 bytes
	MaxActive     int    `json:"max_active"`
	SessionTTLSec int    `json:"session_ttl_sec,omitempty"` // idle time before a slot is freed

	key    []byte
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (WaitRoom) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hi_waitroom",
		New: func() caddy.Module { return new(WaitRoom) },
	}
}

// Provision applies defaults and decodes the secret.
func (wr *WaitRoom) Provision(ctx caddy.Context) error {
	wr.logger = ctx.Logger()
	return wr.setup()
}

func (wr *WaitRoom) setup() error {
	if wr.SessionTTLSec == 0 {
		wr.SessionTTLSec = defaultTTL
	}
	key, err := base64.StdEncoding.DecodeString(wr.Secret)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	wr.key = key
	return nil
}

// Validate checks the config.
func (wr *WaitRoom) Validate() error {
	if wr.SiteID == "" {
		return errors.New("site_id is required")
	}
	if len(wr.key) < 32 {
		return errors.New("secret must decode to at least 32 bytes")
	}
	if wr.MaxActive < 1 {
		return errors.New("max_active must be > 0")
	}
	if wr.SessionTTLSec < 1 {
		return errors.New("session_ttl_sec must be > 0")
	}
	return nil
}

// room is one site's state. It lives in a package-level map so it survives
// config reloads, like the rate-limit state.
type room struct {
	mu     sync.Mutex
	active map[string]time.Time // visitor -> last request
	queue  []string             // waiting visitors, oldest first
	polled map[string]time.Time // waiting visitor -> last poll
}

var (
	roomsMu sync.Mutex
	rooms   = map[string]*room{}
)

func roomFor(site string) *room {
	roomsMu.Lock()
	defer roomsMu.Unlock()
	r, ok := rooms[site]
	if !ok {
		r = &room{active: map[string]time.Time{}, polled: map[string]time.Time{}}
		rooms[site] = r
	}
	return r
}

// Stats reports the active and waiting counts for a site.
func Stats(site string) (active, waiting int) {
	r := roomFor(site)
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active), len(r.queue)
}

// admit decides for visitor id at now: it returns 0 when the visitor may
// proceed, otherwise its 1-based queue position.
func (r *room) admit(id string, max int, ttl time.Duration, now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for v, seen := range r.active {
		if now.Sub(seen) > ttl {
			delete(r.active, v)
		}
	}
	kept := r.queue[:0]
	for _, v := range r.queue {
		if now.Sub(r.polled[v]) <= queueStaleness {
			kept = append(kept, v)
		} else {
			delete(r.polled, v)
		}
	}
	r.queue = kept

	if _, ok := r.active[id]; ok {
		r.active[id] = now
		return 0
	}
	pos := -1
	for i, v := range r.queue {
		if v == id {
			pos = i
			break
		}
	}
	free := max - len(r.active)
	// Admit if a slot is free for this visitor: queued visitors ahead of it
	// take the free slots first.
	if (pos >= 0 && pos < free) || (pos < 0 && len(r.queue) < free) {
		if pos >= 0 {
			r.queue = append(r.queue[:pos], r.queue[pos+1:]...)
			delete(r.polled, id)
		}
		r.active[id] = now
		return 0
	}
	if pos < 0 {
		r.queue = append(r.queue, id)
		pos = len(r.queue) - 1
	}
	r.polled[id] = now
	return pos + 1
}

func (wr *WaitRoom) sign(id string) string {
	h := hmac.New(sha256.New, wr.key)
	h.Write([]byte("wr|" + wr.SiteID + "|" + id))
	return id + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (wr *WaitRoom) visitor(r *http.Request) (string, bool) {
	ck, err := r.Cookie(CookieName)
	if err != nil {
		return "", false
	}
	id, _, ok := strings.Cut(ck.Value, ".")
	if !ok || !hmac.Equal([]byte(wr.sign(id)), []byte(ck.Value)) {
		return "", false
	}
	return id, true
}

// ServeHTTP admits the visitor or serves the waiting page (503).
func (wr *WaitRoom) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	id, ok := wr.visitor(r)
	if !ok {
		var b [12]byte
		_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
		id = hex.EncodeToString(b[:])
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: wr.sign(id), Path: "/",
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	}
	ttl := time.Duration(wr.SessionTTLSec) * time.Second
	pos := roomFor(wr.SiteID).admit(id, wr.MaxActive, ttl, time.Now())
	if pos == 0 {
		return next.ServeHTTP(w, r)
	}
	events.Tag(r, events.ActionWait, events.TypeWaitQueued)
	w.Header().Set("Retry-After", strconv.Itoa(refreshSec))
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		var buf bytes.Buffer
		if err := pageTmpl.Execute(&buf, map[string]any{"Position": pos, "Refresh": refreshSec}); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(buf.Bytes())
		return nil
	}
	return caddyhttp.Error(http.StatusServiceUnavailable, errors.New("waiting room"))
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*WaitRoom)(nil)
	_ caddy.Validator             = (*WaitRoom)(nil)
	_ caddyhttp.MiddlewareHandler = (*WaitRoom)(nil)
)
