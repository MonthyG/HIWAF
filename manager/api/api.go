// Package api is the manager's REST API (spec §7): it validates site
// documents, stores them, compiles every site to one Caddy config and pushes
// it, rolling the database back when Caddy refuses or can't be reached.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

const maxBody = 1 << 20

// Loader pushes configs to the engine and manages its bans.
// *caddyclient.Client implements it.
type Loader interface {
	Load(ctx context.Context, cfg any) error
	Bans(ctx context.Context, siteID string) (map[string][]caddyclient.Ban, error)
	Unban(ctx context.Context, siteID, ip string) (bool, error)
}

// API serves the management endpoints.
type API struct {
	st   *store.Store
	cl   Loader
	opt  compile.Options
	keys [][32]byte // SHA-256 of each API key, so comparisons are fixed-length
	log  *slog.Logger
}

// New returns an API. Empty keys are ignored; with no keys every request is
// refused.
func New(st *store.Store, cl Loader, opt compile.Options, apiKeys []string) *API {
	a := &API{st: st, cl: cl, opt: opt, log: slog.Default()}
	for _, k := range apiKeys {
		if k != "" {
			a.keys = append(a.keys, sha256.Sum256([]byte(k)))
		}
	}
	return a
}

// Handler returns the HTTP handler; every route requires a Bearer API key.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/sites", a.createSite)
	mux.HandleFunc("GET /api/v1/sites", a.listSites)
	mux.HandleFunc("GET /api/v1/sites/{id}", a.getSite)
	mux.HandleFunc("PUT /api/v1/sites/{id}", a.putSite)
	mux.HandleFunc("DELETE /api/v1/sites/{id}", a.deleteSite)
	mux.HandleFunc("POST /api/v1/sites/{id}/certificate", a.putCert)
	mux.HandleFunc("GET /api/v1/events", a.events)
	mux.HandleFunc("GET /api/v1/stats", a.stats)
	mux.HandleFunc("GET /api/v1/bans", a.bans)
	mux.HandleFunc("DELETE /api/v1/bans", a.unban)
	mux.HandleFunc("GET /api/v1/protections", a.protections)
	return a.auth(mux)
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(tok))
		match := 0
		for _, k := range a.keys {
			match |= subtle.ConstantTimeCompare(sum[:], k[:])
		}
		if !ok || tok == "" || match != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, errBody{Error: "missing or invalid API key"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Sync compiles every stored site and loads the result into the engine.
func (a *API) Sync(ctx context.Context) error {
	return a.apply(ctx, func(*store.Tx) error { return nil })
}

// apply runs fn and then rebuilds and loads the whole config, all inside one
// transaction: any error, including Caddy's, rolls fn's changes back. Only
// the *Tx may be used here; the store has a single connection.
func (a *API) apply(ctx context.Context, fn func(*store.Tx) error) error {
	return a.st.Tx(ctx, func(tx *store.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		recs, err := tx.ListSites()
		if err != nil {
			return err
		}
		certs, err := tx.Certs()
		if err != nil {
			return err
		}
		sites := make([]site.Resolved, 0, len(recs))
		for _, r := range recs {
			sites = append(sites, site.Resolve(r.ID, r.Doc))
		}
		if err := site.ValidateAll(sites); err != nil {
			return err
		}
		cfg, err := compile.Config(sites, certs, a.opt)
		if err != nil {
			return &httpError{status: http.StatusBadRequest, msg: err.Error()}
		}
		return a.cl.Load(ctx, cfg)
	})
}

// --- errors ---------------------------------------------------------------

var errNotFound = &httpError{status: http.StatusNotFound, msg: "not found"}

type httpError struct {
	status     int
	msg, field string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(field, msg string) error {
	return &httpError{status: http.StatusBadRequest, msg: msg, field: field}
}

type errBody struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func (a *API) writeErr(w http.ResponseWriter, err error) {
	var he *httpError
	var ve *site.ValidationError
	var le *caddyclient.LoadError
	switch {
	case errors.As(err, &he):
		writeJSON(w, he.status, errBody{Error: he.msg, Field: he.field})
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, errBody{Error: ve.Msg, Field: ve.Field})
	case errors.Is(err, caddyclient.ErrUnreachable):
		writeJSON(w, http.StatusServiceUnavailable, errBody{Error: "engine unreachable; nothing was changed"})
	case errors.As(err, &le):
		writeJSON(w, http.StatusBadGateway, errBody{Error: "engine rejected the config: " + caddyMessage(le.Body)})
	default:
		a.log.Error("api", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{Error: "internal error"})
	}
}

// caddyMessage extracts the "error" field Caddy's admin API puts in its JSON
// error bodies, falling back to the raw text.
func caddyMessage(body string) string {
	var m struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(body), &m) == nil && m.Error != "" {
		return m.Error
	}
	return strings.TrimSpace(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads one JSON value (at most 1 MiB, no unknown fields) into v.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		var extra json.RawMessage
		if dec.Decode(&extra) != io.EOF {
			err = errors.New("unexpected data after the JSON body")
		}
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &httpError{status: http.StatusRequestEntityTooLarge, msg: "request body exceeds 1 MiB"}
		}
		return badRequest("", "invalid JSON body: "+err.Error())
	}
	return nil
}

// --- sites ----------------------------------------------------------------

type siteView struct {
	ID       string       `json:"id"`
	Created  time.Time    `json:"created"`
	Updated  time.Time    `json:"updated"`
	Doc      site.Doc     `json:"doc"`
	Resolved resolvedView `json:"resolved"`
}

// resolvedView is site.Resolved in the document's shape and key names. A
// rate limit that is off is null.
type resolvedView struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Upstreams []string `json:"upstreams"`
	TLS       struct {
		Mode string `json:"mode"`
	} `json:"tls"`
	WAF struct {
		Mode             string          `json:"mode"`
		Paranoia         int             `json:"paranoia"`
		AnomalyThreshold int             `json:"anomaly_threshold"`
		Protections      map[string]bool `json:"protections"`
	} `json:"waf"`
	RateLimit struct {
		Access *ratelimit.Limit `json:"access"`
		Attack *ratelimit.Limit `json:"attack"`
		Error  *ratelimit.Limit `json:"error"`
	} `json:"rate_limit"`
	Access struct {
		AllowIPs       []string      `json:"allow_ips"`
		BlockIPs       []string      `json:"block_ips"`
		AllowCountries []string      `json:"allow_countries"`
		BlockCountries []string      `json:"block_countries"`
		BlockIPsFile   string        `json:"block_ips_file"`
		Rules          []access.Rule `json:"rules"`
	} `json:"access"`
	BotChallenge struct {
		Enabled    bool `json:"enabled"`
		Difficulty int  `json:"difficulty"`
	} `json:"bot_challenge"`
	BlockPage struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"block_page"`
}

func view(rec store.SiteRecord) siteView {
	r := site.Resolve(rec.ID, rec.Doc)
	var v resolvedView
	v.Name, v.Domains, v.Upstreams = r.Name, r.Domains, r.Upstreams
	v.TLS.Mode = r.TLSMode
	v.WAF.Mode, v.WAF.Paranoia, v.WAF.AnomalyThreshold, v.WAF.Protections =
		r.WAFMode, r.Paranoia, r.AnomalyThreshold, r.Protections
	v.RateLimit.Access, v.RateLimit.Attack, v.RateLimit.Error = r.Access, r.Attack, r.Error
	v.Access.AllowIPs, v.Access.BlockIPs = r.AllowIPs, r.BlockIPs
	v.Access.AllowCountries, v.Access.BlockCountries = r.AllowCountries, r.BlockCountries
	v.Access.BlockIPsFile, v.Access.Rules = r.BlockIPsFile, r.Rules
	v.BotChallenge.Enabled, v.BotChallenge.Difficulty = r.Challenge, r.ChallengeDifficulty
	v.BlockPage.Title, v.BlockPage.Message = r.BlockTitle, r.BlockMessage
	return siteView{ID: rec.ID, Created: rec.Created, Updated: rec.Updated, Doc: rec.Doc, Resolved: v}
}

// readDoc decodes and validates a site document; it never touches the DB.
func (a *API) readDoc(w http.ResponseWriter, r *http.Request) (site.Doc, error) {
	var d site.Doc
	if err := decode(w, r, &d); err != nil {
		return d, err
	}
	return d, site.Validate(d, a.opt.GeoIPDB != "")
}

// now is millisecond-truncated, the precision the store keeps.
func now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// mutationCtx keeps a mutation running if the client disconnects, so the DB
// and the engine aren't left to a half-cancelled load.
func mutationCtx(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func (a *API) createSite(w http.ResponseWriter, r *http.Request) {
	d, err := a.readDoc(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	t := now()
	rec := store.SiteRecord{ID: site.NewID(), Doc: d, Created: t, Updated: t}
	if err := a.apply(mutationCtx(r), func(tx *store.Tx) error { return tx.PutSite(rec) }); err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view(rec))
}

func (a *API) listSites(w http.ResponseWriter, r *http.Request) {
	recs, err := a.st.ListSites(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := make([]siteView, 0, len(recs))
	for _, rec := range recs {
		out = append(out, view(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getSite(w http.ResponseWriter, r *http.Request) {
	var rec store.SiteRecord
	err := a.st.Tx(r.Context(), func(tx *store.Tx) error {
		got, ok, err := tx.GetSite(r.PathValue("id"))
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		rec = got
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(rec))
}

func (a *API) putSite(w http.ResponseWriter, r *http.Request) {
	d, err := a.readDoc(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	var rec store.SiteRecord
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error {
		got, ok, err := tx.GetSite(r.PathValue("id"))
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		rec = got // keeps ID and Created: PutSite overwrites created
		rec.Doc, rec.Updated = d, now()
		return tx.PutSite(rec)
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(rec))
}

func (a *API) deleteSite(w http.ResponseWriter, r *http.Request) {
	err := a.apply(mutationCtx(r), func(tx *store.Tx) error {
		ok, err := tx.DeleteSite(r.PathValue("id"))
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- certificates ---------------------------------------------------------

type certReq struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// certView describes a stored certificate; it never includes the key.
type certView struct {
	SiteID   string    `json:"site_id"`
	Subject  string    `json:"subject"`
	DNSNames []string  `json:"dns_names"`
	NotAfter time.Time `json:"not_after"`
}

func (a *API) putCert(w http.ResponseWriter, r *http.Request) {
	var req certReq
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	if req.CertPEM == "" {
		a.writeErr(w, badRequest("cert_pem", "is required"))
		return
	}
	if req.KeyPEM == "" {
		a.writeErr(w, badRequest("key_pem", "is required"))
		return
	}
	pair, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM))
	if err != nil {
		a.writeErr(w, badRequest("", "invalid certificate or key: "+err.Error()))
		return
	}
	id := r.PathValue("id")
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error {
		_, ok, err := tx.GetSite(id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return tx.PutCert(id, site.Cert{CertPEM: req.CertPEM, KeyPEM: req.KeyPEM})
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	cv := certView{SiteID: id}
	if leaf := pair.Leaf; leaf != nil { // set by X509KeyPair since Go 1.23
		cv.Subject, cv.DNSNames, cv.NotAfter = leaf.Subject.CommonName, leaf.DNSNames, leaf.NotAfter.UTC()
	}
	writeJSON(w, http.StatusOK, cv)
}

// --- events and stats -----------------------------------------------------

type eventView struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	SiteID   string    `json:"site_id"`
	Type     string    `json:"type"`
	ClientIP string    `json:"client_ip"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	RuleID   string    `json:"rule_id"`
	Detail   string    `json:"detail"`
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{SiteID: q.Get("site"), Type: q.Get("type"), IP: q.Get("ip")}
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			a.writeErr(w, badRequest("since", "must be an RFC3339 time"))
			return
		}
		f.Since = t
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			a.writeErr(w, badRequest("limit", "must be a positive integer"))
			return
		}
		f.Limit = n
	}
	evs, err := a.st.QueryEvents(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := make([]eventView, 0, len(evs))
	for _, e := range evs {
		out = append(out, eventView{ID: e.ID, TS: e.TS, SiteID: e.SiteID, Type: e.Type, ClientIP: e.ClientIP,
			Host: e.Host, Method: e.Method, URI: e.URI, RuleID: e.RuleID, Detail: e.Msg})
	}
	writeJSON(w, http.StatusOK, out)
}

type countView struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type statsView struct {
	Since    time.Time      `json:"since"`
	ByType   map[string]int `json:"by_type"`
	TopIPs   []countView    `json:"top_ips"`
	TopRules []countView    `json:"top_rules"`
}

func counts(in []store.Count) []countView {
	out := make([]countView, 0, len(in))
	for _, c := range in {
		out = append(out, countView{Key: c.Key, Count: c.N})
	}
	return out
}

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	window := 24 * time.Hour
	if s := q.Get("window"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			a.writeErr(w, badRequest("window", "must be a positive Go duration such as 24h"))
			return
		}
		window = d
	}
	since := now().Add(-window)
	st, err := a.st.Stats(r.Context(), q.Get("site"), since)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, statsView{Since: since, ByType: st.ByType,
		TopIPs: counts(st.TopIPs), TopRules: counts(st.TopRules)})
}

// --- bans -----------------------------------------------------------------

func (a *API) bans(w http.ResponseWriter, r *http.Request) {
	b, err := a.cl.Bans(r.Context(), r.URL.Query().Get("site"))
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if b == nil {
		b = map[string][]caddyclient.Ban{}
	}
	writeJSON(w, http.StatusOK, b)
}

func (a *API) unban(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	siteID, ip := q.Get("site"), q.Get("ip")
	if siteID == "" {
		a.writeErr(w, badRequest("site", "is required"))
		return
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		a.writeErr(w, badRequest("ip", "must be an IP address"))
		return
	}
	ok, err := a.cl.Unban(r.Context(), siteID, ip)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if !ok {
		a.writeErr(w, &httpError{status: http.StatusNotFound, msg: "ip is not banned"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- protections ----------------------------------------------------------

type protectionView struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
}

func (a *API) protections(w http.ResponseWriter, r *http.Request) {
	out := make([]protectionView, 0, len(site.Protections))
	for _, p := range site.Protections {
		out = append(out, protectionView{Key: p.Key, Label: p.Label, Default: p.Default})
	}
	writeJSON(w, http.StatusOK, out)
}
