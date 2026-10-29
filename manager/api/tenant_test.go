package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// as sends a request with the operator key acting for project ("" = as the operator).
func as(t *testing.T, h http.Handler, project, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return asKey(t, h, "Bearer "+testKey, project, method, path, body)
}

func asKey(t *testing.T, h http.Handler, authz, project, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", authz)
	if project != "" {
		req.Header.Set(ProjectHeader, project)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func siteIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var vs []siteView
	decodeBody(t, rec, &vs)
	ids := []string{}
	for _, v := range vs {
		ids = append(ids, v.ID)
	}
	return ids
}

const tenantDoc1 = `{"domains":["shop.alpha.test"],"upstreams":["10.0.0.5:8080"]}`

func TestProjectsSeeOnlyTheirSites(t *testing.T) {
	h, _ := newTestAPI(t)
	rec := as(t, h, "alpha", "POST", "/api/v1/sites", tenantDoc1)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var a siteView
	decodeBody(t, rec, &a)
	assert.Equal(t, "alpha", a.Resolved.Project, "the caller's project owns the new site")
	op := createSite(t, h, `{"domains":["ops.example.test"],"upstreams":["10.0.0.9:80"]}`)

	assert.Equal(t, []string{a.ID}, siteIDs(t, as(t, h, "alpha", "GET", "/api/v1/sites", "")))
	assert.Empty(t, siteIDs(t, as(t, h, "beta", "GET", "/api/v1/sites", "")))
	assert.ElementsMatch(t, []string{a.ID, op}, siteIDs(t, as(t, h, "", "GET", "/api/v1/sites", "")), "the operator sees all")

	// another project's site, and the operator's, do not exist for beta
	for _, id := range []string{a.ID, op} {
		for _, m := range []struct{ method, path, body string }{
			{"GET", "/api/v1/sites/" + id, ""},
			{"PATCH", "/api/v1/sites/" + id, `{"name":"mine now"}`},
			{"PUT", "/api/v1/sites/" + id, tenantDoc1},
			{"DELETE", "/api/v1/sites/" + id, ""},
			{"POST", "/api/v1/sites/" + id + "/exclusions", `{"rule_id":942100}`},
			{"GET", "/api/v1/events?site=" + id, ""},
			{"GET", "/api/v1/stats/overview?site=" + id, ""},
			{"GET", "/api/v1/attacks?site=" + id, ""},
			{"GET", "/api/v1/attacks/" + id + "-0123456789abcdef", ""},
			{"GET", "/api/v1/logs?site=" + id, ""},
			{"DELETE", "/api/v1/bans?site=" + id + "&ip=203.0.113.9", ""},
		} {
			assert.Equal(t, http.StatusNotFound, as(t, h, "beta", m.method, m.path, m.body).Code, m.method+" "+m.path)
		}
	}
	assert.Equal(t, http.StatusOK, as(t, h, "alpha", "GET", "/api/v1/sites/"+a.ID, "").Code)
	assert.Equal(t, http.StatusOK, as(t, h, "alpha", "GET", "/api/v1/events?site="+a.ID, "").Code)
	assert.Equal(t, http.StatusBadRequest, as(t, h, "alpha", "GET", "/api/v1/events", "").Code, "a project names its site")

	// a project can't give its site away or take the operator's settings
	rec = as(t, h, "alpha", "PATCH", "/api/v1/sites/"+a.ID, `{"project":"beta","name":"renamed"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	decodeBody(t, rec, &a)
	assert.Equal(t, "alpha", a.Resolved.Project)
	assert.Equal(t, "renamed", a.Resolved.Name)
}

func TestProjectGuardrails(t *testing.T) {
	h, _ := newTestAPI(t)
	createSite(t, h, `{"domains":["taken.example.test"],"upstreams":["10.0.0.9:80"]}`)
	for _, c := range []struct{ name, doc, field string }{
		{"catch-all", `{"domains":["*"],"upstreams":["10.0.0.5:80"],"tls":{"mode":"off"}}`, "domains[0]"},
		{"top-level wildcard", `{"domains":["*.com"],"upstreams":["10.0.0.5:80"]}`, "domains[0]"},
		{"own ports", `{"domains":["a.alpha.test"],"upstreams":["10.0.0.5:80"],"ports":[{"port":2019}]}`, "ports"},
		{"loopback origin", `{"domains":["a.alpha.test"],"upstreams":["127.0.0.1:2019"]}`, "upstreams[0]"},
		{"metadata origin", `{"domains":["a.alpha.test"],"upstreams":["http://169.254.169.254:80"]}`, "upstreams[0]"},
		{"ipv6 loopback", `{"domains":["a.alpha.test"],"upstreams":["[::1]:9443"]}`, "upstreams[0]"},
		{"host name origin", `{"domains":["a.alpha.test"],"upstreams":["localhost:9443"]}`, "upstreams[0]"},
		{"shared certificate", `{"domains":["a.alpha.test"],"upstreams":["10.0.0.5:80"],"tls":{"mode":"uploaded","cert_id":"c_000000000000"}}`, "tls.cert_id"},
		{"shared ip group", `{"domains":["a.alpha.test"],"upstreams":["10.0.0.5:80"],"access":{"allow_groups":["g_000000000000"]}}`, "access"},
	} {
		rec := as(t, h, "alpha", "POST", "/api/v1/sites", c.doc)
		assert.Equal(t, http.StatusBadRequest, rec.Code, c.name+": "+rec.Body.String())
		var e errBody
		decodeBody(t, rec, &e)
		assert.Equal(t, c.field, e.Field, c.name)
	}
	// someone else's domain: refused without naming the other site
	rec := as(t, h, "alpha", "POST", "/api/v1/sites", `{"domains":["taken.example.test"],"upstreams":["10.0.0.5:80"]}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), "s_")
	// the operator keeps its powers
	assert.Equal(t, http.StatusCreated, as(t, h, "", "POST", "/api/v1/sites", `{"domains":["*"],"upstreams":["127.0.0.1:8080"],"tls":{"mode":"off"}}`).Code)
}

func TestProjectCannotReachOperatorRoutes(t *testing.T) {
	h, _ := newTestAPI(t)
	for _, path := range []string{"/api/v1/system", "/api/v1/rulesets", "/api/v1/backups", "/api/v1/alerts",
		"/api/v1/tokens", "/api/v1/rules", "/api/v1/certificates", "/api/v1/ip-groups", "/api/v1/site-counts", "/api/v1/waitroom"} {
		assert.Equal(t, http.StatusForbidden, as(t, h, "alpha", "GET", path, "").Code, path)
	}
	assert.Equal(t, http.StatusForbidden, as(t, h, "alpha", "POST", "/api/v1/tokens", `{"name":"x"}`).Code)
	assert.Equal(t, http.StatusOK, as(t, h, "alpha", "GET", "/api/v1/protections", "").Code)
	assert.Equal(t, http.StatusBadRequest, as(t, h, "not a project!", "GET", "/api/v1/sites", "").Code)
}

func TestProjectTokens(t *testing.T) {
	h, _ := newTestAPI(t)
	rec := as(t, h, "", "POST", "/api/v1/tokens", `{"name":"alpha service","project":"alpha"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var tok tokenView
	decodeBody(t, rec, &tok)
	assert.Equal(t, "alpha", tok.Project)
	bearer := "Bearer " + tok.Token

	rec = asKey(t, h, bearer, "", "POST", "/api/v1/sites", tenantDoc1)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var s siteView
	decodeBody(t, rec, &s)
	assert.Equal(t, "alpha", s.Resolved.Project, "the token's project, with no header")
	assert.Equal(t, http.StatusOK, asKey(t, h, bearer, "alpha", "GET", "/api/v1/sites", "").Code)
	assert.Equal(t, http.StatusForbidden, asKey(t, h, bearer, "beta", "GET", "/api/v1/sites", "").Code, "a project token can't switch projects")
	assert.Equal(t, http.StatusForbidden, asKey(t, h, bearer, "", "GET", "/api/v1/tokens", "").Code)

	var me meView
	decodeBody(t, asKey(t, h, bearer, "", "GET", "/api/v1/auth/me", ""), &me)
	assert.Equal(t, "alpha", me.Project)
	var list []tokenView
	decodeBody(t, as(t, h, "", "GET", "/api/v1/tokens", ""), &list)
	require.Len(t, list, 1)
	assert.Equal(t, "alpha", list[0].Project)
	assert.Equal(t, http.StatusBadRequest, as(t, h, "", "POST", "/api/v1/tokens", `{"name":"x","project":"a b"}`).Code)
}
