package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

// ProjectHeader lets an operator key or console session act for one project:
// the OpenStack service checks the customer's Keystone token, then calls the
// manager with its own key and this header. A project token carries its
// project itself and may only repeat it here.
const ProjectHeader = "X-Project-Id"

// scope says what a route lets a project caller do. Routes are admin-only
// unless they say otherwise, so a new route is closed to tenants by default.
type scope int

const (
	adminOnly  scope = iota // operator only: a project caller gets 403
	anyCaller               // open; the handler limits what a project sees
	siteInPath              // the {id} site must belong to the caller's project
	siteParam               // ?site= is required and must belong to the project
	txInPath                // the {tx} event's site must belong to the project
)

// gate enforces s for project callers before h runs. Sites of other projects
// answer 404, as if they did not exist.
func (a *API) gate(s scope, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		if p.Project == "" {
			h(w, r)
			return
		}
		var id string
		switch s {
		case anyCaller:
			h(w, r)
			return
		case siteInPath:
			id = r.PathValue("id")
		case siteParam:
			if id = r.URL.Query().Get("site"); id == "" {
				a.writeErr(w, badRequest("site", "a project caller must name one of its sites"))
				return
			}
		case txInPath:
			id, _, _ = strings.Cut(r.PathValue("tx"), "-") // tx IDs are <site>-<hex>
		default:
			a.writeErr(w, &httpError{status: http.StatusForbidden, msg: "this needs the operator, not a project"})
			return
		}
		ok, err := a.owns(r.Context(), p.Project, id)
		if err != nil {
			a.writeErr(w, err)
			return
		}
		if !ok {
			a.writeErr(w, errNotFound)
			return
		}
		h(w, r)
	}
}

// owns reports whether site id belongs to project.
func (a *API) owns(ctx context.Context, project, id string) (bool, error) {
	var ok bool
	err := a.st.Tx(ctx, func(tx *store.Tx) error {
		rec, found, err := tx.GetSite(id)
		ok = found && rec.Doc.Project == project
		return err
	})
	return ok, err
}

// tenantDoc applies the project rules to a site a project caller writes: it
// belongs to the caller's project whatever the document says, and it must
// keep to the tenant limits.
func tenantDoc(p principal, d *site.Doc) error {
	if p.Project == "" {
		return nil
	}
	d.Project = p.Project
	return site.CheckTenant(*d)
}

// hideOthers rewrites a validation error that names another site (a domain
// already taken) so a project caller learns nothing about other projects.
func hideOthers(p principal, err error) error {
	var ve *site.ValidationError
	if p.Project != "" && errors.As(err, &ve) && strings.Contains(ve.Msg, "already used by site") {
		return &site.ValidationError{Field: ve.Field, Msg: "a domain of this site is already used by another site"}
	}
	return err
}
