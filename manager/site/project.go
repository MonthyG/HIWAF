package site

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var projectRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidProject reports whether p is a usable project ID. OpenStack project
// IDs are 32 hex characters; names and other IDs fit too.
func ValidProject(p string) bool { return projectRE.MatchString(p) }

// CheckTenant applies the limits for a site a project owns, on top of
// Validate. Tenants share engines, so a tenant's site must not catch other
// tenants' traffic, claim ports, use the operator's shared objects, or send
// requests back into the WAF host or the cloud's metadata service.
func CheckTenant(d Doc) error {
	for i, dom := range d.Domains {
		at := fmt.Sprintf("domains[%d]", i)
		if dom == "*" {
			return verr(at, "a project's site cannot answer every host name")
		}
		if rest, ok := strings.CutPrefix(dom, "*."); ok && !strings.Contains(rest, ".") {
			return verr(at, "a wildcard needs at least two labels after *., such as *.example.com")
		}
	}
	if len(d.Ports) > 0 {
		return verr("ports", "a project's site uses the standard ports")
	}
	for i, u := range d.Upstreams {
		if err := tenantUpstream(u); err != nil {
			return verr(fmt.Sprintf("upstreams[%d]", i), "%s", err.Error())
		}
	}
	if d.TLS != nil && d.TLS.CertID != "" {
		return verr("tls.cert_id", "shared certificates are the operator's; upload one for the site instead")
	}
	if a := d.Access; a != nil && (len(a.AllowGroups) > 0 || len(a.BlockGroups) > 0) {
		return verr("access", "shared IP groups are the operator's; list the addresses on the site")
	}
	return nil
}

// tenantUpstream accepts an origin given as an IP address that is not the
// WAF host itself (loopback, unspecified) nor link-local (cloud metadata).
// Host names are refused: they could resolve to such an address later.
func tenantUpstream(u string) error {
	hostport := u
	if strings.Contains(u, "://") {
		p, err := url.Parse(u)
		if err != nil {
			return err
		}
		hostport = p.Host
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return fmt.Errorf("must be an IP address, not a host name, got %q", host)
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("%s is not a reachable origin for a project's site", ip)
	}
	return nil
}
