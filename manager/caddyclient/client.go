// Package caddyclient talks to Caddy's admin API: config loads and the
// hi_bans admin module.
package caddyclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnreachable means the Caddy admin endpoint could not be contacted.
var ErrUnreachable = errors.New("caddy admin unreachable")

// LoadError is a non-2xx answer from the admin API; Body is the raw response text.
type LoadError struct {
	Status int
	Body   string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("caddy admin returned %d: %s", e.Status, e.Body)
}

// Client is a Caddy admin API client.
type Client struct {
	BaseURL string       // e.g. http://127.0.0.1:2019
	HTTP    *http.Client // nil uses a client with a 30s timeout
}

// Ban is one banned IP.
type Ban struct {
	IP    string    `json:"ip"`
	Until time.Time `json:"until"`
}

var defaultHTTP = &http.Client{Timeout: 30 * time.Second}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body []byte) (int, []byte, error) {
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	h := c.HTTP
	if h == nil {
		h = defaultHTTP
	}
	resp, err := h.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return resp.StatusCode, b, nil
}

// Load replaces Caddy's running config with cfg (POST /load).
func (c *Client) Load(ctx context.Context, cfg any) error {
	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	status, resp, err := c.do(ctx, http.MethodPost, "/load", nil, body)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return &LoadError{Status: status, Body: string(resp)}
	}
	return nil
}

// Bans lists active bans per site; an empty siteID lists all sites.
func (c *Client) Bans(ctx context.Context, siteID string) (map[string][]Ban, error) {
	q := url.Values{}
	if siteID != "" {
		q.Set("site", siteID)
	}
	status, resp, err := c.do(ctx, http.MethodGet, "/hi/bans", q, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &LoadError{Status: status, Body: string(resp)}
	}
	out := map[string][]Ban{}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decode bans: %w", err)
	}
	return out, nil
}

// Unban lifts a ban; it reports false if the IP was not banned.
func (c *Client) Unban(ctx context.Context, siteID, ip string) (bool, error) {
	q := url.Values{}
	q.Set("site", siteID)
	q.Set("ip", ip)
	status, resp, err := c.do(ctx, http.MethodDelete, "/hi/bans", q, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, &LoadError{Status: status, Body: string(resp)}
}
