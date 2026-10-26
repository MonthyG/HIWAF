package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Request is one access-log line.
type Request struct {
	TS                                      time.Time
	SiteID, ClientIP, Country, Method, Host string
	URI, UA, Referer, Action, Kind, TxID    string
	Status                                  int
	Bytes                                   int64
	DurMS                                   float64
	HTML                                    bool
}

// blockedActions are the access-log actions counted as "blocked".
const blockedActions = `('block','deny','rate_limit')`

// InsertRequests stores requests in one transaction.
func (s *Store) InsertRequests(ctx context.Context, reqs []Request) error {
	if len(reqs) == 0 {
		return nil
	}
	return s.Tx(ctx, func(t *Tx) error {
		stmt, err := t.tx.PrepareContext(ctx,
			`INSERT INTO requests(ts, site_id, client_ip, country, method, host, uri, status, bytes,
			 dur_ms, ua, referer, html, action, kind, tx_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, r := range reqs {
			html := 0
			if r.HTML {
				html = 1
			}
			if _, err := stmt.ExecContext(ctx, r.TS.UnixMilli(), r.SiteID, r.ClientIP, r.Country, r.Method,
				r.Host, r.URI, r.Status, r.Bytes, r.DurMS, r.UA, r.Referer, html, r.Action, r.Kind, r.TxID); err != nil {
				return err
			}
		}
		return nil
	})
}

// RequestFilter narrows the request statistics. Empty fields match everything.
type RequestFilter struct {
	SiteID       string
	Since, Until time.Time
}

func (f RequestFilter) where() (string, []any) {
	clause, args := " WHERE 1=1", []any{}
	if f.SiteID != "" {
		clause += " AND site_id = ?"
		args = append(args, f.SiteID)
	}
	if !f.Since.IsZero() {
		clause += " AND ts >= ?"
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		clause += " AND ts < ?"
		args = append(args, f.Until.UnixMilli())
	}
	return clause, args
}

// Overview holds the Statistics page counters.
type Overview struct {
	Requests, PV, UV, UniqueIPs int
	Blocked, BlockedIPs         int
	Err4xx, Err5xx, Blocked4xx  int
}

// Overview counts requests matching f.
func (s *Store) Overview(ctx context.Context, f RequestFilter) (Overview, error) {
	clause, args := f.where()
	var o Overview
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(html = 1 AND status < 400), 0),
		COUNT(DISTINCT client_ip || '|' || ua),
		COUNT(DISTINCT client_ip),
		COALESCE(SUM(action IN `+blockedActions+`), 0),
		COUNT(DISTINCT CASE WHEN action IN `+blockedActions+` THEN client_ip END),
		COALESCE(SUM(status BETWEEN 400 AND 499), 0),
		COALESCE(SUM(status >= 500), 0),
		COALESCE(SUM(status BETWEEN 400 AND 499 AND action IN `+blockedActions+`), 0)
		FROM requests`+clause, args...).
		Scan(&o.Requests, &o.PV, &o.UV, &o.UniqueIPs, &o.Blocked, &o.BlockedIPs, &o.Err4xx, &o.Err5xx, &o.Blocked4xx)
	return o, err
}

// Point is one bucket of a time series; T is the bucket start.
type Point struct {
	T                 time.Time
	Requests, Blocked int
}

// Series buckets requests matching f into intervals of step.
func (s *Store) Series(ctx context.Context, f RequestFilter, step time.Duration) ([]Point, error) {
	clause, args := f.where()
	ms := step.Milliseconds()
	if ms <= 0 {
		ms = 60000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT (ts / ?) * ?, COUNT(*), COALESCE(SUM(action IN `+blockedActions+`), 0)
		FROM requests`+clause+` GROUP BY 1 ORDER BY 1`, append([]any{ms, ms}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var p Point
		var t int64
		if err := rows.Scan(&t, &p.Requests, &p.Blocked); err != nil {
			return nil, err
		}
		p.T = time.UnixMilli(t).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// TopDim is a column the Statistics page ranks by.
type TopDim string

// Dimensions for TopRequests.
const (
	DimCountry TopDim = "country"
	DimStatus  TopDim = "status"
	DimSite    TopDim = "site"
	DimPage    TopDim = "page"
	DimIP      TopDim = "ip"
	DimUA      TopDim = "ua"
	DimReferer TopDim = "referer"
	DimAction  TopDim = "action"
)

var dimExpr = map[TopDim]string{
	DimCountry: "country",
	DimStatus:  "CAST(status AS TEXT)",
	DimSite:    "site_id",
	DimPage:    "host || CASE WHEN instr(uri, '?') > 0 THEN substr(uri, 1, instr(uri, '?') - 1) ELSE uri END",
	DimIP:      "client_ip",
	DimUA:      "ua",
	DimReferer: "referer",
	DimAction:  "action",
}

// TopRequests ranks requests matching f by dim, with blocked counts. Unknown
// dimensions return nil.
func (s *Store) TopRequests(ctx context.Context, f RequestFilter, dim TopDim, limit int) ([]Count, error) {
	expr, ok := dimExpr[dim]
	if !ok {
		return nil, nil
	}
	clause, args := f.where()
	rows, err := s.db.QueryContext(ctx, `SELECT `+expr+` AS k, COUNT(*) AS n,
		COALESCE(SUM(action IN `+blockedActions+`), 0) FROM requests`+clause+`
		GROUP BY k ORDER BY n DESC, k ASC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.N, &c.Blocked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SiteCounts returns per-site request and blocked counts since a time.
func (s *Store) SiteCounts(ctx context.Context, since time.Time) (map[string]Count, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT site_id, COUNT(*), COALESCE(SUM(action IN `+blockedActions+`), 0)
		FROM requests WHERE ts >= ? GROUP BY site_id`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.N, &c.Blocked); err != nil {
			return nil, err
		}
		out[c.Key] = c
	}
	return out, rows.Err()
}

// RequestByTx returns the request with a Coraza transaction ID.
func (s *Store) RequestByTx(ctx context.Context, tx string) (Request, bool, error) {
	var r Request
	var ts int64
	var html int
	err := s.db.QueryRowContext(ctx, `SELECT ts, site_id, client_ip, country, method, host, uri, status, bytes,
		dur_ms, ua, referer, html, action, kind, tx_id FROM requests WHERE tx_id = ? LIMIT 1`, tx).
		Scan(&ts, &r.SiteID, &r.ClientIP, &r.Country, &r.Method, &r.Host, &r.URI, &r.Status, &r.Bytes,
			&r.DurMS, &r.UA, &r.Referer, &html, &r.Action, &r.Kind, &r.TxID)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, nil
	}
	if err != nil {
		return Request{}, false, err
	}
	r.TS, r.HTML = time.UnixMilli(ts).UTC(), html == 1
	return r, true, nil
}

// LatencyP95 returns the 95th percentile request duration in milliseconds for
// requests matching f, or 0 when there are none.
func (s *Store) LatencyP95(ctx context.Context, f RequestFilter) (float64, error) {
	clause, args := f.where()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM requests`+clause, args...).Scan(&n); err != nil || n == 0 {
		return 0, err
	}
	var ms float64
	err := s.db.QueryRowContext(ctx, `SELECT dur_ms FROM requests`+clause+` ORDER BY dur_ms LIMIT 1 OFFSET ?`,
		append(args, (n*95-1)/100)...).Scan(&ms)
	return ms, err
}
