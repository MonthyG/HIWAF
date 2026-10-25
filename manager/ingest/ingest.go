// Package ingest tails the engine's JSON log and stores security events.
package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hostinginside/waf/manager/store"
)

const (
	offsetKey    = "ingest_offset"
	maxLineBytes = 1 << 20
	batchSize    = 500
)

var siteRe = regexp.MustCompile(`^s_[0-9a-f]{12}$`)

// unquote undoes the escaping Coraza applies to logged values.
func unquote(v string) string {
	if u, err := strconv.Unquote(`"` + v + `"`); err == nil {
		return u
	}
	return v
}

var corazaField = regexp.MustCompile(`\[(\w+) "((?:[^"\\]|\\.)*)"\]`)

// ParseLine converts one Caddy JSON log line into an Event; ok is false for
// lines that are not security events.
func ParseLine(line []byte) (store.Event, bool) {
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(line), &m); err != nil {
		return store.Event{}, false
	}
	str := func(k string) string { s, _ := m[k].(string); return s }
	ts := time.Now().UTC()
	if f, ok := m["ts"].(float64); ok {
		sec, frac := math.Modf(f)
		ts = time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).UTC()
	}

	if str("msg") == "hi_event" {
		return store.Event{
			TS: ts, SiteID: str("site_id"), Type: str("event"), ClientIP: str("client_ip"),
			Host: str("host"), Method: str("method"), URI: str("uri"),
			RuleID: str("rule_id"), Msg: str("detail"),
		}, true
	}

	if str("logger") != "http.handlers.waf" {
		return store.Event{}, false
	}
	text := str("msg") // only msg: other fields may carry attacker-controlled data
	if !strings.Contains(text, `[id "`) {
		return store.Event{}, false
	}
	f := map[string]string{}
	for _, sm := range corazaField.FindAllStringSubmatch(text, -1) {
		if _, dup := f[sm[1]]; !dup {
			f[sm[1]] = unquote(sm[2])
		}
	}
	site, _, _ := strings.Cut(f["unique_id"], "-")
	if !siteRe.MatchString(site) {
		return store.Event{}, false
	}
	return store.Event{
		TS: ts, SiteID: site, Type: "waf_match", ClientIP: f["client"],
		URI: f["uri"], RuleID: f["id"], Msg: f["msg"],
	}, true
}

// Tailer follows a log file and persists events plus its read offset.
type Tailer struct {
	Path     string
	Store    *store.Store
	Interval time.Duration // default 1s
	Logger   *slog.Logger  // default slog.Default()
}

// Once reads all complete lines added since the saved offset. The offset is
// saved after each batch is inserted, so a crash can at worst re-insert a batch.
func (t *Tailer) Once(ctx context.Context) error {
	f, err := os.Open(t.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	var saved int64
	s, ok, err := t.Store.Setting(ctx, offsetKey)
	if err != nil {
		return err
	}
	if ok {
		saved, _ = strconv.ParseInt(s, 10, 64)
	}
	off := saved
	if off < 0 || fi.Size() < off { // rotated or truncated
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}

	var batch []store.Event
	flush := func(newOff int64) error {
		if err := t.Store.InsertEvents(ctx, batch); err != nil {
			return err
		}
		batch = batch[:0]
		if err := t.Store.SetSetting(ctx, offsetKey, strconv.FormatInt(newOff, 10)); err != nil {
			return err
		}
		saved = newOff
		return nil
	}

	r := bufio.NewReaderSize(f, 64<<10)
	var buf []byte
	skipping := false // current line exceeded maxLineBytes: discard it
	consumed := off   // offset just past the last complete line handled
	pos := off        // bytes read so far
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := r.ReadSlice('\n')
		pos += int64(len(chunk))
		if !skipping {
			buf = append(buf, chunk...)
			if len(buf) > maxLineBytes {
				skipping, buf = true, buf[:0]
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break // a trailing partial line stays unconsumed
		}
		if !skipping {
			if ev, ok := ParseLine(bytes.TrimRight(buf, "\r\n")); ok {
				batch = append(batch, ev)
			}
		}
		buf, skipping = buf[:0], false
		consumed = pos
		if len(batch) >= batchSize {
			if err := flush(consumed); err != nil {
				return err
			}
		}
	}
	if len(batch) > 0 || consumed != saved {
		return flush(consumed)
	}
	return nil
}

// Run calls Once every Interval until ctx is done.
func (t *Tailer) Run(ctx context.Context) error {
	iv := t.Interval
	if iv <= 0 {
		iv = time.Second
	}
	log := t.Logger
	if log == nil {
		log = slog.Default()
	}
	tick := time.NewTicker(iv)
	defer tick.Stop()
	for {
		if err := t.Once(ctx); err != nil && ctx.Err() == nil {
			log.Error("ingest", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
