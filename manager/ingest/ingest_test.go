package ingest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hostinginside/waf/manager/store"
)

func TestParseHiEvent(t *testing.T) {
	ev, ok := ParseLine([]byte(`{"ts":1761200000.5,"logger":"http.handlers.hi_access","msg":"hi_event","event":"ip_block","site_id":"s_aaaaaaaaaaaa","client_ip":"1.2.3.4","detail":"why"}` + "\r"))
	if !ok {
		t.Fatal("not parsed")
	}
	want := time.Date(2025, 10, 23, 6, 13, 20, 500_000_000, time.UTC)
	if ev.Type != "ip_block" || ev.SiteID != "s_aaaaaaaaaaaa" || ev.ClientIP != "1.2.3.4" || ev.Msg != "why" || !ev.TS.Equal(want) {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestParseCorazaMatch(t *testing.T) {
	line := `{"ts":1761200002,"logger":"http.handlers.waf","msg":"[client \"1.2.3.4\"] Coraza: Warning. SQL Injection Attack Detected [file \"x\"] [line \"1\"] [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [uri \"/?id=1\"] [unique_id \"s_aaaaaaaaaaaa-0123456789abcdef\"]"}`
	ev, ok := ParseLine([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	if ev.Type != "waf_match" || ev.RuleID != "942100" || ev.SiteID != "s_aaaaaaaaaaaa" || ev.ClientIP != "1.2.3.4" ||
		ev.URI != "/?id=1" || ev.Msg != "SQL Injection Attack Detected via libinjection" {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestParseIgnoresOther(t *testing.T) {
	for _, l := range []string{
		`{"ts":1,"logger":"http.log.access","msg":"handled request"}`,
		`{"ts":1,"logger":"http.handlers.waf","msg":"WAF rule violation detected"}`,
		`not json`,
		``,
	} {
		if ev, ok := ParseLine([]byte(l)); ok {
			t.Errorf("%q parsed as %+v", l, ev)
		}
	}
}

func TestParseFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ev, ok := ParseLine([]byte(l)); ok {
			types = append(types, ev.Type)
		}
	}
	if got := strings.Join(types, ","); got != "ip_block,waf_match,rate_limit_ban" {
		t.Fatalf("types = %s", got)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestTailerOffsetAndRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := filepath.Join(dir, "events.log")
	tl := &Tailer{Path: log, Store: st}

	line := func(ip string) string {
		return `{"ts":1761200000,"msg":"hi_event","event":"ip_block","site_id":"s_aaaaaaaaaaaa","client_ip":"` + ip + `"}`
	}
	count := func(want int) {
		t.Helper()
		evs, err := st.QueryEvents(ctx, store.EventFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != want {
			t.Fatalf("events = %d, want %d", len(evs), want)
		}
	}

	if err := tl.Once(ctx); err != nil { // missing file is fine
		t.Fatal(err)
	}
	appendFile(t, log, line("1.1.1.1")+"\r\n"+line("2.2.2.2")+"\n")
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(2)

	part := line("3.3.3.3")
	appendFile(t, log, part[:20])
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(2)

	appendFile(t, log, part[20:]+"\n")
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(3)

	if err := tl.Once(ctx); err != nil { // nothing new: no duplicates
		t.Fatal(err)
	}
	count(3)

	if err := os.WriteFile(log, []byte(line("4.4.4.4")+"\n"), 0o644); err != nil { // truncated: smaller than offset
		t.Fatal(err)
	}
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(4)
}

func TestTailerSkipsHugeLine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := filepath.Join(dir, "events.log")
	huge := strings.Repeat("x", 2<<20)
	good := `{"ts":1761200000,"msg":"hi_event","event":"geo_block","site_id":"s_aaaaaaaaaaaa"}`
	appendFile(t, log, huge+"\n"+good+"\n")
	tl := &Tailer{Path: log, Store: st}
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	evs, err := st.QueryEvents(ctx, store.EventFilter{Limit: 10})
	if err != nil || len(evs) != 1 || evs[0].Type != "geo_block" {
		t.Fatalf("evs = %+v err = %v", evs, err)
	}
}

func TestParseCorazaHardening(t *testing.T) {
	mk := func(uid string) string {
		return `{"logger":"http.handlers.waf","msg":"[id \"1\"] [unique_id \"` + uid + `\"]"}`
	}
	for _, uid := range []string{"-abc", "garbage-0123", "s_AAAAAAAAAAAA-1", "nodash"} {
		if ev, ok := ParseLine([]byte(mk(uid))); ok {
			t.Errorf("unique_id %q parsed as %+v", uid, ev)
		}
	}
	if _, ok := ParseLine([]byte(`{"logger":"http.handlers.waf","msg":"x","other":"[id \"1\"] [unique_id \"s_aaaaaaaaaaaa-1\"]"}`)); ok {
		t.Error("non-msg field must not produce a match")
	}
	ev, ok := ParseLine([]byte(`{"logger":"http.handlers.waf","msg":"[id \"1\"] [msg \"say \\\"hi\\\"\"] [unique_id \"s_aaaaaaaaaaaa-1\"]"}`))
	if !ok || ev.Msg != `say "hi"` {
		t.Errorf("ev = %+v ok = %v", ev, ok)
	}
}
