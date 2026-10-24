package caddyclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoadErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, "bad")
	}))
	c := &Client{BaseURL: srv.URL}
	err := c.Load(context.Background(), map[string]any{"a": 1})
	var le *LoadError
	if !errors.As(err, &le) || le.Status != 400 || le.Body != "bad" {
		t.Fatalf("err = %#v", err)
	}
	srv.Close()
	err = c.Load(context.Background(), map[string]any{})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestLoadOK(t *testing.T) {
	var gotCT, gotBody, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotCT, gotBody, gotPath = r.Header.Get("Content-Type"), string(b), r.Method+" "+r.URL.Path
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	if err := c.Load(context.Background(), map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/json" || gotBody != `{"a":1}` || gotPath != "POST /load" {
		t.Fatalf("got %q %q %q", gotCT, gotBody, gotPath)
	}
}

func TestBansAndUnban(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/hi/bans":
			if r.URL.Query().Get("site") != "s_a b" {
				t.Errorf("site = %q", r.URL.Query().Get("site"))
			}
			io.WriteString(w, `{"s_a b":[{"ip":"1.2.3.4","until":"2025-10-23T06:13:20Z"}]}`)
		case r.Method == "DELETE":
			if r.URL.Query().Get("ip") == "1.2.3.4" {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(404)
			}
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL + "/"}
	m, err := c.Bans(context.Background(), "s_a b")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 10, 23, 6, 13, 20, 0, time.UTC)
	if len(m["s_a b"]) != 1 || m["s_a b"][0].IP != "1.2.3.4" || !m["s_a b"][0].Until.Equal(want) {
		t.Fatalf("bans = %+v", m)
	}
	if ok, err := c.Unban(context.Background(), "s_a b", "1.2.3.4"); !ok || err != nil {
		t.Fatalf("unban = %v %v", ok, err)
	}
	if ok, err := c.Unban(context.Background(), "s_a b", "9.9.9.9"); ok || err != nil {
		t.Fatalf("unban missing = %v %v", ok, err)
	}
}
