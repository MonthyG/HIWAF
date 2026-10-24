// Command manager is the HostingInside WAF control plane: it serves the REST
// API, keeps sites in SQLite, pushes compiled configs to the Caddy engine and
// ingests the engine's security events.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"hostinginside/waf/manager/api"
	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/ingest"
	"hostinginside/waf/manager/store"
)

type config struct {
	Listen         string   `json:"listen"`
	DBPath         string   `json:"db_path"`
	CaddyAdmin     string   `json:"caddy_admin"`
	EventLog       string   `json:"event_log"`
	APIKeys        []string `json:"api_keys"`
	HTTPPort       int      `json:"http_port"`
	HTTPSPort      int      `json:"https_port"`
	GeoIPDB        string   `json:"geoip_db"`
	FeedsDir       string   `json:"feeds_dir"`
	TrustedProxies []string `json:"trusted_proxies"`
	ACMEInternal   bool     `json:"acme_internal"`
}

const secretKey = "challenge_secret"

func loadConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Listen, ":9000")
	def(&c.CaddyAdmin, "http://127.0.0.1:2019")
	def(&c.EventLog, "events.log")
	def(&c.DBPath, "waf.db")
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	var keys []string
	for _, k := range c.APIKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return c, fmt.Errorf("%s: api_keys must list at least one non-empty key", path)
	}
	c.APIKeys = keys
	// Caddy runs with its own working directory, so paths it opens are made
	// absolute here; the manager reads the event log at the same path.
	for _, p := range []*string{&c.EventLog, &c.GeoIPDB, &c.FeedsDir} {
		if *p == "" {
			continue
		}
		if *p, err = filepath.Abs(*p); err != nil {
			return c, err
		}
	}
	return c, nil
}

// challengeSecret returns the stored secret, creating it on first start.
func challengeSecret(ctx context.Context, st *store.Store) (string, error) {
	s, ok, err := st.Setting(ctx, secretKey)
	if err != nil || ok {
		return s, err
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails since Go 1.24
	s = base64.StdEncoding.EncodeToString(b)
	return s, st.SetSetting(ctx, secretKey, s)
}

func main() {
	cfgPath := flag.String("config", "manager.json", "path to the manager config file")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if err := run(*cfgPath, log); err != nil {
		log.Error("manager", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	admin, err := url.Parse(cfg.CaddyAdmin)
	if err != nil || admin.Host == "" {
		return fmt.Errorf("caddy_admin must be a URL such as http://127.0.0.1:2019, got %q", cfg.CaddyAdmin)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	secret, err := challengeSecret(ctx, st)
	if err != nil {
		return fmt.Errorf("challenge secret: %w", err)
	}

	opt := compile.Options{
		AdminListen:     admin.Host,
		HTTPPort:        cfg.HTTPPort,
		HTTPSPort:       cfg.HTTPSPort,
		EventLog:        cfg.EventLog,
		ChallengeSecret: secret,
		GeoIPDB:         cfg.GeoIPDB,
		FeedsDir:        cfg.FeedsDir,
		TrustedProxies:  cfg.TrustedProxies,
		ACMEInternal:    cfg.ACMEInternal,
	}
	a := api.New(st, &caddyclient.Client{BaseURL: cfg.CaddyAdmin}, opt, cfg.APIKeys)

	syncCtx, cancel := context.WithTimeout(ctx, time.Minute)
	if err := a.Sync(syncCtx); err != nil {
		log.Warn("initial config push failed; the API is up but changes will fail until the engine is reachable", "err", err)
	} else {
		log.Info("config pushed to engine", "admin", cfg.CaddyAdmin)
	}
	cancel()

	tailDone := make(chan struct{})
	go func() {
		defer close(tailDone)
		_ = (&ingest.Tailer{Path: cfg.EventLog, Store: st, Logger: log}).Run(ctx)
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // a config push may take up to the client's 30s timeout
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("manager listening", "addr", cfg.Listen)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err = <-errc:
		stop()
	case <-ctx.Done():
		log.Info("shutting down")
		shCtx, shCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = srv.Shutdown(shCtx)
		shCancel()
	}
	<-tailDone
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
