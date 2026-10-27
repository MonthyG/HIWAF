// Command manager is the HostingInside WAF control plane: it serves the web
// console and the REST API, keeps sites in SQLite, pushes compiled configs to
// the Caddy engine and ingests the engine's security events and access log.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"

	"hostinginside/waf/manager/alert"
	"hostinginside/waf/manager/api"
	"hostinginside/waf/manager/backup"
	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/console"
	"hostinginside/waf/manager/ingest"
	"hostinginside/waf/manager/store"
)

type config struct {
	Listen             string   `json:"listen"`
	DBPath             string   `json:"db_path"`
	DataDir            string   `json:"data_dir"`
	CaddyAdmin         string   `json:"caddy_admin"`
	EventLog           string   `json:"event_log"`
	AccessLog          string   `json:"access_log"`
	APIKeys            []string `json:"api_keys"`
	HTTPPort           int      `json:"http_port"`
	HTTPSPort          int      `json:"https_port"`
	GeoIPDB            string   `json:"geoip_db"`
	FeedsDir           string   `json:"feeds_dir"`
	StaticDir          string   `json:"static_dir"`
	TrustedProxies     []string `json:"trusted_proxies"`
	ACMEInternal       bool     `json:"acme_internal"`
	TLSCert            string   `json:"tls_cert"`        // console certificate (PEM)
	TLSKey             string   `json:"tls_key"`         // console key (PEM)
	SelfSignedTLS      bool     `json:"self_signed_tls"` // generate tls_cert/tls_key in data_dir if missing
	RetentionDays      int      `json:"retention_days"`  // access-log rows; default 7
	EventRetentionDays int      `json:"event_retention_days"`
	BackupDir          string   `json:"backup_dir"`   // default <data_dir>/backups
	BackupHours        int      `json:"backup_hours"` // between backups; default 24, -1 = no scheduled backups
	BackupKeep         int      `json:"backup_keep"`  // newest backups kept; default 7
	RulesetsDir        string   `json:"rulesets_dir"` // unpacked CRS releases; default <data_dir>/rulesets
}

const secretKey = "challenge_secret"

// devKey is the API key shipped in examples/manager.json. It is accepted only
// while the API listens on a loopback address.
const devKey = "change-me-dev-key"

// loopback reports whether a listen address binds only to the local host.
// An empty host (":9000") binds every interface and is not loopback.
func loopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

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
	def(&c.CaddyAdmin, "http://localhost:2019") // Caddy's own default admin address: pushing a different spelling makes Caddy try to bind the port twice
	def(&c.EventLog, "events.log")
	def(&c.DBPath, "waf.db")
	def(&c.DataDir, filepath.Dir(c.DBPath))
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 7
	}
	if c.EventRetentionDays == 0 {
		c.EventRetentionDays = 30
	}
	def(&c.BackupDir, filepath.Join(c.DataDir, "backups"))
	def(&c.RulesetsDir, filepath.Join(c.DataDir, "rulesets"))
	if c.BackupHours == 0 {
		c.BackupHours = 24
	}
	var keys []string
	for _, k := range c.APIKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	c.APIKeys = keys
	if !loopback(c.Listen) {
		for _, k := range keys {
			if k == devKey {
				return c, fmt.Errorf("%s: api key %q is the public example key; replace it or listen on a loopback address (127.0.0.1, ::1, localhost), not %q", path, devKey, c.Listen)
			}
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") && !c.SelfSignedTLS {
		return c, fmt.Errorf("%s: tls_cert and tls_key must be set together", path)
	}
	if c.SelfSignedTLS {
		def(&c.TLSCert, filepath.Join(c.DataDir, "console.crt"))
		def(&c.TLSKey, filepath.Join(c.DataDir, "console.key"))
	}
	// Caddy runs with its own working directory, so paths it opens are made
	// absolute here; the manager reads the logs at the same paths.
	for _, p := range []*string{&c.EventLog, &c.AccessLog, &c.GeoIPDB, &c.FeedsDir, &c.StaticDir, &c.BackupDir, &c.RulesetsDir} {
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

// ensureSelfSigned writes a 10-year self-signed ECDSA certificate for the
// console if certPath doesn't exist yet.
func ensureSelfSigned(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "HostingInside WAF console", Organization: []string{"HostingInside"}},
		DNSNames:     []string{"localhost", host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func main() {
	cfgPath := flag.String("config", "manager.json", "path to the manager config file")
	reset := flag.Bool("resetadmin", false, "set a new random password for the console user admin and exit")
	restore := flag.String("restore", "", "replace the database with this backup file and exit; stop the manager first")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	var err error
	switch {
	case *reset:
		err = resetAdmin(*cfgPath)
	case *restore != "":
		err = restoreDB(*cfgPath, *restore)
	default:
		err = run(*cfgPath, log)
	}
	if err != nil {
		log.Error("manager", "err", err)
		os.Exit(1)
	}
}

func resetAdmin(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	pw, err := api.ResetAdmin(context.Background(), st)
	if err != nil {
		return err
	}
	fmt.Printf("Console user: admin\nNew password: %s\n", pw)
	return nil
}

// restoreDB replaces the database with a backup. The current database is kept
// beside it as <db>.before-restore-<time>. The manager must be stopped: it
// holds the database open.
func restoreDB(cfgPath, file string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := store.CheckFile(ctx, file); err != nil {
		return fmt.Errorf("%s is not a usable backup: %w", file, err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.DBPath); err == nil {
		// opening and closing folds the write-ahead log into the file, so
		// the copy kept aside is complete
		st, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		st.Close()
		aside := cfg.DBPath + ".before-restore-" + time.Now().UTC().Format("20060102-150405")
		if err := os.Rename(cfg.DBPath, aside); err != nil {
			return err
		}
		fmt.Printf("Current database kept as %s\n", aside)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(cfg.DBPath + suffix)
	}
	if err := os.WriteFile(cfg.DBPath, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("Restored %s. Start the manager; it pushes the restored sites to the engine.\n", file)
	return nil
}

// consolePort returns the port of a listen address, or 0.
func consolePort(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	admin, err := url.Parse(cfg.CaddyAdmin)
	if err != nil || admin.Host == "" {
		return fmt.Errorf("caddy_admin must be a URL such as http://localhost:2019, got %q", cfg.CaddyAdmin)
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
	if pw, err := api.EnsureAdmin(ctx, st); err != nil {
		return fmt.Errorf("console admin: %w", err)
	} else if pw != "" {
		note := filepath.Join(cfg.DataDir, "initial-admin.txt")
		_ = os.WriteFile(note, []byte("Console user: admin\nPassword: "+pw+"\n"), 0o600)
		log.Warn("created console user admin; change its password after the first login",
			"password", pw, "also_written_to", note)
	}
	if cfg.StaticDir != "" {
		if err := os.MkdirAll(cfg.StaticDir, 0o755); err != nil {
			return fmt.Errorf("static_dir: %w", err)
		}
	}

	var reserved []int
	_, adminPort, _ := net.SplitHostPort(admin.Host)
	if n, err := strconv.Atoi(adminPort); err == nil {
		reserved = append(reserved, n)
	}
	if n := consolePort(cfg.Listen); n > 0 {
		reserved = append(reserved, n)
	}
	opt := compile.Options{
		AdminListen:     admin.Host,
		HTTPPort:        cfg.HTTPPort,
		HTTPSPort:       cfg.HTTPSPort,
		EventLog:        cfg.EventLog,
		AccessLog:       cfg.AccessLog,
		ChallengeSecret: secret,
		GeoIPDB:         cfg.GeoIPDB,
		FeedsDir:        cfg.FeedsDir,
		StaticDir:       cfg.StaticDir,
		TrustedProxies:  cfg.TrustedProxies,
		ACMEInternal:    cfg.ACMEInternal,
		ReservedPorts:   reserved,
	}
	engine := &caddyclient.Client{BaseURL: cfg.CaddyAdmin}
	a := api.New(st, engine, opt, cfg.APIKeys)
	host, _ := os.Hostname()
	notifier := &alert.Notifier{Store: st, Host: host, Log: log}
	watcher := &alert.Watcher{Notifier: notifier, Probe: func(ctx context.Context) error {
		_, err := engine.WaitRooms(ctx)
		return err
	}}
	backups := &backup.Backups{Store: st, Dir: cfg.BackupDir, Every: time.Duration(cfg.BackupHours) * time.Hour,
		Keep: cfg.BackupKeep, Log: log, Failed: func(err error) {
			notifier.Notify("backup_failed", "the scheduled database backup failed: "+err.Error())
		}}
	a.SetOps(api.Ops{RulesetsDir: cfg.RulesetsDir, Backups: backups, Notifier: notifier, Watcher: watcher})

	syncCtx, cancel := context.WithTimeout(ctx, time.Minute)
	if err := a.Sync(syncCtx); err != nil {
		log.Warn("initial config push failed; the API is up but changes will fail until the engine is reachable", "err", err)
		go retrySync(ctx, a, log)
	} else {
		log.Info("config pushed to engine", "admin", cfg.CaddyAdmin)
	}
	cancel()

	var country func(string) string
	if cfg.GeoIPDB != "" {
		geo, err := geoip2.Open(cfg.GeoIPDB)
		if err != nil {
			return fmt.Errorf("geoip_db: %w", err)
		}
		defer geo.Close()
		country = func(ip string) string {
			p := net.ParseIP(ip)
			if p == nil {
				return ""
			}
			rec, err := geo.Country(p)
			if err != nil || rec == nil {
				return ""
			}
			return strings.ToUpper(rec.Country.IsoCode)
		}
	}

	done := make(chan struct{}, 5)
	go func() {
		defer func() { done <- struct{}{} }()
		_ = (&ingest.Tailer{Path: cfg.EventLog, Store: st, Logger: log, Country: country}).Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if cfg.AccessLog == "" {
			return
		}
		_ = (&ingest.Tailer{Path: cfg.AccessLog, Store: st, Logger: log, Access: true,
			OffsetKey: "access_offset", Country: country}).Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		purge(ctx, st, cfg, log)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		watcher.Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if cfg.BackupHours > 0 {
			backups.Run(ctx)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/api/", a.Handler())
	mux.Handle("/", console.Handler())
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // static site uploads
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	if cfg.SelfSignedTLS {
		if err := ensureSelfSigned(cfg.TLSCert, cfg.TLSKey); err != nil {
			return fmt.Errorf("self-signed console certificate: %w", err)
		}
	}
	go func() {
		if cfg.TLSCert != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			log.Info("console listening", "url", "https://"+displayAddr(cfg.Listen))
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			return
		}
		log.Info("console listening", "url", "http://"+displayAddr(cfg.Listen))
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
	for i := 0; i < cap(done); i++ {
		<-done
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "<server-ip>" + listen
	}
	return listen
}

// retrySync pushes the config every 5 s until it succeeds; Caddy keeps
// serving its last config (--resume) meanwhile.
func retrySync(ctx context.Context, a *api.API, log *slog.Logger) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c, cancel := context.WithTimeout(ctx, time.Minute)
		err := a.Sync(c)
		cancel()
		if err == nil {
			log.Info("config pushed to engine")
			return
		}
	}
}

// purge drops old requests, events and sessions once an hour.
func purge(ctx context.Context, st *store.Store, cfg config, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		n := time.Now()
		if err := st.Purge(ctx, n.AddDate(0, 0, -cfg.RetentionDays), n.AddDate(0, 0, -cfg.EventRetentionDays), n); err != nil && ctx.Err() == nil {
			log.Error("purge", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
