// Command recipe-manager runs the recipe manager HTTP server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/brett6320/recipe-manager/internal/config"
	"github.com/brett6320/recipe-manager/internal/db"
	"github.com/brett6320/recipe-manager/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// healthcheck probes the local /healthz endpoint; used as the container
// health command because the distroless image has no curl.
func healthcheck() int {
	addr := os.Getenv("RM_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if os.Getenv("RM_TLS_CERT") != "" {
		scheme = "https"
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local self-probe only
	resp, err := c.Get(scheme + "://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		return 1
	}
	resp.Body.Close()
	return 0
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var h slog.Handler
	if cfg.LogJSON {
		h = slog.NewJSONHandler(os.Stdout, nil)
	} else {
		h = slog.NewTextHandler(os.Stdout, nil)
	}
	log := slog.New(h)
	slog.SetDefault(log)

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, filepath.Join(cfg.DataDir, "recipes.db"))
	if err != nil {
		return err
	}
	defer database.Close()

	srv, err := server.New(cfg, database, log)
	if err != nil {
		return err
	}

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if cfg.TLSCert != "" {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.TLSClientCA != "" {
			pem, err := os.ReadFile(cfg.TLSClientCA)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return errors.New("RM_TLS_CLIENT_CA: no certificates found")
			}
			tc.ClientCAs = pool
			tc.ClientAuth = tls.RequireAndVerifyClientCert
		}
		hs.TLSConfig = tc
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "", "origin", cfg.Origin)
		if cfg.TLSCert != "" {
			errCh <- hs.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errCh <- hs.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
	return nil
}
