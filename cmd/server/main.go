package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wgkeeper/wgkeeper-node/internal/config"
	"github.com/wgkeeper/wgkeeper-node/internal/server"
	"github.com/wgkeeper/wgkeeper-node/internal/version"
	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const (
	cmdInit      = "init"
	argPrintPath = "--print-path"

	// cleanupShutdownTimeout is how long main waits for the cleanup goroutine
	// to finish an in-flight expiry pass before giving up. Must exceed wgOpTimeout
	// (10 s) to allow a running configureDevice call to complete.
	cleanupShutdownTimeout = 15 * time.Second
)

func main() {
	debug := isDebugEnabled()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	setupGinMode(debug)

	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	if handled, err := handleInit(cfg, os.Args); handled {
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		return
	}

	if _, err := wireguard.EnsureWireGuardConfig(cfg); err != nil {
		slog.Error("ensure WireGuard config", "error", err)
		os.Exit(1)
	}

	wgService, err := wireguard.NewWireGuardService(cfg)
	if err != nil {
		slog.Error("init WireGuard", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := wgService.Close(); err != nil {
			slog.Error("close peer store", "error", err)
		}
	}()

	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		wgService.RunExpiredPeersCleanup(appCtx, time.Minute)
	}()

	addr := cfg.Addr()
	protocol := protocolFromConfig(cfg)
	slog.Info("starting", "service", version.Name, "version", version.Version)
	slog.Info("listening", "addr", addr, "protocol", protocol)
	slog.Info("wireguard ready", "iface", cfg.WGInterface, "listen", cfg.WGListenPort, "subnets", formatSubnetsLog(cfg))
	httpServer := newHTTPServer(appCtx, cfg, addr, wgService, debug)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runServer(cfg, httpServer)
	}()

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if isFatalServerError(err) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	case sig := <-shutdownSignal:
		slog.Info("shutdown signal received", "signal", sig)
	}

	appCancel()
	select {
	case <-cleanupDone:
	case <-time.After(cleanupShutdownTimeout):
		slog.Warn("cleanup goroutine did not finish in time, proceeding with shutdown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

func setupGinMode(debug bool) {
	if debug {
		slog.Warn("DEBUG is enabled; do not use in production (error details exposed to clients)")
		gin.SetMode(gin.DebugMode)
		return
	}
	gin.SetMode(gin.ReleaseMode)
}

func formatSubnetsLog(cfg config.Config) string {
	if cfg.WGSubnet6 == "" {
		return cfg.WGSubnet
	}
	if cfg.WGSubnet != "" {
		return cfg.WGSubnet + "," + cfg.WGSubnet6
	}
	return cfg.WGSubnet6
}

func protocolFromConfig(cfg config.Config) string {
	if cfg.TLSEnabled() {
		return "https"
	}
	return "http"
}

func isFatalServerError(err error) bool {
	return err != nil && !errors.Is(err, http.ErrServerClosed)
}

func newHTTPServer(ctx context.Context, cfg config.Config, addr string, wgService *wireguard.WireGuardService, debug bool) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.NewRouter(ctx, cfg.APIKey, cfg.AllowedNets, wgService, debug),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if cfg.TLSEnabled() {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Restrict TLS 1.2 to ECDHE+AEAD ciphers only (forward secrecy + authenticated encryption).
			// TLS 1.3 cipher suites are not configurable in Go and are always secure.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
	}
	return srv
}

func runServer(cfg config.Config, srv *http.Server) error {
	if cfg.TLSEnabled() {
		return srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

func handleInit(cfg config.Config, args []string) (bool, error) {
	if len(args) < 2 {
		return false, nil
	}
	if args[1] != cmdInit {
		return true, fmt.Errorf("unknown command: %s; use: no args (run server) or init [--print-path]", args[1])
	}

	path, err := wireguard.EnsureWireGuardConfig(cfg)
	if err != nil {
		return true, err
	}
	if len(args) > 2 && args[2] == argPrintPath {
		fmt.Println(path)
		return true, nil
	}
	slog.Info("WireGuard config ready", "path", path)
	return true, nil
}

func isDebugEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("DEBUG")))
	return v == "true" || v == "1"
}
