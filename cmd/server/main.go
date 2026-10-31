package main

import (
	"context"
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
	"github.com/wgkeeper/wgkeeper-node/internal/metrics"
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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(debug)})))
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
	slog.Info("starting", "service", version.Name, "version", version.Version)
	slog.Info("listening", "addr", addr, "protocol", "http")
	slog.Info("wireguard ready", "iface", cfg.WGInterface, "listen", cfg.WGListenPort, "subnets", formatSubnetsLog(cfg))

	var metricsBundle *metrics.Metrics
	metricsDone := make(chan struct{})
	if cfg.MetricsEnabled() {
		metricsBundle = metrics.New()
		wgService.SetRollbackObserver(metricsBundle)
		metricsBundle.BindPeersProvider(peerSnapshotAdapter{svc: wgService})
		metricsBundle.BindWireGuardProvider(wgSnapshotAdapter{svc: wgService})
		metricsSrv := metrics.NewServer(cfg.MetricsAddr(), cfg.MetricsToken, metricsBundle)
		slog.Info("metrics enabled", "addr", cfg.MetricsAddr())
		go func() {
			defer close(metricsDone)
			if err := metrics.Run(appCtx, metricsSrv); err != nil {
				slog.Error("metrics server error", "error", err)
			}
		}()
	} else {
		close(metricsDone)
	}

	httpServer := newHTTPServer(cfg, addr, wgService, metricsBundle)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpServer.ListenAndServe()
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
	// Wait for the metrics listener (if enabled) to finish too. metrics.Run
	// reacts to appCancel and shuts down its own server with a 5s budget.
	<-metricsDone
}

// peerSnapshotAdapter bridges WireGuardService.Stats() to metrics.PeersProvider
// so the wireguard package does not depend on the metrics package.
type peerSnapshotAdapter struct {
	svc *wireguard.WireGuardService
}

func (a peerSnapshotAdapter) PeersSnapshot() (metrics.PeersSnapshot, error) {
	s, err := a.svc.Stats()
	if err != nil {
		return metrics.PeersSnapshot{}, err
	}
	return metrics.PeersSnapshot{
		Possible: s.Peers.Possible,
		Issued:   s.Peers.Issued,
		Active:   s.Peers.Active,
	}, nil
}

// wgSnapshotAdapter bridges WireGuardService.WireGuardSnapshot() to
// metrics.WireGuardProvider. Symmetric with peerSnapshotAdapter — both keep
// the wireguard package free of any prometheus dependency.
type wgSnapshotAdapter struct {
	svc *wireguard.WireGuardService
}

func (a wgSnapshotAdapter) WireGuardSnapshot() (metrics.WireGuardSnapshot, error) {
	s, err := a.svc.WireGuardSnapshot()
	if err != nil {
		return metrics.WireGuardSnapshot{}, err
	}
	return metrics.WireGuardSnapshot{
		ReceiveBytesTotal:  s.ReceiveBytesTotal,
		TransmitBytesTotal: s.TransmitBytesTotal,
		StalePeers:         s.StalePeers,
	}, nil
}

// logLevel returns the log level for DEBUG. DEBUG only makes logs more
// verbose; API responses are the same either way.
func logLevel(debug bool) slog.Level {
	if debug {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func setupGinMode(debug bool) {
	if debug {
		slog.Debug("DEBUG is enabled: verbose logs")
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

func isFatalServerError(err error) bool {
	return err != nil && !errors.Is(err, http.ErrServerClosed)
}

// newHTTPServer serves the API over plain HTTP. TLS, client filtering and
// rate limiting are the reverse proxy's job (see README, Deployment).
func newHTTPServer(cfg config.Config, addr string, wgService *wireguard.WireGuardService, m *metrics.Metrics) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           server.NewRouter(cfg.APIKey, wgService, m),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
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
