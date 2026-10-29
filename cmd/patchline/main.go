// Command patchline runs the Patchline server: webhook intake, finding
// tracking, notifications and the web UI in a single binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rha6780/patchline/internal/config"
	"github.com/rha6780/patchline/internal/intake"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/job"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/policy"
	"github.com/rha6780/patchline/internal/server"
	"github.com/rha6780/patchline/internal/sink/console"
	"github.com/rha6780/patchline/internal/sink/slack"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "patchline:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version)
			return nil
		case "healthcheck":
			// Used by container health checks: the runtime image has no curl.
			return healthcheck(cfg.Addr)
		default:
			return fmt.Errorf("unknown command %q (want: version, healthcheck)", os.Args[1])
		}
	}
	logger := newLogger(cfg)
	slog.SetDefault(logger)

	inv, err := inventory.Load(cfg.InventoryPath)
	if err != nil {
		return err
	}
	logger.Info("inventory loaded", "path", cfg.InventoryPath, "services", len(inv.Services()))
	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return err
	}
	logger.Info("policy loaded", "path", cfg.PolicyPath, "sla", pol.Summary(), "kev", cfg.KEVURL != "")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	applied, err := store.Migrate(ctx, db)
	if err != nil {
		return err
	}
	logger.Info("database ready", "path", cfg.DatabasePath, "migrations_applied", applied)

	st := store.New(db)

	proc := &intake.Processor{Store: st, Inventory: inv, Logger: logger, ReconcileDelay: cfg.DependencyTrackReconcileDelay}
	if cfg.DependencyTrackEnabled() {
		proc.DT = dependencytrack.NewClient(cfg.DependencyTrackURL, cfg.DependencyTrackAPIKey, nil)
	} else {
		logger.Warn("PATCHLINE_DT_URL or PATCHLINE_DT_API_KEY not set: BOM_PROCESSED events will not fetch findings")
	}
	if cfg.WebhookToken == "" {
		logger.Warn("PATCHLINE_WEBHOOK_TOKEN not set: webhooks are accepted without authentication")
	}

	var sink notify.Sink = console.New(os.Stdout)
	if cfg.SlackBotToken != "" {
		sink = slack.New(cfg.SlackBotToken, "", nil)
	} else {
		logger.Info("PATCHLINE_SLACK_BOT_TOKEN not set: notifications are printed to stdout")
	}
	notifier := &notify.Notifier{
		Store:          st,
		Sink:           sink,
		Inventory:      inv,
		Logger:         logger,
		DefaultChannel: cfg.SlackDefaultChannel,
		MinSeverity:    cfg.NotifyMinSeverity,
		DTUIURL:        cfg.DependencyTrackUIURL,
	}
	sla := &job.SLA{Store: st, Policy: pol, Inventory: inv, Logger: logger, KEVURL: cfg.KEVURL, OnChange: notifier.Wake}
	// New findings are posted once the policy has evaluated them, so the
	// SLA job runs first and wakes the notifier.
	proc.OnChange = func() { sla.Wake(); notifier.Wake() }

	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); proc.Run(ctx) }()
	go func() { defer workers.Done(); sla.Run(ctx) }()
	go func() { defer workers.Done(); notifier.Run(ctx) }()

	ui, err := web.New(web.Options{Store: st, Inventory: inv, DTUIURL: cfg.DependencyTrackUIURL, Version: version, Logger: logger})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: server.New(server.Options{
			DB:           st,
			Inbox:        st,
			Findings:     st,
			Inventory:    inv,
			WebhookToken: cfg.WebhookToken,
			GiteaSecret:  cfg.GiteaWebhookSecret,
			UI:           ui,
			OnInbox:      proc.Wake,
			Logger:       logger,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("patchline listening", "addr", cfg.Addr, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	workers.Wait()
	return err
}

func healthcheck(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse PATCHLINE_ADDR: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %s", resp.Status)
	}
	return nil
}

func newLogger(cfg config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
