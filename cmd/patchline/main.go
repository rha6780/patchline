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
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/config"
	"github.com/rha6780/patchline/internal/i18n"
	"github.com/rha6780/patchline/internal/intake"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/job"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/policy"
	"github.com/rha6780/patchline/internal/server"
	"github.com/rha6780/patchline/internal/sink/console"
	"github.com/rha6780/patchline/internal/sink/slack"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/source/osv"
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
		case "reset-admin-password":
			return resetAdminPassword(cfg)
		default:
			return fmt.Errorf("unknown command %q (want: version, healthcheck, reset-admin-password)", os.Args[1])
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
	var dt *dependencytrack.Client
	if cfg.DependencyTrackEnabled() {
		dt = dependencytrack.NewClient(cfg.DependencyTrackURL, cfg.DependencyTrackAPIKey, nil)
		proc.DT = dt
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
		Lang:           i18n.Lang(cfg.NotifyLang),
	}
	sla := &job.SLA{Store: st, Policy: pol, Inventory: inv, Logger: logger, KEVURL: cfg.KEVURL, OnChange: notifier.Wake}
	// New findings are posted once the policy has evaluated them, so the
	// SLA job runs first and wakes the notifier.
	proc.OnChange = func() { sla.Wake(); notifier.Wake() }

	// Patchline's own detection: SBOMs uploaded to /ingest/sbom are matched
	// against a local OSV mirror, and re-analyzed when it changes.
	var osvJob *job.OSV
	if len(cfg.OSVEcosystems) > 0 {
		syncer := &osv.Syncer{Store: st, BaseURL: cfg.OSVURL, Ecosystems: cfg.OSVEcosystems,
			TempDir: filepath.Dir(cfg.DatabasePath), Logger: logger}
		proc.Matcher = osv.Engine{DB: st, Syncer: syncer}
		osvJob = &job.OSV{Syncer: syncer, Interval: cfg.OSVRefresh, Logger: logger,
			OnChanged: func(ctx context.Context) {
				key := "reanalyze-" + time.Now().UTC().Format(time.RFC3339Nano)
				if _, _, err := st.InsertInbox(ctx, intake.SourcePatchline, intake.EventReanalyze, key, []byte("{}")); err != nil {
					logger.Error("schedule re-analysis", "err", err)
					return
				}
				proc.Wake()
			}}
		logger.Info("native detection enabled", "ecosystems", cfg.OSVEcosystems, "osv_url", cfg.OSVURL, "refresh", cfg.OSVRefresh)
	} else {
		logger.Info("PATCHLINE_OSV_ECOSYSTEMS=off: SBOMs uploaded to Patchline are stored but not matched")
	}

	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); proc.Run(ctx) }()
	go func() { defer workers.Done(); sla.Run(ctx) }()
	go func() { defer workers.Done(); notifier.Run(ctx) }()
	if osvJob != nil {
		workers.Add(1)
		go func() { defer workers.Done(); osvJob.Run(ctx) }()
	}

	authn, err := newAuthenticator(ctx, cfg, st, logger)
	if err != nil {
		return err
	}
	webOpts := web.Options{Store: st, Inventory: inv, DTUIURL: cfg.DependencyTrackUIURL, Version: version, Logger: logger,
		OnChange: func() { sla.Wake(); notifier.Wake() }, PublicURL: cfg.PublicURL,
		EnvWebhookToken: cfg.WebhookToken, EnvGiteaSecret: cfg.GiteaWebhookSecret,
		Actions: st, AuthEnabled: true, SSO: authn.SSO(), LocalAdmin: authn.Local(), Impact: st}
	if dt != nil {
		webOpts.DT = dt
	}
	ui, err := web.New(webOpts)
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
			Secrets:      store.WebhookSecrets{Store: st, EnvToken: cfg.WebhookToken, EnvGitea: cfg.GiteaWebhookSecret}.Current,
			Auth:         authn,
			Impact:       st,
			Snapshots:    st,
			Version:      version,
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

// newAuthenticator sets up sign-in: the local admin (created as
// admin/admin on first start) and, when configured, OIDC.
func newAuthenticator(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) (*auth.Authenticator, error) {
	policy, err := auth.LoadPolicy(cfg.AccessPolicyPath)
	if err != nil {
		return nil, err
	}
	opts := auth.Options{LocalAdmin: cfg.LocalAdmin, AllowAnonymous: cfg.AllowAnonymous, PublicURL: cfg.PublicURL, SessionTTL: cfg.SessionTTL}
	if cfg.OIDCEnabled() {
		opts.OIDC = &auth.Config{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
			Scopes: cfg.OIDCScopes, GroupsClaims: cfg.OIDCGroupsClaims}
	}
	if cfg.LocalAdmin {
		hash, err := auth.HashPassword(auth.DefaultPassword)
		if err != nil {
			return nil, err
		}
		created, err := st.EnsureLocalAccount(ctx, auth.AdminUser, hash)
		if err != nil {
			return nil, err
		}
		acct, err := st.GetLocalAccount(ctx, auth.AdminUser)
		if err != nil {
			return nil, err
		}
		if created || acct.MustChange {
			logger.Warn("local admin still has the default password: sign in as admin / admin and change it before exposing Patchline",
				"created", created)
		}
	}
	a, err := auth.New(ctx, opts, policy, st, logger)
	if err != nil {
		return nil, err
	}
	summary := policy.Summary()
	if cfg.LocalAdmin {
		summary = "admin (local): all permissions; " + summary
	}
	logger.Info("sign-in", "local_admin", cfg.LocalAdmin, "oidc_issuer", cfg.OIDCIssuer, "anonymous_read", cfg.AllowAnonymous,
		"access_policy", cfg.AccessPolicyPath, "policy", summary)
	if cfg.AllowAnonymous {
		logger.Warn("PATCHLINE_ALLOW_ANONYMOUS=true: anyone who can reach Patchline can read findings")
	}
	if cfg.PublicURL == "" {
		logger.Info("PATCHLINE_PUBLIC_URL not set: session cookies are Secure only on direct TLS; set it to the https URL when a proxy terminates TLS")
	}
	return a, nil
}

// resetAdminPassword sets the local admin back to admin/admin (to be
// changed at the next sign-in) and ends its sessions. It is the way back in
// when the password is lost: it needs access to the database.
func resetAdminPassword(cfg config.Config) error {
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := store.Migrate(ctx, db); err != nil {
		return err
	}
	hash, err := auth.HashPassword(auth.DefaultPassword)
	if err != nil {
		return err
	}
	if err := store.New(db).SetLocalPassword(ctx, auth.AdminUser, hash, true, store.Actor{Subject: "cli", Name: "reset-admin-password"}, ""); err != nil {
		return err
	}
	fmt.Println("The local admin password is now \"admin\". Sign in as admin and choose a new one.")
	return nil
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
