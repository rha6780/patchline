package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/source/gitea"
	"github.com/rha6780/patchline/internal/store"
)

// MaxWebhookBody bounds a webhook payload. BOM notifications embed the
// whole BOM, so this is generous.
const MaxWebhookBody = 32 << 20

// Pinger reports whether a dependency (such as the database) is reachable.
type Pinger interface {
	PingContext(ctx context.Context) error
}

// Inbox stores raw webhook deliveries.
type Inbox interface {
	InsertInbox(ctx context.Context, source, eventType, dedupKey string, payload []byte) (int64, bool, error)
}

// Findings reads findings for the API.
type Findings interface {
	ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	FindingEvents(ctx context.Context, findingID int64) ([]store.FindingEvent, error)
	FindingPullRequests(ctx context.Context, findingID int64) ([]store.PullRequestLink, error)
}

// Options wires the handler's dependencies.
type Options struct {
	DB        Pinger
	Inbox     Inbox
	Findings  Findings
	Inventory *inventory.Inventory
	// WebhookToken, when set, must be sent as ?token=... or
	// "Authorization: Bearer ...". Leave empty only for local development.
	WebhookToken string
	// GiteaSecret, when set, is the webhook secret configured in Gitea /
	// Forgejo / GitHub; requests must carry a valid HMAC signature. When
	// empty, the Gitea webhook falls back to WebhookToken.
	GiteaSecret string
	// Secrets, when set, returns the token and Git webhook secret in
	// effect for each request (settings changed in the UI replace
	// WebhookToken and GiteaSecret).
	Secrets func(ctx context.Context) (token, giteaSecret string, err error)
	// Auth signs people in and guards the UI and the API. Nil leaves them
	// open and read-only. Webhooks authenticate with their own secrets.
	Auth *auth.Authenticator
	// UI, when set, serves every path not handled above (the web pages).
	UI http.Handler
	// OnInbox is called after a new delivery is stored (to wake the processor).
	OnInbox func()
	Logger  *slog.Logger
}

// New returns the root HTTP handler.
//
//	GET  /healthz                      liveness: the process is up
//	GET  /readyz                       readiness: the database answers
//	POST /webhooks/dependency-track    Dependency-Track outbound webhook
//	POST /webhooks/gitea               Gitea / Forgejo / GitHub pull_request webhook
//	POST /ingest/sbom                  SBOM upload for Patchline's own detection
//	GET  /api/v1/findings              findings with owners (?service=&environment=&state=&assignee=&limit=)
//	GET  /api/v1/findings/{id}/events  a finding's timeline
//	GET  /api/v1/findings/{id}/pull-requests  linked pull requests
func New(o Options) http.Handler {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Inventory == nil {
		o.Inventory = inventory.Empty()
	}
	if o.OnInbox == nil {
		o.OnInbox = func() {}
	}
	h := &handler{o: o}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", h.readyz)
	if o.Inbox != nil {
		mux.HandleFunc("POST /webhooks/dependency-track", h.dependencyTrackWebhook)
		mux.HandleFunc("POST /webhooks/gitea", h.giteaWebhook)
		mux.HandleFunc("POST /ingest/sbom", h.ingestSBOM)
	}
	if o.Findings != nil {
		mux.HandleFunc("GET /api/v1/findings", h.listFindings)
		mux.HandleFunc("GET /api/v1/findings/{id}/events", h.findingEvents)
		mux.HandleFunc("GET /api/v1/findings/{id}/pull-requests", h.findingPullRequests)
	}
	if o.UI != nil {
		mux.Handle("/", o.UI)
	}
	o.Auth.Routes(mux)
	return securityHeaders(o.Auth.Middleware(mux))
}

// contentSecurityPolicy fits the UI: server-rendered pages, one stylesheet,
// no scripts, forms that post to Patchline only, and no framing (the
// approve buttons must not be clickable from another site).
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; img-src 'self' data:; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

type handler struct{ o Options }

func (h *handler) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.o.DB.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "database": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}

// secrets returns the webhook token and Git webhook secret in effect.
func (h *handler) secrets(r *http.Request) (token, gitea string, err error) {
	if h.o.Secrets == nil {
		return h.o.WebhookToken, h.o.GiteaSecret, nil
	}
	return h.o.Secrets(r.Context())
}

func (h *handler) authorized(r *http.Request, want string) bool {
	if want == "" {
		return true
	}
	got := r.URL.Query().Get("token")
	if auth := r.Header.Get("Authorization"); got == "" && strings.HasPrefix(auth, "Bearer ") {
		got = strings.TrimPrefix(auth, "Bearer ")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (h *handler) dependencyTrackWebhook(w http.ResponseWriter, r *http.Request) {
	token, _, err := h.secrets(r)
	if err != nil {
		h.o.Logger.Error("load webhook secrets", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load webhook settings")
		return
	}
	if !h.authorized(r, token) {
		writeError(w, http.StatusUnauthorized, "invalid or missing webhook token")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	n, err := dependencytrack.ParseNotification(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sum := sha256.Sum256(body)
	id, inserted, err := h.o.Inbox.InsertInbox(r.Context(), "dependencytrack", n.Group, hex.EncodeToString(sum[:]), body)
	if err != nil {
		h.o.Logger.Error("store webhook", "err", err)
		writeError(w, http.StatusInternalServerError, "could not store delivery")
		return
	}
	if inserted {
		h.o.OnInbox()
	}
	h.o.Logger.Debug("dependency-track webhook stored", "inbox_id", id, "group", n.Group, "duplicate", !inserted)
	writeJSON(w, http.StatusAccepted, map[string]any{"inbox_id": id, "duplicate": !inserted})
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxWebhookBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		} else {
			writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		}
		return nil, false
	}
	return body, true
}

func (h *handler) giteaWebhook(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	token, secret, err := h.secrets(r)
	if err != nil {
		h.o.Logger.Error("load webhook secrets", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load webhook settings")
		return
	}
	if secret != "" {
		if !gitea.VerifySignature(r.Header, body, secret) {
			writeError(w, http.StatusUnauthorized, "invalid or missing webhook signature")
			return
		}
	} else if !h.authorized(r, token) {
		writeError(w, http.StatusUnauthorized, "invalid or missing webhook token")
		return
	}

	event := gitea.EventType(r.Header)
	if event != gitea.EventPullRequest {
		// Ping and other events are acknowledged and dropped.
		writeJSON(w, http.StatusAccepted, map[string]any{"ignored": true, "event": event})
		return
	}
	if _, err := gitea.ParsePullRequestEvent(body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	key := gitea.DeliveryID(r.Header)
	if key == "" {
		sum := sha256.Sum256(body)
		key = hex.EncodeToString(sum[:])
	}
	id, inserted, err := h.o.Inbox.InsertInbox(r.Context(), "gitea", event, key, body)
	if err != nil {
		h.o.Logger.Error("store webhook", "err", err)
		writeError(w, http.StatusInternalServerError, "could not store delivery")
		return
	}
	if inserted {
		h.o.OnInbox()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"inbox_id": id, "duplicate": !inserted})
}

func (h *handler) findingPullRequests(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	prs, err := h.o.Findings.FindingPullRequests(r.Context(), id)
	if err != nil {
		h.o.Logger.Error("finding pull requests", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load pull requests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pull_requests": prs})
}

// findingView adds inventory context to a stored finding.
type findingView struct {
	store.Finding
	Owners       []string `json:"owners"`
	SlackChannel string   `json:"slack_channel,omitempty"`
	Exposure     string   `json:"exposure,omitempty"`
}

func (h *handler) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	list, err := h.o.Findings.ListFindings(r.Context(), store.FindingFilter{
		Service: q.Get("service"), Environment: q.Get("environment"), State: q.Get("state"), Assignee: q.Get("assignee"), Limit: limit,
	})
	if err != nil {
		h.o.Logger.Error("list findings", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list findings")
		return
	}
	out := make([]findingView, 0, len(list))
	for _, f := range list {
		v := findingView{Finding: f, Owners: []string{}}
		if f.Registered {
			if s, ok := h.o.Inventory.Service(f.Service); ok {
				v.Owners = append(v.Owners, s.Owners...)
				v.SlackChannel = s.SlackChannel
				v.Exposure = string(s.Exposure)
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out})
}

func (h *handler) findingEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	events, err := h.o.Findings.FindingEvents(r.Context(), id)
	if err != nil {
		h.o.Logger.Error("finding events", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
