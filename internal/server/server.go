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

	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
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
	// OnInbox is called after a new delivery is stored (to wake the processor).
	OnInbox func()
	Logger  *slog.Logger
}

// New returns the root HTTP handler.
//
//	GET  /healthz                      liveness: the process is up
//	GET  /readyz                       readiness: the database answers
//	POST /webhooks/dependency-track    Dependency-Track outbound webhook
//	GET  /api/v1/findings              findings with owners (?service=&environment=&state=&limit=)
//	GET  /api/v1/findings/{id}/events  a finding's timeline
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
	}
	if o.Findings != nil {
		mux.HandleFunc("GET /api/v1/findings", h.listFindings)
		mux.HandleFunc("GET /api/v1/findings/{id}/events", h.findingEvents)
	}
	return mux
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

func (h *handler) authorized(r *http.Request) bool {
	want := h.o.WebhookToken
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
	if !h.authorized(r) {
		writeError(w, http.StatusUnauthorized, "invalid or missing webhook token")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxWebhookBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		}
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
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
		Service: q.Get("service"), Environment: q.Get("environment"), State: q.Get("state"), Limit: limit,
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
