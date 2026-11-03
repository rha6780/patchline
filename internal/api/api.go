// Package api serves Patchline's JSON API under /api/v1, for tools and
// scripts. Its contract is openapi.yaml (served at /api/v1/openapi.yaml);
// responses use this package's types, not the store's.
//
// Authentication is done before these handlers: the auth middleware lets
// requests through with a session or an API token holding findings.read.
package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/rha6780/patchline/internal/impact"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/store"
)

// OpenAPI is the API description.
//
//go:embed openapi.yaml
var OpenAPI []byte

// Findings reads findings.
type Findings interface {
	ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	FindingEvents(ctx context.Context, findingID int64) ([]store.FindingEvent, error)
	FindingPullRequests(ctx context.Context, findingID int64) ([]store.PullRequestLink, error)
}

// Options wires the API's dependencies. Endpoints whose dependency is nil
// are not served.
type Options struct {
	Findings  Findings
	Inventory *inventory.Inventory
	// Impact serves component search and vulnerability impact.
	Impact impact.Store
	// Snapshots serves VEX for the SBOMs uploaded to Patchline.
	Snapshots Snapshots
	// Version is Patchline's version, named as the tool in VEX documents.
	Version string
	Logger  *slog.Logger
}

// Register adds the API routes to mux.
//
//	GET /api/v1/openapi.yaml                  this API's description
//	GET /api/v1/findings                      findings with owners (?q=&service=&environment=&branch=&repository=&severity=&state=&assignee=&open=1&limit=)
//	GET /api/v1/findings/{id}/events          a finding's timeline
//	GET /api/v1/findings/{id}/pull-requests   linked pull requests
//	GET /api/v1/components                    where packages are used (?q=&ecosystem=&version=&limit=)
//	GET /api/v1/vulnerabilities/{id}          what a CVE / GHSA affects
//	GET /api/v1/vex                           CycloneDX VEX of a project version (?project=&version=)
func Register(mux *http.ServeMux, o Options) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Inventory == nil {
		o.Inventory = inventory.Empty()
	}
	h := &handler{o: o}
	mux.HandleFunc("GET /api/v1/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(OpenAPI)
	})
	if o.Findings != nil {
		mux.HandleFunc("GET /api/v1/findings", h.listFindings)
		mux.HandleFunc("GET /api/v1/findings/{id}/events", h.findingEvents)
		mux.HandleFunc("GET /api/v1/findings/{id}/pull-requests", h.findingPullRequests)
	}
	if o.Snapshots != nil {
		mux.HandleFunc("GET /api/v1/vex", h.vex)
	}
	if o.Impact != nil {
		mux.HandleFunc("GET /api/v1/components", h.components)
		mux.HandleFunc("GET /api/v1/vulnerabilities/{id}", h.vulnerability)
	}
	// Unknown API paths answer in JSON rather than falling through to
	// the web pages.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "no such API endpoint; see /api/v1/openapi.yaml")
	})
}

type handler struct{ o Options }

func (h *handler) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	list, err := h.o.Findings.ListFindings(r.Context(), store.FindingFilter{
		Service: q.Get("service"), Environment: q.Get("environment"), State: q.Get("state"), Assignee: q.Get("assignee"), Limit: limit,
		Severity: q.Get("severity"), Branch: q.Get("branch"), Repository: q.Get("repository"), Query: q.Get("q"),
		Open: q.Get("open") == "1",
	})
	if err != nil {
		h.fail(w, "list findings", err, "could not list findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": newFindings(list, h.o.Inventory)})
}

func (h *handler) findingEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := findingID(w, r)
	if !ok {
		return
	}
	events, err := h.o.Findings.FindingEvents(r.Context(), id)
	if err != nil {
		h.fail(w, "finding events", err, "could not load events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": newEvents(events)})
}

func (h *handler) findingPullRequests(w http.ResponseWriter, r *http.Request) {
	id, ok := findingID(w, r)
	if !ok {
		return
	}
	prs, err := h.o.Findings.FindingPullRequests(r.Context(), id)
	if err != nil {
		h.fail(w, "finding pull requests", err, "could not load pull requests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pull_requests": newPullRequests(prs)})
}

func (h *handler) components(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	uses, err := impact.Search(r.Context(), h.o.Impact, impact.Query{Text: q.Get("q"), Ecosystem: q.Get("ecosystem"),
		Version: q.Get("version"), Limit: limit})
	if errors.Is(err, impact.ErrBadConstraint) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		h.fail(w, "search components", err, "could not search components")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": newComponentUses(uses)})
}

func (h *handler) vulnerability(w http.ResponseWriter, r *http.Request) {
	rep, err := impact.Analyze(r.Context(), h.o.Impact, r.PathValue("id"))
	if err != nil {
		h.fail(w, "vulnerability impact", err, "could not analyze the vulnerability")
		return
	}
	writeJSON(w, http.StatusOK, newImpact(rep, h.o.Inventory))
}

func findingID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return 0, false
	}
	return id, true
}

// fail logs err and answers 500 with msg.
func (h *handler) fail(w http.ResponseWriter, what string, err error, msg string) {
	h.o.Logger.Error(what, "err", err)
	writeError(w, http.StatusInternalServerError, msg)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
