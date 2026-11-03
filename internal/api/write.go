package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/rha6780/patchline/internal/app"
	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/i18n"
	"github.com/rha6780/patchline/internal/store"
)

// Requests reads exception requests.
type Requests interface {
	GetRequest(ctx context.Context, id int64) (store.ExceptionRequest, error)
	ListRequests(ctx context.Context, f store.RequestFilter) ([]store.ExceptionRequest, error)
}

// Request is an exception request on a finding.
type Request struct {
	ID              int64   `json:"id"`
	FindingID       int64   `json:"finding_id"`
	Kind            string  `json:"kind"`
	Reason          string  `json:"reason"`
	Justification   string  `json:"justification,omitempty"`
	RequestedDue    *string `json:"requested_due,omitempty"`
	RequestedBy     string  `json:"requested_by"`
	RequestedByName string  `json:"requested_by_name,omitempty"`
	RequestedAt     string  `json:"requested_at"`
	Status          string  `json:"status"`
	DecidedBy       string  `json:"decided_by,omitempty"`
	DecidedByName   string  `json:"decided_by_name,omitempty"`
	DecidedAt       *string `json:"decided_at,omitempty"`
	DecisionNote    string  `json:"decision_note,omitempty"`
}

func newRequest(r store.ExceptionRequest) Request {
	return Request{ID: r.ID, FindingID: r.FindingID, Kind: r.Kind, Reason: r.Reason, Justification: r.Justification,
		RequestedDue: r.RequestedDue, RequestedBy: r.RequestedBy, RequestedByName: r.RequestedByName,
		RequestedAt: r.RequestedAt, Status: r.Status, DecidedBy: r.DecidedBy, DecidedByName: r.DecidedByName,
		DecidedAt: r.DecidedAt, DecisionNote: r.DecisionNote}
}

// maxWriteBody bounds a write request's JSON body.
const maxWriteBody = 64 << 10

// assign sets or clears a finding's assignee.
//
//	PUT /api/v1/findings/{id}/assignee   {"assignee": "bob@example.com"}   ("" clears)
func (h *handler) assign(w http.ResponseWriter, r *http.Request) {
	id, ok := findingID(w, r)
	if !ok {
		return
	}
	var body struct {
		Assignee *string `json:"assignee"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Assignee == nil {
		writeError(w, http.StatusBadRequest, `"assignee" is required ("" clears it)`)
		return
	}
	if err := h.o.App.Assign(r.Context(), auth.FromContext(r.Context()), id, *body.Assignee); err != nil {
		h.refused(w, err)
		return
	}
	f, err := h.o.Findings.GetFinding(r.Context(), id)
	if err != nil {
		h.fail(w, "get finding", err, "could not load the finding")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding": newFinding(f, h.o.Inventory)})
}

// createRequest asks an approver for an exception.
//
//	POST /api/v1/findings/{id}/requests   {"kind": "...", "reason": "...", "justification": "...", "due": "YYYY-MM-DD"}
func (h *handler) createRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := findingID(w, r)
	if !ok {
		return
	}
	var body struct {
		Kind          string `json:"kind"`
		Reason        string `json:"reason"`
		Justification string `json:"justification"`
		Due           string `json:"due"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	rid, err := h.o.App.Request(r.Context(), auth.FromContext(r.Context()), app.RequestInput{FindingID: id,
		Kind: body.Kind, Reason: body.Reason, Justification: body.Justification, Due: body.Due})
	if err != nil {
		h.refused(w, err)
		return
	}
	h.writeRequest(w, r, rid, http.StatusCreated)
}

func (h *handler) listRequests(w http.ResponseWriter, r *http.Request) {
	id, ok := findingID(w, r)
	if !ok {
		return
	}
	list, err := h.o.Requests.ListRequests(r.Context(), store.RequestFilter{FindingID: id})
	if err != nil {
		h.fail(w, "list requests", err, "could not list requests")
		return
	}
	out := make([]Request, 0, len(list))
	for _, rq := range list {
		out = append(out, newRequest(rq))
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// cancelRequest withdraws a pending request; only its requester can.
//
//	POST /api/v1/requests/{id}/cancel   {"note": "..."} (optional)
func (h *handler) cancelRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request id")
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &body) {
		return
	}
	if _, err := h.o.App.Decide(r.Context(), auth.FromContext(r.Context()), id, app.Cancel, body.Note); err != nil {
		h.refused(w, err)
		return
	}
	h.writeRequest(w, r, id, http.StatusOK)
}

func (h *handler) writeRequest(w http.ResponseWriter, r *http.Request, id int64, status int) {
	rq, err := h.o.Requests.GetRequest(r.Context(), id)
	if err != nil {
		h.fail(w, "get request", err, "could not load the request")
		return
	}
	writeJSON(w, status, map[string]any{"request": newRequest(rq)})
}

// refused answers a change the service did not make, with the reason as
// "code" and the same message the web pages show.
func (h *handler) refused(w http.ResponseWriter, err error) {
	var e *app.Error
	if !errors.As(err, &e) {
		h.fail(w, "change", err, "could not make the change")
		return
	}
	status := http.StatusBadRequest
	switch e.Code {
	case "forbidden":
		status = http.StatusForbidden
	case "not_found":
		status = http.StatusNotFound
	case "closed", "pending", "not_pending", "no_dt":
		status = http.StatusConflict
	case "dt_write":
		status = http.StatusBadGateway
		h.o.Logger.Warn("change refused", "code", e.Code, "err", e.Err)
	}
	msg := e.Code
	if key := "ui.err." + e.Code; i18n.Has(key) {
		msg = i18n.Lang("en").T(key)
	}
	writeJSON(w, status, map[string]string{"error": msg, "code": e.Code})
}

// readJSON decodes a JSON object body, rejecting unknown fields.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWriteBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		msg := "invalid JSON body: " + err.Error()
		if errors.Is(err, io.EOF) {
			msg = "a JSON body is required"
		}
		writeError(w, http.StatusBadRequest, msg)
		return false
	}
	return true
}
