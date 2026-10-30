package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/sbom"
)

// ingestSBOM receives an SBOM for Patchline's own detection.
//
//	POST /ingest/sbom?project=storefront-api&version=main   (JSON body)
//	POST /ingest/sbom  -F project=... -F version=... -F bom=@bom.json  (multipart)
//
// It authenticates with the webhook token, checks that the document is a
// readable CycloneDX or SPDX JSON SBOM, and stores it in the inbox; the
// processor matches it.
func (h *handler) ingestSBOM(w http.ResponseWriter, r *http.Request) {
	token, _, err := h.secrets(r)
	if err != nil {
		h.o.Logger.Error("load webhook secrets", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load webhook settings")
		return
	}
	// CI authenticates with the shared webhook token or an API token
	// holding sbom.upload.
	byToken, err := h.o.Auth.RequestAllows(r, auth.SBOMUpload)
	if err != nil {
		h.o.Logger.Error("check api token", "err", err)
		writeError(w, http.StatusInternalServerError, "could not check the token")
		return
	}
	if !byToken && !h.authorized(r, token) {
		writeError(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	project, version := r.URL.Query().Get("project"), r.URL.Query().Get("version")
	var body []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, MaxWebhookBody)
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			writeError(w, http.StatusBadRequest, "read form: "+err.Error())
			return
		}
		if v := r.FormValue("project"); v != "" {
			project = v
		}
		if v := r.FormValue("version"); v != "" {
			version = v
		}
		f, _, err := r.FormFile("bom")
		if err != nil {
			writeError(w, http.StatusBadRequest, `missing "bom" file`)
			return
		}
		body, err = io.ReadAll(f)
		f.Close()
		if err != nil {
			writeError(w, http.StatusBadRequest, "read bom: "+err.Error())
			return
		}
	} else {
		var ok bool
		if body, ok = readBody(w, r); !ok {
			return
		}
	}
	project, version = strings.TrimSpace(project), strings.TrimSpace(version)
	if project == "" || len(project) > 255 || len(version) > 255 {
		writeError(w, http.StatusBadRequest, "project is required (and project and version at most 255 characters)")
		return
	}
	doc, err := sbom.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	received := time.Now().UTC().Format(time.RFC3339)
	payload, err := json.Marshal(sbom.Upload{Project: project, Version: version, ReceivedAt: received, BOM: body})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store the upload")
		return
	}
	// Every upload is a new snapshot, even of an identical SBOM (uploading
	// the old one again reopens what it fixed); only a retry within the
	// same second counts as a duplicate.
	sum := sha256.Sum256(append([]byte(project+"\x00"+version+"\x00"+received+"\x00"), body...))
	id, inserted, err := h.o.Inbox.InsertInbox(r.Context(), finding.SourcePatchline, "sbom", hex.EncodeToString(sum[:]), payload)
	if err != nil {
		h.o.Logger.Error("store sbom", "err", err)
		writeError(w, http.StatusInternalServerError, "could not store the upload")
		return
	}
	if inserted {
		h.o.OnInbox()
	}
	h.o.Logger.Debug("sbom stored", "inbox_id", id, "project", project, "version", version,
		"format", doc.Format, "components", len(doc.Components), "duplicate", !inserted)
	writeJSON(w, http.StatusAccepted, map[string]any{"inbox_id": id, "duplicate": !inserted,
		"format": doc.Format, "components": len(doc.Components), "without_purl": doc.WithoutPURL})
}
