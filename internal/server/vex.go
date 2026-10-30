package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/sbom"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/vex"
)

// Snapshots reads the SBOM snapshots uploaded to Patchline and their findings.
type Snapshots interface {
	SourceProjects(ctx context.Context, source string) ([]store.SourceProject, error)
	SnapshotFindings(ctx context.Context, source, project string) ([]store.Finding, error)
	Components(ctx context.Context, source, project string) ([]store.Component, error)
}

// vex serves the CycloneDX VEX of a project version: every vulnerability
// its latest SBOM reports, with the decision on it.
func (h *handler) vex(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name, version := strings.TrimSpace(q.Get("project")), strings.TrimSpace(q.Get("version"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "project is required")
		return
	}
	ctx := r.Context()
	projects, err := h.o.Snapshots.SourceProjects(ctx, finding.SourcePatchline)
	if err != nil {
		h.o.Logger.Error("vex projects", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load the project")
		return
	}
	id := sbom.ProjectID(name, version)
	var project *store.SourceProject
	for i := range projects {
		if projects[i].ProjectID == id {
			project = &projects[i]
		}
	}
	if project == nil {
		writeError(w, http.StatusNotFound, "no SBOM uploaded to Patchline for this project and version")
		return
	}
	findings, err := h.o.Snapshots.SnapshotFindings(ctx, finding.SourcePatchline, id)
	if err != nil {
		h.o.Logger.Error("vex findings", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load findings")
		return
	}
	comps, err := h.o.Snapshots.Components(ctx, finding.SourcePatchline, id)
	if err != nil {
		h.o.Logger.Error("vex components", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load components")
		return
	}
	doc := vex.Build(*project, findings, comps, h.o.Version, time.Now())
	if q.Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(name+"-"+version)+`.vex.json"`)
	}
	writeJSON(w, http.StatusOK, doc)
}

// safeFilename keeps letters, digits, dots, dashes and underscores.
func safeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
}
