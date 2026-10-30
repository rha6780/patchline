package web

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/impact"
	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
)

// vulnID recognizes vulnerability ids typed into the component search:
// CVE-2021-44228, GHSA-jfh8-c2jp-5v3q, PYSEC-2021-1, GO-2022-0001, ...
var vulnID = regexp.MustCompile(`^(?i:CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|[A-Z]+-\d{4}-[0-9A-Za-z-]+)$`)

// components searches the stored SBOM snapshots: where is a package used,
// in which versions. A vulnerability id goes to its impact page.
func (u *UI) components(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if id := strings.TrimSpace(q.Get("q")); vulnID.MatchString(id) {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") || strings.HasPrefix(strings.ToUpper(id), "GHSA-") {
			id = strings.ToUpper(id[:4]) + id[4:]
		}
		http.Redirect(w, r, "/vulnerabilities/"+url.PathEscape(id), http.StatusSeeOther)
		return
	}
	query := impact.Query{Text: strings.TrimSpace(q.Get("q")), Ecosystem: q.Get("ecosystem"),
		Version: strings.TrimSpace(q.Get("version")), Limit: 1000}
	data := map[string]any{"Q": query, "Ecosystems": purl.Ecosystems, "Searched": query.Text != "" || query.Ecosystem != ""}
	uses, err := impact.Search(r.Context(), u.o.Impact, query)
	switch {
	case errors.Is(err, impact.ErrBadConstraint):
		data["BadVersion"] = true
	case err != nil:
		u.fail(w, err)
		return
	default:
		data["Uses"] = uses
		data["Capped"] = len(uses) == query.Limit
		packages := map[string]bool{}
		for _, use := range uses {
			packages[use.Ecosystem+"\x00"+use.Package+"\x00"+use.Name] = true
		}
		data["Packages"] = len(packages)
	}
	u.render(w, r, "components", "ui.components", data)
}

// vulnerability shows what a CVE or advisory affects.
func (u *UI) vulnerability(w http.ResponseWriter, r *http.Request) {
	rep, err := impact.Analyze(r.Context(), u.o.Impact, r.PathValue("id"))
	if err != nil {
		u.fail(w, err)
		return
	}
	open := 0
	for _, f := range rep.Findings {
		if finding.State(f.State).Open() {
			open++
		}
	}
	u.render(w, r, "vulnerability", rep.ID, map[string]any{"R": rep, "OpenFindings": open,
		"Now": store.FormatTime(u.o.Now())})
}
