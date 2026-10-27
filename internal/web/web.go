// Package web serves Patchline's read-only UI: an overview, per-service
// environment comparison, finding timelines and integration health.
//
// Pages are rendered on the server with html/template; there is no
// JavaScript. Decisions stay in Dependency-Track and configuration stays
// in Git, so the UI only links out to them. Put it behind your
// authenticating proxy: it has no login of its own.
package web

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Store is what the UI reads.
type Store interface {
	ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	GetFinding(ctx context.Context, id int64) (store.Finding, error)
	FindingEvents(ctx context.Context, findingID int64) ([]store.FindingEvent, error)
	FindingPullRequests(ctx context.Context, findingID int64) ([]store.PullRequestLink, error)
	ListSourceProjects(ctx context.Context) ([]store.SourceProjectStatus, error)
	ListInboxProblems(ctx context.Context, limit int) ([]store.InboxProblem, error)
	ListNotificationProblems(ctx context.Context, limit int) ([]store.NotificationProblem, error)
}

// Options configures the UI.
type Options struct {
	Store     Store
	Inventory *inventory.Inventory
	// DTUIURL is the Dependency-Track frontend, for links.
	DTUIURL string
	Version string
	Logger  *slog.Logger
	// Now returns the current time (default time.Now).
	Now func() time.Time
}

// UI is the web handler.
type UI struct {
	o     Options
	pages map[string]*template.Template
	mux   *http.ServeMux
}

// New parses the templates and returns the UI.
func New(o Options) (*UI, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Inventory == nil {
		o.Inventory = inventory.Empty()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	u := &UI{o: o, pages: map[string]*template.Template{}, mux: http.NewServeMux()}
	for _, page := range []string{"overview", "findings", "finding", "service", "integrations"} {
		t, err := template.New("layout.html").Funcs(u.funcs()).ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s template: %w", page, err)
		}
		u.pages[page] = t
	}

	static, _ := fs.Sub(staticFS, "static")
	u.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	u.mux.HandleFunc("GET /{$}", u.overview)
	u.mux.HandleFunc("GET /findings", u.findings)
	u.mux.HandleFunc("GET /findings/{id}", u.finding)
	u.mux.HandleFunc("GET /services/{name}", u.service)
	u.mux.HandleFunc("GET /integrations", u.integrations)
	return u, nil
}

func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) { u.mux.ServeHTTP(w, r) }

func (u *UI) render(w http.ResponseWriter, page, title string, data map[string]any) {
	data["Title"] = title
	data["Page"] = page
	data["Version"] = u.o.Version
	data["DTUIURL"] = u.o.DTUIURL
	var buf strings.Builder
	if err := u.pages[page].Execute(&buf, data); err != nil {
		u.o.Logger.Error("render page", "page", page, "err", err)
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(buf.String()))
}

func (u *UI) fail(w http.ResponseWriter, err error) {
	u.o.Logger.Error("ui query", "err", err)
	http.Error(w, "could not load data", http.StatusInternalServerError)
}

// ---- overview ---------------------------------------------------------

type serviceRow struct {
	Name       string
	Registered bool
	Counts     map[string]int
	Open       int
}

func (u *UI) overview(w http.ResponseWriter, r *http.Request) {
	all, err := u.o.Store.ListFindings(r.Context(), store.FindingFilter{Limit: 10000})
	if err != nil {
		u.fail(w, err)
		return
	}
	now := u.o.Now()
	var (
		open, critHigh, awaiting, resolved30 int
		mttrSum                              time.Duration
		mttrN                                int
		attention, recent                    []store.Finding
	)
	rows := map[string]*serviceRow{}
	for _, f := range all {
		st := finding.State(f.State)
		if st.Open() {
			open++
			if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
				critHigh++
				attention = append(attention, f)
			}
			if st == finding.StateAwaitingVerification {
				awaiting++
			}
			row, ok := rows[f.Service]
			if !ok {
				row = &serviceRow{Name: f.Service, Registered: f.Registered, Counts: map[string]int{}}
				rows[f.Service] = row
			}
			row.Counts[f.Severity]++
			row.Open++
		}
		if st == finding.StateResolved && f.ResolvedAt != nil {
			recent = append(recent, f)
			if t, err := parseTime(*f.ResolvedAt); err == nil {
				if now.Sub(t) <= 30*24*time.Hour {
					resolved30++
				}
				if first, err := parseTime(f.FirstSeenAt); err == nil && t.After(first) {
					mttrSum += t.Sub(first)
					mttrN++
				}
			}
		}
	}

	services := make([]*serviceRow, 0, len(rows))
	for _, row := range rows {
		services = append(services, row)
	}
	sort.Slice(services, func(i, j int) bool {
		a, b := services[i], services[j]
		for _, sev := range severities {
			if a.Counts[sev] != b.Counts[sev] {
				return a.Counts[sev] > b.Counts[sev]
			}
		}
		return a.Name < b.Name
	})
	sort.SliceStable(attention, func(i, j int) bool { return attention[i].FirstSeenAt < attention[j].FirstSeenAt })
	sort.SliceStable(attention, func(i, j int) bool {
		return finding.SeverityRank(attention[i].Severity) < finding.SeverityRank(attention[j].Severity)
	})
	sort.Slice(recent, func(i, j int) bool { return *recent[i].ResolvedAt > *recent[j].ResolvedAt })

	mttr := "—"
	if mttrN > 0 {
		mttr = humanDuration(mttrSum / time.Duration(mttrN))
	}
	u.render(w, "overview", "Overview", map[string]any{
		"Open": open, "CritHigh": critHigh, "Awaiting": awaiting, "Resolved30": resolved30, "MTTR": mttr,
		"Services": services, "Severities": severities,
		"Attention": limit(attention, 10), "Recent": limit(recent, 10), "Total": len(all),
	})
}

// ---- findings list ----------------------------------------------------

func (u *UI) findings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FindingFilter{
		Service: q.Get("service"), Environment: q.Get("environment"),
		State: q.Get("state"), Severity: q.Get("severity"), Open: q.Get("open") == "1", Limit: 500,
	}
	list, err := u.o.Store.ListFindings(r.Context(), f)
	if err != nil {
		u.fail(w, err)
		return
	}
	u.render(w, "findings", "Findings", map[string]any{
		"Findings": list, "Filter": f, "Severities": severities, "States": states,
	})
}

// ---- finding detail ---------------------------------------------------

type timelineItem struct {
	Kind string
	At   string
	Text string
	Icon string
}

func (u *UI) finding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := u.o.Store.GetFinding(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		u.fail(w, err)
		return
	}
	events, err := u.o.Store.FindingEvents(r.Context(), id)
	if err != nil {
		u.fail(w, err)
		return
	}
	prs, err := u.o.Store.FindingPullRequests(r.Context(), id)
	if err != nil {
		u.fail(w, err)
		return
	}
	var timeline []timelineItem
	for _, e := range events {
		timeline = append(timeline, timelineItem{Kind: e.Kind, At: e.OccurredAt, Text: describe(e), Icon: eventIcon(e.Kind)})
	}
	var svc *inventory.Service
	if f.Registered {
		svc, _ = u.o.Inventory.Service(f.Service)
	}
	u.render(w, "finding", f.VulnID, map[string]any{
		"F": f, "Service": svc, "Timeline": timeline, "PRs": prs, "DTLink": u.dtLink(f),
	})
}

// ---- service ----------------------------------------------------------

type envRow struct {
	Component string
	Version   string
	VulnID    string
	Severity  string
	Cells     map[string]store.Finding
	Gap       bool // resolved somewhere but still open in another environment
}

func (u *UI) service(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	list, err := u.o.Store.ListFindings(r.Context(), store.FindingFilter{Service: name, Limit: 10000})
	if err != nil {
		u.fail(w, err)
		return
	}
	svc, registered := u.o.Inventory.Service(name)
	if !registered && len(list) == 0 {
		http.NotFound(w, r)
		return
	}

	envSet := map[string]bool{}
	rows := map[string]*envRow{}
	var keys []string
	for _, f := range list {
		envSet[f.Environment] = true
		key := f.ComponentName + "\x00" + f.VulnID
		row, ok := rows[key]
		if !ok {
			row = &envRow{Component: f.ComponentName, Version: f.ComponentVersion, VulnID: f.VulnID, Severity: f.Severity, Cells: map[string]store.Finding{}}
			rows[key] = row
			keys = append(keys, key)
		}
		if prev, dup := row.Cells[f.Environment]; !dup || prev.ID < f.ID {
			row.Cells[f.Environment] = f
		}
	}
	envs := orderEnvironments(envSet)
	var table []*envRow
	open := 0
	for _, k := range keys {
		row := rows[k]
		anyResolved, anyOpen := false, false
		for _, c := range row.Cells {
			st := finding.State(c.State)
			anyResolved = anyResolved || st == finding.StateResolved
			anyOpen = anyOpen || st.Open()
		}
		row.Gap = anyResolved && anyOpen
		if anyOpen {
			open++
		}
		table = append(table, row)
	}
	sort.SliceStable(table, func(i, j int) bool {
		if table[i].Gap != table[j].Gap {
			return table[i].Gap
		}
		return finding.SeverityRank(table[i].Severity) < finding.SeverityRank(table[j].Severity)
	})

	gaps := 0
	for _, row := range table {
		if row.Gap {
			gaps++
		}
	}
	u.render(w, "service", name, map[string]any{
		"Name": name, "Service": svc, "Registered": registered, "Envs": envs, "Rows": table,
		"Open": open, "Gaps": gaps,
	})
}

// ---- integrations -----------------------------------------------------

type missingProject struct {
	Service    string
	Repository string
	Project    string
}

func (u *UI) integrations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, err := u.o.Store.ListSourceProjects(ctx)
	if err != nil {
		u.fail(w, err)
		return
	}
	inbox, err := u.o.Store.ListInboxProblems(ctx, 50)
	if err != nil {
		u.fail(w, err)
		return
	}
	notes, err := u.o.Store.ListNotificationProblems(ctx, 50)
	if err != nil {
		u.fail(w, err)
		return
	}

	seen := map[string]bool{}
	for _, p := range projects {
		seen[p.Name] = true
	}
	var missing []missingProject
	for _, s := range u.o.Inventory.Services() {
		for _, repo := range s.Repositories {
			for _, proj := range repo.Projects() {
				if !seen[proj] {
					missing = append(missing, missingProject{Service: s.Name, Repository: repo.Repo, Project: proj})
				}
			}
		}
	}
	u.render(w, "integrations", "Integrations", map[string]any{
		"Projects": projects, "Missing": missing, "Inbox": inbox, "Notifications": notes,
		"Stale": staleBefore(u.o.Now()),
	})
}

// ---- helpers ----------------------------------------------------------

var severities = []string{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo, finding.SeverityUnassigned}

var states = []finding.State{
	finding.StateNeedsReview, finding.StateNew, finding.StateInProgress, finding.StateAwaitingVerification,
	finding.StateReopened, finding.StateResolved, finding.StateNotAffected, finding.StateRiskAccepted,
}

func (u *UI) funcs() template.FuncMap {
	return template.FuncMap{
		"stateLabel": notify.StateLabel,
		"stateClass": func(s string) string { return "state-" + strings.ReplaceAll(s, "_", "-") },
		"sevClass":   func(s string) string { return "sev-" + s },
		"component":  notify.Component,
		"verdict":    notify.VerdictLabel,
		"prRef":      notify.PRRef,
		"ts":         formatTS,
		"short":      shortSHA,
		"join":       strings.Join,
		"query":      url.QueryEscape,
		"pathEscape": url.PathEscape,
		"count":      func(m map[string]int, k string) int { return m[k] },
		"cell": func(m map[string]store.Finding, k string) *store.Finding {
			if f, ok := m[k]; ok {
				return &f
			}
			return nil
		},
		"isOpen":    func(s string) bool { return finding.State(s).Open() },
		"staleBOM":  func(lastBOM, before string) bool { return lastBOM == "" || lastBOM < before },
		"dtProject": func(uuid string) string { return u.dtProjectLink(uuid) },
		"rich":      rich,
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
	}
}

func (u *UI) dtProjectLink(uuid string) string {
	if u.o.DTUIURL == "" || uuid == "" {
		return ""
	}
	return strings.TrimRight(u.o.DTUIURL, "/") + "/projects/" + uuid
}

func (u *UI) dtLink(f store.Finding) string {
	if l := u.dtProjectLink(f.DTProjectUUID); l != "" {
		return l + "/findings"
	}
	return ""
}

func describe(e store.FindingEvent) string {
	if t := notify.EventText(e); t != "" {
		return t
	}
	switch e.Kind {
	case finding.EventDetected:
		return "Detected by Dependency-Track"
	case finding.EventNotified:
		var ev struct {
			Sink    string `json:"sink"`
			Channel string `json:"channel"`
		}
		_ = json.Unmarshal(e.Evidence, &ev)
		if ev.Sink != "" {
			return strings.TrimSpace("Posted to " + ev.Sink + " " + ev.Channel)
		}
		return "Notification posted"
	}
	return e.Kind
}

var (
	codeSpan = regexp.MustCompile("`([^`]+)`")
	urlText  = regexp.MustCompile(`https?://[^\s<>"']+`)
)

// rich renders event text: `code` spans and URLs become markup; everything
// else is escaped.
func rich(s string) template.HTML {
	var b strings.Builder
	for len(s) > 0 {
		c := codeSpan.FindStringSubmatchIndex(s)
		l := urlText.FindStringIndex(s)
		switch {
		case c == nil && l == nil:
			b.WriteString(template.HTMLEscapeString(s))
			s = ""
		case l == nil || (c != nil && c[0] < l[0]):
			b.WriteString(template.HTMLEscapeString(s[:c[0]]))
			b.WriteString("<code>" + template.HTMLEscapeString(s[c[2]:c[3]]) + "</code>")
			s = s[c[1]:]
		default:
			b.WriteString(template.HTMLEscapeString(s[:l[0]]))
			u := s[l[0]:l[1]]
			b.WriteString(`<a href="` + template.HTMLEscapeString(u) + `">` + template.HTMLEscapeString(u) + "</a>")
			s = s[l[1]:]
		}
	}
	return template.HTML(b.String())
}

func eventIcon(kind string) string {
	switch kind {
	case finding.EventDetected:
		return "🔍"
	case finding.EventNotified:
		return "📣"
	case finding.EventStateChanged:
		return "🔄"
	case finding.EventSeverityChanged:
		return "📈"
	case finding.EventPRLinked, finding.EventPRUpdated:
		return "🔧"
	case finding.EventPRMerged:
		return "🔀"
	case finding.EventPRClosed:
		return "🚫"
	}
	return "•"
}

func orderEnvironments(set map[string]bool) []string {
	rank := map[string]int{"main": 0, "master": 0, "default": 1, "staging": 2, "prod": 3, "production": 3}
	var envs []string
	for e := range set {
		envs = append(envs, e)
	}
	sort.Slice(envs, func(i, j int) bool {
		ri, iok := rank[envs[i]]
		rj, jok := rank[envs[j]]
		if !iok {
			ri = 10
		}
		if !jok {
			rj = 10
		}
		if ri != rj {
			return ri < rj
		}
		return envs[i] < envs[j]
	})
	return envs
}

const storeTimeLayout = "2006-01-02T15:04:05.000Z"

func parseTime(s string) (time.Time, error) { return time.Parse(storeTimeLayout, s) }

func formatTS(s string) string {
	t, err := parseTime(s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func staleBefore(now time.Time) string {
	return now.Add(-7 * 24 * time.Hour).UTC().Format(storeTimeLayout)
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func limit[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}
