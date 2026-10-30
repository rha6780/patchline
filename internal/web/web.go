// Package web serves Patchline's UI: an overview, per-service environment
// comparison, finding timelines and integration health.
//
// Pages are rendered on the server with html/template; there is no
// JavaScript. With sign-in configured (package auth), people with the
// right permissions also assign findings, request and approve risk
// acceptances and due date extensions, and rotate webhook secrets.
// Without it the UI is read-only.
package web

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/i18n"
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
	FindingSightings(ctx context.Context, findingID int64) ([]store.Sighting, error)
	FindingFacets(ctx context.Context) (services, environments []string, err error)
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

	// Actions enables the pages and forms that change things. Nil keeps
	// the UI read-only.
	Actions Actions
	// DT writes approved risk acceptances to Dependency-Track.
	DT AnalysisWriter
	// OnChange is called after a change (to wake the notifier).
	OnChange func()
	// AuthEnabled shows the signed-in user and the sign-out button.
	AuthEnabled bool
	// SSO and LocalAdmin choose what the sign-in page offers.
	SSO        bool
	LocalAdmin bool
	// PublicURL is where users reach Patchline, for webhook URLs.
	PublicURL string
	// EnvWebhookToken and EnvGiteaSecret are the environment's values,
	// shown (as hints) on the settings page when the UI has not replaced
	// them.
	EnvWebhookToken string
	EnvGiteaSecret  string
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
	if o.OnChange == nil {
		o.OnChange = func() {}
	}
	u := &UI{o: o, pages: map[string]*template.Template{}, mux: http.NewServeMux()}
	for _, page := range []string{"overview", "findings", "finding", "service", "integrations", "guide", "approvals", "settings", "signedout", "login", "password"} {
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
	u.mux.HandleFunc("GET /docs/integrations", u.guide)
	u.mux.HandleFunc("GET /prefs", u.prefs)
	u.mux.HandleFunc("GET /signed-out", u.signedOut)
	u.mux.HandleFunc("GET /login", u.login)
	u.mux.HandleFunc("GET /account/password", u.password)
	if o.Actions != nil {
		u.mux.HandleFunc("POST /findings/{id}/assign", u.assign)
		u.mux.HandleFunc("POST /findings/{id}/requests", u.request)
		u.mux.HandleFunc("POST /requests/{id}", u.decide)
		u.mux.HandleFunc("GET /approvals", u.approvals)
		u.mux.HandleFunc("GET /settings", u.settings)
		u.mux.HandleFunc("POST /settings/webhooks", u.saveSecret)
	}
	return u, nil
}

func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) { u.mux.ServeHTTP(w, r) }

func (u *UI) render(w http.ResponseWriter, r *http.Request, page, titleKey string, data map[string]any) {
	l := langOf(r)
	data["L"] = l
	data["Langs"] = i18n.Supported
	data["Theme"] = themeOf(r)
	data["Themes"] = themes
	data["Path"] = r.URL.RequestURI()
	data["Title"] = titleKey
	if i18n.Has(titleKey) {
		data["Title"] = l.T(titleKey)
	}
	data["Page"] = page
	data["P"] = auth.FromContext(r.Context())
	data["AuthEnabled"] = u.o.AuthEnabled
	data["Writable"] = u.o.Actions != nil
	data["Notice"], data["Error"] = notice(l, r)
	data["Version"] = u.o.Version
	data["DTUIURL"] = u.o.DTUIURL
	// Documentation lives in the repository; Korean pages end in .ko.md.
	data["Docs"] = docsURL
	data["DocExt"] = ".md"
	if l == i18n.KO {
		data["DocExt"] = ".ko.md"
	}
	var buf strings.Builder
	if err := u.pages[page].Execute(&buf, data); err != nil {
		u.o.Logger.Error("render page", "page", page, "err", err)
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", string(l))
	w.Header().Set("Vary", "Accept-Language, Cookie")
	_, _ = w.Write([]byte(buf.String()))
}

// ---- preferences ------------------------------------------------------

const (
	cookieLang  = "patchline_lang"
	cookieTheme = "patchline_theme"
)

var themes = []string{"system", "light", "dark"}

func langOf(r *http.Request) i18n.Lang {
	if c, err := r.Cookie(cookieLang); err == nil {
		if l, ok := i18n.Parse(c.Value); ok {
			return l
		}
	}
	return i18n.Negotiate(r.Header.Get("Accept-Language"))
}

func themeOf(r *http.Request) string {
	if c, err := r.Cookie(cookieTheme); err == nil {
		for _, t := range themes {
			if c.Value == t {
				return t
			}
		}
	}
	return "system"
}

// prefs stores the language or theme in a cookie and returns to "next".
// It works without JavaScript: the header links point here.
func (u *UI) prefs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	set := func(name, value string) {
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || strings.HasPrefix(u.o.PublicURL, "https://")})
	}
	if l, ok := i18n.Parse(q.Get("lang")); ok {
		set(cookieLang, string(l))
	}
	for _, t := range themes {
		if q.Get("theme") == t {
			set(cookieTheme, t)
		}
	}
	http.Redirect(w, r, auth.SafeNext(q.Get("next")), http.StatusSeeOther)
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
	nowS, weekS := store.FormatTime(now), store.FormatTime(now.Add(7*24*time.Hour))
	var (
		overdue, dueWeek                     int
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
			if f.Overdue(nowS) {
				overdue++
			} else if f.DueAt != nil && *f.DueAt < weekS {
				dueWeek++
			}
			if sev := f.DisplaySeverity(); sev == finding.SeverityCritical || sev == finding.SeverityHigh {
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
			row.Counts[f.DisplaySeverity()]++
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
	// Overdue first, then by due date, then severity.
	sort.SliceStable(attention, func(i, j int) bool {
		a, b := attention[i], attention[j]
		if ao, bo := a.Overdue(nowS), b.Overdue(nowS); ao != bo {
			return ao
		}
		if (a.DueAt != nil) != (b.DueAt != nil) {
			return a.DueAt != nil
		}
		if a.DueAt != nil && *a.DueAt != *b.DueAt {
			return *a.DueAt < *b.DueAt
		}
		return finding.SeverityRank(a.DisplaySeverity()) < finding.SeverityRank(b.DisplaySeverity())
	})
	sort.Slice(recent, func(i, j int) bool { return *recent[i].ResolvedAt > *recent[j].ResolvedAt })

	mttr := "—"
	if mttrN > 0 {
		mttr = humanDuration(langOf(r), mttrSum/time.Duration(mttrN))
	}
	u.render(w, r, "overview", "ui.overview", map[string]any{
		"Open": open, "CritHigh": critHigh, "Awaiting": awaiting, "Resolved30": resolved30, "MTTR": mttr,
		"Overdue": overdue, "DueWeek": dueWeek, "Now": nowS,
		"Services": services, "Severities": severities,
		"Attention": limit(attention, 10), "Recent": limit(recent, 10), "Total": len(all),
	})
}

// ---- findings list ----------------------------------------------------

// filterParams are the query parameters the findings page understands.
var filterParams = []string{"service", "environment", "severity", "state", "due", "assignee", "open"}

type preset struct {
	Key    string // i18n key
	URL    string
	Active bool
}

type activeFilter struct {
	Label     string
	Value     string
	RemoveURL string
}

// canonical keeps only known, non-empty filter parameters in a stable order.
func canonical(q url.Values) url.Values {
	out := url.Values{}
	for _, k := range filterParams {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	return out
}

func findingsURL(q url.Values) string {
	if enc := q.Encode(); enc != "" {
		return "/findings?" + enc
	}
	return "/findings"
}

func (u *UI) findings(w http.ResponseWriter, r *http.Request) {
	l := langOf(r)
	q := canonical(r.URL.Query())
	f := store.FindingFilter{
		Service: q.Get("service"), Environment: q.Get("environment"),
		State: q.Get("state"), Severity: q.Get("severity"), Assignee: q.Get("assignee"), Open: q.Get("open") == "1", Limit: 500,
	}
	due := q.Get("due")
	switch due {
	case "overdue":
		f.DueBefore = store.FormatTime(u.o.Now())
	case "week":
		f.DueBefore = store.FormatTime(u.o.Now().Add(7 * 24 * time.Hour))
	default:
		due = ""
		q.Del("due")
	}
	list, err := u.o.Store.ListFindings(r.Context(), f)
	if err != nil {
		u.fail(w, err)
		return
	}
	services, envs, err := u.o.Store.FindingFacets(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	for _, s := range u.o.Inventory.Services() {
		if !slices.Contains(services, s.Name) {
			services = append(services, s.Name)
		}
	}
	sort.Strings(services)

	current := q.Encode()
	var presets []preset
	quick := []struct{ key, query string }{
		{"ui.preset.open", "open=1"},
		{"ui.preset.overdue", "due=overdue"},
		{"ui.preset.week", "due=week"},
		{"ui.preset.critical", "open=1&severity=critical"},
		{"ui.preset.awaiting", "state=awaiting_verification"},
		{"ui.preset.all", ""},
	}
	if p := auth.FromContext(r.Context()); p.Authenticated {
		mine := struct{ key, query string }{"ui.preset.mine", "open=1&assignee=" + url.QueryEscape(p.Identity())}
		quick = append([]struct{ key, query string }{mine}, quick...)
	}
	for _, p := range quick {
		pq, _ := url.ParseQuery(p.query)
		enc := canonical(pq).Encode()
		presets = append(presets, preset{Key: p.key, URL: findingsURL(canonical(pq)), Active: enc == current})
	}

	var active []activeFilter
	for _, k := range filterParams {
		v := q.Get(k)
		if v == "" {
			continue
		}
		rest := canonical(q)
		rest.Del(k)
		label, value := l.T("ui.filter."+k), v
		switch k {
		case "state":
			value = notify.StateLabel(l, v)
		case "due":
			value = l.T("ui.filter." + v)
		case "open":
			label, value = l.T("ui.filter.open_only"), ""
		}
		active = append(active, activeFilter{Label: label, Value: value, RemoveURL: findingsURL(rest)})
	}

	u.render(w, r, "findings", "ui.findings", map[string]any{
		"Findings": list, "Filter": f, "Severities": severities, "States": states, "Due": due,
		"Now": store.FormatTime(u.o.Now()), "Presets": presets, "Active": active,
		"Services": services, "Environments": envs,
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
	sightings, err := u.o.Store.FindingSightings(r.Context(), id)
	if err != nil {
		u.fail(w, err)
		return
	}
	var timeline []timelineItem
	for _, e := range events {
		timeline = append(timeline, timelineItem{Kind: e.Kind, At: e.OccurredAt, Text: notify.Describe(langOf(r), e), Icon: eventIcon(e.Kind)})
	}
	var svc *inventory.Service
	if f.Registered {
		svc, _ = u.o.Inventory.Service(f.Service)
	}
	data := map[string]any{
		"F": f, "Service": svc, "Timeline": timeline, "PRs": prs, "DTLink": u.dtLink(f), "Sightings": sightings,
		"Now": store.FormatTime(u.o.Now()),
	}
	if u.o.Actions != nil {
		reqs, err := u.o.Actions.ListRequests(r.Context(), store.RequestFilter{FindingID: id})
		if err != nil {
			u.fail(w, err)
			return
		}
		pendingKinds := map[string]bool{}
		var pending, decided []store.ExceptionRequest
		for _, rq := range reqs {
			if rq.Status == store.RequestPending {
				pending = append(pending, rq)
				pendingKinds[rq.Kind] = true
			} else {
				decided = append(decided, rq)
			}
		}
		// The earliest date a due extension may ask for.
		minDue := u.o.Now()
		if f.DueAt != nil {
			if t, err := parseTime(*f.DueAt); err == nil && t.After(minDue) {
				minDue = t
			}
		}
		data["Pending"], data["Decided"], data["PendingKinds"] = pending, decided, pendingKinds
		data["MinDue"] = minDue.Add(24 * time.Hour).UTC().Format("2006-01-02")
		data["CanAccept"] = u.o.DT != nil && f.DTComponentUUID != "" && f.DTVulnerabilityUUID != ""
	}
	u.render(w, r, "finding", f.VulnID, data)
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
			row = &envRow{Component: f.ComponentName, Version: f.ComponentVersion, VulnID: f.VulnID, Severity: f.DisplaySeverity(), Cells: map[string]store.Finding{}}
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
	u.render(w, r, "service", name, map[string]any{
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
	u.render(w, r, "integrations", "ui.integrations", map[string]any{
		"Projects": projects, "Missing": missing, "Inbox": inbox, "Notifications": notes,
		"Stale": staleBefore(u.o.Now()),
	})
}

// docsURL is where the Markdown documentation is published.
const docsURL = "https://github.com/rha6780/patchline/blob/main/docs/"

func (u *UI) signedOut(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "signedout", "ui.signed_out", map[string]any{"LocalAdmin": u.o.LocalAdmin})
}

// login offers single sign-on and the local admin form.
func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "login", "ui.sign_in", map[string]any{"Next": auth.SafeNext(r.URL.Query().Get("next")), "SSO": u.o.SSO, "LocalAdmin": u.o.LocalAdmin})
}

func (u *UI) password(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Local {
		http.NotFound(w, r)
		return
	}
	u.render(w, r, "password", "ui.change_password", map[string]any{"Min": auth.MinPasswordLength})
}

// guide introduces the tools Patchline can take alerts from and how to
// connect them. It is static: connection health is on /integrations.
func (u *UI) guide(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "guide", "ui.guide", map[string]any{})
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
		"t":          func(l i18n.Lang, key string, args ...any) string { return l.T(key, args...) },
		"stateClass": func(s string) string { return "state-" + strings.ReplaceAll(s, "_", "-") },
		"sevClass":   func(s string) string { return "sev-" + s },
		"component":  notify.Component,
		"verdict":    notify.VerdictLabel,
		"prRef":      notify.PRRef,
		"ts":         formatTS,
		"short":      shortSHA,
		"join":       strings.Join,
		"hasPrefix":  strings.HasPrefix,
		"pathEscape": url.PathEscape,
		"count":      func(m map[string]int, k string) int { return m[k] },
		"cell": func(m map[string]store.Finding, k string) *store.Finding {
			if f, ok := m[k]; ok {
				return &f
			}
			return nil
		},
		"isOpen": func(s string) bool { return finding.State(s).Open() },
		"can": func(p *auth.Principal, perm string) bool {
			return u.o.Actions != nil && p.Can(auth.Permission(perm))
		},
		"kindLabel":   notify.RequestKindLabel,
		"sourceLabel": notify.SourceLabel,
		"statusLabel": notify.RequestStatusLabel,
		"day":         func(s string) string { return dateOnly(s) },
		"dayPtr": func(s *string) string {
			if s == nil {
				return ""
			}
			return dateOnly(*s)
		},
		"staleBOM":  func(lastBOM, before string) bool { return lastBOM == "" || lastBOM < before },
		"dtProject": func(uuid string) string { return u.dtProjectLink(uuid) },
		"rich":      rich,
		"dueText":   func(l i18n.Lang, due string) string { return notify.DueText(l, due, u.o.Now()) },
		"sevText":   notify.SeverityText,
		"overdue":   func(f store.Finding, now string) bool { return f.Overdue(now) },
		"epss":      func(v *float64) string { return fmt.Sprintf("%.2f", *v) },
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

func humanDuration(l i18n.Lang, d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return l.T("ui.mttr.days", d.Hours()/24)
	case d >= time.Hour:
		return l.T("ui.mttr.hours", d.Hours())
	default:
		return l.T("ui.mttr.minutes", int(d.Minutes()))
	}
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
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
