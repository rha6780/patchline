// Package gitea reads pull request webhooks from Gitea and Forgejo (and
// GitHub, whose payload has the same shape) and extracts the dependency
// updates a Renovate pull request makes.
package gitea

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// EventPullRequest is the webhook event Patchline handles.
const EventPullRequest = "pull_request"

// EventType returns the event name from the platform's header.
func EventType(h http.Header) string {
	for _, k := range []string{"X-Gitea-Event", "X-Forgejo-Event", "X-GitHub-Event"} {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// DeliveryID returns the platform's delivery id, if any.
func DeliveryID(h http.Header) string {
	for _, k := range []string{"X-Gitea-Delivery", "X-Forgejo-Delivery", "X-GitHub-Delivery"} {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// VerifySignature checks the HMAC-SHA256 signature of body against secret.
// Gitea and Forgejo send it hex-encoded in X-Gitea-Signature /
// X-Forgejo-Signature; GitHub sends "sha256=<hex>" in X-Hub-Signature-256.
func VerifySignature(h http.Header, body []byte, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, k := range []string{"X-Gitea-Signature", "X-Forgejo-Signature", "X-Hub-Signature-256"} {
		v := strings.TrimPrefix(h.Get(k), "sha256=")
		if v == "" {
			continue
		}
		got, err := hex.DecodeString(v)
		if err == nil && hmac.Equal(got, want) {
			return true
		}
	}
	return false
}

// PullRequestEvent is the subset of the pull_request payload Patchline uses.
type PullRequestEvent struct {
	Action      string      `json:"action"`
	Number      int         `json:"number"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

// PullRequest is a pull request.
type PullRequest struct {
	Number         int     `json:"number"`
	HTMLURL        string  `json:"html_url"`
	Title          string  `json:"title"`
	Body           string  `json:"body"`
	State          string  `json:"state"` // open | closed
	Merged         bool    `json:"merged"`
	MergeCommitSHA string  `json:"merge_commit_sha"`
	Head           Branch  `json:"head"`
	Base           Branch  `json:"base"`
	Labels         []Label `json:"labels"`
	User           struct {
		Login string `json:"login"`
	} `json:"user"`
}

// Branch is a pull request head or base.
type Branch struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

// Label is a pull request label.
type Label struct {
	Name string `json:"name"`
}

// ParsePullRequestEvent decodes a pull_request webhook body.
func ParsePullRequestEvent(body []byte) (PullRequestEvent, error) {
	var ev PullRequestEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return PullRequestEvent{}, fmt.Errorf("decode pull_request event: %w", err)
	}
	if ev.Repository.FullName == "" || ev.PullRequest.HTMLURL == "" {
		return PullRequestEvent{}, fmt.Errorf("decode pull_request event: missing repository or pull_request")
	}
	if ev.PullRequest.Number == 0 {
		ev.PullRequest.Number = ev.Number
	}
	return ev, nil
}

// Outcome classifies an event for Patchline.
type Outcome string

const (
	OutcomeOpen   Outcome = "open"   // opened, reopened, updated
	OutcomeMerged Outcome = "merged" // closed with merge
	OutcomeClosed Outcome = "closed" // closed without merge
	OutcomeIgnore Outcome = ""
)

// Outcome maps the action to what happened to the pull request.
func (ev PullRequestEvent) Outcome() Outcome {
	switch ev.Action {
	case "opened", "reopened", "synchronized", "synchronize", "edited":
		if ev.PullRequest.State == "closed" {
			return OutcomeIgnore
		}
		return OutcomeOpen
	case "closed":
		if ev.PullRequest.Merged {
			return OutcomeMerged
		}
		return OutcomeClosed
	}
	return OutcomeIgnore
}

// Update is one dependency change proposed by a pull request.
type Update struct {
	Package string `json:"package"`
	From    string `json:"from,omitempty"`
	To      string `json:"to"`
}

var (
	// "| [name](url) ([source](url)) | dependencies | patch | [`1.0` -> `1.1`](diff) |"
	tableChange  = regexp.MustCompile("`?(v?[0-9][^`\\s|\\]]*)`?\\s*(?:->|→)\\s*`?(v?[0-9][^`\\s|\\]]*)`?")
	markdownLink = regexp.MustCompile(`\[([^\]]+)\]\([^)]*\)`)
	// "Update dependency org.example:lib to v1.2.3 [SECURITY]"
	titleUpdate = regexp.MustCompile(`(?i)\bupdate (?:dependency |module |docker tag |image )?([^\s]+) to v?([0-9][^\s\]]*)`)
)

// RenovateUpdates extracts dependency updates from a Renovate pull request:
// the change table in the body when present, otherwise the title.
func RenovateUpdates(pr PullRequest) []Update {
	var out []Update
	seen := map[string]bool{}
	for _, line := range strings.Split(pr.Body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 2 {
			continue
		}
		var from, to string
		for _, c := range cells[1:] {
			if m := tableChange.FindStringSubmatch(c); m != nil {
				from, to = m[1], m[2]
				break
			}
		}
		if to == "" {
			continue
		}
		name := packageName(cells[0])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, Update{Package: name, From: from, To: to})
	}
	if len(out) == 0 {
		if m := titleUpdate.FindStringSubmatch(pr.Title); m != nil {
			out = append(out, Update{Package: strings.Trim(m[1], "`'\""), To: m[2]})
		}
	}
	return out
}

func packageName(cell string) string {
	cell = strings.TrimSpace(cell)
	if m := markdownLink.FindStringSubmatch(cell); m != nil {
		cell = m[1]
	} else if i := strings.Index(cell, " ("); i > 0 {
		cell = cell[:i]
	}
	cell = strings.Trim(strings.TrimSpace(cell), "`*")
	if cell == "" || strings.EqualFold(cell, "package") || strings.Trim(cell, "-: ") == "" {
		return ""
	}
	return cell
}

// NormalizePackage lowercases a package name and uses "/" as the group
// separator, so Maven "group:artifact" matches "group/artifact".
func NormalizePackage(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), ":", "/")
}
