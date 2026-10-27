package dependencytrack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a minimal Dependency-Track REST client.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient returns a client for the API server at baseURL (for example
// http://dtrack-apiserver:8080). The API key needs VIEW_PORTFOLIO and
// VIEW_VULNERABILITY.
func NewClient(baseURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: httpClient}
}

// apiFinding is one element of GET /api/v1/finding/project/{uuid}.
type apiFinding struct {
	Component     Component     `json:"component"`
	Vulnerability Vulnerability `json:"vulnerability"`
	Analysis      struct {
		State        string `json:"state"`
		IsSuppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
}

// ProjectSightings returns the current, unsuppressed findings of a project.
func (c *Client) ProjectSightings(ctx context.Context, project Project) ([]Sighting, error) {
	u := c.baseURL + "/api/v1/finding/project/" + url.PathEscape(project.UUID) + "?suppressed=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dependency-track: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("dependency-track: GET findings for %s: %s: %s", project.UUID, resp.Status, strings.TrimSpace(string(body)))
	}

	var findings []apiFinding
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		return nil, fmt.Errorf("dependency-track: decode findings: %w", err)
	}
	out := make([]Sighting, 0, len(findings))
	for _, f := range findings {
		if f.Analysis.IsSuppressed {
			continue
		}
		out = append(out, Sighting{Project: project, Component: f.Component, Vulnerability: f.Vulnerability})
	}
	return out, nil
}

// AffectedComponent is one affected package (or CPE) of a vulnerability,
// with the affected versions as an exact version or a range.
type AffectedComponent struct {
	IdentityType          string `json:"identityType"` // PURL | CPE
	Identity              string `json:"identity"`
	VersionType           string `json:"versionType"` // EXACT | RANGE
	Version               string `json:"version"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// VulnerabilityDetail is the part of a vulnerability used to judge fixes.
type VulnerabilityDetail struct {
	VulnID             string              `json:"vulnId"`
	Source             string              `json:"source"`
	PatchedVersions    string              `json:"patchedVersions"`
	AffectedComponents []AffectedComponent `json:"affectedComponents"`
}

// Vulnerability returns a vulnerability with its affected components
// (GET /api/v1/vulnerability/source/{source}/vuln/{vulnId}).
func (c *Client) Vulnerability(ctx context.Context, source, vulnID string) (VulnerabilityDetail, error) {
	u := c.baseURL + "/api/v1/vulnerability/source/" + url.PathEscape(source) + "/vuln/" + url.PathEscape(vulnID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return VulnerabilityDetail{}, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return VulnerabilityDetail{}, fmt.Errorf("dependency-track: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return VulnerabilityDetail{}, fmt.Errorf("dependency-track: GET vulnerability %s/%s: %s: %s", source, vulnID, resp.Status, strings.TrimSpace(string(body)))
	}
	var v VulnerabilityDetail
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return VulnerabilityDetail{}, fmt.Errorf("dependency-track: decode vulnerability: %w", err)
	}
	return v, nil
}
