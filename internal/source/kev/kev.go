// Package kev reads CISA's Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultURL is CISA's JSON feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Entry is one catalog entry.
type Entry struct {
	CVEID      string `json:"cveID"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// Catalog is the feed.
type Catalog struct {
	Version         string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

// Fetch downloads and decodes the catalog.
func Fetch(ctx context.Context, url string, client *http.Client) (Catalog, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Catalog{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Catalog{}, fmt.Errorf("kev: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return Catalog{}, fmt.Errorf("kev: GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	var c Catalog
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&c); err != nil {
		return Catalog{}, fmt.Errorf("kev: decode: %w", err)
	}
	if len(c.Vulnerabilities) == 0 {
		return Catalog{}, fmt.Errorf("kev: catalog is empty")
	}
	for i := range c.Vulnerabilities {
		c.Vulnerabilities[i].CVEID = strings.ToUpper(strings.TrimSpace(c.Vulnerabilities[i].CVEID))
	}
	return c, nil
}
