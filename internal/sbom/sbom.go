// Package sbom reads the components of an SBOM uploaded to Patchline:
// CycloneDX and SPDX, in JSON.
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rha6780/patchline/internal/purl"
)

// BOM property names CI sets so a resolution can point at the commit that
// fixed it (the same ones Dependency-Track uploads carry).
const (
	PropertyCommit = "patchline:git:commit"
	PropertyRef    = "patchline:git:ref"
)

// Component is one package in the SBOM.
type Component struct {
	PURL    string `json:"purl"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Ecosystem and Package are the OSV lookup key; empty when the purl
	// type has no OSV ecosystem (for example OS packages).
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
}

// Document is what Patchline keeps from an SBOM.
type Document struct {
	Format     string // CycloneDX or SPDX
	Serial     string
	Commit     string
	Ref        string
	Components []Component
	// WithoutPURL counts components that could not be identified.
	WithoutPURL int
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// Parse reads a CycloneDX or SPDX JSON document.
func Parse(data []byte) (Document, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Document{}, errors.New("sbom: empty document")
	}
	if data[0] == '<' {
		return Document{}, errors.New("sbom: XML is not supported, upload CycloneDX or SPDX as JSON")
	}
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Document{}, fmt.Errorf("sbom: not JSON: %w", err)
	}
	var (
		doc Document
		err error
	)
	switch {
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		doc, err = parseCycloneDX(data)
	case probe.SPDXVersion != "":
		doc, err = parseSPDX(data)
	default:
		return Document{}, errors.New("sbom: neither CycloneDX (bomFormat) nor SPDX (spdxVersion)")
	}
	if err != nil {
		return Document{}, err
	}
	sort.Slice(doc.Components, func(i, j int) bool { return doc.Components[i].PURL < doc.Components[j].PURL })
	return doc, nil
}

type cdxComponent struct {
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

func parseCycloneDX(data []byte) (Document, error) {
	var bom struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Component  *cdxComponent `json:"component"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return Document{}, fmt.Errorf("sbom: CycloneDX: %w", err)
	}
	doc := Document{Format: "CycloneDX", Serial: bom.SerialNumber}
	for _, p := range bom.Metadata.Properties {
		doc.setProperty(p.Name, p.Value)
	}
	root := ""
	if bom.Metadata.Component != nil {
		root = bom.Metadata.Component.PURL
	}
	seen := map[string]bool{}
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			name := c.Name
			if c.Group != "" {
				name = c.Group + "/" + c.Name
			}
			if c.PURL != root || root == "" {
				doc.add(seen, c.PURL, name, c.Version)
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return doc, nil
}

func parseSPDX(data []byte) (Document, error) {
	var bom struct {
		DocumentNamespace string `json:"documentNamespace"`
		Packages          []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Annotations []struct {
			Comment string `json:"comment"`
		} `json:"annotations"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return Document{}, fmt.Errorf("sbom: SPDX: %w", err)
	}
	doc := Document{Format: "SPDX", Serial: bom.DocumentNamespace}
	// SPDX has no properties; "patchline:git:commit=<sha>" annotations work.
	for _, a := range bom.Annotations {
		if k, v, ok := strings.Cut(a.Comment, "="); ok {
			doc.setProperty(strings.TrimSpace(k), v)
		}
	}
	seen := map[string]bool{}
	for _, p := range bom.Packages {
		ref := ""
		for _, r := range p.ExternalRefs {
			if strings.EqualFold(r.ReferenceType, "purl") {
				ref = r.ReferenceLocator
				break
			}
		}
		doc.add(seen, ref, p.Name, p.VersionInfo)
	}
	return doc, nil
}

func (d *Document) setProperty(name, value string) {
	switch name {
	case PropertyCommit:
		if v := strings.ToLower(strings.TrimSpace(value)); shaPattern.MatchString(v) {
			d.Commit = v
		}
	case PropertyRef:
		d.Ref = strings.TrimSpace(value)
	}
}

func (d *Document) add(seen map[string]bool, ref, name, version string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		d.WithoutPURL++
		return
	}
	if seen[ref] {
		return
	}
	seen[ref] = true
	c := Component{PURL: ref, Name: name, Version: version}
	if p, err := purl.Parse(ref); err == nil {
		c.Ecosystem, c.Package = p.OSV()
		if c.Version == "" {
			c.Version = p.Version
		}
		if c.Name == "" {
			c.Name = p.Name
		}
	}
	d.Components = append(d.Components, c)
}

// Upload is an SBOM received by Patchline, as stored in the inbox.
type Upload struct {
	Project    string          `json:"project"`
	Version    string          `json:"version"`
	ReceivedAt string          `json:"received_at"`
	BOM        json.RawMessage `json:"bom"`
}

// ProjectID is the source project id of an uploaded SBOM: name@version.
func ProjectID(project, version string) string { return project + "@" + version }
