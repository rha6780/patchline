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
	// BOMRef is the CycloneDX bom-ref, for VEX BOM-Links.
	BOMRef string `json:"bom_ref,omitempty"`
	// SrcName and SrcVersion name an OS package's source package, from
	// Trivy's properties or the purl's upstream qualifier.
	SrcName    string `json:"src_name,omitempty"`
	SrcVersion string `json:"src_version,omitempty"`
}

// Document is what Patchline keeps from an SBOM.
type Document struct {
	Format string // CycloneDX or SPDX
	Serial string
	// Version is the CycloneDX document version (1 when absent).
	Version    int
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
	BOMRef     string         `json:"bom-ref"`
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

func parseCycloneDX(data []byte) (Document, error) {
	var bom struct {
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
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
	doc := Document{Format: "CycloneDX", Serial: bom.SerialNumber, Version: bom.Version}
	if doc.Version == 0 {
		doc.Version = 1
	}
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
				doc.add(seen, c.PURL, name, c.Version, c.BOMRef)
				if n := len(doc.Components); n > 0 && doc.Components[n-1].PURL == c.PURL {
					doc.Components[n-1].setSource(c)
				}
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
		doc.add(seen, ref, p.Name, p.VersionInfo, "")
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

// Trivy's CycloneDX properties for an OS package's source package.
const (
	propSrcName    = "aquasecurity:trivy:SrcName"
	propSrcVersion = "aquasecurity:trivy:SrcVersion"
	propSrcRelease = "aquasecurity:trivy:SrcRelease"
	propSrcEpoch   = "aquasecurity:trivy:SrcEpoch"
)

func (c *Component) setSource(cdx cdxComponent) {
	props := map[string]string{}
	for _, p := range cdx.Properties {
		props[p.Name] = p.Value
	}
	if n := props[propSrcName]; n != "" {
		c.SrcName = n
		v := props[propSrcVersion]
		if r := props[propSrcRelease]; r != "" && v != "" {
			v += "-" + r
		}
		if e := props[propSrcEpoch]; e != "" && e != "0" && v != "" {
			v = e + ":" + v
		}
		c.SrcVersion = v
	}
}

func (d *Document) add(seen map[string]bool, ref, name, version, bomRef string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		d.WithoutPURL++
		return
	}
	if seen[ref] {
		return
	}
	seen[ref] = true
	c := Component{PURL: ref, Name: name, Version: version, BOMRef: bomRef}
	if p, err := purl.Parse(ref); err == nil {
		c.Ecosystem, c.Package = p.OSV()
		if c.Version == "" {
			c.Version = p.Version
		}
		if c.Name == "" {
			c.Name = p.Name
		}
		// Syft writes the source package as upstream=name or name@version.
		if up := p.Qualifiers["upstream"]; up != "" {
			c.SrcName, c.SrcVersion, _ = strings.Cut(up, "@")
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
