package dependencytrack

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// BOM property names Patchline reads from metadata.properties. CI sets them
// when generating the SBOM so a resolution can point at the commit that
// fixed it.
const (
	PropertyCommit = "patchline:git:commit"
	PropertyRef    = "patchline:git:ref"
)

// BOMInfo is what Patchline extracts from an uploaded BOM.
type BOMInfo struct {
	Format      string `json:"format,omitempty"`
	SpecVersion string `json:"spec_version,omitempty"`
	Serial      string `json:"serial,omitempty"`
	Commit      string `json:"commit,omitempty"`
	Ref         string `json:"ref,omitempty"`
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// SubjectBOM decodes the BOM carried by BOM_CONSUMED / BOM_PROCESSED. A
// missing or unreadable BOM yields an empty BOMInfo, not an error: the
// BOM only adds evidence.
func (n Notification) SubjectBOM() BOMInfo {
	var s struct {
		BOM struct {
			Content     string `json:"content"`
			Format      string `json:"format"`
			SpecVersion string `json:"specVersion"`
		} `json:"bom"`
	}
	if err := json.Unmarshal(n.Subject, &s); err != nil {
		return BOMInfo{}
	}
	info := BOMInfo{Format: s.BOM.Format, SpecVersion: s.BOM.SpecVersion}
	raw, err := base64.StdEncoding.DecodeString(s.BOM.Content)
	if err != nil || len(raw) == 0 {
		return info
	}
	meta := parseBOM(raw)
	info.Serial = meta.serial
	for _, p := range meta.properties {
		switch p.name {
		case PropertyCommit:
			if v := strings.ToLower(strings.TrimSpace(p.value)); shaPattern.MatchString(v) {
				info.Commit = v
			}
		case PropertyRef:
			info.Ref = strings.TrimSpace(p.value)
		}
	}
	return info
}

type property struct{ name, value string }

type bomMeta struct {
	serial     string
	properties []property
}

func parseBOM(raw []byte) bomMeta {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '<' {
		return parseXMLBOM(raw)
	}
	var doc struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return bomMeta{}
	}
	m := bomMeta{serial: doc.SerialNumber}
	for _, p := range doc.Metadata.Properties {
		m.properties = append(m.properties, property{p.Name, p.Value})
	}
	return m
}

func parseXMLBOM(raw []byte) bomMeta {
	var doc struct {
		SerialNumber string `xml:"serialNumber,attr"`
		Metadata     struct {
			Properties struct {
				Property []struct {
					Name  string `xml:"name,attr"`
					Value string `xml:",chardata"`
				} `xml:"property"`
			} `xml:"properties"`
		} `xml:"metadata"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return bomMeta{}
	}
	m := bomMeta{serial: doc.SerialNumber}
	for _, p := range doc.Metadata.Properties.Property {
		m.properties = append(m.properties, property{p.Name, p.Value})
	}
	return m
}
