// Package trivy matches SBOM components with a Trivy server, the optional
// second engine of Patchline's own detection. It covers what OSV data does
// not: OS packages (deb, rpm, apk) of container images. With All set it
// also matches language packages, which then merge with the OSV matches.
//
// It speaks the server's Twirp API in JSON, like Trivy's own client:
// PutBlob (the packages), Scan, DeleteBlobs. That API is not documented as
// stable, so the engine is optional and pinned to a tested Trivy version.
package trivy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/detect"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/version"
)

// Engine matches components with a Trivy server.
type Engine struct {
	URL   string // e.g. http://trivy:8080
	Token string // the server's --token
	// All also sends language packages (Maven, npm, ...), not only OS
	// packages.
	All  bool
	HTTP *http.Client
}

// Ready is always true: the server holds the data. When it cannot be
// reached, MatchAll fails and the analysis is retried later.
func (e *Engine) Ready(context.Context) (bool, error) { return true, nil }

type pkgIdentifier struct {
	PURL   string `json:"purl,omitempty"`
	BOMRef string `json:"bom_ref,omitempty"`
}

type pkg struct {
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Release    string        `json:"release,omitempty"`
	Epoch      int           `json:"epoch,omitempty"`
	Arch       string        `json:"arch,omitempty"`
	SrcName    string        `json:"src_name,omitempty"`
	SrcVersion string        `json:"src_version,omitempty"`
	SrcRelease string        `json:"src_release,omitempty"`
	SrcEpoch   int           `json:"src_epoch,omitempty"`
	Identifier pkgIdentifier `json:"identifier"`
}

type osInfo struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type application struct {
	Type     string `json:"type"`
	Packages []pkg  `json:"packages"`
}

type blobInfo struct {
	SchemaVersion int           `json:"schema_version"`
	OS            *osInfo       `json:"os,omitempty"`
	PackageInfos  []packageInfo `json:"package_infos,omitempty"`
	Applications  []application `json:"applications,omitempty"`
}

type packageInfo struct {
	Packages []pkg `json:"packages"`
}

// appTypes are Trivy's language package types by purl type.
var appTypes = map[string]string{
	"maven": "jar", "npm": "node-pkg", "pypi": "python-pkg", "golang": "gobinary",
	"cargo": "cargo", "nuget": "nuget", "gem": "gemspec", "composer": "composer",
}

// families maps the distro qualifier's name to Trivy's OS family.
var families = map[string]string{"rhel": "redhat", "almalinux": "alma", "ol": "oracle", "amzn": "amazon"}

// MatchAll scans the components: one blob per OS release (with the
// language packages on the first), then reads the vulnerabilities back by
// the bom-ref each package was sent with.
func (e *Engine) MatchAll(ctx context.Context, comps []store.Component) (map[string][]detect.Match, error) {
	byRef := map[string]string{} // bom-ref sent -> component purl
	oses := map[osInfo][]pkg{}
	apps := map[string][]pkg{}
	for i, c := range comps {
		p, err := purl.Parse(c.PURL)
		if err != nil {
			continue
		}
		ref := "c" + strconv.Itoa(i)
		id := pkgIdentifier{PURL: c.PURL, BOMRef: ref}
		switch p.Type {
		case "deb", "rpm", "apk":
			os, ok := osOf(p)
			if !ok {
				continue // without the distro the advisories cannot be chosen
			}
			oses[os] = append(oses[os], osPackage(p, c, id))
			byRef[ref] = c.PURL
		default:
			t, ok := appTypes[p.Type]
			if !e.All || !ok || p.Version == "" {
				continue
			}
			apps[t] = append(apps[t], pkg{Name: appName(p), Version: p.Version, Identifier: id})
			byRef[ref] = c.PURL
		}
	}
	if len(byRef) == 0 {
		return map[string][]detect.Match{}, nil
	}

	var blobs []blobInfo
	keys := make([]osInfo, 0, len(oses))
	for k := range oses {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Family+keys[i].Name < keys[j].Family+keys[j].Name })
	for _, k := range keys {
		os := k
		blobs = append(blobs, blobInfo{SchemaVersion: 2, OS: &os, PackageInfos: []packageInfo{{Packages: oses[k]}}})
	}
	if len(apps) > 0 {
		var as []application
		types := make([]string, 0, len(apps))
		for t := range apps {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			as = append(as, application{Type: t, Packages: apps[t]})
		}
		if len(blobs) == 0 {
			blobs = append(blobs, blobInfo{SchemaVersion: 2})
		}
		blobs[0].Applications = as
	}

	out := map[string][]detect.Match{}
	for _, b := range blobs {
		vulns, err := e.scan(ctx, b)
		if err != nil {
			return nil, err
		}
		for _, v := range vulns {
			p, ok := byRef[v.PkgIdentifier.BOMRef]
			if !ok {
				continue
			}
			out[p] = append(out[p], v.match())
		}
	}
	return out, nil
}

type vulnerability struct {
	VulnerabilityID  string        `json:"vulnerability_id"`
	VendorIDs        []string      `json:"vendor_ids"`
	PkgName          string        `json:"pkg_name"`
	InstalledVersion string        `json:"installed_version"`
	FixedVersion     string        `json:"fixed_version"`
	Title            string        `json:"title"`
	Severity         string        `json:"severity"`
	PkgIdentifier    pkgIdentifier `json:"pkg_identifier"`
}

func (v vulnerability) match() detect.Match {
	m := detect.Match{ID: v.VulnerabilityID, Aliases: v.VendorIDs, Summary: v.Title,
		Severity: finding.NormalizeSeverity(v.Severity), Engine: "trivy", Range: "= " + v.InstalledVersion}
	// Several fix lines ("2.12.3, 2.17.1"): the upgrade is the lowest fixed
	// version above the installed one.
	for _, f := range strings.Split(v.FixedVersion, ",") {
		f = strings.TrimSpace(f)
		if f == "" || version.Compare(f, v.InstalledVersion) <= 0 {
			continue
		}
		if m.Fixed == "" || version.Compare(f, m.Fixed) < 0 {
			m.Fixed = f
		}
	}
	if m.Fixed != "" && !strings.Contains(v.FixedVersion, ",") {
		m.Range = "< " + m.Fixed
	}
	return m
}

// scan uploads one blob, scans it and deletes it.
func (e *Engine) scan(ctx context.Context, b blobInfo) ([]vulnerability, error) {
	id := newDiffID()
	if err := e.call(ctx, "trivy.cache.v1.Cache/PutBlob", map[string]any{"diff_id": id, "blob_info": b}, nil); err != nil {
		return nil, err
	}
	defer func() {
		// Best effort: the server also expires blobs.
		_ = e.call(context.WithoutCancel(ctx), "trivy.cache.v1.Cache/DeleteBlobs", map[string]any{"blob_ids": []string{id}}, nil)
	}()
	var resp struct {
		Results []struct {
			Vulnerabilities []vulnerability `json:"vulnerabilities"`
		} `json:"results"`
	}
	req := map[string]any{"target": "patchline", "artifact_id": id, "blob_ids": []string{id},
		"options": map[string]any{"scanners": []string{"vuln"}, "pkg_types": []string{"os", "library"}}}
	if err := e.call(ctx, "trivy.scanner.v1.Scanner/Scan", req, &resp); err != nil {
		return nil, err
	}
	var out []vulnerability
	for _, r := range resp.Results {
		out = append(out, r.Vulnerabilities...)
	}
	return out, nil
}

func (e *Engine) call(ctx context.Context, method string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.URL, "/")+"/twirp/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.Token != "" {
		req.Header.Set("Trivy-Token", e.Token)
	}
	client := e.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("trivy %s: %w", method, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("trivy %s: %s: %s", method, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("trivy %s: decode: %w", method, err)
	}
	return nil
}

// osOf reads the OS release from the distro qualifier ("debian-11.6",
// "alpine-3.18.4", "ubuntu-22.04", "redhat-8.9").
func osOf(p purl.PURL) (osInfo, bool) {
	d := p.Qualifiers["distro"]
	family, name, ok := strings.Cut(d, "-")
	if !ok || family == "" || name == "" {
		return osInfo{}, false
	}
	family = strings.ToLower(family)
	if f, ok := families[family]; ok {
		family = f
	}
	return osInfo{Family: family, Name: name}, true
}

// osPackage splits [epoch:]version[-release] the way Trivy keeps OS
// packages; Alpine versions keep their "-r0".
func osPackage(p purl.PURL, c store.Component, id pkgIdentifier) pkg {
	k := pkg{Name: p.Name, Arch: p.Qualifiers["arch"], Identifier: id}
	k.Epoch, k.Version, k.Release = splitVersion(p.Type, p.Version)
	if e, err := strconv.Atoi(p.Qualifiers["epoch"]); err == nil && k.Epoch == 0 {
		k.Epoch = e
	}
	k.SrcName, k.SrcEpoch, k.SrcVersion, k.SrcRelease = k.Name, k.Epoch, k.Version, k.Release
	srcName, srcVersion := c.SrcName, c.SrcVersion
	if srcName == "" {
		// Syft: upstream=name or name@version.
		srcName, srcVersion, _ = strings.Cut(p.Qualifiers["upstream"], "@")
	}
	if srcName != "" {
		k.SrcName = srcName
		if srcVersion != "" {
			k.SrcEpoch, k.SrcVersion, k.SrcRelease = splitVersion(p.Type, srcVersion)
		}
	}
	return k
}

func splitVersion(typ, v string) (epoch int, version, release string) {
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.Atoi(e); err == nil {
			epoch, v = n, rest
		}
	}
	if typ == "apk" {
		return epoch, v, ""
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func appName(p purl.PURL) string {
	switch {
	case p.Namespace == "":
		return p.Name
	case p.Type == "maven":
		return p.Namespace + ":" + p.Name
	}
	return p.Namespace + "/" + p.Name
}

func newDiffID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return "sha256:" + hex.EncodeToString(b[:])
}
