// Package selfscan lets Patchline watch itself: at start-up it describes
// its own binary (the Go modules it was built from and the Go standard
// library) as an SBOM and queues it like an upload. The usual detection
// then turns advisories against Patchline into findings of the project
// "patchline", and the notifiers tell the people running it that it needs
// an upgrade. Re-analyses after vulnerability data changes cover advisories
// published later; upgrading Patchline replaces the snapshot and resolves
// what the new build fixed.
package selfscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/sbom"
)

// Project is the project name Patchline's own findings are filed under.
const Project = "patchline"

// Inbox stores the upload for the processor.
type Inbox interface {
	InsertInbox(ctx context.Context, source, eventType, dedupKey string, payload []byte) (int64, bool, error)
}

// BOM returns a CycloneDX document of the modules in info and the Go
// standard library of goVersion (as runtime.Version reports it).
func BOM(info *debug.BuildInfo, goVersion, version string) ([]byte, error) {
	if info == nil {
		return nil, errors.New("selfscan: no build information in the binary")
	}
	type component struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	}
	var comps []component
	if v := stdlibVersion(goVersion); v != "" {
		comps = append(comps, component{Type: "library", Name: "stdlib", Version: v, PURL: "pkg:golang/stdlib@" + v})
	}
	for _, m := range info.Deps {
		if m.Replace != nil {
			m = m.Replace
		}
		if m.Path == "" || m.Version == "" || m.Version == "(devel)" || strings.HasPrefix(m.Path, ".") || strings.HasPrefix(m.Path, "/") {
			continue // a local replacement has no published version
		}
		comps = append(comps, component{Type: "library", Name: m.Path, Version: m.Version,
			PURL: "pkg:golang/" + m.Path + "@" + m.Version})
	}
	main := info.Main.Path
	if main == "" {
		main = "github.com/rha6780/patchline"
	}
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"component": map[string]any{"type": "application", "name": Project, "version": version,
				"purl": "pkg:golang/" + main + "@" + version},
		},
		"components": comps,
	}
	return json.Marshal(doc)
}

// stdlibVersion turns "go1.23.4" (possibly followed by " X:experiment")
// into "1.23.4"; development toolchains ("devel ...") give "".
func stdlibVersion(goVersion string) string {
	v, _, _ := strings.Cut(goVersion, " ")
	if !strings.HasPrefix(v, "go") {
		return ""
	}
	return strings.TrimPrefix(v, "go")
}

// Enqueue queues an SBOM of the running binary for analysis. The snapshot
// has no version, so each start replaces the previous one: findings an
// upgrade fixed are resolved.
func Enqueue(ctx context.Context, inbox Inbox, version string, now time.Time) (bool, error) {
	info, _ := debug.ReadBuildInfo()
	bom, err := BOM(info, runtime.Version(), version)
	if err != nil {
		return false, err
	}
	received := now.UTC().Format(time.RFC3339)
	payload, err := json.Marshal(sbom.Upload{Project: Project, ReceivedAt: received, BOM: bom})
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(append([]byte("self\x00"+received+"\x00"), bom...))
	_, inserted, err := inbox.InsertInbox(ctx, finding.SourcePatchline, "sbom", hex.EncodeToString(sum[:]), payload)
	if err != nil {
		return false, fmt.Errorf("selfscan: queue sbom: %w", err)
	}
	return inserted, nil
}
