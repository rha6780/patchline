package selfscan

import (
	"context"
	"encoding/json"
	"runtime/debug"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/sbom"
)

func TestBOM(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Path: "github.com/rha6780/patchline", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "golang.org/x/net", Version: "v0.30.0"},
			{Path: "example.com/old", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1"}},
			{Path: "example.com/local", Version: "v1.0.0", Replace: &debug.Module{Path: "../local"}},
		},
	}
	data, err := BOM(info, "go1.23.4 X:loopvar", "v1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbom.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range doc.Components {
		got[c.PURL] = c.Ecosystem + " " + c.Package
	}
	want := map[string]string{
		"pkg:golang/stdlib@1.23.4":            "Go stdlib",
		"pkg:golang/golang.org/x/net@v0.30.0": "Go golang.org/x/net",
		"pkg:golang/example.com/fork@v1.0.1":  "Go example.com/fork",
	}
	if len(got) != len(want) {
		t.Fatalf("components %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if _, err := BOM(nil, "go1.23.4", ""); err == nil {
		t.Error("nil build info: want an error")
	}
	if v := stdlibVersion("devel go1.24-abcdef"); v != "" {
		t.Errorf("devel toolchain: got %q", v)
	}
}

type inbox struct {
	source, event string
	payload       []byte
}

func (b *inbox) InsertInbox(_ context.Context, source, eventType, _ string, payload []byte) (int64, bool, error) {
	b.source, b.event, b.payload = source, eventType, payload
	return 1, true, nil
}

func TestEnqueue(t *testing.T) {
	var b inbox
	if _, err := Enqueue(context.Background(), &b, "v1.2.0", time.Now()); err != nil {
		t.Fatal(err)
	}
	if b.source != finding.SourcePatchline || b.event != "sbom" {
		t.Fatalf("queued as %s/%s", b.source, b.event)
	}
	var up sbom.Upload
	if err := json.Unmarshal(b.payload, &up); err != nil {
		t.Fatal(err)
	}
	if up.Project != Project || up.Version != "" {
		t.Errorf("project %q version %q", up.Project, up.Version)
	}
	doc, err := sbom.Parse(up.BOM)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Components {
		if c.Package == "stdlib" {
			return
		}
	}
	t.Errorf("no stdlib component in %v", doc.Components)
}
