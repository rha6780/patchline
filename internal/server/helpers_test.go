package server

import "github.com/rha6780/patchline/internal/finding"

func observation(service string, registered bool) finding.Observation {
	return finding.Observation{
		Service: service, Registered: registered, Environment: "main",
		ComponentRef: "pkg:npm/express@4.17.1", ComponentName: "express", ComponentVersion: "4.17.1",
		VulnID: "CVE-2024-29041", Severity: finding.SeverityMedium,
	}
}
