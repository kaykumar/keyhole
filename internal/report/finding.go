// Package report defines findings and renders them as human-readable text or
// SARIF 2.1.0 for GitHub code scanning and other SARIF consumers.
package report

// Severity ranks a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityWarning  Severity = "warning"
	SeverityNote     Severity = "note"
)

// Finding is one issue discovered during a scan.
type Finding struct {
	RuleID   string   // stable id, e.g. "weak-ec-key" or "compromised-cert"
	Severity Severity
	Title    string
	Detail   string
	File     string // path the finding was discovered in
	Subject  string // certificate subject DN, when applicable
	Issuer   string // certificate issuer DN, when applicable
	SHA256   string // certificate fingerprint, when applicable
}
