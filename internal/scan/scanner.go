// Package scan walks a file or directory, loads certificates, and runs the
// weak-key and blocklist detectors over them.
package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaykumar/keyhole/internal/blocklist"
	"github.com/kaykumar/keyhole/internal/report"
	"github.com/kaykumar/keyhole/internal/weakkey"
)

// Options configures a scan.
type Options struct {
	Blocklist *blocklist.Blocklist
	MaxScalar uint64
}

// Run scans root (a file or directory) and returns any findings.
func Run(root string, opts Options) ([]report.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	collect := func(path string) {
		for _, lc := range loadCertsFromFile(path) {
			findings = append(findings, analyze(lc, opts)...)
		}
	}

	if !info.IsDir() {
		collect(root)
		return findings, nil
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if looksLikeCert(path) {
			collect(path)
		}
		return nil
	})
	return findings, err
}

func analyze(lc LoadedCert, opts Options) []report.Finding {
	var out []report.Finding

	if e, ok := opts.Blocklist.Match(lc.SHA256); ok {
		out = append(out, report.Finding{
			RuleID:   "compromised-cert",
			Severity: report.SeverityCritical,
			Title:    "Certificate matches a known-compromised fingerprint",
			Detail:   fmt.Sprintf("%s (source: %s)", e.Reason, e.Source),
			File:     lc.File,
			Subject:  lc.Cert.Subject.String(),
			Issuer:   lc.Cert.Issuer.String(),
			SHA256:   lc.SHA256,
		})
	}

	if res := weakkey.Check(lc.Cert.PublicKey, opts.MaxScalar); res.Weak {
		out = append(out, report.Finding{
			RuleID:   "weak-ec-key",
			Severity: report.SeverityCritical,
			Title:    "Recoverable low-entropy EC key",
			Detail:   fmt.Sprintf("public key equals %s*G on curve %s; the private scalar was recovered from the certificate alone", res.Scalar, res.Curve),
			File:     lc.File,
			Subject:  lc.Cert.Subject.String(),
			Issuer:   lc.Cert.Issuer.String(),
			SHA256:   lc.SHA256,
		})
	}

	return out
}

func skipDir(name string) bool {
	switch name {
	case ".git", ".svn", ".hg", "node_modules", "vendor":
		return true
	}
	return false
}

func looksLikeCert(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pem", ".crt", ".cer", ".der", ".cert", ".ca-bundle":
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	return base == "cacert.pem" || base == "ca-bundle.crt" || strings.Contains(base, "cacerts")
}
