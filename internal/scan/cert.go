package scan

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
)

// LoadedCert is a parsed certificate with where it came from.
type LoadedCert struct {
	Cert   *x509.Certificate
	File   string
	SHA256 string
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// loadCertsFromFile parses a file as PEM (possibly many blocks) or DER and
// returns every certificate it contains. Files that hold no certificate yield
// an empty slice, not an error, so a scan over mixed content keeps going.
func loadCertsFromFile(path string) []LoadedCert {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var out []LoadedCert

	// PEM first: a bundle may contain several CERTIFICATE blocks.
	rest := data
	foundPEM := false
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				foundPEM = true
				out = append(out, LoadedCert{Cert: c, File: path, SHA256: fingerprint(c.Raw)})
			}
		}
	}
	if foundPEM {
		return out
	}

	// Otherwise try a single DER-encoded certificate.
	if c, err := x509.ParseCertificate(data); err == nil {
		out = append(out, LoadedCert{Cert: c, File: path, SHA256: fingerprint(c.Raw)})
	}
	return out
}
