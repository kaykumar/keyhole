// Package blocklist loads and matches a list of known-compromised certificate
// fingerprints (SHA-256 of the DER encoding). A default list is embedded, and
// callers may supply their own with Load so the fingerprints can be updated
// without rebuilding the binary.
package blocklist

import (
	_ "embed"
	"encoding/json"
	"os"
	"strings"
)

//go:embed default_blocklist.json
var defaultJSON []byte

// Entry is one known-compromised certificate.
type Entry struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Source string `json:"source"`
}

// Blocklist is a set of compromised fingerprints keyed by normalized SHA-256.
type Blocklist struct {
	byFP map[string]Entry
}

type document struct {
	Note    string  `json:"note"`
	Updated string  `json:"updated"`
	Entries []Entry `json:"entries"`
}

// LoadDefault returns the embedded default blocklist.
func LoadDefault() (*Blocklist, error) {
	return parse(defaultJSON)
}

// Load reads a blocklist JSON file from disk.
func Load(path string) (*Blocklist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

func parse(b []byte) (*Blocklist, error) {
	var doc document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	bl := &Blocklist{byFP: make(map[string]Entry, len(doc.Entries))}
	for _, e := range doc.Entries {
		fp := normalize(e.SHA256)
		if fp == "" {
			continue // unpopulated placeholder entry
		}
		bl.byFP[fp] = e
	}
	return bl, nil
}

func normalize(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// Match reports whether a fingerprint is on the blocklist.
func (b *Blocklist) Match(fingerprint string) (Entry, bool) {
	if b == nil {
		return Entry{}, false
	}
	e, ok := b.byFP[normalize(fingerprint)]
	return e, ok
}

// Size is the number of populated fingerprints in the list.
func (b *Blocklist) Size() int {
	if b == nil {
		return 0
	}
	return len(b.byFP)
}
