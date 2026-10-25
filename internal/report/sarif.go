package report

import (
	"encoding/json"
	"io"
)

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF renders findings as a SARIF 2.1.0 document.
func WriteSARIF(w io.Writer, findings []Finding, version string) error {
	rulesSeen := map[string]bool{}
	rules := []sarifRule{}
	results := []sarifResult{}

	for _, f := range findings {
		if !rulesSeen[f.RuleID] {
			rulesSeen[f.RuleID] = true
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: sarifText{Text: f.Title},
			})
		}
		uri := f.File
		if uri == "" {
			uri = "unknown"
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Title + ": " + f.Detail},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}},
		})
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Keyhole",
				InformationURI: "https://github.com/kaykumar/keyhole",
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
