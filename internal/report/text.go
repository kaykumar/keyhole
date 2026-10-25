package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteText renders findings as a readable summary.
func WriteText(w io.Writer, findings []Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	for _, f := range findings {
		fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, "  %s\n", f.Detail)
		}
		if f.File != "" {
			fmt.Fprintf(w, "  file:    %s\n", f.File)
		}
		if f.Subject != "" {
			fmt.Fprintf(w, "  subject: %s\n", f.Subject)
		}
		if f.Issuer != "" {
			fmt.Fprintf(w, "  issuer:  %s\n", f.Issuer)
		}
		if f.SHA256 != "" {
			fmt.Fprintf(w, "  sha256:  %s\n", f.SHA256)
		}
		fmt.Fprintln(w)
	}
	_, err := fmt.Fprintf(w, "%d finding(s).\n", len(findings))
	return err
}
