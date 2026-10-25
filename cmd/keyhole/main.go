// Command keyhole scans files, directories, and trust bundles for weak and
// compromised certificate keys.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kaykumar/keyhole/internal/blocklist"
	"github.com/kaykumar/keyhole/internal/report"
	"github.com/kaykumar/keyhole/internal/scan"
)

// version is overridden at release time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		usage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text or sarif")
	output := fs.String("output", "-", "output file, or - for stdout")
	blPath := fs.String("blocklist", "", "path to a fingerprint blocklist JSON (defaults to the embedded list)")
	maxScalar := fs.Uint64("max-scalar", 0, "upper bound for the weak-key scalar search (0 uses the default)")
	failOn := fs.String("fail-on", "none", "minimum severity that exits non-zero: critical|high|warning|note|none")
	_ = fs.Parse(os.Args[2:])

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	var (
		bl  *blocklist.Blocklist
		err error
	)
	if *blPath != "" {
		bl, err = blocklist.Load(*blPath)
	} else {
		bl, err = blocklist.LoadDefault()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyhole: blocklist:", err)
		os.Exit(2)
	}

	findings, err := scan.Run(root, scan.Options{Blocklist: bl, MaxScalar: *maxScalar})
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyhole:", err)
		os.Exit(2)
	}

	w := os.Stdout
	if *output != "-" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "keyhole:", err)
			os.Exit(2)
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "sarif":
		err = report.WriteSARIF(w, findings, version)
	case "text":
		err = report.WriteText(w, findings)
	default:
		fmt.Fprintln(os.Stderr, "keyhole: unknown format:", *format)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyhole:", err)
		os.Exit(2)
	}

	if exceeds(findings, *failOn) {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "keyhole "+version+" - scan for weak and compromised certificate keys")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "usage: keyhole scan [flags] <path>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "flags:")
	fmt.Fprintln(os.Stderr, "  --format text|sarif   output format (default text)")
	fmt.Fprintln(os.Stderr, "  --output FILE         write to FILE instead of stdout")
	fmt.Fprintln(os.Stderr, "  --blocklist FILE      fingerprint blocklist JSON (default: embedded list)")
	fmt.Fprintln(os.Stderr, "  --max-scalar N        weak-key search bound (default 65536)")
	fmt.Fprintln(os.Stderr, "  --fail-on LEVEL       exit non-zero at critical|high|warning|note|none (default none)")
}

func rank(s report.Severity) int {
	switch s {
	case report.SeverityCritical:
		return 4
	case report.SeverityHigh:
		return 3
	case report.SeverityWarning:
		return 2
	case report.SeverityNote:
		return 1
	}
	return 0
}

func threshold(name string) int {
	switch strings.ToLower(name) {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning":
		return 2
	case "note":
		return 1
	}
	return 0 // "none" or unknown: never fail
}

func exceeds(findings []report.Finding, failOn string) bool {
	t := threshold(failOn)
	if t == 0 {
		return false
	}
	for _, f := range findings {
		if rank(f.Severity) >= t {
			return true
		}
	}
	return false
}
