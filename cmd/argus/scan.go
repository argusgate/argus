// Package main provides the Argus CLI entry point, including the install
// command which gates package installation behind manifest and SAST scanning.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/argusgate/argus/pkg/scanner"
)

var version = "dev"

// scanCmd is the top-level handler for `argus scan <source>`.
// source may be:
//   - a local .tar.gz or .zip archive
//   - a directory (e.g. a previously cloned git repository)
func scanCmd(source string, jsonOut bool) error {
	report, cleanup, err := scanPath(source)
	if err != nil {
		return err
	}
	defer cleanup()

	if !jsonOut {
		fmt.Fprintf(os.Stderr, "argus: running SAST scan on %s\n", source)
	}

	if jsonOut {
		printReportJSON(source, report)
		if report.HasCritical {
			return exitCode(1)
		}
		return nil
	}

	if len(report.Findings) > 0 {
		printReport(source, report)
	}

	if report.HasCritical {
		if !confirmInstall() {
			fmt.Fprintln(os.Stderr, "argus: scan blocked — critical findings present.")
			return exitCode(1)
		}
	}

	return nil
}

// scanPath resolves source into a directory, runs the scanner, and returns the
// report plus a cleanup function. Callers own cleanup and process exit handling.
func scanPath(source string) (*scanner.Report, func(), error) {
	workDir, cleanup, err := prepareWorkDir(source)
	if err != nil {
		return nil, nil, fmt.Errorf("preparing package: %w", err)
	}

	report, err := scanner.Scan(workDir)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("SAST scan failed: %w", err)
	}
	return report, cleanup, nil
}

// ---------------------------------------------------------------------------
// Unpacking
// ---------------------------------------------------------------------------

// prepareWorkDir resolves source into a temporary directory ready for scanning.
// It returns the directory path and a cleanup function that removes it.
// For a plain directory, no copy is made; cleanup is a no-op.
func prepareWorkDir(source string) (dir string, cleanup func(), err error) {
	info, err := os.Stat(source)
	if err != nil {
		return "", nil, fmt.Errorf("accessing source: %w", err)
	}

	if info.IsDir() {
		// Git clone or pre-extracted directory — scan in place.
		return source, func() {}, nil
	}

	tmp, err := os.MkdirTemp("", "argus-sast-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp directory: %w", err)
	}
	cleanup = func() { os.RemoveAll(tmp) }

	limits := newExtractLimits()
	extractFn, ok := archiveExtractorFor(source)
	if !ok {
		err = fmt.Errorf("unsupported archive format: %s", filepath.Ext(source))
	} else {
		err = extractFn(source, tmp, limits)
	}

	if err != nil {
		cleanup()
		return "", nil, err
	}
	if err = expandNestedArchives(tmp, 0, limits); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp, cleanup, nil
}

// maxNestDepth caps how many layers of nested archives are expanded to guard
// against archive bombs constructed from recursively embedded archives.
const maxNestDepth = 2

// extractLimits tracks cumulative resource usage across an entire extraction
// session. All archive operations within a single prepareWorkDir call share
// one instance so that the caps apply globally, not per-archive.
type extractLimits struct {
	bytesWritten int64
	fileCount    int
	maxBytes     int64 // ceiling on total decompressed bytes
	maxFiles     int   // ceiling on total number of extracted files
}

// newExtractLimits returns an extractLimits configured with production-safe
// defaults: 500 MiB total decompressed size and 50,000 files.
func newExtractLimits() *extractLimits {
	return &extractLimits{
		maxBytes: 500 << 20, // 500 MiB
		maxFiles: 50_000,
	}
}

// addFile records one more extracted file and returns an error if the session
// file-count ceiling has been exceeded.
func (l *extractLimits) addFile() error {
	l.fileCount++
	if l.fileCount > l.maxFiles {
		return fmt.Errorf("archive contains too many files (session limit: %d)", l.maxFiles)
	}
	return nil
}

// addBytes records n additional decompressed bytes and returns an error if the
// session byte ceiling has been exceeded.
func (l *extractLimits) addBytes(n int64) error {
	l.bytesWritten += n
	if l.bytesWritten > l.maxBytes {
		return fmt.Errorf("total extraction size exceeded %d MiB session limit", l.maxBytes>>20)
	}
	return nil
}

// expandNestedArchives walks dir and extracts any archive files it finds,
// placing the contents in a sibling directory named "<archive>!" so that
// scanner findings reference the archive name in their file path.
// Expansion is limited to maxNestDepth levels. The shared limits instance
// enforces cumulative resource caps across all nested extractions.
func expandNestedArchives(dir string, depth int, limits *extractLimits) error {
	if depth >= maxNestDepth {
		return nil
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		extractFn, ok := archiveExtractorFor(path)
		if !ok {
			return nil
		}
		subDir := path + "!"
		if mkErr := os.MkdirAll(subDir, 0o755); mkErr != nil {
			return nil // skip; do not abort the whole walk
		}
		if exErr := extractFn(path, subDir, limits); exErr != nil {
			os.RemoveAll(subDir)
			return fmt.Errorf("nested archive %s: %w", filepath.Base(path), exErr)
		}
		return expandNestedArchives(subDir, depth+1, limits)
	})
}

type archiveExtractor func(string, string, *extractLimits) error

// archiveExtractorFor returns the extractor for supported archive formats. Some
// package-manager archive extensions are format aliases: wheels are zip files,
// and Rust crates are gzip-compressed tar archives.
func archiveExtractorFor(path string) (archiveExtractor, bool) {
	lp := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lp, ".tar.gz") || strings.HasSuffix(lp, ".tgz") || strings.HasSuffix(lp, ".crate"):
		return extractTarGz, true
	case strings.HasSuffix(lp, ".zip") || strings.HasSuffix(lp, ".whl"):
		return extractZip, true
	case strings.HasSuffix(lp, ".gem"):
		return extractGem, true
	default:
		return nil, false
	}
}

// extractTarGz unpacks a .tar.gz archive into dst, updating limits with each
// extracted file. Returns an error if either the per-file or session cap is hit.
func extractTarGz(src, dst string, limits *extractLimits) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading gzip stream: %w", err)
	}
	defer gz.Close()

	return extractTar(gz, dst, limits)
}

func extractTar(r io.Reader, dst string, limits *extractLimits) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		target, err := sanitisePath(dst, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := limits.addFile(); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := writeFile(target, tr, hdr.FileInfo().Mode(), limits); err != nil {
				return err
			}
		}
	}
	return nil
}

// extractGem unpacks the source payload from a Ruby .gem archive. A .gem is a
// tar file whose data.tar.gz member contains the files to scan.
func extractGem(src, dst string, limits *extractLimits) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading gem entry: %w", err)
		}
		if filepath.Base(hdr.Name) != "data.tar.gz" {
			continue
		}
		gz, err := gzip.NewReader(tr)
		if err != nil {
			return fmt.Errorf("reading gem data.tar.gz: %w", err)
		}
		defer gz.Close()
		return extractTar(gz, dst, limits)
	}
	return fmt.Errorf("gem archive missing data.tar.gz")
}

// extractZip unpacks a .zip archive into dst, updating limits with each
// extracted file. Returns an error if either the per-file or session cap is hit.
func extractZip(src, dst string, limits *extractLimits) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		target, err := sanitisePath(dst, f.Name)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := limits.addFile(); err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		writeErr := writeFile(target, rc, f.Mode(), limits)
		rc.Close()
		if writeErr != nil {
			return writeErr
		}
	}
	return nil
}

// sanitisePath constructs the target path for an archive entry, rejecting
// path traversal (zip-slip) attempts. filepath.Join resolves any ".." components,
// so we compare the cleaned result against the base directory to detect escapes.
func sanitisePath(base, entryName string) (string, error) {
	target := filepath.Join(base, entryName)
	cleanBase := filepath.Clean(base) + string(os.PathSeparator)
	cleanTarget := filepath.Clean(target) + string(os.PathSeparator)
	if !strings.HasPrefix(cleanTarget, cleanBase) {
		return "", fmt.Errorf("archive entry escapes destination: %s", entryName)
	}
	return filepath.Clean(target), nil
}

// maxExtractBytes is the per-file ceiling applied during archive extraction to
// guard against zip-bomb payloads and runaway decompression streams.
const maxExtractBytes = 100 << 20 // 100 MiB

// writeFile writes r into a new file at path with the given permissions.
// It caps the write at maxExtractBytes per file and strips setuid/setgid/sticky
// bits from the archive-supplied mode to prevent privilege-escalation via
// crafted archives. The session limits are updated with the bytes written;
// an error is returned if the session total would be exceeded.
func writeFile(path string, r io.Reader, mode os.FileMode, limits *extractLimits) error {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o666)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(r, maxExtractBytes+1))
	if err != nil {
		return err
	}
	if n > maxExtractBytes {
		_ = out.Truncate(maxExtractBytes)
		return fmt.Errorf("extracted file exceeded %d MiB per-file limit", maxExtractBytes>>20)
	}
	return limits.addBytes(n)
}

// ---------------------------------------------------------------------------
// User-facing output
// ---------------------------------------------------------------------------

// printReport writes the SAST findings to stderr in a readable format.
func printReport(packageName string, report *scanner.Report) {
	critCount := 0
	for _, f := range report.Findings {
		if f.Severity == scanner.Critical {
			critCount++
		}
	}

	if critCount > 0 {
		fmt.Fprintf(os.Stderr, "\nARGUS SAST — %d critical finding(s) in %s\n\n", critCount, packageName)
	}

	for _, f := range report.Findings {
		if f.Severity == scanner.Critical {
			fmt.Fprintf(os.Stderr, "  CRITICAL  %s:%d   %s\n", f.File, f.Line, f.Rule)
			if f.Snippet != "" {
				fmt.Fprintf(os.Stderr, "            > %s\n\n", f.Snippet)
			}
		}
	}

	for _, f := range report.Findings {
		if f.Severity == scanner.Warning {
			fmt.Fprintf(os.Stderr, "  WARNING   %s:%d   %s\n", f.File, f.Line, f.Rule)
			if f.Snippet != "" {
				fmt.Fprintf(os.Stderr, "            > %s\n", f.Snippet)
			}
		}
	}

	if len(report.Findings) > 0 {
		fmt.Fprintln(os.Stderr)
	}
}

// printReportJSON writes the SAST findings to stdout as a JSON object.
// When --json is set, no other output is written to stdout so the caller can
// pipe the result directly into jq or another tool.
func printReportJSON(packageName string, report *scanner.Report) {
	type jFinding struct {
		File     string           `json:"file"`
		Line     int              `json:"line"`
		Rule     string           `json:"rule"`
		Snippet  string           `json:"snippet,omitempty"`
		Severity scanner.Severity `json:"severity"`
	}
	type jReport struct {
		Package     string     `json:"package"`
		HasCritical bool       `json:"has_critical"`
		Findings    []jFinding `json:"findings"`
	}

	findings := make([]jFinding, len(report.Findings))
	for i, f := range report.Findings {
		findings[i] = jFinding{File: f.File, Line: f.Line, Rule: f.Rule, Snippet: f.Snippet, Severity: f.Severity}
	}

	out := jReport{Package: packageName, HasCritical: report.HasCritical, Findings: findings}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// confirmInstall prompts the user for explicit consent when critical findings
// are present. In non-interactive environments (no TTY) it returns false
// automatically, so CI pipelines never silently install flagged packages.
func confirmInstall() bool {
	if !isTTY(os.Stdin) {
		fmt.Fprintln(os.Stderr, "argus: non-interactive session — blocking installation due to critical findings.")
		return false
	}
	fmt.Fprint(os.Stderr, "Install anyway? [y/N]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(scanner.Text())
		return answer == "y" || answer == "Y"
	}
	return false
}

// isTTY returns true when f is connected to a terminal.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	// ModeCharDevice is set for TTY file descriptors on Unix and Windows.
	return (info.Mode() & os.ModeCharDevice) != 0
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	os.Exit(runCLI(os.Args[1:]))
}
