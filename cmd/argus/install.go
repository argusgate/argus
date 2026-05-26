// Package main provides the Argus CLI entry point, including the install
// command which gates package installation behind manifest and SAST scanning.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/argusgate/argus/pkg/scanner"
)

// installCmd is the top-level handler for `argus install <source>`.
// source may be:
//   - a local .tar.gz or .zip archive
//   - a directory (e.g. a previously cloned git repository)
func installCmd(source string) error {
	// Resolve the package into a directory we can scan.
	workDir, cleanup, err := prepareWorkDir(source)
	if err != nil {
		return fmt.Errorf("preparing package: %w", err)
	}
	defer cleanup()

	// ── Stage 1: manifest scanner (pre-existing) ──────────────────────────
	// Placeholder for the existing manifest scanner integration.
	// if err := manifest.Scan(workDir); err != nil { return err }

	// ── Stage 2: SAST scan ───────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "argus: running SAST scan on %s\n", source)

	report, err := scanner.Scan(workDir)
	if err != nil {
		return fmt.Errorf("SAST scan failed: %w", err)
	}

	if len(report.Findings) > 0 {
		printReport(source, report)
	}

	if report.HasCritical {
		if !confirmInstall() {
			fmt.Fprintln(os.Stderr, "argus: installation aborted.")
			os.Exit(1)
		}
	}

	// ── Stage 3: hand off to package manager ─────────────────────────────
	// Placeholder: invoke the appropriate package manager here.
	fmt.Printf("argus: installing %s\n", source)
	return nil
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

	switch {
	case strings.HasSuffix(source, ".tar.gz") || strings.HasSuffix(source, ".tgz"):
		err = extractTarGz(source, tmp)
	case strings.HasSuffix(source, ".zip"):
		err = extractZip(source, tmp)
	default:
		err = fmt.Errorf("unsupported archive format: %s", filepath.Ext(source))
	}

	if err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp, cleanup, nil
}

// extractTarGz unpacks a .tar.gz archive into dst.
func extractTarGz(src, dst string) error {
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

	tr := tar.NewReader(gz)
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
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := writeFile(target, tr, hdr.FileInfo().Mode()); err != nil {
				return err
			}
		}
	}
	return nil
}

// extractZip unpacks a .zip archive into dst.
func extractZip(src, dst string) error {
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

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		writeErr := writeFile(target, rc, f.Mode())
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
// It caps the write at maxExtractBytes and strips setuid/setgid/sticky bits
// from the archive-supplied mode to prevent privilege-escalation via crafted
// archives.
func writeFile(path string, r io.Reader, mode os.FileMode) error {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o666)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(r, maxExtractBytes))
	return err
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
		}
	}

	if len(report.Findings) > 0 {
		fmt.Fprintln(os.Stderr)
	}
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
	if len(os.Args) < 3 || os.Args[1] != "install" {
		fmt.Fprintln(os.Stderr, "usage: argus install <package>")
		os.Exit(1)
	}
	if err := installCmd(os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "argus: %v\n", err)
		os.Exit(1)
	}
}
