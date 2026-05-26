package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusgate/argus/pkg/scanner"
)

// ---------------------------------------------------------------------------
// prepareWorkDir
// ---------------------------------------------------------------------------

func TestPrepareWorkDir_Directory(t *testing.T) {
	// A plain directory should be returned as-is with a no-op cleanup.
	dir := t.TempDir()
	got, cleanup, err := prepareWorkDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()
	if got != dir {
		t.Errorf("expected same directory path; got %s", got)
	}
}

func TestPrepareWorkDir_MissingSource(t *testing.T) {
	_, _, err := prepareWorkDir("/nonexistent/path/argus-test-missing.tar.gz")
	if err == nil {
		t.Fatal("expected an error for a missing source; got nil")
	}
}

func TestPrepareWorkDir_UnsupportedExtension(t *testing.T) {
	// Write a dummy file with an unrecognised extension.
	f, err := os.CreateTemp(t.TempDir(), "archive*.rar")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, _, extractErr := prepareWorkDir(f.Name())
	if extractErr == nil {
		t.Fatal("expected an error for an unsupported archive format; got nil")
	}
}

// ---------------------------------------------------------------------------
// sanitisePath
// ---------------------------------------------------------------------------

func TestSanitisePath_Valid(t *testing.T) {
	base := t.TempDir()
	got, err := sanitisePath(base, "subdir/file.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Error("expected a non-empty path")
	}
}

func TestSanitisePath_Traversal(t *testing.T) {
	base := t.TempDir()
	_, err := sanitisePath(base, "../../etc/passwd")
	if err == nil {
		t.Fatal("expected a path-traversal error; got nil")
	}
}

// ---------------------------------------------------------------------------
// scanCmd — integration
// ---------------------------------------------------------------------------

func TestInstallCmd_NoFindings(t *testing.T) {
	// A directory containing only clean source should not trigger any output
	// or exit behaviour.
	dir := t.TempDir()
	writeFile := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("main.go", `package main
import "fmt"
func main() { fmt.Println("clean") }`)

	if err := scanCmd(dir, false); err != nil {
		t.Fatalf("scanCmd returned unexpected error: %v", err)
	}
}

func TestInstallCmd_WarningsOnly(t *testing.T) {
	// A WARNING-only finding should not block installation.
	dir := t.TempDir()
	// Write a file with a public IP address (WARNING severity).
	if err := os.WriteFile(filepath.Join(dir, "config.py"),
		[]byte(`endpoint = "203.0.113.42"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := scanCmd(dir, false); err != nil {
		t.Fatalf("warnings should not block installation; got error: %v", err)
	}
}

func TestInstallCmd_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.py"),
		[]byte(`endpoint = "203.0.113.42"`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Redirect stdout so we can capture the JSON.
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	installErr := scanCmd(dir, true)

	w.Close()
	os.Stdout = orig

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	r.Close()
	out := string(buf[:n])

	if installErr != nil {
		t.Fatalf("unexpected error: %v", installErr)
	}
	if out == "" {
		t.Fatal("expected JSON output on stdout; got nothing")
	}
	if out[0] != '{' {
		t.Errorf("expected JSON object; got: %.80s", out)
	}
}

// ---------------------------------------------------------------------------
// expandNestedArchives
// ---------------------------------------------------------------------------

func TestExpandNestedArchives_Zip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "vendor.zip")

	// Build a zip containing a Python file with an eval call.
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	entry, err := zw.Create("evil.py")
	if err != nil {
		t.Fatal(err)
	}
	entry.Write([]byte(`eval(user_input)`))
	zw.Close()
	zf.Close()

	if err := expandNestedArchives(dir, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	extractedDir := zipPath + "!"
	if _, err := os.Stat(extractedDir); err != nil {
		t.Fatalf("expected extracted dir %s; got: %v", extractedDir, err)
	}
	if _, err := os.Stat(filepath.Join(extractedDir, "evil.py")); err != nil {
		t.Fatal("expected evil.py in extracted directory")
	}
}

func TestExpandNestedArchives_DepthLimit(t *testing.T) {
	// Calling with depth >= maxNestDepth must be a no-op (no extraction).
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bomb.zip")
	zf, _ := os.Create(zipPath)
	zw := zip.NewWriter(zf)
	zw.Create("x.py")
	zw.Close()
	zf.Close()

	if err := expandNestedArchives(dir, maxNestDepth); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(zipPath + "!"); err == nil {
		t.Error("should not have extracted archive at max depth")
	}
}

func TestExpandNestedArchives_Integration(t *testing.T) {
	// End-to-end: nested archive findings surface via scanner.Scan.
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "vendor.zip")

	zf, _ := os.Create(zipPath)
	zw := zip.NewWriter(zf)
	entry, _ := zw.Create("setup.py")
	entry.Write([]byte(`import subprocess; subprocess.Popen(["curl", "203.0.113.1"])`))
	zw.Close()
	zf.Close()

	if err := expandNestedArchives(dir, 0); err != nil {
		t.Fatalf("expandNestedArchives error: %v", err)
	}

	report, err := scanner.Scan(dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !report.HasCritical {
		t.Error("expected critical finding inside nested archive; got none")
	}
	found := false
	for _, f := range report.Findings {
		if strings.Contains(f.File, "vendor.zip!") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding with 'vendor.zip!' in path; findings: %+v", report.Findings)
	}
}

// TestInstallCmd_CriticalNonTTY verifies that a critical finding in a
// non-interactive (non-TTY) session causes os.Exit(1). We test this by
// invoking scanCmd in a subprocess via os.Exec would require a separate
// binary build, so instead we validate the report directly and assert that
// confirmInstall returns false when stdin is not a TTY.
func TestInstallCmd_CriticalAutoDeclineNonTTY(t *testing.T) {
	// Replace stdin with a pipe (non-TTY) so isTTY returns false.
	origStdin := os.Stdin
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close()
	}()

	if confirmInstall() {
		t.Error("confirmInstall should return false on a non-TTY stdin")
	}
}
