package main

import (
	"os"
	"path/filepath"
	"testing"
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
// installCmd — integration
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

	if err := installCmd(dir, false); err != nil {
		t.Fatalf("installCmd returned unexpected error: %v", err)
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
	if err := installCmd(dir, false); err != nil {
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

	installErr := installCmd(dir, true)

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

// TestInstallCmd_CriticalNonTTY verifies that a critical finding in a
// non-interactive (non-TTY) session causes os.Exit(1). We test this by
// invoking installCmd in a subprocess via os.Exec would require a separate
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
