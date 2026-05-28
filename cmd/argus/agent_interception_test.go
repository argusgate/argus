package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusgate/argus/pkg/scanner"
)

func TestPrepareWorkDir_WheelArchive(t *testing.T) {
	dir := t.TempDir()
	whl := filepath.Join(dir, "evil-0.1.0-py3-none-any.whl")
	writeZip(t, whl, map[string]string{
		"evil.py": `eval(user_input)`,
	})

	workDir, cleanup, err := prepareWorkDir(whl)
	if err != nil {
		t.Fatalf("prepareWorkDir returned error: %v", err)
	}
	defer cleanup()

	report, err := scanner.Scan(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.HasCritical {
		t.Fatal("expected critical finding from .whl archive")
	}
}

func TestPrepareWorkDir_CrateArchive(t *testing.T) {
	dir := t.TempDir()
	crate := filepath.Join(dir, "evil-0.1.0.crate")
	writeTarGz(t, crate, map[string]string{
		"evil-0.1.0/src/lib.rs": `fn main() { unsafe { do_bad(); } }`,
	})

	workDir, cleanup, err := prepareWorkDir(crate)
	if err != nil {
		t.Fatalf("prepareWorkDir returned error: %v", err)
	}
	defer cleanup()

	report, err := scanner.Scan(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.HasCritical {
		t.Fatal("expected critical finding from .crate archive")
	}
}

func TestPrepareWorkDir_GemArchive(t *testing.T) {
	dir := t.TempDir()
	gem := filepath.Join(dir, "evil-0.1.0.gem")
	writeGem(t, gem, map[string]string{
		"lib/evil.rb": `eval(user_input)`,
	})

	workDir, cleanup, err := prepareWorkDir(gem)
	if err != nil {
		t.Fatalf("prepareWorkDir returned error: %v", err)
	}
	defer cleanup()

	report, err := scanner.Scan(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.HasCritical {
		t.Fatal("expected critical finding from .gem archive")
	}
}

func TestResolvePipTargets_RequirementsFile(t *testing.T) {
	dir := t.TempDir()
	req := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(req, []byte("requests==2.31.0\n# comment\nflask\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	targets, err := resolvePipTargets([]string{"-r", req})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].spec != "requests==2.31.0" || targets[1].spec != "flask" {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}

func TestParseHookCommand_FindsPackageManagerInCompoundCommand(t *testing.T) {
	manager, args, ok := parseHookCommand("cd app && npm install lodash")
	if !ok {
		t.Fatal("expected hook parser to find npm install")
	}
	if manager != "npm" || strings.Join(args, " ") != "install lodash" {
		t.Fatalf("unexpected parse result: manager=%s args=%v", manager, args)
	}
}

func TestInterceptManager_LocalPathBlocks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(`eval(user_input)`), 0o644); err != nil {
		t.Fatal(err)
	}

	err := interceptManager("pip", []string{"install", dir}, 1)
	var status exitStatus
	if !errors.As(err, &status) || status.code != 1 {
		t.Fatalf("expected exit status 1, got %v", err)
	}
}

func TestFindRealBinary_SkipsArgusShim(t *testing.T) {
	base := t.TempDir()
	shimDir := filepath.Join(base, "shim")
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shimDir, "npm"), []byte("#!/bin/sh\n# argus-managed shim\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(realDir, "npm")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_SHIM_DIR", shimDir)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)

	got, err := findRealBinary("npm")
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("expected %s, got %s", real, got)
	}
}

func TestHookInstallClaudeProject(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldwd)

	if err := hookInstallClaude([]string{"--project"}); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dir, ".claude", "settings.json")
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "PreToolUse") || !strings.Contains(string(data), "argus intercept hook") {
		t.Fatalf("Claude settings missing hook: %s", data)
	}
	if err := hookInstallClaude([]string{"--project"}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "argus intercept hook") != 1 {
		t.Fatalf("hook install should be idempotent: %s", data)
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	writeTarEntries(t, tw, files)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeGem(t *testing.T, path string, files map[string]string) {
	t.Helper()
	var inner bytes.Buffer
	gz := gzip.NewWriter(&inner)
	tw := tar.NewWriter(gz)
	writeTarEntries(t, tw, files)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	outer := tar.NewWriter(f)
	if err := outer.WriteHeader(&tar.Header{
		Name: "data.tar.gz",
		Mode: 0o644,
		Size: int64(inner.Len()),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := outer.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := outer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTarEntries(t *testing.T, tw *tar.Writer, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
}
