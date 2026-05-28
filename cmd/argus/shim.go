package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var defaultShimBinaries = []string{"pip", "pip3", "uv", "npm", "pnpm", "yarn", "cargo", "go", "gem"}

const (
	shimBlockBegin = "# >>> argus shims >>>"
	shimBlockEnd   = "# <<< argus shims <<<"
)

func shimCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: argus shim install|uninstall|which")
	}
	switch args[0] {
	case "install":
		return shimInstallCmd(args[1:])
	case "uninstall":
		return shimUninstallCmd(args[1:])
	case "which":
		if len(args) != 2 {
			return fmt.Errorf("usage: argus shim which <binary>")
		}
		real, err := findRealBinary(args[1])
		if err != nil {
			return err
		}
		fmt.Println(real)
		return nil
	default:
		return fmt.Errorf("usage: argus shim install|uninstall|which")
	}
}

func shimInstallCmd(args []string) error {
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("shim install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", filepath.Join(home, ".argus", "shims"), "directory to write shims into")
	shellName := fs.String("shell", detectShell(), "shell profile to update")
	managers := fs.String("managers", "all", "comma-separated managers to shim")
	dryRun := fs.Bool("dry-run", false, "print changes without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	shimDir := expandHome(*dir)
	bins := expandManagers(*managers)
	if len(bins) == 0 {
		return fmt.Errorf("no shim managers selected")
	}
	argusPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating argus binary: %w", err)
	}

	if *dryRun {
		fmt.Fprintf(os.Stdout, "would write %d shim(s) to %s\n", len(bins), shimDir)
		for _, bin := range bins {
			fmt.Fprintf(os.Stdout, "  %s\n", bin)
		}
		if profile := shellProfile(*shellName); profile != "" {
			fmt.Fprintf(os.Stdout, "would update profile %s\n", profile)
		}
		return nil
	}

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return err
	}
	for _, bin := range bins {
		content := renderShim(bin, argusPath, shimDir)
		if err := os.WriteFile(filepath.Join(shimDir, bin), []byte(content), 0o755); err != nil {
			return err
		}
	}
	if profile := shellProfile(*shellName); profile != "" {
		if err := ensureShimProfileBlock(profile, shimDir, *shellName); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stdout, "argus: installed %d shim(s) in %s\n", len(bins), shimDir)
	return nil
}

func shimUninstallCmd(args []string) error {
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("shim uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", filepath.Join(home, ".argus", "shims"), "shim directory to remove")
	shellName := fs.String("shell", detectShell(), "shell profile to update")
	dryRun := fs.Bool("dry-run", false, "print changes without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	shimDir := expandHome(*dir)
	if *dryRun {
		fmt.Fprintf(os.Stdout, "would remove shim directory %s\n", shimDir)
		if profile := shellProfile(*shellName); profile != "" {
			fmt.Fprintf(os.Stdout, "would remove argus block from %s\n", profile)
		}
		return nil
	}
	if err := os.RemoveAll(shimDir); err != nil {
		return err
	}
	if profile := shellProfile(*shellName); profile != "" {
		if err := removeShimProfileBlock(profile); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stdout, "argus: removed shims from %s\n", shimDir)
	return nil
}

func renderShim(binary, argusPath, shimDir string) string {
	return fmt.Sprintf(`#!/bin/sh
# argus-managed shim
ARGUS_BIN=%s
ARGUS_SHIM_DIR=%s
export ARGUS_SHIM_DIR

REAL=$("$ARGUS_BIN" shim which %s)
if [ -z "$REAL" ]; then
  echo "argus: could not locate real %s binary; run 'argus doctor'" >&2
  exit 127
fi

"$ARGUS_BIN" intercept %s "$@" || exit $?
exec "$REAL" "$@"
`, shellQuote(argusPath), shellQuote(shimDir), shellQuote(binary), binary, shellQuote(binary))
}

func expandManagers(value string) []string {
	if value == "" || value == "all" {
		return append([]string(nil), defaultShimBinaries...)
	}
	seen := make(map[string]bool)
	var bins []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		switch part {
		case "pip":
			for _, bin := range []string{"pip", "pip3"} {
				if !seen[bin] {
					bins = append(bins, bin)
					seen[bin] = true
				}
			}
		case "node":
			for _, bin := range []string{"npm", "pnpm", "yarn"} {
				if !seen[bin] {
					bins = append(bins, bin)
					seen[bin] = true
				}
			}
		case "":
			continue
		default:
			if !seen[part] {
				bins = append(bins, part)
				seen[part] = true
			}
		}
	}
	return bins
}

func findRealBinary(binary string) (string, error) {
	pathEntries := filepath.SplitList(os.Getenv("PATH"))
	skipDirs := make(map[string]bool)
	for _, dir := range filepath.SplitList(os.Getenv("ARGUS_SHIM_DIR")) {
		if dir != "" {
			skipDirs[filepath.Clean(dir)] = true
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("ARGUS_SHIM_DIRS")) {
		if dir != "" {
			skipDirs[filepath.Clean(dir)] = true
		}
	}

	for _, dir := range pathEntries {
		if dir == "" || skipDirs[filepath.Clean(dir)] {
			continue
		}
		candidate := filepath.Join(dir, binary)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		if isArgusShim(candidate) {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("real %s binary not found on PATH", binary)
}

func isArgusShim(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return strings.Contains(string(buf[:n]), "argus-managed shim")
}

func ensureShimProfileBlock(profile, shimDir, shellName string) error {
	data, _ := os.ReadFile(profile)
	text := string(data)
	if strings.Contains(text, shimBlockBegin) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(profile), 0o755); err != nil {
		return err
	}
	block := profileBlock(shimDir, shellName)
	f, err := os.OpenFile(profile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(text) > 0 && !strings.HasSuffix(text, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	_, err = f.WriteString(block)
	return err
}

func removeShimProfileBlock(profile string) error {
	data, err := os.ReadFile(profile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	text := string(data)
	start := strings.Index(text, shimBlockBegin)
	end := strings.Index(text, shimBlockEnd)
	if start < 0 || end < 0 || end < start {
		return nil
	}
	end += len(shimBlockEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return os.WriteFile(profile, []byte(text[:start]+text[end:]), 0o644)
}

func profileBlock(shimDir, shellName string) string {
	switch shellName {
	case "fish":
		return fmt.Sprintf("%s\nset -gx PATH %s $PATH\n%s\n", shimBlockBegin, shellQuote(shimDir), shimBlockEnd)
	default:
		return fmt.Sprintf("%s\nexport PATH=%s:$PATH\n%s\n", shimBlockBegin, shellQuote(shimDir), shimBlockEnd)
	}
}

func shellProfile(shellName string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch shellName {
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	case "sh":
		return filepath.Join(home, ".profile")
	default:
		return filepath.Join(home, ".profile")
	}
}

func detectShell() string {
	base := filepath.Base(os.Getenv("SHELL"))
	if base == "" {
		return "sh"
	}
	return base
}

func expandHome(path string) string {
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
