package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func doctorCmd(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, "argus doctor")
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "Shims:")
	for _, bin := range defaultShimBinaries {
		status, detail := shimStatus(bin)
		fmt.Fprintf(os.Stdout, "  %-5s %-10s %s\n", bin, status, detail)
	}
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "Agent hooks:")
	if path := claudeSettingsPath(true); fileContains(path, "argus intercept hook") {
		fmt.Fprintf(os.Stdout, "  claude protected  %s\n", path)
	} else {
		fmt.Fprintln(os.Stdout, "  claude missing    install with: argus hook install claude")
	}
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "Warnings:")
	fmt.Fprintln(os.Stdout, "  PATH shims do not catch absolute binary paths, python -m pip, curl | sh, or PATH resets.")
	return nil
}

func shimStatus(binary string) (string, string) {
	first, ok := firstOnPath(binary)
	if !ok {
		return "missing", "not found on PATH"
	}
	if isArgusShim(first) {
		real, err := findRealBinary(binary)
		if err != nil {
			return "broken", err.Error()
		}
		return "protected", first + " -> " + real
	}
	return "unprotected", first
}

func firstOnPath(binary string) (string, bool) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, binary)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, true
		}
	}
	return "", false
}

func fileContains(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}
