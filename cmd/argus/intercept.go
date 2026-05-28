package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type installTarget struct {
	spec    string
	display string
}

func interceptCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: argus intercept <manager> [args...]")
	}
	if args[0] == "hook" {
		return interceptHook()
	}
	return interceptManager(args[0], args[1:], 1)
}

func interceptManager(manager string, args []string, blockCode int) error {
	rawManager := manager
	manager = normalizeManager(manager)
	if manager == "" {
		return fmt.Errorf("unsupported package manager: %s", rawManager)
	}
	if !isInstallCommand(manager, args) {
		return nil
	}

	command := manager + " " + strings.Join(args, " ")
	if os.Getenv("ARGUS_ALLOW") == "1" {
		auditOverride("shim", command, "ARGUS_ALLOW=1")
		return nil
	}

	targets, err := resolveInstallTargets(manager, args)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}

	tmp, err := os.MkdirTemp("", "argus-intercept-*")
	if err != nil {
		return fmt.Errorf("creating intercept temp directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	blocked := false
	for _, target := range targets {
		paths, err := materializeTarget(manager, target, tmp)
		if err != nil {
			return err
		}
		for _, path := range paths {
			report, cleanup, err := scanPath(path)
			if err != nil {
				return err
			}
			if len(report.Findings) > 0 {
				printReport(target.display, report)
			}
			if report.HasCritical {
				blocked = true
			}
			cleanup()
		}
	}
	if blocked {
		fmt.Fprintln(os.Stderr, "argus: install blocked - critical findings present.")
		return exitCode(blockCode)
	}
	return nil
}

func interceptHook() error {
	var payload struct {
		ToolInput struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading hook payload: %w", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("parsing hook payload: %w", err)
	}

	manager, args, ok := parseHookCommand(payload.ToolInput.Command)
	if !ok {
		return nil
	}
	if os.Getenv("ARGUS_ALLOW") == "1" {
		auditOverride("claude-hook", payload.ToolInput.Command, "ARGUS_ALLOW=1")
		return nil
	}
	return interceptManager(manager, args, 2)
}

func parseHookCommand(command string) (string, []string, bool) {
	fields := strings.Fields(command)
	for i := 0; i < len(fields); i++ {
		if i+3 < len(fields) && isPythonBinary(fields[i]) && fields[i+1] == "-m" && fields[i+2] == "pip" {
			args := fields[i+3:]
			if isInstallCommand("pip", args) {
				return "pip", args, true
			}
		}
		manager := normalizeManager(filepath.Base(fields[i]))
		if manager == "" {
			continue
		}
		args := fields[i+1:]
		if isInstallCommand(manager, args) {
			return manager, args, true
		}
	}
	return "", nil, false
}

func isPythonBinary(name string) bool {
	base := filepath.Base(name)
	return base == "python" || base == "python3"
}

func normalizeManager(manager string) string {
	switch filepath.Base(manager) {
	case "pip", "pip3":
		return "pip"
	case "uv":
		return "uv"
	case "npm":
		return "npm"
	case "pnpm":
		return "pnpm"
	case "yarn":
		return "yarn"
	case "cargo":
		return "cargo"
	case "go":
		return "go"
	case "gem":
		return "gem"
	default:
		return ""
	}
}

func isInstallCommand(manager string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch manager {
	case "pip":
		return args[0] == "install"
	case "uv":
		return args[0] == "add" || (len(args) > 1 && args[0] == "pip" && args[1] == "install")
	case "npm":
		return args[0] == "install" || args[0] == "i" || args[0] == "add" || args[0] == "ci"
	case "pnpm":
		return args[0] == "install" || args[0] == "add" || args[0] == "dlx"
	case "yarn":
		return args[0] == "install" || args[0] == "add"
	case "cargo":
		return args[0] == "install" || args[0] == "add"
	case "go":
		return args[0] == "install" || args[0] == "get"
	case "gem":
		return args[0] == "install"
	default:
		return false
	}
}

func resolveInstallTargets(manager string, args []string) ([]installTarget, error) {
	switch manager {
	case "pip":
		return resolvePipTargets(args[1:])
	case "uv":
		if args[0] == "add" {
			return resolveGenericTargets(args[1:], true)
		}
		return resolvePipTargets(args[2:])
	case "npm", "pnpm", "yarn":
		return resolveNodeTargets(args)
	case "cargo":
		return resolveCargoTargets(args)
	case "go":
		return resolveGenericTargets(args[1:], false)
	case "gem":
		return resolveGenericTargets(args[1:], true)
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", manager)
	}
}

func resolvePipTargets(args []string) ([]installTarget, error) {
	var targets []installTarget
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-r" || arg == "--requirement" {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a file path", arg)
			}
			reqTargets, err := parseRequirementFile(args[i+1])
			if err != nil {
				return nil, err
			}
			targets = append(targets, reqTargets...)
			i++
			continue
		}
		if strings.HasPrefix(arg, "--requirement=") {
			reqTargets, err := parseRequirementFile(strings.TrimPrefix(arg, "--requirement="))
			if err != nil {
				return nil, err
			}
			targets = append(targets, reqTargets...)
			continue
		}
		if arg == "-e" || arg == "--editable" {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a target", arg)
			}
			targets = append(targets, newInstallTarget(args[i+1]))
			i++
			continue
		}
		if shouldSkipOptionValue(arg) {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		targets = append(targets, newInstallTarget(arg))
	}
	return targets, nil
}

func resolveNodeTargets(args []string) ([]installTarget, error) {
	if len(args) == 0 {
		return nil, nil
	}
	sub := args[0]
	if sub == "ci" || (sub == "install" && len(args) == 1) {
		return []installTarget{newInstallTarget(".")}, nil
	}
	return resolveGenericTargets(args[1:], true)
}

func resolveCargoTargets(args []string) ([]installTarget, error) {
	var targets []installTarget
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--path" {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--path requires a value")
			}
			targets = append(targets, newInstallTarget(args[i+1]))
			i++
			continue
		}
		if shouldSkipOptionValue(arg) {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		targets = append(targets, newInstallTarget(arg))
	}
	return targets, nil
}

func resolveGenericTargets(args []string, defaultDot bool) ([]installTarget, error) {
	var targets []installTarget
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if shouldSkipOptionValue(arg) {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		targets = append(targets, newInstallTarget(arg))
	}
	if len(targets) == 0 && defaultDot {
		targets = append(targets, newInstallTarget("."))
	}
	return targets, nil
}

func shouldSkipOptionValue(arg string) bool {
	switch arg {
	case "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host",
		"-c", "--constraint", "-t", "--target", "--prefix", "--src", "--platform",
		"--implementation", "--abi", "--python-version", "--registry", "--cache",
		"--cwd", "--manifest-path", "--package", "-p", "--version", "-v", "--source":
		return true
	default:
		return false
	}
}

func parseRequirementFile(path string) ([]installTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading requirements file %s: %w", path, err)
	}
	var targets []installTarget
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		targets = append(targets, newInstallTarget(line))
	}
	return targets, nil
}

func newInstallTarget(spec string) installTarget {
	return installTarget{spec: spec, display: spec}
}

func materializeTarget(manager string, target installTarget, tmp string) ([]string, error) {
	if target.spec == "" {
		return nil, nil
	}
	if _, err := os.Stat(target.spec); err == nil {
		return []string{target.spec}, nil
	}
	if _, ok := archiveExtractorFor(target.spec); ok {
		return []string{target.spec}, nil
	}

	dir := filepath.Join(tmp, safeFileName(manager+"-"+target.spec))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := downloadPackage(manager, target.spec, dir); err != nil {
		return nil, err
	}
	archives, err := findArchives(dir)
	if err != nil {
		return nil, err
	}
	if len(archives) == 0 {
		return nil, fmt.Errorf("no downloadable archive produced for %s", target.spec)
	}
	return archives, nil
}

func downloadPackage(manager, spec, dir string) error {
	switch manager {
	case "pip":
		real, err := findRealBinary("pip")
		if err != nil {
			return err
		}
		return run(real, "download", spec, "-d", dir)
	case "uv":
		real, err := findRealBinary("uv")
		if err != nil {
			return err
		}
		return run(real, "pip", "download", spec, "-d", dir)
	case "npm", "pnpm", "yarn":
		real, err := findRealBinary("npm")
		if err != nil {
			return err
		}
		return runInDir(dir, real, "pack", spec)
	case "cargo":
		return downloadCrate(spec, dir)
	case "go":
		return downloadGoModule(spec, dir)
	case "gem":
		real, err := findRealBinary("gem")
		if err != nil {
			return err
		}
		return runInDir(dir, real, "fetch", spec)
	default:
		return fmt.Errorf("remote resolution not implemented for %s", manager)
	}
}

func downloadCrate(spec, dir string) error {
	name, version := splitAtVersion(spec)
	if version == "" {
		latest, err := latestCrateVersion(name)
		if err != nil {
			return err
		}
		version = latest
	}
	url := fmt.Sprintf("https://static.crates.io/crates/%s/%s-%s.crate", name, name, version)
	return downloadURL(url, filepath.Join(dir, fmt.Sprintf("%s-%s.crate", name, version)))
}

func splitAtVersion(spec string) (string, string) {
	parts := strings.SplitN(spec, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return spec, ""
}

func latestCrateVersion(name string) (string, error) {
	resp, err := http.Get("https://crates.io/api/v1/crates/" + name)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crates.io returned %s for %s", resp.Status, name)
	}
	var payload struct {
		Crate struct {
			MaxVersion string `json:"max_version"`
		} `json:"crate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.Crate.MaxVersion == "" {
		return "", fmt.Errorf("could not resolve latest crate version for %s", name)
	}
	return payload.Crate.MaxVersion, nil
}

func downloadURL(url, dst string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("download failed for %s: %s", url, resp.Status)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func downloadGoModule(spec, dir string) error {
	real, err := findRealBinary("go")
	if err != nil {
		return err
	}
	cmd := exec.Command(real, "mod", "download", "-json", spec)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("go mod download failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return err
	}
	var payload struct {
		Zip string `json:"Zip"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return err
	}
	if payload.Zip == "" {
		return fmt.Errorf("go mod download did not return a module zip")
	}
	dst := filepath.Join(dir, filepath.Base(payload.Zip))
	return copyFile(payload.Zip, dst)
}

func findArchives(dir string) ([]string, error) {
	var archives []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if _, ok := archiveExtractorFor(path); ok {
			archives = append(archives, path)
		}
		return nil
	})
	return archives, err
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runInDir(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func safeFileName(s string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "@", "_", " ", "_")
	return replacer.Replace(s)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func auditOverride(source, command, reason string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s source=%s cwd=%s reason=%q command=%q\n",
		time.Now().UTC().Format(time.RFC3339), source, mustGetwd(), reason, command)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}
