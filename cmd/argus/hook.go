package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func hookCmd(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: argus hook install|uninstall claude")
	}
	action, agent := args[0], args[1]
	if agent != "claude" {
		return fmt.Errorf("unsupported hook agent %q", agent)
	}
	switch action {
	case "install":
		return hookInstallClaude(args[2:])
	case "uninstall":
		return hookUninstallClaude(args[2:])
	default:
		return fmt.Errorf("usage: argus hook install|uninstall claude")
	}
}

func hookInstallClaude(args []string) error {
	fs := flag.NewFlagSet("hook install claude", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	global := fs.Bool("global", false, "write user-level Claude settings")
	project := fs.Bool("project", false, "write project-level Claude settings")
	dryRun := fs.Bool("dry-run", false, "print changes without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	useGlobal := !*project || *global
	path := claudeSettingsPath(useGlobal)
	root, err := readJSONMap(path)
	if err != nil {
		return err
	}
	changed := addClaudeHook(root)
	if *dryRun {
		if changed {
			fmt.Fprintf(os.Stdout, "would install Claude hook in %s\n", path)
		} else {
			fmt.Fprintf(os.Stdout, "Claude hook already present in %s\n", path)
		}
		return nil
	}
	if !changed {
		fmt.Fprintf(os.Stdout, "argus: Claude hook already present in %s\n", path)
		return nil
	}
	if err := writeJSONMap(path, root); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "argus: installed Claude hook in %s\n", path)
	return nil
}

func hookUninstallClaude(args []string) error {
	fs := flag.NewFlagSet("hook uninstall claude", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	global := fs.Bool("global", false, "remove user-level Claude hook")
	project := fs.Bool("project", false, "remove project-level Claude hook")
	dryRun := fs.Bool("dry-run", false, "print changes without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	useGlobal := !*project || *global
	path := claudeSettingsPath(useGlobal)
	root, err := readJSONMap(path)
	if err != nil {
		return err
	}
	changed := removeClaudeHook(root)
	if *dryRun {
		if changed {
			fmt.Fprintf(os.Stdout, "would remove Claude hook from %s\n", path)
		} else {
			fmt.Fprintf(os.Stdout, "Claude hook not present in %s\n", path)
		}
		return nil
	}
	if !changed {
		fmt.Fprintf(os.Stdout, "argus: Claude hook not present in %s\n", path)
		return nil
	}
	if err := writeJSONMap(path, root); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "argus: removed Claude hook from %s\n", path)
	return nil
}

func claudeSettingsPath(global bool) string {
	if global {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".claude", "settings.json")
	}
	return filepath.Join(".claude", "settings.json")
}

func readJSONMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	return root, nil
}

func writeJSONMap(path string, root map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func addClaudeHook(root map[string]any) bool {
	pre := preToolUseSlice(root)
	if hookSliceContainsArgus(pre) {
		return false
	}
	pre = append(pre, map[string]any{
		"matcher": "Bash",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": "argus intercept hook",
			},
		},
	})
	setPreToolUseSlice(root, pre)
	return true
}

func removeClaudeHook(root map[string]any) bool {
	pre := preToolUseSlice(root)
	var kept []any
	changed := false
	for _, entry := range pre {
		if jsonContains(entry, "argus intercept hook") {
			changed = true
			continue
		}
		kept = append(kept, entry)
	}
	if changed {
		setPreToolUseSlice(root, kept)
	}
	return changed
}

func preToolUseSlice(root map[string]any) []any {
	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		return nil
	}
	pre, _ := hooks["PreToolUse"].([]any)
	return pre
}

func setPreToolUseSlice(root map[string]any, pre []any) {
	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		root["hooks"] = hooks
	}
	hooks["PreToolUse"] = pre
}

func hookSliceContainsArgus(pre []any) bool {
	for _, entry := range pre {
		if jsonContains(entry, "argus intercept hook") {
			return true
		}
	}
	return false
}

func jsonContains(v any, needle string) bool {
	data, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}
