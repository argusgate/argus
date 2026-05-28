package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func shellCmd(args []string) error {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	managers := fs.String("managers", "all", "comma-separated managers to expose as shims")
	noPromptMarker := fs.Bool("no-prompt-marker", false, "do not modify the prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	shimDir, err := os.MkdirTemp("", "argus-shell-shims-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(shimDir)

	argusPath, err := os.Executable()
	if err != nil {
		return err
	}
	for _, bin := range expandManagers(*managers) {
		if err := os.WriteFile(filepath.Join(shimDir, bin), []byte(renderShim(bin, argusPath, shimDir)), 0o755); err != nil {
			return err
		}
	}

	shellPath := os.Getenv("SHELL")
	if shellPath == "" {
		shellPath = "/bin/sh"
	}
	cmd := exec.Command(shellPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"ARGUS_ACTIVE=1",
		"ARGUS_SHIM_DIR="+shimDir,
		"PATH="+shimDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	if !*noPromptMarker {
		cmd.Env = append(cmd.Env, "ARGUS_PROMPT_MARKER=[argus] ")
	}

	fmt.Fprintf(os.Stderr, "argus: starting protected shell with shims in %s\n", shimDir)
	err = cmd.Run()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitCode(exitErr.ExitCode())
	}
	return err
}
