package main

import (
	"errors"
	"fmt"
	"os"
)

type exitStatus struct {
	code int
}

func (e exitStatus) Error() string {
	return ""
}

func exitCode(code int) error {
	return exitStatus{code: code}
}

func runCLI(args []string) int {
	if err := runCommand(args); err != nil {
		var status exitStatus
		if errors.As(err, &status) {
			return status.code
		}
		fmt.Fprintf(os.Stderr, "argus: %v\n", err)
		return 1
	}
	return 0
}

func runCommand(args []string) error {
	if len(args) >= 1 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Println("argus", version)
		return nil
	}
	if len(args) == 0 {
		return usageError()
	}

	if args[0] == "--json" || args[0] == "-json" {
		if len(args) < 2 || args[1] != "scan" {
			return usageError()
		}
		source, _, err := parseScanArgs(args[2:])
		if err != nil {
			return err
		}
		return scanCmd(source, true)
	}

	switch args[0] {
	case "scan":
		source, jsonOut, err := parseScanArgs(args[1:])
		if err != nil {
			return err
		}
		return scanCmd(source, jsonOut)
	case "intercept":
		return interceptCmd(args[1:])
	case "shim":
		return shimCmd(args[1:])
	case "shell":
		return shellCmd(args[1:])
	case "hook":
		return hookCmd(args[1:])
	case "doctor":
		return doctorCmd(args[1:])
	default:
		return usageError()
	}
}

func parseScanArgs(args []string) (string, bool, error) {
	jsonOut := false
	var sources []string
	for _, a := range args {
		if a == "--json" || a == "-json" {
			jsonOut = true
			continue
		}
		sources = append(sources, a)
	}
	if len(sources) != 1 {
		return "", false, usageError()
	}
	return sources[0], jsonOut, nil
}

func usageError() error {
	fmt.Fprintln(os.Stderr, "usage: argus <command> [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  scan [--json] <source>")
	fmt.Fprintln(os.Stderr, "  intercept <manager> [args...]")
	fmt.Fprintln(os.Stderr, "  shim install|uninstall|which")
	fmt.Fprintln(os.Stderr, "  shell")
	fmt.Fprintln(os.Stderr, "  hook install|uninstall claude")
	fmt.Fprintln(os.Stderr, "  doctor")
	return exitCode(1)
}
