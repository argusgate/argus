# Changelog

## Unreleased (v0.1.5)

- **Entropy false-positive fix** — high-entropy string detection now restricted to assignment expressions (`x = "..."`) rather than all quoted strings; eliminates noise from base64-encoded assets, test fixtures, and function-call arguments

---

## v0.1.4

- **Rust scanner** — `.rs` files: `unsafe` blocks, `Command::new` shell execution, hardcoded secrets, AWS/GitHub/OpenAI keys; FFI `extern "C"` blocks, `include_bytes!`/`include_str!` macros, raw IPs as warnings; `build.rs` always flagged as WARNING (Cargo compile-time execution)

---

## v0.1.3

- **Ruby scanner** — `.rb`, `.rake`, `.gemspec`: `eval`, `exec`, `system`, `spawn`, `IO.popen`, `Open3`, `Marshal.load`, unsafe `YAML.load`, backtick and `%x` shell execution, hardcoded secrets, AWS/GitHub/OpenAI keys; `open()` pipe, `send()`, `VERIFY_NONE` as warnings
- **Nested archive scanning** — `.tar.gz` and `.zip` files embedded inside a package are automatically extracted (up to 2 levels deep) and scanned; findings reference the archive path (e.g. `vendor.zip!/evil.py`)

---

## v0.1.2

- **Go network rules** — `net.Dial*` and `http.Get/Post/PostForm/Head` flagged as WARNING via the Go AST scanner (import-alias-aware)
- **`--json` flag** — structured JSON output to stdout; non-interactive; exits 1 on critical findings; pipe-friendly for CI integrations

> **Website snapshot** — the argusgate.dev content was published at this version. Ruby scanning and nested archive scanning (v0.1.3) are not yet reflected on the site.

---

## v0.1.1

- **`--version` flag** — prints `argus <version>` and exits cleanly; version injected at build time via ldflags
- **Warning snippets** — offending code lines now shown for WARNING findings in report output
- **Automated Homebrew updates** — release workflow updates `argusgate/homebrew-tap` formula (URL + SHA256) on every tagged release

---

## v0.1.0 — Initial release

- **Go AST scanner** — `exec.Command`, `os.StartProcess`, `syscall.Exec`, `plugin.Open`, `unsafe`; import aliases resolved
- **Python regex scanner** — `eval`, `exec`, `os.system`, `subprocess`, `pty.spawn`, `pickle.loads`, unsafe `yaml.load`, hardcoded secrets, AWS/GitHub/OpenAI keys, dynamic imports, SSL verification disabled, raw IPs
- **JavaScript / TypeScript scanner** — `eval`, `exec`, `child_process`, `new Function`, `vm.runInNewContext`, hardcoded secrets, AWS/GitHub/OpenAI keys, SSL disabled, raw IPs
- **Shell scanner** — `eval`, `exec`, hardcoded secrets, raw IPs
- **High-entropy string detection** — Shannon entropy ≥ 4.5 on quoted strings > 20 chars, all languages
- **Archive extraction** — `.tar.gz` and `.zip` with zip-slip protection and 100 MiB per-file cap
- **CI-safe** — non-interactive sessions auto-decline critical findings and exit 1
- **GitHub Actions Marketplace action** — `argusgate/argus@v0.1.0`
- **Homebrew tap** — `brew tap argusgate/tap && brew install argus`
