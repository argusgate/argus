// Package scanner provides a lightweight Static Application Security Testing
// (SAST) module for the Argus security gateway. It inspects downloaded package
// source files before installation, flagging dangerous patterns that would
// otherwise bypass manifest-level checks.
package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Severity classifies the impact of a finding.
type Severity string

const (
	// Critical findings block installation and prompt the user.
	Critical Severity = "CRITICAL"
	// Warning findings are reported but do not block installation.
	Warning Severity = "WARNING"
)

// Finding represents a single rule match within a source file.
type Finding struct {
	File     string   // path relative to the scanned package root
	Line     int      // 1-based line number of the match
	Rule     string   // human-readable rule name
	Snippet  string   // the offending source line, trimmed of whitespace
	Severity Severity
}

// Report aggregates all findings for a scanned package directory.
type Report struct {
	PackageDir  string // absolute path of the scanned root
	Findings    []Finding
	HasCritical bool // true if any Finding carries Critical severity
}

// Scanner inspects the content of a single source file and returns all
// findings. Implementations are registered per file extension.
type Scanner interface {
	Scan(path string, content []byte) ([]Finding, error)
}

// maxFileBytes is a silent upper bound on individual file size. Files larger
// than this are skipped without error to guard against scanning build artefacts
// or embedded binary blobs.
const maxFileBytes = 1 << 20 // 1 MiB

// extensionScanners maps lowercase file extensions to their Scanner.
// Extensions absent from this map are silently skipped.
var extensionScanners = map[string]Scanner{
	".go":   &GoASTScanner{},
	".js":   &RegexScanner{rules: jsRules},
	".ts":   &RegexScanner{rules: jsRules},
	".mjs":  &RegexScanner{rules: jsRules},
	".py":   &RegexScanner{rules: pyRules},
	".sh":   &RegexScanner{rules: shellRules},
	".bash": &RegexScanner{rules: shellRules},
}

// Scan walks dir, dispatches each recognised source file to the appropriate
// Scanner, and returns an aggregated Report. The walk continues even when
// individual files cannot be read or parsed.
func Scan(dir string) (*Report, error) {
	report := &Report{PackageDir: dir}

	err := fs.WalkDir(os.DirFS(dir), ".", func(relPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable directories; continue walking
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(relPath))
		sc, ok := extensionScanners[ext]
		if !ok {
			return nil
		}

		absPath := filepath.Join(dir, relPath)
		content, err := os.ReadFile(absPath)
		if err != nil {
			report.Findings = append(report.Findings, Finding{
				File:     relPath,
				Line:     0,
				Rule:     "unreadable file",
				Snippet:  err.Error(),
				Severity: Warning,
			})
			return nil
		}

		findings, _ := sc.Scan(relPath, content)
		for _, f := range findings {
			if f.Severity == Critical {
				report.HasCritical = true
			}
			report.Findings = append(report.Findings, f)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking package directory: %w", err)
	}

	return report, nil
}

// ---------------------------------------------------------------------------
// GoASTScanner
// ---------------------------------------------------------------------------

// GoASTScanner uses the standard go/ast package to perform precise call-site
// analysis on Go source files, avoiding the false positives common in regex
// approaches.
type GoASTScanner struct{}

// goASTRule describes a package/function pair to flag in the AST.
type goASTRule struct {
	importPath string // full import path, e.g. "os/exec"
	fn         string // function name within that package, e.g. "Command"
	ruleName   string
	severity   Severity
}

var goRules = []goASTRule{
	{"os/exec", "Command", "exec.Command usage", Critical},
	{"os/exec", "CommandContext", "exec.Command usage", Critical},
	{"os", "StartProcess", "os.StartProcess usage", Critical},
	{"syscall", "Exec", "syscall.Exec usage", Critical},
	{"syscall", "ForkExec", "syscall.Exec usage", Critical},
	{"plugin", "Open", "plugin.Open usage (dynamic loading)", Critical},
	{"net", "Dial", "net.Dial usage (outbound connection)", Warning},
	{"net", "DialContext", "net.Dial usage (outbound connection)", Warning},
	{"net", "DialTCP", "net.Dial usage (outbound connection)", Warning},
	{"net", "DialUDP", "net.Dial usage (outbound connection)", Warning},
	{"net/http", "Get", "http.Get usage (outbound request)", Warning},
	{"net/http", "Post", "http.Post usage (outbound request)", Warning},
	{"net/http", "PostForm", "http.Post usage (outbound request)", Warning},
	{"net/http", "Head", "http.Head usage (outbound request)", Warning},
}

// Scan parses the Go source file and walks the AST looking for dangerous call
// expressions and uses of the unsafe package. On parse failure it falls back
// to the catch-all regex scanner so coverage is never zero.
func (g *GoASTScanner) Scan(path string, content []byte) ([]Finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, content, 0)
	if err != nil {
		// Syntax errors in third-party code are common; fall back silently.
		return (&RegexScanner{rules: catchAllRules}).Scan(path, content)
	}

	// Build a map from the local identifier used in this file to the full
	// import path. This handles aliased imports (e.g. import ex "os/exec")
	// so that ex.Command is caught just as exec.Command would be.
	importMap := make(map[string]string)
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		var localName string
		if imp.Name != nil {
			localName = imp.Name.Name // explicit alias or "."
		} else {
			parts := strings.Split(importPath, "/")
			localName = parts[len(parts)-1]
		}
		importMap[localName] = importPath
	}

	lines := strings.Split(string(content), "\n")
	var findings []Finding

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {

		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			resolvedPath := importMap[ident.Name]
			for _, rule := range goRules {
				if resolvedPath == rule.importPath && sel.Sel.Name == rule.fn {
					pos := fset.Position(node.Pos())
					findings = append(findings, Finding{
						File:     path,
						Line:     pos.Line,
						Rule:     rule.ruleName,
						Snippet:  snippetAt(lines, pos.Line),
						Severity: rule.severity,
					})
				}
			}

		// Flag any selector whose left-hand operand resolves to the unsafe
		// package, including when it has been imported under an alias.
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok && importMap[ident.Name] == "unsafe" {
				pos := fset.Position(node.Pos())
				findings = append(findings, Finding{
					File:     path,
					Line:     pos.Line,
					Rule:     "unsafe package usage",
					Snippet:  snippetAt(lines, pos.Line),
					Severity: Critical,
				})
			}
		}
		return true
	})

	return findings, nil
}

// ---------------------------------------------------------------------------
// RegexScanner
// ---------------------------------------------------------------------------

// regexRule associates a compiled pattern with metadata. The optional exclude
// field suppresses a match when it also appears on the same source line —
// used, for example, to allow yaml.load(..., Loader=yaml.SafeLoader).
type regexRule struct {
	re       *regexp.Regexp
	exclude  *regexp.Regexp // if non-nil and matches the line, the rule is skipped
	ruleName string
	severity Severity
}

// RegexScanner applies a slice of regex rules to a source file line by line.
type RegexScanner struct {
	rules []regexRule
}

// Scan checks each line of content against the receiver's rule set and returns
// all matches. High-entropy string detection runs as a second independent pass.
func (r *RegexScanner) Scan(path string, content []byte) ([]Finding, error) {
	lines := strings.Split(string(content), "\n")
	var findings []Finding

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		for _, rule := range r.rules {
			if !rule.re.MatchString(line) {
				continue
			}
			if rule.exclude != nil && rule.exclude.MatchString(line) {
				continue
			}

			// For raw IP rules, extract each address and skip the finding if
			// every address on the line falls within a private range.
			if rule.ruleName == "raw IP address" {
				if allPrivate(line) {
					continue
				}
			}

			findings = append(findings, Finding{
				File:     path,
				Line:     lineNum + 1,
				Rule:     rule.ruleName,
				Snippet:  trimmed,
				Severity: rule.severity,
			})
			break // one finding per rule pass per line is sufficient
		}

		// High-entropy string detection is language-agnostic.
		if f, ok := highEntropyFinding(path, lineNum+1, line); ok {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// ---------------------------------------------------------------------------
// Rule sets
// ---------------------------------------------------------------------------

// must compiles a regex and panics on error. Only called at package init time.
func must(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

// catchAllRules are applied to Go files that fail to parse.
var catchAllRules = []regexRule{
	{re: must(`\beval\s*\(`), ruleName: "eval() usage", severity: Critical},
	{re: must(`\bexec\s*\(`), ruleName: "exec() usage", severity: Critical},
	{re: must(`os\.system\s*\(`), ruleName: "os.system() usage", severity: Critical},
}

// pyRules covers Python-specific dangerous patterns.
var pyRules = []regexRule{
	{re: must(`\beval\s*\(`), ruleName: "eval() usage", severity: Critical},
	{re: must(`\bexec\s*\(`), ruleName: "exec() usage", severity: Critical},
	{re: must(`os\.system\s*\(`), ruleName: "os.system() usage", severity: Critical},
	{re: must(`subprocess\.(call|run|Popen)\s*\(`), ruleName: "subprocess usage", severity: Critical},
	{re: must(`pty\.spawn\s*\(`), ruleName: "pty.spawn() usage", severity: Critical},
	{re: must(`pickle\.loads?\s*\(`), ruleName: "pickle deserialisation", severity: Critical},
	// yaml.load is dangerous unless a safe Loader is explicitly supplied.
	// The exclude pattern suppresses the finding when SafeLoader or safe_load
	// appears on the same line.
	{
		re:       must(`yaml\.load\s*\(`),
		exclude:  must(`SafeLoader|safe_load`),
		ruleName: "unsafe yaml.load() — use yaml.safe_load or pass Loader=yaml.SafeLoader",
		severity: Critical,
	},
	{re: must(`(?i)(password|secret|api_key|token)\s*=\s*['"][^'"]{8,}`), ruleName: "hardcoded secret", severity: Critical},
	{re: must(`AKIA[0-9A-Z]{16}`), ruleName: "AWS access key", severity: Critical},
	{re: must(`ghp_[a-zA-Z0-9]{36}`), ruleName: "GitHub personal access token", severity: Critical},
	{re: must(`sk-[a-zA-Z0-9]{32,}`), ruleName: "OpenAI API key", severity: Critical},
	{re: must(`importlib\.import_module\s*\(`), ruleName: "dynamic import via importlib", severity: Warning},
	{re: must(`verify\s*=\s*False`), ruleName: "SSL certificate verification disabled", severity: Warning},
	{re: must(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), ruleName: "raw IP address", severity: Warning},
}

// jsRules covers JavaScript and TypeScript dangerous patterns.
var jsRules = []regexRule{
	{re: must(`\beval\s*\(`), ruleName: "eval() usage", severity: Critical},
	{re: must(`\bexec\s*\(`), ruleName: "exec() usage", severity: Critical},
	{re: must(`require\s*\(\s*['"]child_process`), ruleName: "child_process usage", severity: Critical},
	{re: must(`new\s+Function\s*\(`), ruleName: "new Function() usage (eval equivalent)", severity: Critical},
	{re: must(`vm\.runInNewContext\s*\(`), ruleName: "vm.runInNewContext() usage", severity: Critical},
	{re: must(`(?i)(password|secret|api_key|token)\s*=\s*['"][^'"]{8,}`), ruleName: "hardcoded secret", severity: Critical},
	{re: must(`AKIA[0-9A-Z]{16}`), ruleName: "AWS access key", severity: Critical},
	{re: must(`ghp_[a-zA-Z0-9]{36}`), ruleName: "GitHub personal access token", severity: Critical},
	{re: must(`sk-[a-zA-Z0-9]{32,}`), ruleName: "OpenAI API key", severity: Critical},
	{re: must(`verify\s*=\s*false`), ruleName: "SSL certificate verification disabled", severity: Warning},
	{re: must(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), ruleName: "raw IP address", severity: Warning},
}

// shellRules covers Bash/sh scripts; kept intentionally narrow to reduce noise.
var shellRules = []regexRule{
	{re: must(`\beval\s+`), ruleName: "eval usage", severity: Critical},
	{re: must(`\bexec\s+`), ruleName: "exec usage", severity: Critical},
	{re: must(`(?i)(password|secret|api_key|token)\s*=\s*['"]?[^'"$\s]{8,}`), ruleName: "hardcoded secret", severity: Critical},
	{re: must(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), ruleName: "raw IP address", severity: Warning},
}

// ---------------------------------------------------------------------------
// Private IP filtering
// ---------------------------------------------------------------------------

// privateRangePrefix matches the leading octets of RFC-1918, loopback, and
// unspecified address ranges.
var privateRangePrefix = regexp.MustCompile(
	`^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0$)`,
)

// ipTokens extracts all dotted-decimal tokens from a source line.
var ipTokens = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// allPrivate returns true when every IP address found in line is a private or
// loopback address. A line with no addresses also returns true (no public IPs).
func allPrivate(line string) bool {
	matches := ipTokens.FindAllString(line, -1)
	if len(matches) == 0 {
		return true
	}
	for _, addr := range matches {
		if !privateRangePrefix.MatchString(addr) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// High-entropy detection
// ---------------------------------------------------------------------------

const (
	entropyThreshold = 4.5
	minStringLength  = 20
)

// quotedString captures the inner content of single- or double-quoted literals
// long enough to warrant entropy analysis.
var quotedString = regexp.MustCompile(`['"]([^'"]{` + fmt.Sprintf("%d", minStringLength) + `,})['"]`)

// shannonEntropy returns the Shannon entropy (bits per character) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	total := float64(len([]rune(s)))
	var h float64
	for _, f := range freq {
		p := f / total
		h -= p * math.Log2(p)
	}
	return h
}

// isPrintableASCII returns true when every rune in s is a printable ASCII
// character. Non-printable or non-ASCII content is likely a binary blob.
func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// highEntropyFinding checks a single source line for high-entropy quoted
// strings and returns a Finding if one is detected.
func highEntropyFinding(path string, lineNum int, line string) (Finding, bool) {
	for _, m := range quotedString.FindAllStringSubmatch(line, -1) {
		s := m[1]
		if !isPrintableASCII(s) {
			continue
		}
		if shannonEntropy(s) >= entropyThreshold {
			return Finding{
				File:     path,
				Line:     lineNum,
				Rule:     "high-entropy string (possible obfuscated payload or embedded secret)",
				Snippet:  strings.TrimSpace(line),
				Severity: Warning,
			}, true
		}
	}
	return Finding{}, false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// snippetAt returns the source line at the given 1-based line number, trimmed
// of leading and trailing whitespace. Returns an empty string if out of range.
func snippetAt(lines []string, lineNum int) string {
	idx := lineNum - 1
	if idx < 0 || idx >= len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[idx])
}
