package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/sdk"
)

var (
	ErrGuardrailFilesExceeded   = errors.New("guardrail exceeded: patch touches too many files")
	ErrGuardrailAddedExceeded   = errors.New("guardrail exceeded: too many added lines")
	ErrGuardrailRemovedExceeded = errors.New("guardrail exceeded: too many removed lines")
)

// Guardrails constrain patch application blast radius.
type Guardrails struct {
	MaxFiles        int
	MaxAddedLines   int
	MaxRemovedLines int
}

func (g Guardrails) Validate(plan PatchPlan) error {
	if g.MaxFiles > 0 && len(plan.Patches) > g.MaxFiles {
		return fmt.Errorf("%w: max=%d actual=%d", ErrGuardrailFilesExceeded, g.MaxFiles, len(plan.Patches))
	}
	var added, removed int
	for _, p := range plan.Patches {
		added += p.AddedLines
		removed += p.RemovedLines
	}
	if g.MaxAddedLines > 0 && added > g.MaxAddedLines {
		return fmt.Errorf("%w: max=%d actual=%d", ErrGuardrailAddedExceeded, g.MaxAddedLines, added)
	}
	if g.MaxRemovedLines > 0 && removed > g.MaxRemovedLines {
		return fmt.Errorf("%w: max=%d actual=%d", ErrGuardrailRemovedExceeded, g.MaxRemovedLines, removed)
	}
	return nil
}

// Patch describes a deterministic file-level rewrite.
type Patch struct {
	FilePath     string
	RuleID       string
	Description  string
	AddedLines   int
	RemovedLines int
	Before       string
	After        string
}

// PatchPlan is the output of plan_code.
type PatchPlan struct {
	Patches []Patch
}

// ApplyResult captures applied patch metadata.
type ApplyResult struct {
	AppliedFiles []string
	// OriginalContent maps file path -> pre-apply content, used for Rollback.
	OriginalContent map[string]string
}

// VerificationResult captures verify_code outcome.
type VerificationResult struct {
	Ok       bool
	Messages []string
}

// fixerFunc applies a single rule to source and returns modified source + whether it changed.
type fixerFunc func(src string) (string, bool)

type fileFixer struct {
	ext   string
	rule  string
	desc  string
	fixer fixerFunc
}

var fixerRegistry = []fileFixer{
	{ext: ".go", rule: "WEB-SEC-001", desc: "Add baseline HTTP security header middleware", fixer: applyGoHeaderMiddleware},
	{ext: ".js", rule: "WEB-SEC-001", desc: "Add baseline HTTP security header middleware", fixer: applyExpressHelmetMiddleware},
	{ext: ".go", rule: "AI-LOG-001", desc: "Redact sensitive prompt/response logging to metadata-only", fixer: applyGoAILogRedaction},
	{ext: ".py", rule: "AI-LOG-001", desc: "Redact sensitive prompt/response logging to metadata-only", fixer: applyPythonAILogRedaction},
	{ext: ".js", rule: "AI-LOG-001", desc: "Redact sensitive prompt/response logging to metadata-only", fixer: applyJSAILogRedaction},
	{ext: ".go", rule: "SEC-003", desc: "Rewrite hardcoded secret to environment variable lookup", fixer: applyGoSecretRewrite},
	{ext: ".py", rule: "SEC-003", desc: "Rewrite hardcoded secret to environment variable lookup", fixer: applyPythonSecretRewrite},
	{ext: ".js", rule: "SEC-003", desc: "Rewrite hardcoded secret to environment variable lookup", fixer: applyJSSecretRewrite},
	{ext: ".go", rule: "SEC-002", desc: "Rewrite string-concatenated SQL to parameterized query", fixer: applyGoSQLParameterization},
	{ext: ".py", rule: "SEC-002", desc: "Rewrite string-concatenated SQL to parameterized query", fixer: applyPythonSQLParameterization},
	{ext: ".js", rule: "SEC-002", desc: "Rewrite string-concatenated SQL to parameterized query", fixer: applyJSSQLParameterization},
	{ext: ".go", rule: "SEC-001", desc: "Harden shell-based subprocess invocation", fixer: applyGoSubprocessHardening},
	{ext: ".py", rule: "SEC-001", desc: "Harden shell-based subprocess invocation", fixer: applyPythonSubprocessHardening},
	{ext: ".js", rule: "SEC-001", desc: "Harden shell-based subprocess invocation", fixer: applyJSSubprocessHardening},
}

type PatchEngine struct{}

func NewPatchEngine() *PatchEngine {
	return &PatchEngine{}
}

func (e *PatchEngine) Plan(req sdk.ToolRequest) (PatchPlan, error) {
	if req.WorkspaceRoot == "" {
		return PatchPlan{Patches: nil}, nil
	}

	var patches []Patch
	err := filepath.WalkDir(req.WorkspaceRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".go" && ext != ".js" && ext != ".py" {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".test.js") || strings.HasSuffix(path, "_test.py") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		before := string(raw)

		for _, ff := range fixerRegistry {
			if ff.ext != ext {
				continue
			}
			after, changed := ff.fixer(before)
			if changed {
				added, removed := lineDelta(before, after)
				patches = append(patches, Patch{
					FilePath:     path,
					RuleID:       ff.rule,
					Description:  ff.desc,
					AddedLines:   added,
					RemovedLines: removed,
					Before:       before,
					After:        after,
				})
				before = after
			}
		}
		return nil
	})
	if err != nil {
		return PatchPlan{}, err
	}

	return PatchPlan{Patches: patches}, nil
}

func (e *PatchEngine) Apply(plan PatchPlan) (ApplyResult, error) {
	files := make([]string, 0, len(plan.Patches))
	originals := make(map[string]string, len(plan.Patches))
	for _, p := range plan.Patches {
		if _, recorded := originals[p.FilePath]; !recorded {
			if existing, err := os.ReadFile(p.FilePath); err == nil {
				originals[p.FilePath] = string(existing)
			} else if os.IsNotExist(err) {
				originals[p.FilePath] = ""
			} else {
				return ApplyResult{}, err
			}
		}
		if err := os.WriteFile(p.FilePath, []byte(p.After), 0o644); err != nil {
			return ApplyResult{}, err
		}
		files = append(files, p.FilePath)
	}
	return ApplyResult{AppliedFiles: files, OriginalContent: originals}, nil
}

// Rollback restores files to the content captured in result.OriginalContent.
// Used after a failed verification to leave the workspace in its pre-apply state.
func (e *PatchEngine) Rollback(result ApplyResult) error {
	for path, original := range result.OriginalContent {
		if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
			return fmt.Errorf("rollback %s: %w", path, err)
		}
	}
	return nil
}

// ApplyAndVerify applies the plan, then runs Verify. If verification fails,
// the patches are rolled back automatically and the failed verification is returned.
func (e *PatchEngine) ApplyAndVerify(plan PatchPlan, req sdk.ToolRequest) (ApplyResult, VerificationResult, error) {
	result, err := e.Apply(plan)
	if err != nil {
		return result, VerificationResult{}, err
	}
	verification := e.Verify(req)
	if !verification.Ok {
		if rbErr := e.Rollback(result); rbErr != nil {
			verification.Messages = append(verification.Messages, fmt.Sprintf("rollback failed: %v", rbErr))
			return result, verification, rbErr
		}
		verification.Messages = append(verification.Messages, fmt.Sprintf("rolled back %d file(s) after failed verification", len(result.OriginalContent)))
	}
	return result, verification, nil
}

func (e *PatchEngine) Verify(req sdk.ToolRequest) VerificationResult {
	var messages []string
	if req.WorkspaceRoot == "" {
		return VerificationResult{Ok: true, Messages: []string{"verification passed: no workspace root provided"}}
	}

	if cmdStr := strings.TrimSpace(req.InputString("command")); cmdStr != "" {
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Dir = req.WorkspaceRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			messages = append(messages, fmt.Sprintf("verification command failed: %s", cmdStr))
			if len(out) > 0 {
				messages = append(messages, fmt.Sprintf("command output: %s", strings.TrimSpace(string(out))))
			}
			return VerificationResult{Ok: false, Messages: messages}
		}
		messages = append(messages, fmt.Sprintf("verification command passed: %s", cmdStr))
	}

	plan, err := e.Plan(req)
	if err != nil {
		return VerificationResult{Ok: false, Messages: []string{fmt.Sprintf("verification planning failed: %v", err)}}
	}
	if len(plan.Patches) > 0 {
		messages = append(messages, fmt.Sprintf("verification failed: remediation not idempotent, %d patch(es) still planned", len(plan.Patches)))
		return VerificationResult{Ok: false, Messages: messages}
	}

	messages = append(messages, "verification passed: no remaining deterministic remediation patches")
	return VerificationResult{Ok: true, Messages: messages}
}

func lineDelta(before, after string) (added, removed int) {
	b := strings.Split(before, "\n")
	a := strings.Split(after, "\n")
	if len(a) > len(b) {
		added = len(a) - len(b)
	}
	if len(b) > len(a) {
		removed = len(b) - len(a)
	}
	return added, removed
}

func applyGoHeaderMiddleware(src string) (string, bool) {
	if !strings.Contains(src, "http.ListenAndServe(") {
		return src, false
	}
	if strings.Contains(src, "securityHeadersMiddleware(") {
		return src, false
	}

	out := src
	out = strings.ReplaceAll(out, "http.ListenAndServe(\":8080\", mux)", "http.ListenAndServe(\":8080\", securityHeadersMiddleware(mux))")
	out = strings.ReplaceAll(out, "http.ListenAndServe(addr, mux)", "http.ListenAndServe(addr, securityHeadersMiddleware(mux))")
	out = strings.ReplaceAll(out, "http.ListenAndServe(\":8080\", router)", "http.ListenAndServe(\":8080\", securityHeadersMiddleware(router))")
	out = strings.ReplaceAll(out, "http.ListenAndServe(addr, router)", "http.ListenAndServe(addr, securityHeadersMiddleware(router))")

	if out == src {
		return src, false
	}

	helper := `

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
`

	if !strings.Contains(out, "func securityHeadersMiddleware(") {
		out += helper
	}
	return out, true
}

func applyExpressHelmetMiddleware(src string) (string, bool) {
	if !strings.Contains(src, "express()") {
		return src, false
	}
	if strings.Contains(src, "app.use(helmet())") {
		return src, false
	}

	out := src
	addedRequire := false
	if strings.Contains(out, "const express = require('express')") && !strings.Contains(out, "const helmet = require('helmet')") {
		out = strings.Replace(out, "const express = require('express')", "const express = require('express')\nconst helmet = require('helmet')", 1)
		addedRequire = true
	}
	if strings.Contains(out, "const app = express()") {
		out = strings.Replace(out, "const app = express()", "const app = express()\napp.use(helmet())", 1)
		return out, true
	}

	if addedRequire {
		return out, true
	}
	return src, false
}

// applyGoAILogRedaction detects common Go logging patterns that
// log raw prompt/response content and redacts them to metadata-only.
func applyGoAILogRedaction(src string) (string, bool) {
	if !strings.Contains(src, "log.") && !strings.Contains(src, "fmt.") {
		return src, false
	}
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		if isGologRedactable(line) {
			replacement := redactGoLog(line)
			if replacement != line {
				changed = true
				out = append(out, replacement)
				continue
			}
		}
		out = append(out, line)
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

func isGologRedactable(line string) bool {
	aiKeywords := []string{"prompt", "response", "completion", "message", "input", "output"}
	for _, kw := range aiKeywords {
		if strings.Contains(strings.ToLower(line), kw) {
			return true
		}
	}
	return false
}

func redactGoLog(line string) string {
	trimmed := strings.TrimSpace(line)

	// Detect: log.Printf("...%s...", promptVar)
	if strings.HasPrefix(trimmed, "log.Printf(") || strings.HasPrefix(trimmed, "fmt.Printf(") {
		if !strings.Contains(trimmed, "%s") && !strings.Contains(trimmed, "%+v") && !strings.Contains(trimmed, "%v") {
			return line
		}
		if strings.Contains(trimmed, "redacted") || strings.Contains(trimmed, "len(") {
			return line
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		return indent + "// REDACTED: raw content log stripped for security (AI-LOG-001)"
	}

	// Detect: log.Println("response:", response)
	if (strings.HasPrefix(trimmed, "log.Println(") || strings.HasPrefix(trimmed, "fmt.Println(")) &&
		(strings.Contains(trimmed, "prompt") || strings.Contains(trimmed, "response") ||
			strings.Contains(trimmed, "completion") || strings.Contains(trimmed, "message")) {
		if strings.Contains(trimmed, "redacted") || strings.Contains(trimmed, "len(") {
			return line
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		return indent + "// REDACTED: raw content log stripped for security (AI-LOG-001)"
	}

	return line
}

// applyPythonAILogRedaction redacts Python logging of raw AI content.
func applyPythonAILogRedaction(src string) (string, bool) {
	if !strings.Contains(src, "logging.") && !strings.Contains(src, "print(") {
		return src, false
	}
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))

	aiKeywords := []string{"prompt", "response", "completion", "message", "input", "output"}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		shouldRedact := false
		if strings.HasPrefix(trimmed, "logging.") || strings.HasPrefix(trimmed, "print(") {
			for _, kw := range aiKeywords {
				if strings.Contains(strings.ToLower(trimmed), kw) {
					shouldRedact = true
					break
				}
			}
		}
		if shouldRedact {
			if strings.Contains(trimmed, "redacted") || strings.Contains(trimmed, "len(") {
				out = append(out, line)
				continue
			}
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			changed = true
			out = append(out, indent+"# REDACTED: raw content log stripped for security (AI-LOG-001)")
			continue
		}
		out = append(out, line)
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

// applyJSAILogRedaction redacts JS logging of raw AI content.
func applyJSAILogRedaction(src string) (string, bool) {
	if !strings.Contains(src, "console.") && !strings.Contains(src, "logger.") && !strings.Contains(src, ".info(") && !strings.Contains(src, ".error(") {
		return src, false
	}
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))

	aiKeywords := []string{"prompt", "response", "completion", "message", "input", "output"}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		shouldRedact := false
		if strings.HasPrefix(trimmed, "console.") || strings.HasPrefix(trimmed, "logger.") || strings.Contains(trimmed, ".info(") || strings.Contains(trimmed, ".error(") {
			for _, kw := range aiKeywords {
				if strings.Contains(strings.ToLower(trimmed), kw) && !strings.Contains(trimmed, "// REDACTED") {
					shouldRedact = true
					break
				}
			}
		}
		if shouldRedact {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			changed = true
			out = append(out, indent+"// REDACTED: raw content log stripped for security (AI-LOG-001)")
			continue
		}
		out = append(out, line)
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

var sensitiveVarPatterns = []string{
	"password",
	"secret",
	"api_key",
	"apikey",
	"api.key",
	"token",
	"access_key",
	"accesskey",
	"private_key",
	"auth_token",
	"db_password",
	"connection_string",
}

// toEnvName converts a Go/Python/JS variable name to an env var name.
// e.g., "dbPassword" -> "DB_PASSWORD"
func toEnvName(varName string) string {
	var parts []string
	current := strings.Builder{}
	for _, r := range varName {
		if r >= 'A' && r <= 'Z' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
			}
			current.Reset()
			current.WriteRune(r)
			continue
		}
		if r == '_' || r == '.' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
			}
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return strings.ToUpper(strings.Join(parts, "_"))
}

func isSensitiveVar(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, p := range sensitiveVarPatterns {
		if lower == p || strings.HasSuffix(lower, "."+p) || strings.HasSuffix(lower, "_"+p) {
			return true
		}
	}
	return false
}

// applyGoSecretRewrite replaces hardcoded secret strings with os.Getenv("NAME").
func applyGoSecretRewrite(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Must have = and a string literal
		if !strings.Contains(trimmed, "=") || !strings.Contains(trimmed, `"`) {
			out = append(out, line)
			continue
		}
		// Skip if already using os.Getenv or has SEC-003 comment
		if strings.Contains(trimmed, "os.Getenv(") || strings.Contains(trimmed, "// SEC-003") {
			out = append(out, line)
			continue
		}

		// Find = position
		idx := strings.Index(trimmed, "=")
		if idx < 0 {
			out = append(out, line)
			continue
		}

		// Extract variable name (before =)
		varName := strings.TrimSpace(trimmed[:idx])
		// Strip := or = (assignment operators) from right side
		varName = strings.TrimRight(varName, ":=")
		// Strip var/const/let prefixes
		for _, kw := range []string{"var ", "const "} {
			varName = strings.TrimPrefix(varName, kw)
		}
		varName = strings.TrimSpace(varName)

		// Check if sensitive variable
		if !isSensitiveVar(varName) {
		out = append(out, line)
		continue
	}

		// Get the right side (after =)
		rhs := strings.TrimSpace(trimmed[idx+1:])
		// Must have a string literal on right side
		if !strings.HasPrefix(rhs, `"`) {
			out = append(out, line)
			continue
		}

		// Build replacement
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		envName := toEnvName(varName)
		origPrefix := strings.TrimSpace(trimmed[:idx+1])

		changed = true
		out = append(out, fmt.Sprintf(`%s%s os.Getenv("%s")`, indent, origPrefix, envName))
		out = append(out, fmt.Sprintf(`%s// TODO: Set %s env var via deployment config. (SEC-003)`, indent, envName))
		continue
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

// applyPythonSecretRewrite replaces hardcoded secret strings with os.environ.get("NAME").
func applyPythonSecretRewrite(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !strings.Contains(trimmed, `"`) || !strings.Contains(trimmed, `=`) {
			out = append(out, line)
			continue
		}
		if strings.Contains(trimmed, "os.environ.get(") || strings.Contains(trimmed, "# SEC-003") {
			out = append(out, line)
			continue
		}

		idx := strings.Index(trimmed, `=`)
		varName := strings.TrimSpace(trimmed[:idx])
		if !isSensitiveVar(varName) {
			out = append(out, line)
			continue
		}

		rhs := strings.TrimSpace(trimmed[idx+1:])
		if !strings.HasPrefix(rhs, `"`) && !strings.HasPrefix(rhs, `'`) {
			out = append(out, line)
			continue
		}

		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		envName := toEnvName(varName)
		changed = true
		out = append(out, fmt.Sprintf(`%s%s os.environ.get("%s")`, indent, strings.TrimSpace(trimmed[:idx+1]), envName))
		out = append(out, fmt.Sprintf(`%s# TODO: Set %s env var via deployment config. (SEC-003)`, indent, envName))
		continue
	}

	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

// applyJSSecretRewrite replaces hardcoded secret strings with process.env.NAME.
func applyJSSecretRewrite(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !strings.Contains(trimmed, `"`) || !strings.Contains(trimmed, `=`) {
			out = append(out, line)
			continue
		}
		if strings.Contains(trimmed, "process.env.") || strings.Contains(trimmed, "// SEC-003") {
			out = append(out, line)
			continue
		}

		idx := strings.Index(trimmed, `=`)
		varName := strings.TrimSpace(trimmed[:idx])
		for _, kw := range []string{"let ", "const ", "var "} {
			varName = strings.TrimPrefix(varName, kw)
		}
		varName = strings.TrimSpace(varName)

		if !isSensitiveVar(varName) {
			out = append(out, line)
			continue
		}

		rhs := strings.TrimSpace(trimmed[idx+1:])
		if !strings.HasPrefix(rhs, `"`) && !strings.HasPrefix(rhs, `'`) && !strings.HasPrefix(rhs, "`") {
			out = append(out, line)
			continue
		}

		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		envName := toEnvName(varName)
		origPrefix := strings.TrimSpace(trimmed[:idx+1])
		changed = true
		out = append(out, fmt.Sprintf(`%s%s process.env.%s`, indent, origPrefix, envName))
		out = append(out, fmt.Sprintf(`%s// TODO: Set %s env var via deployment config. (SEC-003)`, indent, envName))
		continue
	}

	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

func applyGoSQLParameterization(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "Query(") && !strings.Contains(line, "Exec(") {
			continue
		}
		if !strings.Contains(line, `"`) || !strings.Contains(line, `+`) {
			continue
		}
		if strings.Contains(line, "SEC-002") || strings.Contains(line, "?") {
			continue
		}
		idxPlus := strings.Index(line, "+")
		idxClose := strings.LastIndex(line, ")")
		if idxPlus < 0 || idxClose < idxPlus {
			continue
		}
		arg := strings.TrimSpace(strings.TrimRight(line[idxPlus+1:idxClose], ","))
		if arg == "" || strings.Contains(arg, " ") {
			continue
		}
		beforePlus := line[:idxPlus]
		quotePos := strings.LastIndex(beforePlus, `"`)
		if quotePos < 0 {
			continue
		}
		prefix := line[:quotePos]
		suffix := line[idxClose:]
		lines[i] = prefix + `?", ` + arg + suffix
		lines = append(lines[:i+1], append([]string{"// TODO: Verify SQL semantics and placeholders. (SEC-002)"}, lines[i+1:]...)...)
		changed = true
		i++
	}
	if !changed {
		return src, false
	}
	return strings.Join(lines, "\n"), true
}

func applyPythonSQLParameterization(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, ".execute(") || !strings.Contains(trimmed, `+`) || !strings.Contains(trimmed, `"`) {
			out = append(out, line)
			continue
		}
		if strings.Contains(trimmed, "SEC-002") || strings.Contains(trimmed, "%s") {
			out = append(out, line)
			continue
		}
		idxPlus := strings.Index(trimmed, "+")
		idxClose := strings.LastIndex(trimmed, ")")
		if idxPlus < 0 || idxClose < idxPlus {
			out = append(out, line)
			continue
		}
		arg := strings.TrimSpace(trimmed[idxPlus+1 : idxClose])
		if arg == "" || strings.Contains(arg, " ") {
			out = append(out, line)
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		prefix := strings.TrimSpace(trimmed[:idxPlus])
		out = append(out, indent+prefix+` %s", (`+arg+`,))`)
		out = append(out, indent+"# TODO: Verify SQL semantics and placeholders. (SEC-002)")
		changed = true
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

func applyJSSQLParameterization(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !(strings.Contains(trimmed, ".query(") || strings.Contains(trimmed, ".execute(")) || !strings.Contains(trimmed, `+`) || !strings.Contains(trimmed, `"`) {
			out = append(out, line)
			continue
		}
		if strings.Contains(trimmed, "SEC-002") || strings.Contains(trimmed, "?") {
			out = append(out, line)
			continue
		}
		idxPlus := strings.Index(trimmed, "+")
		idxClose := strings.LastIndex(trimmed, ")")
		if idxPlus < 0 || idxClose < idxPlus {
			out = append(out, line)
			continue
		}
		arg := strings.TrimSpace(strings.TrimRight(trimmed[idxPlus+1:idxClose], ";"))
		if arg == "" || strings.Contains(arg, " ") {
			out = append(out, line)
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		prefix := strings.TrimSpace(trimmed[:idxPlus])
		out = append(out, indent+prefix+` ?", [`+arg+`])`+func() string {
			if strings.HasSuffix(strings.TrimSpace(line), ";") {
				return ";"
			}
			return ""
		}())
		out = append(out, indent+"// TODO: Verify SQL semantics and placeholders. (SEC-002)")
		changed = true
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

func applyGoSubprocessHardening(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, `exec.Command("sh", "-c", "`) {
			out = append(out, line)
			continue
		}
		if strings.Contains(trimmed, "SEC-001") {
			out = append(out, line)
			continue
		}
		start := strings.Index(trimmed, `exec.Command("sh", "-c", "`)
		end := strings.Index(trimmed[start+len(`exec.Command("sh", "-c", "`):], `")`)
		if end < 0 {
			out = append(out, line)
			continue
		}
		cmdBody := trimmed[start+len(`exec.Command("sh", "-c", "`) : start+len(`exec.Command("sh", "-c", "`)+end]
		parts := strings.Fields(cmdBody)
		if len(parts) == 0 {
			out = append(out, line)
			continue
		}
		argv := make([]string, 0, len(parts))
		for _, p := range parts {
			argv = append(argv, fmt.Sprintf("\"%s\"", p))
		}
		repl := `exec.Command(` + strings.Join(argv, ", ") + `)`
		newline := strings.Replace(line, `exec.Command("sh", "-c", "`+cmdBody+`")`, repl, 1)
		out = append(out, newline)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		out = append(out, indent+"// TODO: Validate command behavior without shell expansion. (SEC-001)")
		changed = true
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

func applyPythonSubprocessHardening(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "subprocess.run(") || !strings.Contains(trimmed, "shell=True") {
			out = append(out, line)
			continue
		}
		if !strings.Contains(trimmed, `"`) || strings.Contains(trimmed, "SEC-001") {
			out = append(out, line)
			continue
		}
		start := strings.Index(trimmed, `subprocess.run("`)
		if start < 0 {
			out = append(out, line)
			continue
		}
		rest := trimmed[start+len(`subprocess.run("`):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			out = append(out, line)
			continue
		}
		cmdBody := rest[:end]
		parts := strings.Fields(cmdBody)
		if len(parts) == 0 {
			out = append(out, line)
			continue
		}
		argv := "[\"" + strings.Join(parts, "\", \"") + "\"]"
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		out = append(out, indent+`subprocess.run(`+argv+`, check=True)`)
		out = append(out, indent+"# TODO: Validate command behavior without shell expansion. (SEC-001)")
		changed = true
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}

func applyJSSubprocessHardening(src string) (string, bool) {
	changed := false
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, `exec("`) || strings.Contains(trimmed, "SEC-001") {
			out = append(out, line)
			continue
		}
		start := strings.Index(trimmed, `exec("`)
		rest := trimmed[start+len(`exec("`):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			out = append(out, line)
			continue
		}
		cmdBody := rest[:end]
		parts := strings.Fields(cmdBody)
		if len(parts) == 0 {
			out = append(out, line)
			continue
		}
		cmd := parts[0]
		args := parts[1:]
		argsQuoted := make([]string, 0, len(args))
		for _, a := range args {
			argsQuoted = append(argsQuoted, fmt.Sprintf("\"%s\"", a))
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		suffix := ""
		if strings.Contains(trimmed, ",") {
			suffix = rest[end+1:]
		}
		out = append(out, indent+`execFile("`+cmd+`", [`+strings.Join(argsQuoted, ", ")+`]`+suffix)
		out = append(out, indent+"// TODO: Validate command behavior without shell expansion. (SEC-001)")
		changed = true
	}
	if !changed {
		return src, false
	}
	return strings.Join(out, "\n"), true
}
