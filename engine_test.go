package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/sdk"
)

func TestGuardrailsValidate(t *testing.T) {
	tests := []struct {
		name    string
		g       Guardrails
		plan    PatchPlan
		wantErr error
	}{
		{
			name: "within limits",
			g: Guardrails{MaxFiles: 2, MaxAddedLines: 20, MaxRemovedLines: 20},
			plan: PatchPlan{Patches: []Patch{{FilePath: "a.go", AddedLines: 10, RemovedLines: 5}}},
		},
		{
			name: "too many files",
			g: Guardrails{MaxFiles: 1},
			plan: PatchPlan{Patches: []Patch{{FilePath: "a.go"}, {FilePath: "b.go"}}},
			wantErr: ErrGuardrailFilesExceeded,
		},
		{
			name: "too many added lines",
			g: Guardrails{MaxAddedLines: 5},
			plan: PatchPlan{Patches: []Patch{{FilePath: "a.go", AddedLines: 6}}},
			wantErr: ErrGuardrailAddedExceeded,
		},
		{
			name: "too many removed lines",
			g: Guardrails{MaxRemovedLines: 5},
			plan: PatchPlan{Patches: []Patch{{FilePath: "a.go", RemovedLines: 6}}},
			wantErr: ErrGuardrailRemovedExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.g.Validate(tc.plan)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() error = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
		})
	}
}

func TestPatchEngineNoop(t *testing.T) {
	e := NewPatchEngine()

	plan, err := e.Plan(sdk.ToolRequest{})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) != 0 {
		t.Fatalf("Plan() patches = %d, want 0", len(plan.Patches))
	}

	apply, err := e.Apply(plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(apply.AppliedFiles) != 0 {
		t.Fatalf("Apply() files = %d, want 0", len(apply.AppliedFiles))
	}

	verify := e.Verify(sdk.ToolRequest{})
	if !verify.Ok {
		t.Fatal("Verify().Ok = false, want true")
	}
	if len(verify.Messages) == 0 {
		t.Fatal("Verify().Messages empty, want at least 1 message")
	}
}

func TestWEBSEC001GoFixerAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.go")
	before := `package main

import "net/http"

func main() {
	mux := http.NewServeMux()
	_ = http.ListenAndServe(":8080", mux)
}
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) != 1 {
		t.Fatalf("Plan() patches = %d, want 1", len(plan.Patches))
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, "securityHeadersMiddleware(mux)") {
		t.Fatal("expected security middleware wrapping on ListenAndServe")
	}
	if !strings.Contains(after, "X-Content-Type-Options") {
		t.Fatal("expected header helper to be added")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestAILOG001GoLoggingRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.go")
	before := `package main

import "log"

func callAPI(prompt string) {
	resp := "some response data here"
	log.Printf("prompt: %s", prompt)
	log.Println("response:", resp)
}
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 AI-LOG-001 patch")
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, "REDACTED") {
		t.Fatal("expected REDACTED comment in fixed file")
	}
	if strings.Contains(after, `"prompt: %s"`) {
		t.Fatal("raw prompt log pattern should be redacted")
	}
	if strings.Contains(after, `"response:"`) {
		t.Fatal("raw response log pattern should be redacted")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestAILOG001PythonLoggingRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.py")
	before := `import logging

def chat(prompt: str, messages: list):
    logging.info(f"user prompt: {prompt}")
    logging.error(f"response: {get_response(prompt)}")
    print(f"completion input: {messages}")
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 AI-LOG-001 patch")
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, "# REDACTED") {
		t.Fatal("expected REDACTED comment in fixed file")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestAILOG001JSLoggingRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.js")
	before := `const prompt = "hello"
const response = "world"
console.log("prompt:", prompt)
logger.info("response:", response)
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 AI-LOG-001 patch")
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, "// REDACTED") {
		t.Fatal("expected REDACTED comment in fixed file")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestAILOG001NoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "safe.py")
	before := `import logging

def safe_func():
    logging.info("system startup complete")
    print("hello world")
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) != 0 {
		t.Fatalf("Plan() patches = %d, want 0 (no false positives)", len(plan.Patches))
	}
}

func TestSEC003GoSecretRewriteAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	// Original fixture - has sensitive vars (password, apiKey) AND non-sensitive (normalName)
	before := "package main\n\nfunc init() {\n    password := \"s3cret!\"\n    apiKey := \"abc123def456\"\n    normalName := \"hello\"\n}"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// Patch plans are file-scoped, so both rewrites should appear in one patch.
	if len(plan.Patches) != 1 {
		t.Fatalf("Expected 1 file patch for sensitive vars, got %d", len(plan.Patches))
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	// Verify sensitive vars ARE rewritten
	if !strings.Contains(after, `os.Getenv("PASSWORD")`) {
		t.Fatal("expected os.Getenv(\"PASSWORD\") in fixed file")
	}
	if !strings.Contains(after, `os.Getenv("API_KEY")`) {
		t.Fatal("expected os.Getenv(\"API_KEY\") in fixed file")
	}
	// Verify non-sensitive var is NOT rewritten
	if !strings.Contains(after, `normalName := "hello"`) {
		t.Fatal("normalName line missing from output")
	}
	for _, l := range strings.Split(after, "\n") {
		if strings.Contains(l, `normalName :=`) && strings.Contains(l, "os.Getenv") {
			t.Fatal("normalName was incorrectly rewritten")
		}
	}

	// Idempotence check - second pass should have 0 patches
	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

// TestSEC003GoSecretRewriteNoRewrite checks that non-sensitive vars are NOT rewritten.
// Fixture has only normalName (not a sensitive var), so expect 0 patches.
func TestSEC003GoSecretRewriteNoRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	// Only non-sensitive variable - should NOT be rewritten
	before := "package main\n\nfunc init() {\n    normalName := \"hello\"\n}"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// Should have 0 patches (normalName is not sensitive)
	if len(plan.Patches) != 0 {
		t.Fatalf("Expected 0 patches for normalName-only fixture, got %d", len(plan.Patches))
	}
}

func TestSEC003PythonSecretRewriteAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.py")
	// Only non-sensitive variable - should have 0 patches
	before := `import os

def setup():
    name = "test-user"
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// Should have 0 patches (name is not sensitive)
	if len(plan.Patches) != 0 {
		t.Fatalf("Expected 0 patches for name-only fixture, got %d", len(plan.Patches))
	}
}

func TestSEC003JSSecretRewriteAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.js")
	before := `const password = "hunter2"
const apiKey = "sk-12345"
const name = "admin"
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-003 patch")
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, `process.env.PASSWORD`) {
		t.Fatal("expected process.env.PASSWORD in fixed file")
	}
	if !strings.Contains(after, `process.env.API_KEY`) {
		t.Fatal("expected process.env.API_KEY in fixed file")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestSEC003AlreadyUsingEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "safe.go")
	before := `package main

import "os"

func init() {
    password := os.Getenv("PASSWORD")
}
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) != 0 {
		t.Fatalf("Plan() patches = %d, want 0", len(plan.Patches))
	}
}

func TestSEC003ToEnvName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"password", "PASSWORD"},
		{"apiKey", "API_KEY"},
		{"db_password", "DB_PASSWORD"},
		{"auth_token", "AUTH_TOKEN"},
		{"connectionString", "CONNECTION_STRING"},
	}
	for _, tc := range tests {
		got := toEnvName(tc.in)
		if got != tc.want {
			t.Errorf("toEnvName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSEC002GoSQLParameterizationAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repo.go")
	before := `package main

func run(db DB, userID string) {
	_ = db.Query("SELECT * FROM users WHERE id = " + userID)
}
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-002 patch")
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, `SELECT * FROM users WHERE id = ?", userID`) {
		t.Fatalf("expected Go SQL to be parameterized with ? and arg; got:\n%s", after)
	}
	if !strings.Contains(after, "SEC-002") {
		t.Fatal("expected SEC-002 TODO marker")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestSEC001PythonSubprocessHardeningAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.py")
	before := `import subprocess

def run_it():
	subprocess.run("ls -la", shell=True)
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-001 patch")
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, `subprocess.run(["ls", "-la"], check=True)`) {
		t.Fatal("expected subprocess hardening rewrite")
	}
	if !strings.Contains(after, "SEC-001") {
		t.Fatal("expected SEC-001 TODO marker")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

func TestVerifyCommandFailureAndSuccess(t *testing.T) {
	e := NewPatchEngine()
	dir := t.TempDir()

	failed := e.Verify(sdk.ToolRequest{WorkspaceRoot: dir, Input: map[string]any{"command": "exit 1"}})
	if failed.Ok {
		t.Fatal("Verify().Ok = true for failing command, want false")
	}

	ok := e.Verify(sdk.ToolRequest{WorkspaceRoot: dir, Input: map[string]any{"command": "printf ok"}})
	if !ok.Ok {
		t.Fatalf("Verify().Ok = false, want true; messages=%v", ok.Messages)
	}
}

func TestWEBSEC001ExpressFixerAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.js")
	before := `const express = require('express')
const app = express()

app.get('/health', (_req, res) => res.send('ok'))
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) != 1 {
		t.Fatalf("Plan() patches = %d, want 1", len(plan.Patches))
	}

	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	after := string(raw)
	if !strings.Contains(after, "const helmet = require('helmet')") {
		t.Fatal("expected helmet import to be added")
	}
	if !strings.Contains(after, "app.use(helmet())") {
		t.Fatal("expected helmet middleware to be added")
	}

	plan2, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() second pass error = %v", err)
	}
	if len(plan2.Patches) != 0 {
		t.Fatalf("Plan() second pass patches = %d, want 0", len(plan2.Patches))
	}
}

// --- task-62: SEC-001 / SEC-002 cross-language coverage + verification gates ---

func TestSEC002PythonSQLParameterizationAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repo.py")
	before := `def lookup(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-002 Python patch")
	}
	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, _ := os.ReadFile(path)
	after := string(raw)
	if !strings.Contains(after, `%s", (user_id,))`) {
		t.Fatalf("expected parameterized python execute; got:\n%s", after)
	}
	if !strings.Contains(after, "SEC-002") {
		t.Fatal("expected SEC-002 marker")
	}
	plan2, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if len(plan2.Patches) != 0 {
		t.Fatalf("idempotence violated; second-pass patches = %d", len(plan2.Patches))
	}
}

func TestSEC002JSSQLParameterizationAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repo.js")
	before := `function lookup(db, userId) {
  db.query("SELECT * FROM users WHERE id = " + userId);
}
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-002 JS patch")
	}
	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, _ := os.ReadFile(path)
	after := string(raw)
	if !strings.Contains(after, `?", [userId])`) {
		t.Fatalf("expected parameterized js query; got:\n%s", after)
	}
	if !strings.Contains(after, "SEC-002") {
		t.Fatal("expected SEC-002 marker")
	}
	plan2, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if len(plan2.Patches) != 0 {
		t.Fatalf("idempotence violated; second-pass patches = %d", len(plan2.Patches))
	}
}

func TestSEC002ConservativeSkipAlreadyParameterized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "safe.go")
	before := "package main\n\nfunc q(db DB, id string) { _ = db.Query(\"SELECT * FROM users WHERE id = ?\", id) }\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if len(plan.Patches) != 0 {
		t.Fatalf("expected conservative skip on already-parameterized SQL; got %d patches", len(plan.Patches))
	}
}

func TestSEC001GoSubprocessHardeningAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.go")
	before := "package main\n\nimport \"os/exec\"\n\nfunc run() { _ = exec.Command(\"sh\", \"-c\", \"ls -la\") }\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-001 Go patch")
	}
	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, _ := os.ReadFile(path)
	after := string(raw)
	if !strings.Contains(after, `exec.Command("ls", "-la")`) {
		t.Fatalf("expected argv-form exec.Command; got:\n%s", after)
	}
	if !strings.Contains(after, "SEC-001") {
		t.Fatal("expected SEC-001 marker")
	}
	plan2, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if len(plan2.Patches) != 0 {
		t.Fatalf("idempotence violated; second-pass patches = %d", len(plan2.Patches))
	}
}

func TestSEC001JSSubprocessHardeningAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.js")
	before := "const { exec } = require('child_process');\nexec(\"ls -la\");\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 SEC-001 JS patch")
	}
	if _, err := e.Apply(plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	raw, _ := os.ReadFile(path)
	after := string(raw)
	if !strings.Contains(after, `execFile("ls", ["-la"]`) {
		t.Fatalf("expected execFile rewrite; got:\n%s", after)
	}
	if !strings.Contains(after, "SEC-001") {
		t.Fatal("expected SEC-001 marker")
	}
	plan2, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if len(plan2.Patches) != 0 {
		t.Fatalf("idempotence violated; second-pass patches = %d", len(plan2.Patches))
	}
}

func TestSEC001ConservativeSkipDynamicCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dyn.go")
	before := "package main\n\nimport \"os/exec\"\n\nfunc run(cmd string) { _ = exec.Command(\"sh\", \"-c\", cmd) }\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if len(plan.Patches) != 0 {
		t.Fatalf("expected conservative skip on dynamic shell command; got %d patches", len(plan.Patches))
	}
}

func TestApplyAndVerifyRollbackOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	before := "package main\n\nfunc init() {\n    password := \"s3cret!\"\n}\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, err := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan.Patches) == 0 {
		t.Fatal("expected at least 1 patch to drive verify+rollback")
	}
	req := sdk.ToolRequest{WorkspaceRoot: dir, Input: map[string]any{"command": "exit 1"}}
	_, verification, err := e.ApplyAndVerify(plan, req)
	if err != nil {
		t.Fatalf("ApplyAndVerify() unexpected error = %v", err)
	}
	if verification.Ok {
		t.Fatal("expected verification.Ok = false")
	}
	got, _ := os.ReadFile(path)
	if string(got) != before {
		t.Fatalf("expected file rolled back to original\n--- want ---\n%s\n--- got ---\n%s", before, string(got))
	}
	rolledBackMsg := false
	for _, m := range verification.Messages {
		if strings.Contains(m, "rolled back") {
			rolledBackMsg = true
			break
		}
	}
	if !rolledBackMsg {
		t.Fatalf("expected rollback diagnostic in messages; got %v", verification.Messages)
	}
}

func TestApplyAndVerifyKeepsChangesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	before := "package main\n\nfunc init() {\n    password := \"s3cret!\"\n}\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	e := NewPatchEngine()
	plan, _ := e.Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	req := sdk.ToolRequest{WorkspaceRoot: dir, Input: map[string]any{"command": "printf ok"}}
	_, verification, err := e.ApplyAndVerify(plan, req)
	if err != nil {
		t.Fatalf("ApplyAndVerify() unexpected error = %v", err)
	}
	if !verification.Ok {
		t.Fatalf("expected verification.Ok = true; messages=%v", verification.Messages)
	}
	got, _ := os.ReadFile(path)
	if string(got) == before {
		t.Fatal("expected file content to differ from original after successful apply")
	}
	if !strings.Contains(string(got), `os.Getenv("PASSWORD")`) {
		t.Fatalf("expected SEC-003 rewrite to persist; got:\n%s", string(got))
	}
}
