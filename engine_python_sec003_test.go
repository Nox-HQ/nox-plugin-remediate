package main

import (
	"strings"
	"testing"
)

// These tests exercise applyPythonSecretRewrite directly. The function rewrites
// a hardcoded secret string literal assigned to a sensitive-named identifier
// into an os.getenv lookup, and — critically — SKIPS (returns the source
// unchanged, ok=false) whenever it cannot do so losslessly and correctly.

func TestPythonSecretRewrite_SingleQuoted(t *testing.T) {
	// The single-quote style is the dominant Python idiom; the previous
	// implementation guarded on a double-quote substring and silently skipped
	// this, a large false-negative surface for a secrets fixer.
	src := `password = 'hunter2'`
	got, ok := applyPythonSecretRewrite(src)
	if !ok {
		t.Fatalf("expected rewrite of single-quoted secret, got ok=false; src unchanged:\n%s", got)
	}
	if !strings.Contains(got, `password = os.getenv("PASSWORD")`) {
		t.Fatalf("expected os.getenv rewrite, got:\n%s", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("secret literal must not survive the rewrite, got:\n%s", got)
	}
	if !strings.Contains(got, secretRotationNotice) {
		t.Fatalf("expected rotation notice on rewrite, got:\n%s", got)
	}
}

func TestPythonSecretRewrite_DoubleQuoted(t *testing.T) {
	src := `api_key = "sk-12345"`
	got, ok := applyPythonSecretRewrite(src)
	if !ok {
		t.Fatalf("expected rewrite of double-quoted secret, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `api_key = os.getenv("API_KEY")`) {
		t.Fatalf("expected os.getenv rewrite, got:\n%s", got)
	}
	if !strings.Contains(got, secretRotationNotice) {
		t.Fatalf("expected rotation notice on rewrite, got:\n%s", got)
	}
}

func TestPythonSecretRewrite_FStringSkipped(t *testing.T) {
	// f-strings are evaluated; rewriting one would drop interpolation. SKIP.
	src := `password = f"hunter2-{user}"`
	got, ok := applyPythonSecretRewrite(src)
	if ok {
		t.Fatalf("f-string must be skipped, got ok=true:\n%s", got)
	}
	if got != src {
		t.Fatalf("f-string source must be returned unchanged, got:\n%s", got)
	}
}

func TestPythonSecretRewrite_ConcatenationSkipped(t *testing.T) {
	// Trailing tokens after the literal mean this is not a bare assignment. SKIP.
	src := `password = "hunter" + suffix`
	got, ok := applyPythonSecretRewrite(src)
	if ok {
		t.Fatalf("concatenation must be skipped, got ok=true:\n%s", got)
	}
	if got != src {
		t.Fatalf("concatenation source must be returned unchanged, got:\n%s", got)
	}
}

func TestPythonSecretRewrite_TrailingCommentPreserved(t *testing.T) {
	// The previous implementation rebuilt the line from the left of '=' and
	// dropped everything after the literal, destroying trailing comments.
	src := `password = "hunter2"  # legacy default`
	got, ok := applyPythonSecretRewrite(src)
	if !ok {
		t.Fatalf("expected rewrite, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `password = os.getenv("PASSWORD")  # legacy default`) {
		t.Fatalf("expected trailing comment preserved on the rewritten line, got:\n%s", got)
	}
}

func TestPythonSecretRewrite_ComparisonUntouched(t *testing.T) {
	// A comparison is not an assignment and must never be rewritten.
	src := `if x == 'secret':`
	got, ok := applyPythonSecretRewrite(src)
	if ok {
		t.Fatalf("comparison must be skipped, got ok=true:\n%s", got)
	}
	if got != src {
		t.Fatalf("comparison source must be returned unchanged, got:\n%s", got)
	}
}

func TestPythonSecretRewrite_IdempotentOnGetenv(t *testing.T) {
	// A second pass over already-rewritten code must be a no-op: the RHS starts
	// with os.getenv, not a quote, so the structural scan skips it.
	src := `password = os.getenv("PASSWORD")`
	got, ok := applyPythonSecretRewrite(src)
	if ok {
		t.Fatalf("already-os.getenv line must be skipped, got ok=true:\n%s", got)
	}
	if got != src {
		t.Fatalf("already-os.getenv source must be returned unchanged, got:\n%s", got)
	}
}
