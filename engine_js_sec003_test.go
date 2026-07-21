package main

import (
	"strings"
	"testing"
)

// These tests exercise applyJSSecretRewrite directly (rather than through the
// file-walking engine) so each case pins one behaviour of the string-literal
// detector: the false-negative fixes (single-quote / template), the data-loss
// fixes (trailing `;` and `// comment`), and the skip-when-unsure guarantees.

func TestJSSEC003SingleQuotedRewritten(t *testing.T) {
	// Regression: the previous implementation gated on a double quote being
	// present, so single-quoted secrets were silently left hardcoded.
	got, changed := applyJSSecretRewrite(`const password = 'hunter2'`)
	if !changed {
		t.Fatal("single-quoted secret was not rewritten (false negative)")
	}
	if !strings.Contains(got, "process.env.PASSWORD") {
		t.Fatalf("expected process.env.PASSWORD, got:\n%s", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("secret literal survived the rewrite:\n%s", got)
	}
	if !strings.Contains(got, secretRotationNotice) {
		t.Fatalf("rotation notice missing from rewrite:\n%s", got)
	}
}

func TestJSSEC003DoubleQuotedRewritten(t *testing.T) {
	got, changed := applyJSSecretRewrite(`const apiKey = "sk-12345"`)
	if !changed {
		t.Fatal("double-quoted secret was not rewritten")
	}
	if !strings.Contains(got, "process.env.API_KEY") {
		t.Fatalf("expected process.env.API_KEY, got:\n%s", got)
	}
	if !strings.Contains(got, secretRotationNotice) {
		t.Fatalf("rotation notice missing from rewrite:\n%s", got)
	}
}

func TestJSSEC003PlainTemplateLiteralRewritten(t *testing.T) {
	// A template literal with no interpolation is a constant string and is safe
	// to rewrite.
	got, changed := applyJSSecretRewrite("const token = `abc123`")
	if !changed {
		t.Fatal("plain template-literal secret was not rewritten (false negative)")
	}
	if !strings.Contains(got, "process.env.TOKEN") {
		t.Fatalf("expected process.env.TOKEN, got:\n%s", got)
	}
	if strings.Contains(got, "abc123") {
		t.Fatalf("secret literal survived the rewrite:\n%s", got)
	}
}

func TestJSSEC003InterpolatedTemplateSkipped(t *testing.T) {
	// `${x}` means the value is not a constant; rewriting to a single env var
	// would drop the interpolation. Must skip.
	src := "const password = `abc${x}`"
	got, changed := applyJSSecretRewrite(src)
	if changed {
		t.Fatalf("interpolated template literal must be skipped, got rewrite:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be returned verbatim, got:\n%s", got)
	}
}

func TestJSSEC003ConcatenationSkipped(t *testing.T) {
	// `"a" + b` is a concatenation; collapsing it to one env var is lossy.
	src := `const secret = "abc" + suffix`
	got, changed := applyJSSecretRewrite(src)
	if changed {
		t.Fatalf("concatenation must be skipped, got rewrite:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be returned verbatim, got:\n%s", got)
	}
}

func TestJSSEC003TrailingSemicolonPreserved(t *testing.T) {
	// Regression: the previous implementation dropped the trailing `;`.
	got, changed := applyJSSecretRewrite(`const password = "hunter2";`)
	if !changed {
		t.Fatal("expected rewrite")
	}
	first := strings.SplitN(got, "\n", 2)[0]
	if first != `const password = process.env.PASSWORD;` {
		t.Fatalf("trailing semicolon not preserved, got first line:\n%q", first)
	}
}

func TestJSSEC003TrailingCommentPreserved(t *testing.T) {
	got, changed := applyJSSecretRewrite(`const password = "hunter2"; // prod creds`)
	if !changed {
		t.Fatal("expected rewrite")
	}
	first := strings.SplitN(got, "\n", 2)[0]
	if first != `const password = process.env.PASSWORD; // prod creds` {
		t.Fatalf("trailing semicolon+comment not preserved, got first line:\n%q", first)
	}
}

func TestJSSEC003ComparisonUntouched(t *testing.T) {
	// `===` is not an assignment; the string is a comparison operand, not a
	// hardcoded credential being defined.
	src := `if (x === "secret") { doThing(); }`
	got, changed := applyJSSecretRewrite(src)
	if changed {
		t.Fatalf("equality comparison must be untouched, got rewrite:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be returned verbatim, got:\n%s", got)
	}
}

func TestJSSEC003IdempotentOnAlreadyEnv(t *testing.T) {
	// Running the fixer over its own output must be a no-op.
	src := `const password = process.env.PASSWORD;`
	got, changed := applyJSSecretRewrite(src)
	if changed {
		t.Fatalf("already-env line must not be rewritten, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be returned verbatim, got:\n%s", got)
	}
}

func TestJSSEC003RewriteIsFullyIdempotent(t *testing.T) {
	// First pass rewrites; a second pass over the result changes nothing.
	first, changed := applyJSSecretRewrite(`const password = 'hunter2';`)
	if !changed {
		t.Fatal("expected first pass to rewrite")
	}
	second, changed2 := applyJSSecretRewrite(first)
	if changed2 {
		t.Fatalf("second pass must be a no-op, got:\n%s", second)
	}
	if second != first {
		t.Fatalf("second pass altered output:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}
