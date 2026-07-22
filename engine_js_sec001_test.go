package main

import (
	"strings"
	"testing"
)

// A static command on the resolved child_process namespace binding is de-shelled
// into execFile(cmd, [args]).
func TestJSSubprocessRewritesStaticCommand(t *testing.T) {
	src := "const cp = require('child_process')\ncp.exec(\"ls -la\")\n"

	out, changed := applyJSSubprocessHardening(src)
	if !changed {
		t.Fatal("expected the static command to be de-shelled")
	}
	if !strings.Contains(out, `cp.execFile("ls", ["-la"])`) {
		t.Fatalf("expected cp.execFile(\"ls\", [\"-la\"]); got:\n%s", out)
	}
	if !strings.Contains(out, "(SEC-001)") {
		t.Fatalf("expected the SEC-001 TODO advisory; got:\n%s", out)
	}
}

// The object prefix and a trailing callback argument must be preserved, so the
// rewrite produces valid execFile(file, args, callback).
func TestJSSubprocessPreservesCallbackAndPrefix(t *testing.T) {
	src := "const cp = require('child_process')\nconst child = cp.exec(\"ls -la\", (err, out) => {})\n"

	out, changed := applyJSSubprocessHardening(src)
	if !changed {
		t.Fatal("expected rewrite")
	}
	if !strings.Contains(out, `const child = cp.execFile("ls", ["-la"], (err, out) => {})`) {
		t.Fatalf("expected preserved prefix and callback; got:\n%s", out)
	}
}

// A pipe is a shell feature: skip.
func TestJSSubprocessSkipsPipe(t *testing.T) {
	src := "const cp = require('child_process')\ncp.exec(\"ls | grep foo\")\n"

	out, changed := applyJSSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a piped command must be left untouched; got:\n%s", out)
	}
}

// A template literal is interpolation and uses backticks, not double quotes: skip.
func TestJSSubprocessSkipsTemplateLiteral(t *testing.T) {
	src := "const cp = require('child_process')\ncp.exec(`echo ${name}`)\n"

	out, changed := applyJSSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a template-literal command must be left untouched; got:\n%s", out)
	}
}

// $VAR expansion is the injection surface: skip.
func TestJSSubprocessSkipsVariableExpansion(t *testing.T) {
	src := "const cp = require('child_process')\ncp.exec(\"echo $HOME\")\n"

	out, changed := applyJSSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a $VAR command must be left untouched; got:\n%s", out)
	}
}

// String concatenation right after the literal: skip.
func TestJSSubprocessSkipsConcatenation(t *testing.T) {
	src := "const cp = require('child_process')\ncp.exec(\"ls \" + dir)\n"

	out, changed := applyJSSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a concatenated command must be left untouched; got:\n%s", out)
	}
}

// A destructured bare exec(...) is de-shelled to execFile(...), and — crucially —
// execFile is added to the SAME destructuring binding, so we never emit a call to
// an unimported symbol (the SEC-003 missing-import lesson applied to JS).
func TestJSSubprocessRewritesDestructuredAndAddsExecFileImport(t *testing.T) {
	src := "const { exec } = require('child_process')\nexec(\"ls -la\")\n"

	out, changed := applyJSSubprocessHardening(src)
	if !changed {
		t.Fatal("expected the destructured bare exec to be de-shelled")
	}
	if !strings.Contains(out, `execFile("ls", ["-la"])`) {
		t.Fatalf("expected execFile(\"ls\", [\"-la\"]); got:\n%s", out)
	}
	if !strings.Contains(out, "{ exec, execFile }") {
		t.Fatalf("execFile must be added to the destructuring import; got:\n%s", out)
	}
}

// A destructured import that already has execFile is not duplicated.
func TestJSSubprocessDestructuredDoesNotDuplicateExecFile(t *testing.T) {
	src := "const { exec, execFile } = require('child_process')\nexec(\"ls -la\")\n"

	out, changed := applyJSSubprocessHardening(src)
	if !changed {
		t.Fatal("expected rewrite")
	}
	if strings.Count(out, "execFile") != 2 { // one in import, one in the call
		t.Fatalf("execFile should not be duplicated in the import; got:\n%s", out)
	}
}

// Without any child_process import, an identical-looking RegExp.exec must NOT be
// converted into a broken regex.execFile call.
func TestJSSubprocessSkipsRegExpExec(t *testing.T) {
	src := "const re = /foo/\nconst m = re.exec(\"foo bar\")\n"

	out, changed := applyJSSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("RegExp.exec must never be rewritten; got:\n%s", out)
	}
}

// Already de-shelled code is idempotent: execFile does not match the .exec("
// marker, so a second pass changes nothing.
func TestJSSubprocessIdempotent(t *testing.T) {
	src := "const cp = require('child_process')\ncp.execFile(\"ls\", [\"-la\"])\n"

	out, changed := applyJSSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("already-execFile call must not change; got:\n%s", out)
	}

	first, _ := applyJSSubprocessHardening("const cp = require('child_process')\ncp.exec(\"ls -la\")\n")
	second, changed2 := applyJSSubprocessHardening(first)
	if changed2 || second != first {
		t.Fatalf("rewrite is not idempotent across two passes; got:\n%s", second)
	}
}
