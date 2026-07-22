package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// mustParseGoSEC001 asserts the rewritten output is still valid Go. A de-shelling
// fixer that emits code which no longer compiles is worse than one that does
// nothing, so every rewrite path is checked for parseability.
func mustParseGoSEC001(t *testing.T, out string) {
	t.Helper()
	if _, err := parser.ParseFile(token.NewFileSet(), "", out, parser.ParseComments); err != nil {
		t.Fatalf("rewritten output does not parse as Go: %v\n--- output ---\n%s", err, out)
	}
}

// A static, single-command, metacharacter-free command is de-shelled into argv.
// This is the ONLY shape the fixer is allowed to rewrite.
func TestGoSubprocessRewritesStaticCommand(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"ls -la /tmp\")\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if !changed {
		t.Fatal("expected the static command to be de-shelled")
	}
	if !strings.Contains(out, `exec.Command("ls", "-la", "/tmp")`) {
		t.Fatalf("expected argv exec.Command(\"ls\", \"-la\", \"/tmp\"); got:\n%s", out)
	}
	if strings.Contains(out, `"sh", "-c"`) {
		t.Fatalf("the sh -c wrapper should be gone; got:\n%s", out)
	}
	if !strings.Contains(out, "(SEC-001)") {
		t.Fatalf("expected the SEC-001 TODO advisory; got:\n%s", out)
	}
	mustParseGoSEC001(t, out)
}

// A pipe is a shell feature; exec.Command(argv...) would not reproduce it, so the
// command MUST be skipped and the finding left reported.
func TestGoSubprocessSkipsPipe(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"ls | grep foo\")\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a piped command must be left untouched; got:\n%s", out)
	}
}

// Interpolation/variable expansion ($VAR) is the actual injection; de-shelling it
// changes behaviour, so skip.
func TestGoSubprocessSkipsVariableExpansion(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"echo $HOME\")\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a $VAR command must be left untouched; got:\n%s", out)
	}
}

// A command built by concatenation is a BinaryExpr, not a string literal, so the
// third argument is not provably static: skip.
func TestGoSubprocessSkipsConcatenation(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tdir := \"/tmp\"\n\tc := exec.Command(\"sh\", \"-c\", \"ls \"+dir)\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a concatenated command must be left untouched; got:\n%s", out)
	}
}

// A non-literal (variable) command argument must be skipped.
func TestGoSubprocessSkipsVariableArg(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc run(cmd string) {\n\tc := exec.Command(\"sh\", \"-c\", cmd)\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a variable command must be left untouched; got:\n%s", out)
	}
}

// A trailing comment on the rewritten line must be preserved.
func TestGoSubprocessPreservesTrailingComment(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"ls -la\") // list files\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if !changed {
		t.Fatal("expected rewrite")
	}
	if !strings.Contains(out, `exec.Command("ls", "-la") // list files`) {
		t.Fatalf("trailing comment must be preserved on the rewritten line; got:\n%s", out)
	}
	mustParseGoSEC001(t, out)
}

// Already de-shelled code is idempotent: no exec.Command("sh","-c",...) remains,
// so a second pass changes nothing.
func TestGoSubprocessIdempotent(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"ls\", \"-la\")\n\t_ = c\n}\n"

	out, changed := applyGoSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("already-argv call must not change; got:\n%s", out)
	}

	first, _ := applyGoSubprocessHardening("package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"ls -la\")\n\t_ = c\n}\n")
	second, changed2 := applyGoSubprocessHardening(first)
	if changed2 || second != first {
		t.Fatalf("rewrite is not idempotent across two passes; got:\n%s", second)
	}
}

// Unparseable Go must be skipped, not mangled.
func TestGoSubprocessSkipsUnparseable(t *testing.T) {
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"ls -la\")\n" // missing brace

	out, changed := applyGoSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("unparseable source must be returned unchanged; got:\n%s", out)
	}
}
