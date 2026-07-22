package main

import (
	"strings"
	"testing"
)

// A static, metacharacter-free command is de-shelled into an argv list.
func TestPythonSubprocessRewritesStaticCommand(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(\"ls -la\", shell=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if !changed {
		t.Fatal("expected the static command to be de-shelled")
	}
	if !strings.Contains(out, `subprocess.run(["ls", "-la"], check=True)`) {
		t.Fatalf("expected argv subprocess.run([\"ls\", \"-la\"], check=True); got:\n%s", out)
	}
	if strings.Contains(out, "shell=True") {
		t.Fatalf("shell=True must be gone after de-shelling; got:\n%s", out)
	}
	if !strings.Contains(out, "(SEC-001)") {
		t.Fatalf("expected the SEC-001 TODO advisory; got:\n%s", out)
	}
}

// A pipe is a shell feature: skip.
func TestPythonSubprocessSkipsPipe(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(\"ls | grep foo\", shell=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a piped command must be left untouched; got:\n%s", out)
	}
}

// An f-string is interpolation; the marker subprocess.run(" does not match an
// f-string prefix subprocess.run(f", so it is skipped.
func TestPythonSubprocessSkipsFString(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(f\"echo {name}\", shell=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("an f-string command must be left untouched; got:\n%s", out)
	}
}

// $VAR expansion is the injection surface: skip.
func TestPythonSubprocessSkipsVariableExpansion(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(\"echo $HOME\", shell=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a $VAR command must be left untouched; got:\n%s", out)
	}
}

// String concatenation right after the literal means the argument is not a lone
// static literal: skip.
func TestPythonSubprocessSkipsConcatenation(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(\"ls \" + path, shell=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a concatenated command must be left untouched; got:\n%s", out)
	}
}

// A command passed as a variable is not a literal: skip.
func TestPythonSubprocessSkipsVariableArg(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(cmd, shell=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("a variable command must be left untouched; got:\n%s", out)
	}
}

// Extra kwargs we would otherwise silently drop force a skip — dropping them
// would change behaviour.
func TestPythonSubprocessSkipsExtraKwargs(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(\"ls -la\", shell=True, capture_output=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("extra kwargs must force a skip to avoid dropping them; got:\n%s", out)
	}
}

// A trailing comment must be preserved on the rewritten line, and indentation
// must be kept.
func TestPythonSubprocessPreservesCommentAndIndent(t *testing.T) {
	src := "import subprocess\n\ndef run():\n    subprocess.run(\"ls -la\", shell=True)  # list files\n"

	out, changed := applyPythonSubprocessHardening(src)
	if !changed {
		t.Fatal("expected rewrite")
	}
	if !strings.Contains(out, `    subprocess.run(["ls", "-la"], check=True)  # list files`) {
		t.Fatalf("expected preserved indent and trailing comment; got:\n%s", out)
	}
}

// Already de-shelled code (no shell=True) is left unchanged, and a second pass is
// a no-op.
func TestPythonSubprocessIdempotent(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run([\"ls\", \"-la\"], check=True)\n"

	out, changed := applyPythonSubprocessHardening(src)
	if changed || out != src {
		t.Fatalf("already-argv call must not change; got:\n%s", out)
	}

	first, _ := applyPythonSubprocessHardening("import subprocess\n\nsubprocess.run(\"ls -la\", shell=True)\n")
	second, changed2 := applyPythonSubprocessHardening(first)
	if changed2 || second != first {
		t.Fatalf("rewrite is not idempotent across two passes; got:\n%s", second)
	}
}
