package main

import (
	"strings"
	"testing"
)

// These tests exercise applyPythonSQLParameterization directly. The previous
// implementation required a double-quote substring and SILENTLY SKIPPED
// single-quoted SQL (`cur.execute('...' + x)`) -- the dominant Python string
// style, a large false-negative surface. It also emitted BROKEN Python for the
// double-quote case (a stray quote outside the string). The hardened fixer
// handles both quote styles for the single trailing-value shape and SKIPS
// everything it cannot prove safe. DB-API uses the %s placeholder.

func TestPythonSQLParam_SingleQuoted_Rewritten(t *testing.T) {
	// The former false negative: single quotes were skipped entirely.
	src := "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
	got, ok := applyPythonSQLParameterization(src)
	if !ok {
		t.Fatalf("single-quoted SQL must now be rewritten (was the false negative), got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `'SELECT * FROM users WHERE id = %s', (user_id,)`) {
		t.Fatalf("expected %%s placeholder + (user_id,) arg, got:\n%s", got)
	}
	if !strings.Contains(got, "SEC-002") {
		t.Fatalf("expected SEC-002 TODO marker, got:\n%s", got)
	}
}

func TestPythonSQLParam_DoubleQuoted_Rewritten(t *testing.T) {
	src := "    cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n"
	got, ok := applyPythonSQLParameterization(src)
	if !ok {
		t.Fatalf("expected rewrite, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `"SELECT * FROM users WHERE id = %s", (user_id,)`) {
		t.Fatalf("expected %%s placeholder + (user_id,) arg, got:\n%s", got)
	}
}

func TestPythonSQLParam_DynamicTableName_Skipped(t *testing.T) {
	src := "    cursor.execute('SELECT * FROM ' + table)\n"
	got, ok := applyPythonSQLParameterization(src)
	if ok {
		t.Fatalf("dynamic table name must be skipped, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be unchanged, got:\n%s", got)
	}
}

func TestPythonSQLParam_OrderByColumn_Skipped(t *testing.T) {
	src := "    cursor.execute('SELECT * FROM t ORDER BY ' + col)\n"
	got, ok := applyPythonSQLParameterization(src)
	if ok {
		t.Fatalf("ORDER BY column must be skipped, got:\n%s", got)
	}
}

func TestPythonSQLParam_TrailingComment_Preserved(t *testing.T) {
	src := "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)  # lookup\n"
	got, ok := applyPythonSQLParameterization(src)
	if !ok {
		t.Fatalf("expected rewrite, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `(user_id,))  # lookup`) {
		t.Fatalf("trailing comment must be preserved verbatim, got:\n%s", got)
	}
}

func TestPythonSQLParam_AlreadyParameterized_Idempotent(t *testing.T) {
	src := "    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
	got, ok := applyPythonSQLParameterization(src)
	if ok {
		t.Fatalf("already-parameterized line must be untouched, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("idempotent skip must return source unchanged, got:\n%s", got)
	}
}

func TestPythonSQLParam_Comparison_Untouched(t *testing.T) {
	// Not an execute() call; must never be touched.
	src := "    if q == 'SELECT 1':\n        pass\n"
	got, ok := applyPythonSQLParameterization(src)
	if ok {
		t.Fatalf("string comparison must not be rewritten, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("expected source unchanged, got:\n%s", got)
	}
}

func TestPythonSQLParam_MultipleVariables_Skipped(t *testing.T) {
	src := "    cursor.execute('a = ' + x + ' and b = ' + y)\n"
	got, ok := applyPythonSQLParameterization(src)
	if ok {
		t.Fatalf("multi-variable concat must be skipped, got:\n%s", got)
	}
}
