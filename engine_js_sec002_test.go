package main

import (
	"strings"
	"testing"
)

// These tests exercise applyJSSQLParameterization directly. Like the Python
// fixer, the previous implementation required a double-quote substring (silently
// skipping single-quoted SQL) and emitted BROKEN JS for the double-quote case (a
// stray quote outside the string). The hardened fixer handles both ' and " for
// the single trailing-value shape, uses the ? placeholder with an args array,
// preserves a trailing ';', and SKIPS everything it cannot prove safe. Backtick
// template literals are a different shape and are out of scope.

func TestJSSQLParam_SingleQuoted_Rewritten(t *testing.T) {
	// The former false negative: single quotes were skipped entirely.
	src := "  db.query('SELECT * FROM users WHERE id = ' + userId);\n"
	got, ok := applyJSSQLParameterization(src)
	if !ok {
		t.Fatalf("single-quoted SQL must now be rewritten (was the false negative), got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `'SELECT * FROM users WHERE id = ?', [userId]`) {
		t.Fatalf("expected ? placeholder + [userId] arg, got:\n%s", got)
	}
	if !strings.Contains(got, "SEC-002") {
		t.Fatalf("expected SEC-002 TODO marker, got:\n%s", got)
	}
}

func TestJSSQLParam_DoubleQuoted_Rewritten(t *testing.T) {
	src := "  db.query(\"SELECT * FROM users WHERE id = \" + userId);\n"
	got, ok := applyJSSQLParameterization(src)
	if !ok {
		t.Fatalf("expected rewrite, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `"SELECT * FROM users WHERE id = ?", [userId])`) {
		t.Fatalf("expected ? placeholder + [userId] arg, got:\n%s", got)
	}
	// The trailing semicolon must survive.
	if !strings.Contains(got, `[userId]);`) {
		t.Fatalf("trailing semicolon must be preserved, got:\n%s", got)
	}
}

func TestJSSQLParam_DynamicTableName_Skipped(t *testing.T) {
	src := "  db.query('SELECT * FROM ' + table);\n"
	got, ok := applyJSSQLParameterization(src)
	if ok {
		t.Fatalf("dynamic table name must be skipped, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be unchanged, got:\n%s", got)
	}
}

func TestJSSQLParam_OrderByColumn_Skipped(t *testing.T) {
	src := "  db.query('SELECT * FROM t ORDER BY ' + col);\n"
	got, ok := applyJSSQLParameterization(src)
	if ok {
		t.Fatalf("ORDER BY column must be skipped, got:\n%s", got)
	}
}

func TestJSSQLParam_TrailingComment_Preserved(t *testing.T) {
	src := "  db.query('SELECT * FROM users WHERE id = ' + userId); // by id\n"
	got, ok := applyJSSQLParameterization(src)
	if !ok {
		t.Fatalf("expected rewrite, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `[userId]); // by id`) {
		t.Fatalf("trailing comment must be preserved verbatim, got:\n%s", got)
	}
}

func TestJSSQLParam_AlreadyParameterized_Idempotent(t *testing.T) {
	src := "  db.query('SELECT * FROM users WHERE id = ?', [userId]);\n"
	got, ok := applyJSSQLParameterization(src)
	if ok {
		t.Fatalf("already-parameterized line must be untouched, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("idempotent skip must return source unchanged, got:\n%s", got)
	}
}

func TestJSSQLParam_Comparison_Untouched(t *testing.T) {
	// Not a query/execute call; must never be touched.
	src := "  if (q === 'SELECT 1') {}\n"
	got, ok := applyJSSQLParameterization(src)
	if ok {
		t.Fatalf("string comparison must not be rewritten, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("expected source unchanged, got:\n%s", got)
	}
}

func TestJSSQLParam_TemplateLiteral_Skipped(t *testing.T) {
	// Backtick template literals interpolate directly -- a different shape, out
	// of scope, and must be skipped rather than mangled.
	src := "  db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
	got, ok := applyJSSQLParameterization(src)
	if ok {
		t.Fatalf("template literal must be skipped, got:\n%s", got)
	}
}

func TestJSSQLParam_MultipleVariables_Skipped(t *testing.T) {
	src := "  db.query('a = ' + x + ' and b = ' + y);\n"
	got, ok := applyJSSQLParameterization(src)
	if ok {
		t.Fatalf("multi-variable concat must be skipped, got:\n%s", got)
	}
}
