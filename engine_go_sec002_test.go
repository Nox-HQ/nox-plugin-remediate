package main

import (
	"strings"
	"testing"
)

// These tests exercise applyGoSQLParameterization directly. The fixer recognises
// exactly ONE safe shape -- a complete SQL fragment ending at a value position
// concatenated with a single trailing identifier -- and SKIPS (returns the source
// unchanged, ok=false) for everything else. SQL placeholders bind VALUES only,
// never identifiers, so anything it cannot prove lands at a value position is
// declined and left for a human. Coverage is deliberately narrow.

func TestGoSQLParam_ValueConcat_Rewritten(t *testing.T) {
	src := "\t_ = db.Query(\"SELECT * FROM users WHERE id = \" + userID)\n"
	got, ok := applyGoSQLParameterization(src)
	if !ok {
		t.Fatalf("expected rewrite of value-position concat, got ok=false:\n%s", got)
	}
	// Both the placeholder and the argument must be emitted.
	if !strings.Contains(got, `"SELECT * FROM users WHERE id = ?", userID`) {
		t.Fatalf("expected ? placeholder + userID arg, got:\n%s", got)
	}
	if !strings.Contains(got, "SEC-002") {
		t.Fatalf("expected SEC-002 TODO marker, got:\n%s", got)
	}
}

func TestGoSQLParam_DynamicTableName_Skipped(t *testing.T) {
	// A table/column name is an identifier position: a ? there is invalid SQL.
	// This is the most important skip.
	src := "\t_ = db.Query(\"SELECT * FROM \" + table)\n"
	got, ok := applyGoSQLParameterization(src)
	if ok {
		t.Fatalf("dynamic table name must be skipped, but was rewritten:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be returned unchanged, got:\n%s", got)
	}
}

func TestGoSQLParam_OrderByColumn_Skipped(t *testing.T) {
	src := "\t_ = db.Query(\"SELECT * FROM t ORDER BY \" + col)\n"
	got, ok := applyGoSQLParameterization(src)
	if ok {
		t.Fatalf("ORDER BY column is an identifier position and must be skipped:\n%s", got)
	}
	if got != src {
		t.Fatalf("skipped source must be returned unchanged, got:\n%s", got)
	}
}

func TestGoSQLParam_TrailingComment_Preserved(t *testing.T) {
	src := "\t_ = db.Query(\"SELECT * FROM users WHERE id = \" + id) // lookup by id\n"
	got, ok := applyGoSQLParameterization(src)
	if !ok {
		t.Fatalf("expected rewrite, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `"SELECT * FROM users WHERE id = ?", id) // lookup by id`) {
		t.Fatalf("trailing comment must be preserved verbatim, got:\n%s", got)
	}
}

func TestGoSQLParam_MultipleVariables_Skipped(t *testing.T) {
	// More than one interpolated variable cannot be mapped to a single trailing
	// placeholder deterministically, so we decline.
	src := "\t_ = db.Query(\"a = \" + x + \" and b = \" + y)\n"
	got, ok := applyGoSQLParameterization(src)
	if ok {
		t.Fatalf("multi-variable concat must be skipped, got:\n%s", got)
	}
}

func TestGoSQLParam_AlreadyParameterized_Idempotent(t *testing.T) {
	src := "\t_ = db.Query(\"SELECT * FROM users WHERE id = ?\", id)\n"
	got, ok := applyGoSQLParameterization(src)
	if ok {
		t.Fatalf("already-parameterized line must be left untouched, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("idempotent skip must return source unchanged, got:\n%s", got)
	}
}

func TestGoSQLParam_Comparison_Untouched(t *testing.T) {
	// A string equality comparison is not a query call and must never be touched.
	src := "\tif q == \"SELECT 1\" {\n\t}\n"
	got, ok := applyGoSQLParameterization(src)
	if ok {
		t.Fatalf("string comparison must not be rewritten, got:\n%s", got)
	}
	if got != src {
		t.Fatalf("expected source unchanged, got:\n%s", got)
	}
}

func TestGoSQLParam_INList_Skipped(t *testing.T) {
	// IN ( ... ) with a single trailing variable: the ')' belongs to the call,
	// not the SQL, and IN wants a list -- a single ? would emit broken SQL.
	src := "\t_ = db.Query(\"SELECT * FROM t WHERE id IN (\" + ids)\n"
	got, ok := applyGoSQLParameterization(src)
	if ok {
		t.Fatalf("IN (...) single-variable concat must be skipped, got:\n%s", got)
	}
}

func TestGoSQLParam_Like_Rewritten(t *testing.T) {
	src := "\t_ = db.Query(\"SELECT * FROM users WHERE name LIKE \" + pat)\n"
	got, ok := applyGoSQLParameterization(src)
	if !ok {
		t.Fatalf("LIKE is a value position and should be parameterized, got ok=false:\n%s", got)
	}
	if !strings.Contains(got, `WHERE name LIKE ?", pat`) {
		t.Fatalf("expected LIKE ? placeholder + arg, got:\n%s", got)
	}
}
