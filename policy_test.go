package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/sdk"
)

func TestLoadPolicyDefaultsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	p, err := LoadPolicy(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	if !p.Enabled {
		t.Fatal("Enabled = false, want true")
	}
	if p.Risk.BlastRadius.AutoMergeMax != BlastRadiusLow {
		t.Fatalf("AutoMergeMax = %q, want %q", p.Risk.BlastRadius.AutoMergeMax, BlastRadiusLow)
	}
}

func TestLoadPolicyFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox.yaml")
	content := []byte(`remediation:
  enabled: true
  risk:
    auto_apply:
      severities: [critical, high]
      allow_major: true
    blast_radius:
      auto_merge_max: medium
      require_human_review_at: high
  merge:
    min_approval_count: 2
    auto_merge_when:
      blast_radius_in: [low, medium]
      checks_passed: true
      review_approved: true
  verify:
    allowed_commands: ["go test ./...", "go vet ./..."]
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	p, err := LoadPolicy(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	if !p.Risk.AutoApply.AllowMajor {
		t.Fatal("AllowMajor = false, want true")
	}
	if p.Risk.BlastRadius.AutoMergeMax != BlastRadiusMedium {
		t.Fatalf("AutoMergeMax = %q, want %q", p.Risk.BlastRadius.AutoMergeMax, BlastRadiusMedium)
	}
	if p.Merge.MinApprovals != 2 {
		t.Fatalf("MinApprovals = %d, want 2", p.Merge.MinApprovals)
	}
}

func TestLoadPolicyInvalidBlastRadius(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox.yaml")
	content := []byte(`remediation:
  risk:
    blast_radius:
      auto_merge_max: extreme
      require_human_review_at: high
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadPolicy(sdk.ToolRequest{WorkspaceRoot: dir})
	if !errors.Is(err, ErrInvalidBlastRadius) {
		t.Fatalf("LoadPolicy() error = %v, want ErrInvalidBlastRadius", err)
	}
}

func TestLoadPolicyInvalidMergeCombination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox.yaml")
	content := []byte(`remediation:
  risk:
    blast_radius:
      auto_merge_max: low
      require_human_review_at: high
  merge:
    auto_merge_when:
      blast_radius_in: [medium]
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadPolicy(sdk.ToolRequest{WorkspaceRoot: dir})
	if !errors.Is(err, ErrInvalidMergePolicy) {
		t.Fatalf("LoadPolicy() error = %v, want ErrInvalidMergePolicy", err)
	}
}

func TestAllowedCommand(t *testing.T) {
	allow := []string{"go test ./...", "go vet ./..."}
	if !allowedCommand(allow, "go test ./...") {
		t.Fatal("allowedCommand() false, want true")
	}
	if allowedCommand(allow, "go test ./core/...") {
		t.Fatal("allowedCommand() true, want false")
	}
}
