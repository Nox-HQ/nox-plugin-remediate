package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/sdk"
	"gopkg.in/yaml.v3"
)

// BlastRadius is a normalized blast-radius level.
type BlastRadius string

const (
	BlastRadiusLow    BlastRadius = "low"
	BlastRadiusMedium BlastRadius = "medium"
	BlastRadiusHigh   BlastRadius = "high"
)

// RemediationPolicy is the plugin-level policy model loaded from .nox.yaml.
type RemediationPolicy struct {
	Enabled bool `yaml:"enabled"`
	Risk    struct {
		AutoApply struct {
			Severities []string `yaml:"severities"`
			AllowMajor bool     `yaml:"allow_major"`
		} `yaml:"auto_apply"`
		BlastRadius struct {
			AutoMergeMax        BlastRadius `yaml:"auto_merge_max"`
			RequireHumanReviewAt BlastRadius `yaml:"require_human_review_at"`
		} `yaml:"blast_radius"`
	} `yaml:"risk"`
	Merge struct {
		RequireChecks []string `yaml:"require_checks"`
		MinApprovals  int      `yaml:"min_approval_count"`
		AutoMergeWhen struct {
			BlastRadiusIn []BlastRadius `yaml:"blast_radius_in"`
			ChecksPassed  bool          `yaml:"checks_passed"`
			ReviewApproved bool         `yaml:"review_approved"`
		} `yaml:"auto_merge_when"`
	} `yaml:"merge"`
	Verify struct {
		AllowedCommands []string `yaml:"allowed_commands"`
	} `yaml:"verify"`
}

type rootConfig struct {
	Remediation RemediationPolicy `yaml:"remediation"`
}

var (
	ErrInvalidSeverity        = errors.New("invalid remediation severity")
	ErrInvalidBlastRadius     = errors.New("invalid remediation blast radius")
	ErrInvalidMergePolicy     = errors.New("invalid remediation merge policy")
	ErrInvalidVerificationCmd = errors.New("invalid remediation verification command")
)

func defaultPolicy() RemediationPolicy {
	var p RemediationPolicy
	p.Enabled = true
	p.Risk.AutoApply.Severities = []string{"critical", "high", "medium"}
	p.Risk.AutoApply.AllowMajor = false
	p.Risk.BlastRadius.AutoMergeMax = BlastRadiusLow
	p.Risk.BlastRadius.RequireHumanReviewAt = BlastRadiusHigh
	p.Merge.MinApprovals = 1
	p.Merge.AutoMergeWhen.BlastRadiusIn = []BlastRadius{BlastRadiusLow}
	p.Merge.AutoMergeWhen.ChecksPassed = true
	p.Merge.AutoMergeWhen.ReviewApproved = true
	p.Verify.AllowedCommands = []string{"go test ./...", "go vet ./..."}
	return p
}

// LoadPolicy loads remediation policy from .nox.yaml at workspace root.
// If no config exists, defaults are returned.
func LoadPolicy(req sdk.ToolRequest) (RemediationPolicy, error) {
	p := defaultPolicy()
	if req.WorkspaceRoot == "" {
		return p, nil
	}
	path := filepath.Join(req.WorkspaceRoot, ".nox.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return p, nil
		}
		return p, fmt.Errorf("read remediation policy: %w", err)
	}
	var root rootConfig
	if err := yaml.Unmarshal(data, &root); err != nil {
		return p, fmt.Errorf("parse remediation policy: %w", err)
	}
	mergePolicy(&p, root.Remediation)
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func mergePolicy(dst *RemediationPolicy, src RemediationPolicy) {
	if src.Enabled {
		dst.Enabled = true
	}
	if len(src.Risk.AutoApply.Severities) > 0 {
		dst.Risk.AutoApply.Severities = src.Risk.AutoApply.Severities
	}
	if src.Risk.AutoApply.AllowMajor {
		dst.Risk.AutoApply.AllowMajor = true
	}
	if src.Risk.BlastRadius.AutoMergeMax != "" {
		dst.Risk.BlastRadius.AutoMergeMax = src.Risk.BlastRadius.AutoMergeMax
	}
	if src.Risk.BlastRadius.RequireHumanReviewAt != "" {
		dst.Risk.BlastRadius.RequireHumanReviewAt = src.Risk.BlastRadius.RequireHumanReviewAt
	}
	if len(src.Merge.RequireChecks) > 0 {
		dst.Merge.RequireChecks = src.Merge.RequireChecks
	}
	if src.Merge.MinApprovals > 0 {
		dst.Merge.MinApprovals = src.Merge.MinApprovals
	}
	if len(src.Merge.AutoMergeWhen.BlastRadiusIn) > 0 {
		dst.Merge.AutoMergeWhen.BlastRadiusIn = src.Merge.AutoMergeWhen.BlastRadiusIn
	}
	if src.Merge.AutoMergeWhen.ChecksPassed {
		dst.Merge.AutoMergeWhen.ChecksPassed = true
	}
	if src.Merge.AutoMergeWhen.ReviewApproved {
		dst.Merge.AutoMergeWhen.ReviewApproved = true
	}
	if len(src.Verify.AllowedCommands) > 0 {
		dst.Verify.AllowedCommands = src.Verify.AllowedCommands
	}
}

func (p RemediationPolicy) Validate() error {
	for _, sev := range p.Risk.AutoApply.Severities {
		switch strings.ToLower(sev) {
		case "critical", "high", "medium", "low", "info":
		default:
			return fmt.Errorf("%w: %q", ErrInvalidSeverity, sev)
		}
	}
	if !validBlast(p.Risk.BlastRadius.AutoMergeMax) {
		return fmt.Errorf("%w: auto_merge_max=%q", ErrInvalidBlastRadius, p.Risk.BlastRadius.AutoMergeMax)
	}
	if !validBlast(p.Risk.BlastRadius.RequireHumanReviewAt) {
		return fmt.Errorf("%w: require_human_review_at=%q", ErrInvalidBlastRadius, p.Risk.BlastRadius.RequireHumanReviewAt)
	}
	if blastLevel(p.Risk.BlastRadius.RequireHumanReviewAt) < blastLevel(p.Risk.BlastRadius.AutoMergeMax) {
		return fmt.Errorf("%w: require_human_review_at cannot be lower than auto_merge_max", ErrInvalidMergePolicy)
	}
	if p.Merge.MinApprovals < 0 {
		return fmt.Errorf("%w: min_approval_count must be >= 0", ErrInvalidMergePolicy)
	}
	for _, b := range p.Merge.AutoMergeWhen.BlastRadiusIn {
		if !validBlast(b) {
			return fmt.Errorf("%w: auto_merge_when.blast_radius_in=%q", ErrInvalidBlastRadius, b)
		}
		if blastLevel(b) > blastLevel(p.Risk.BlastRadius.AutoMergeMax) {
			return fmt.Errorf("%w: auto_merge_when includes %q above auto_merge_max=%q", ErrInvalidMergePolicy, b, p.Risk.BlastRadius.AutoMergeMax)
		}
	}
	for _, cmd := range p.Verify.AllowedCommands {
		if strings.TrimSpace(cmd) == "" {
			return fmt.Errorf("%w: empty command", ErrInvalidVerificationCmd)
		}
	}
	return nil
}

func validBlast(b BlastRadius) bool {
	switch b {
	case BlastRadiusLow, BlastRadiusMedium, BlastRadiusHigh:
		return true
	default:
		return false
	}
}

func blastLevel(b BlastRadius) int {
	switch b {
	case BlastRadiusLow:
		return 1
	case BlastRadiusMedium:
		return 2
	case BlastRadiusHigh:
		return 3
	default:
		return 0
	}
}
