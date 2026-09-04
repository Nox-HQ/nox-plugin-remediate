package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/plugin"
	"github.com/nox-hq/nox/sdk"
)

// The whole plugin was refused registration under a passive policy — the
// default, and what `nox scan` runs with — because every tool inherited the
// plugin-level ceiling (active, needs_confirmation, file_paths **). The
// read-only planner went down with the two writers, so a scan listing
// nox/remediate got nothing at all rather than fix plans.
//
// ValidateManifest admits a plugin whose ceiling exceeds the policy when some
// tool declares narrower requirements the policy allows. plan_code's own
// ToolSafety is what establishes that.
func TestManifestIsAdmissibleUnderThePassiveDefault(t *testing.T) {
	policy := plugin.DefaultPolicy()

	if v := plugin.ValidateManifest(buildManifest(), &policy); len(v) != 0 {
		t.Fatalf("manifest refused under the default passive policy: %v", v)
	}
}

// Admission is not permission. The two tools that write to the workspace or
// execute commands must still be refused per invocation under the same policy,
// or this change would have widened what a scan may do instead of narrowing
// what it refuses.
func TestOnlyPlanCodeIsInvocableUnderThePassiveDefault(t *testing.T) {
	policy := plugin.DefaultPolicy()
	m := buildManifest()

	if v := plugin.ValidateToolInvocation(m, "plan_code", &policy); len(v) != 0 {
		t.Errorf("plan_code refused under the passive policy: %v", v)
	}
	for _, name := range []string{"apply_code", "verify_code"} {
		if v := plugin.ValidateToolInvocation(m, name, &policy); len(v) == 0 {
			t.Errorf("%s was permitted under a passive policy; it must require an explicit opt-in", name)
		}
	}
}

// plan_code declares itself passive. PatchEngine.Plan must therefore not write,
// or the declaration is a claim the host has no way to check.
func TestPlanDoesNotTouchTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	// The static, metacharacter-free shape SEC-001 rewrites; taken from
	// TestGoSubprocessRewritesStaticCommand so the fixture is known to plan.
	src := "package main\n\nimport \"os/exec\"\n\nfunc main() {\n\tc := exec.Command(\"sh\", \"-c\", \"ls -la /tmp\")\n\t_ = c\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "sample.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	before := snapshotTree(t, dir)
	plan, err := NewPatchEngine().Plan(sdk.ToolRequest{WorkspaceRoot: dir})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// A plan that found nothing would pass this test vacuously.
	if len(plan.Patches) == 0 {
		t.Fatal("fixture produced no patches, so the no-write assertion proves nothing")
	}
	if after := snapshotTree(t, dir); after != before {
		t.Errorf("Plan modified the workspace:\n before %s\n after  %s", before, after)
	}
}

// snapshotTree renders every file's path and contents so any write — content,
// creation or deletion — shows up as a difference.
func snapshotTree(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, readErr := os.ReadFile(path) // #nosec G304 -- test fixture under t.TempDir
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(dir, path)
		lines = append(lines, rel+"\x00"+string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
