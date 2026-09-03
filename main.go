package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// buildManifest declares what this plugin is allowed to do. Split out of
// buildServer so the safety declarations can be asserted directly: they are
// the difference between a scan getting fix plans and getting nothing.
func buildManifest() *pluginv1.GetManifestResponse {
	return sdk.NewManifest("nox/remediate", version).
		Capability("remediate", "Deterministic remediation planning and application for code findings").
		// Per-tool safety, declared honestly rather than copied from the
		// plugin-level ceiling.
		//
		// Without it every tool inherits that ceiling, so a passive policy —
		// the default, and what `nox scan` uses — refused the whole plugin and
		// took the read-only planner down with the two writers. The host is
		// built for exactly this shape: ValidateManifest admits a plugin whose
		// ceiling exceeds the policy when some tool declares narrower
		// requirements the policy allows, and refuses the others individually
		// at invocation.
		//
		// plan_code walks the workspace it is handed and returns patches. It
		// writes nothing — PatchEngine.Plan has no filesystem writes — so it is
		// passive and needs no file_paths grant, exactly like every analysis
		// plugin that reads the workspace root it is given.
		ToolWithContext("plan_code", "Plan deterministic code remediations for supported rules", true).
		ToolSafety(sdk.WithRiskClass(sdk.RiskPassive)).
		// apply_code writes patched files back to the workspace.
		ToolWithContext("apply_code", "Apply deterministic code remediations from a prepared plan", false).
		ToolSafety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithFilePaths("**"),
		).
		// verify_code runs `sh -c` with an operator-supplied command (gated by
		// policy.Verify.AllowedCommands). Arbitrary execution is active whatever
		// the allowlist says.
		ToolWithContext("verify_code", "Verify remediation changes and emit pass/fail diagnostics", false).
		ToolSafety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithFilePaths("**"),
		).
		Done().
		// The plugin-level block stays the ceiling: everything this plugin
		// might ever need, visible to an operator before anything runs.
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithFilePaths("**"),
		).
		Build()
}

func buildServer() *sdk.PluginServer {
	manifest := buildManifest()

	engine := NewPatchEngine()
	guardrails := Guardrails{
		MaxFiles:        25,
		MaxAddedLines:   800,
		MaxRemovedLines: 800,
	}

	return sdk.NewPluginServer(manifest).
		HandleTool("plan_code", handlePlanCode(engine)).
		HandleTool("apply_code", handleApplyCode(engine, guardrails)).
		HandleTool("verify_code", handleVerifyCode(engine))
}

func handlePlanCode(engine *PatchEngine) sdk.ToolHandler {
	return func(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
		resp := sdk.NewResponse()
		policy, err := LoadPolicy(req)
		if err != nil {
			return nil, err
		}
		if !policy.Enabled {
			resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, "remediation is disabled by policy", "nox/remediate")
			return resp.Build(), nil
		}
		plan, err := engine.Plan(req)
		if err != nil {
			return nil, err
		}
		resp.Diagnostic(
			pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO,
			fmt.Sprintf("policy: auto_merge_max=%s require_human_review_at=%s allow_major=%t", policy.Risk.BlastRadius.AutoMergeMax, policy.Risk.BlastRadius.RequireHumanReviewAt, policy.Risk.AutoApply.AllowMajor),
			"nox/remediate",
		)
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, fmt.Sprintf("generated remediation plan with %d patch(es)", len(plan.Patches)), "nox/remediate")
		for _, p := range plan.Patches {
			resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, fmt.Sprintf("planned patch: %s (%d + / %d -)", p.FilePath, p.AddedLines, p.RemovedLines), "nox/remediate")
		}
		emitRemediationNotes(resp, plan)
		return resp.Build(), nil
	}
}

func handleApplyCode(engine *PatchEngine, guardrails Guardrails) sdk.ToolHandler {
	return func(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
		resp := sdk.NewResponse()
		policy, err := LoadPolicy(req)
		if err != nil {
			return nil, err
		}
		if !policy.Enabled {
			resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, "remediation is disabled by policy", "nox/remediate")
			return resp.Build(), nil
		}
		plan, err := engine.Plan(req)
		if err != nil {
			return nil, err
		}
		if err := guardrails.Validate(plan); err != nil {
			return nil, err
		}

		verifyCmd := strings.TrimSpace(req.InputString("command"))
		if verifyCmd != "" && !allowedCommand(policy.Verify.AllowedCommands, verifyCmd) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidVerificationCmd, verifyCmd)
		}
		autoVerify, _ := req.Input["verify"].(bool)

		// Emitted before apply so the advisory reaches the caller on both the
		// verified and unverified paths. Some fixes are not complete once the
		// code changes; SEC-003 needs credential rotation out of band.
		emitRemediationNotes(resp, plan)

		if !autoVerify {
			result, err := engine.Apply(plan)
			if err != nil {
				return nil, err
			}
			resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, fmt.Sprintf("applied %d patch(es)", len(result.AppliedFiles)), "nox/remediate")
			return resp.Build(), nil
		}

		result, verification, err := engine.ApplyAndVerify(plan, req)
		if err != nil {
			return nil, err
		}
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, fmt.Sprintf("applied %d patch(es)", len(result.AppliedFiles)), "nox/remediate")
		sev := pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO
		if !verification.Ok {
			sev = pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR
		}
		for _, msg := range verification.Messages {
			resp.Diagnostic(sev, msg, "nox/remediate")
		}
		return resp.Build(), nil
	}
}

func handleVerifyCode(engine *PatchEngine) sdk.ToolHandler {
	return func(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
		resp := sdk.NewResponse()
		policy, err := LoadPolicy(req)
		if err != nil {
			return nil, err
		}
		if !policy.Enabled {
			resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, "remediation is disabled by policy", "nox/remediate")
			return resp.Build(), nil
		}
		requested := strings.TrimSpace(req.InputString("command"))
		if requested != "" && !allowedCommand(policy.Verify.AllowedCommands, requested) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidVerificationCmd, requested)
		}
		verification := engine.Verify(req)
		sev := pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO
		if !verification.Ok {
			sev = pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR
		}
		for _, msg := range verification.Messages {
			resp.Diagnostic(sev, msg, "nox/remediate")
		}
		return resp.Build(), nil
	}
}

// emitRemediationNotes surfaces rule-level advisories as warnings so they land
// in the tool result, not only inside the patch diff a reviewer may skim past.
func emitRemediationNotes(resp *sdk.ResponseBuilder, plan PatchPlan) {
	for _, note := range plan.RemediationNotes() {
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, note, "nox/remediate")
	}
}

func allowedCommand(allowlist []string, cmd string) bool {
	for _, a := range allowlist {
		if strings.TrimSpace(a) == cmd {
			return true
		}
	}
	return false
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-remediate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return buildServer().Serve(ctx)
}
