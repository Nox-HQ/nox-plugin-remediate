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

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/remediate", version).
		Capability("remediate", "Deterministic remediation planning and application for code findings").
		ToolWithContext("plan_code", "Plan deterministic code remediations for supported rules", true).
		ToolWithContext("apply_code", "Apply deterministic code remediations from a prepared plan", false).
		ToolWithContext("verify_code", "Verify remediation changes and emit pass/fail diagnostics", false).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithFilePaths("**"),
		).
		Build()

	engine := NewPatchEngine()
	guardrails := Guardrails{
		MaxFiles:       25,
		MaxAddedLines:  800,
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
