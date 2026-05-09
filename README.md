# nox-plugin-remediate

`nox-plugin-remediate` is the remediation orchestration plugin for deterministic code fixes.

Current scope (task-57):

- tool scaffolding for `plan_code`, `apply_code`, and `verify_code`
- deterministic patch engine interfaces
- blast-radius guardrails (max files / added lines / removed lines)
- rollback-friendly apply/verify plumbing scaffold

Current scope (task-59):

- WEB-SEC-001 deterministic fixer for baseline header middleware
  - Go `net/http`: wraps common `http.ListenAndServe` handler args with `securityHeadersMiddleware`
  - Node Express: adds `helmet` import and `app.use(helmet())`
- idempotence coverage in tests (second planning pass yields zero patches)

Current scope (task-60):

- AI-LOG-001 deterministic fixer for sensitive prompt/response logging redaction
  - Go: redacts `log.Printf` and `log.Println` calls with AI-related keywords (prompt, response, completion, message)
  - Python: redacts `logging.*` and `print()` calls with AI-related keyword content
  - JS: redacts `console.*` and `logger.*` calls with AI-related keyword content
- Redaction replaces raw content log lines with `// REDACTED` or `# REDACTED` comment markers
- No false positives on safe logging (covered by negative test)

Rule-specific fixers and policy parsing are implemented in follow-up tasks.
