# Changelog

All notable changes to this project will be documented in this file.

- chore(deps): Go 1.26.5 and nox SDK v1.17.0 (#14)
- chore(security): nox remediation (deps + actions) (#13)
- ci: add nox-remediate caller (deps + action-pin remediation)
- fix(SEC-001): only de-shell provably-static subprocess commands, skip the rest (#12)
- fix(SEC-002): harden SQL parameterization to skip identifier positions and catch single-quoted SQL (#11)
- fix(SEC-003): rewrite JS secrets detector to catch all quote styles, stop losing trailing content (#8)
- fix(SEC-003): robust Python secret rewrite that skips when unsure (#9)
- fix(SEC-003): make the Go secret rewrite AST-aware and skip when unsure (#10)
- fix(SEC-003): warn that rewritten secrets are compromised and need rotation (#7)
- ci: point the registry notice at where entries actually go (#6)
- ci: SHA-pin nox-remediate-action (IAC-013) (#5)

