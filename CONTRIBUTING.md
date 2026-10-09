# Contributing

Use a separate checkout and synthetic fixtures. Run every check in [TESTING.md](docs/TESTING.md), including the release checker, unit tests, setup integration and exact coverage gates, before submitting a change. Never use production bot credentials or private memory in tests or pull requests.

Every shipped Python module must have 100% statement and branch coverage without exclusions. Do not remove modules from measurement or add coverage pragmas to meet the threshold. Add behavior tests for reachable paths; simplify provably unreachable code while preserving behavior. JavaScript production configuration also requires 100% coverage. Windows native integration must pass before release; a Linux-only run cannot verify Windows setup.

Keep configuration and credentials out of source. Add regression tests for changes to routing, numeric authorization, privacy filtering, bounded queues, cancellation, state transitions and log cleanup. Tests should assert behavior, including failures, rather than duplicate implementation.

Preserve the Windows duplicate-process mutex and kill-on-close job. Review CLI flags against the installed version before changing provider behavior. Keep public chat free of local execution tools and inherited integrations.

Pull requests need an independent approval of the latest push, resolved conversations and all required checks. Review approvals are dismissed when code changes. The enforced default-branch ruleset has no bypass list. See [security review policy](docs/security-review.md); MIT licensing and private vulnerability reporting are configured.

Run `ruff check .`, `ruff format --check .`, `mypy`, `bandit -r . -c pyproject.toml -ll`, and `python -m pip_audit --strict` after installing development requirements. Audit both locked npm manifests with `npm ci --ignore-scripts --prefix dependencies/pm2`, `npm audit --prefix dependencies/pm2 --audit-level=low` and the equivalent commands for `dependencies/logrotate`. CI also runs extended CodeQL analysis for Python and JavaScript. Type checking currently covers the provider contract and health I/O boundary; expand it when changing additional interfaces.
