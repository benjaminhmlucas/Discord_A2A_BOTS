# Contributing

Use a separate checkout and synthetic fixtures. Run every check in [TESTING.md](docs/TESTING.md), including the release checker, unit tests, setup integration and exact coverage gates, before submitting a change. Never use production bot credentials or private memory in tests or pull requests.

Every shipped Python module must have 100% statement and branch coverage without exclusions. Do not remove modules from measurement or add coverage pragmas to meet the threshold. Add behavior tests for reachable paths; simplify provably unreachable code while preserving behavior. JavaScript production configuration also requires 100% coverage. Windows native integration must pass before release; a Linux-only run cannot verify Windows setup.

Keep configuration and credentials out of source. Add regression tests for changes to routing, numeric authorization, privacy filtering, bounded queues, cancellation, state transitions and log cleanup. Tests should assert behavior, including failures, rather than duplicate implementation.

Preserve the Windows duplicate-process mutex and kill-on-close job. Review CLI flags against the installed version before changing provider behavior. Keep public chat free of local execution tools and inherited integrations.

The owner should choose a license and enable private vulnerability reporting before accepting external contributions.
