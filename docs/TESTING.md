# Testing and coverage policy

Unit tests are required alongside integration tests. Unit tests exercise routing, authorization, privacy, state transitions, provider failures, cancellation, cleanup and setup failure propagation. Integration tests verify that the pieces work together through their actual consumers.

Install `requirements-dev.txt` into a development venv and run the commands under README's Development checks. Python 3.11 and Node 24.15.0 are the tested runtimes. Native Windows tests additionally require PowerShell 7 and the `py -3.11` launcher. No Discord tokens or provider credentials are needed for tests.

## Exact coverage gates

`.coveragerc` measures every production Python module, including launchers and scripts. It excludes test code and installed dependencies only. Its exclusion and partial-branch patterns are empty. The standard report requires 100%; `scripts/check_coverage.py` additionally rejects any missing statement, missing branch, exclusion or omitted production module using raw JSON counts. A rounded percentage cannot pass that gate.

The Node command in README uses V8 coverage and requires 100% lines, branches and functions for `ecosystem.config.js`, `scripts/pm2_namespace.cjs`, `scripts/pm2_recovery.cjs` and `scripts/recover_pm2.cjs`. PowerShell wrappers contain no conditional control flow: setup decisions are in the fully measured Python module and recovery decisions in the fully measured Node module. `tests/verify_wrappers.ps1` checks parsed syntax and observes setup/start statements in successful and failed installations. The recovery installer is executed against actual Windows Task Scheduler in the native PM2 test.

## Windows integration

`tests/test_native_setup.py` runs these checks automatically as part of pytest on Windows:

- Copies the template into a new path containing spaces and `&`, builds a real venv, installs the exact runtime dependencies from a wheel cache, checks Python's version and runs `pip check`.
- Runs actual PowerShell setup/start wrappers, synthetic initialization, preflight and the rotation patch through real Python and Node processes. A deterministic PM2 adapter records each command without starting bots. Failed installation stops immediately; failed Python launching preserves the exit code.
- Creates only its own temporary processes to verify the real Windows duplicate-process mutex and kill-on-close job behavior.
- Creates sparse files representing more than 1 GB of active or archived logs, then verifies cleanup reaches the configured budget and preserves unrelated content. Sparse allocation avoids writing a gigabyte of payload to the drive.

Optional test environment variables `BOTBRIDGE_TEST_NODE` and `BOTBRIDGE_TEST_POWERSHELL` select installed executables; otherwise PATH is used. `BOTBRIDGE_TEST_WHEELS` selects a predownloaded wheel directory. Without it, the native setup test downloads runtime wheels before testing offline installation. None of these values belong in tracked configuration.

`tests/test_real_pm2.py` adds a real PM2 7.0.1 integration test. It installs actual npm packages, runs the real startup procedure and logrotate module in a path with spaces and `&`, checks two distinct daemon sockets and process lists, verifies exit 103 stops without restart, checks compressed rotation/retention and the real aggregate manager, then saves and resurrects the process list. Its bot consumers are temporary Python fixtures; they produce test logs without contacting Discord or AI. Both owned daemons are stopped during cleanup. The scoped preloader is verified before any daemon command.

Optional `BOTBRIDGE_TEST_PM2_PREFIX` selects a previously installed PM2 prefix to copy into the temporary checkout. Otherwise the pinned package is installed with npm. `BOTBRIDGE_TEST_NPM_CLI` can select the npm JavaScript entry; by default it is located beside Node. `BOTBRIDGE_TEST_PM2_RECEIPT` optionally saves a result receipt outside the checkout.

The native tests are skipped on Linux. The GitHub Actions matrix runs portable unit checks on Linux and Windows, and actual Windows setup checks on Windows. Missing native prerequisites fail the Windows suite rather than silently skipping it.

## Independent recovery verification

`tests/test_recovery_native.py` registers a uniquely named hidden recovery task, stops only its isolated saved daemon, starts that task through actual Windows Task Scheduler, and verifies a real supervised Python process is restored after the task finishes. It verifies that a manually stopped process stays stopped while its daemon is alive. The task and isolated daemon are removed in cleanup. Unit fault injection additionally covers fatal-stop preservation, invalid saved rosters, callback deadlines, errors, maintenance pause and bounded recovery logging.

## Real providers: private opt-in

`tests/test_live_providers.py` is skipped by default. To run it privately, set `BOTBRIDGE_RUN_PROVIDER_TESTS=1` and `BOTBRIDGE_PROVIDER_TEST_SETTINGS` to an ignored JSON file containing your installed `node_executable`, `codex_cli`, `claude_cli`, chosen `codex_model` and `gemini_model`. Supply `GEMINI_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN` privately; Codex uses its existing authenticated CLI store. Do not add credentials to the settings file. `BOTBRIDGE_TEST_PROVIDER_RECEIPT` can save provider pass/fail evidence outside Git.

Run `python -m pytest tests/test_live_providers.py -q`. It calls each real backend through the shipped provider implementation using a temporary public-only checkout and checks the exact response. It uses account capacity or credits. It sends no Discord messages and does not use private memory. Keep these opt-in account tests out of public CI.

## Boundaries

The default suite simulates Discord destinations and AI replies. A deterministic setup adapter remains useful for command failure injection, while the separate real PM2 test verifies actual integration. Private opt-in tests cover real provider authentication and replies. Discord gateway delivery, reconnect behavior, real mentions/references and a live bounded discussion remain separate deployment acceptance checks; passing mocks or provider calls alone cannot establish those results.

100% branch coverage proves that measured paths executed. It does not prove correctness for every possible input, network timing or upstream service change. Preserve behavior assertions and add a regression test for each discovered defect.

References: [coverage.py branch measurement](https://coverage.readthedocs.io/en/latest/branch.html), [Node test-runner coverage](https://nodejs.org/api/test.html), [setup-node configuration](https://github.com/actions/setup-node).
