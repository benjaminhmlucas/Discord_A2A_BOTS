# Publish the clean template

The repository folder should contain only the source, blank/fictional examples, tests and documentation listed in README. Start a new Git history from that folder. Do not copy the runtime installation or import its backups or process dumps.

Before uploading:

1. Preserve the included MIT `LICENSE` file and copyright notice.
2. Run all [testing procedures](TESTING.md), including the release checker, Windows setup integration and strict 100% coverage gates.
3. Inspect every staged file with `git diff --cached`, including Markdown, fixtures and scripts. `.gitignore` does not remove previously tracked files.
4. Run a dedicated secret scanner against the full Git history if any commits already exist. The included release checker does not examine history.
5. Enable GitHub secret scanning/push protection and private vulnerability reporting where available. Review the security alert settings.
6. Push only after the exact staged tree is reviewed. Do not supply bot credentials as Actions secrets; this CI workflow does not use live bots.

After upload, inspect the repository file list, rendered README and Actions result. Verify that private configuration and runtime files are absent. If a credential is exposed, revoke or rotate it; deletion alone does not invalidate it.

References: [GitHub sensitive-data guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository), [GitHub Python CI](https://docs.github.com/en/actions/tutorials/build-and-test-code/python), [PM2 log rotation](https://github.com/keymetrics/pm2-logrotate).
