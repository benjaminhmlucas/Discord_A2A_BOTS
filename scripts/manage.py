"""Testable setup/start orchestration. Every command uses this checkout's paths."""

import argparse
import os
import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# PM2 7.0.1 global options, used only to select the metadata optimization.
# Unknown options fall back to normal PM2 behavior; argv is always forwarded intact.
PM2_SWITCHES = set(
    """
-v --version -s --silent -m --mini-list --time --disable-logs -a --update-env
-f --force --shutdown-with-message -x --execute-command --wait-ip -w --write
--no-daemon --source-map-support --disable-source-map-support --wait-ready
--merge-logs --no-color --no-vizion --no-autostart --no-autorestart --no-treekill
--no-pmx --no-automation --trace --disable-trace --attach --v8
--event-loop-inspector --deep-monitoring -h --help
""".split()
)
PM2_VALUE_OPTIONS = set(
    """
--ext -n --name --interpreter --interpreter-args --node-args -o --output -e --error
-l --log --filter-env --log-type --log-date-format --env -i --instances --parallel
-p --pid -k --kill-timeout --listen-timeout --max-memory-restart --restart-delay
--exp-backoff-restart-delay --max-restarts -u --user --uid --gid --namespace --cwd
--hp --service-name -c --cron --cron-restart --only --watch --ignore-watch
--watch-delay --stop-exit-codes --sort
""".split()
)


def pm2_command(arguments):
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if not argument.startswith("-"):
            return argument
        option, separator, _ = argument.partition("=")
        if option in PM2_SWITCHES:
            index += 1
        elif option in PM2_VALUE_OPTIONS:
            optional_without_value = option in {
                "--log",
                "-l",
                "--filter-env",
                "--max-restarts",
                "--watch",
            } and (index + 1 == len(arguments) or arguments[index + 1].startswith("-"))
            index += 1 if separator or optional_without_value else 2
        else:
            return None
    return None


def stop_command(proc):
    """Stop only this command's live process tree; never address a daemon by name."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        killer = Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32/taskkill.exe"
        try:
            subprocess.run(
                [str(killer), "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=10)


def run(command, root, env, timeout=120):
    command = [str(arg) for arg in command]
    # Inherit output streams: descendants cannot hold a communicate() capture pipe open.
    proc = subprocess.Popen(
        command,
        cwd=root,
        env=env,
        start_new_session=os.name != "nt",
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_command(proc)
        raise
    if code:
        raise subprocess.CalledProcessError(code, command)
    return subprocess.CompletedProcess(command, code)


def manage(action, root=ROOT, pm2_args=()):
    root = Path(root).resolve()
    env = os.environ.copy()
    env["PM2_HOME"] = str(root / ".pm2")
    env["NODE_OPTIONS"] = "--require=" + json.dumps(str(root / "scripts/pm2_namespace.cjs"))
    python = root / ".venv/Scripts/python.exe"
    if action == "setup":
        run([sys.executable, "-m", "venv", root / ".venv"], root, env)
        run([python, "-m", "pip", "install", "-r", root / "requirements.txt"], root, env)
        run([python, "-c", "import sys; print(sys.version)"], root, env)
        return
    if action not in ("start", "pm2"):
        raise ValueError("Unknown setup action")
    if not python.is_file():
        raise RuntimeError("Create the checkout venv before starting bots")
    if action == "start":
        run([python, root / "preflight.py"], root, env)
    settings = json.loads((root / "local_settings.json").read_text(encoding="utf-8"))
    node = Path(shutil.which(settings["node_executable"]) or settings["node_executable"])
    node = node if node.is_absolute() else root / node
    entry = Path(settings["pm2_cli"])
    entry = entry if entry.is_absolute() else root / entry
    if not Path(node).is_file() or not entry.is_file():
        raise RuntimeError("Configure Node and install the checkout-local PM2 CLI before starting")
    # Direct Node invocation preserves paths containing spaces or shell metacharacters.
    # Management needs identities/status, not potentially blocking Windows WMI metrics.
    # Explicit opt-in also covers module clients; normal operator monitoring is unchanged.
    if action == "start" or (
        pm2_command(pm2_args)
        in (
            "start",
            "restart",
            "stop",
            "delete",
            "kill",
            "save",
            "resurrect",
            "install",
            "set",
            "multiset",
        )
    ):
        env["BOTBRIDGE_PM2_METADATA_ONLY"] = "1"
    pm2 = [node, entry]
    if action == "pm2":
        run([*pm2, *pm2_args], root, env)
        return
    run([*pm2, "install", "pm2-logrotate@3.0.0"], root, env)
    run([python, root / "scripts/fix_logrotate.py"], root, env)
    run(
        [
            *pm2,
            "multiset",
            "pm2-logrotate:max_size 10M pm2-logrotate:retain 5 "
            "pm2-logrotate:compress true pm2-logrotate:workerInterval 5",
        ],
        root,
        env,
    )
    run([*pm2, "set", "pm2-logrotate:rotateInterval", "0 0 * * *"], root, env)
    run([*pm2, "restart", "pm2-logrotate"], root, env)
    run([*pm2, "start", root / "ecosystem.config.js"], root, env)
    print("Started in repository-local PM2 home. Inspect health and logs before pm2 save.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "start", "pm2"))
    parser.add_argument("pm2_args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    manage(options.action, pm2_args=options.pm2_args)


if __name__ == "__main__":
    main()
