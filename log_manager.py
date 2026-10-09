"""Aggregate retention for PM2/BotBridge logs. Never scans arbitrary project files."""

import argparse
import json
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_NAME = re.compile(r".+\.log(?:\.\d+)?(?:\.gz)?$", re.IGNORECASE)
TRANSCRIPTS = ("codex_incoming.md", "codex_discord_log.md", "incoming.md")


def load_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    limits = [
        config[k]
        for k in ("cleanup_target_bytes", "cleanup_trigger_bytes", "aggregate_limit_bytes")
    ]
    if not (0 < limits[0] < limits[1] < limits[2]):
        raise ValueError("Require target < trigger < total budget")
    if not (0 < config["active_tail_bytes"] <= config["max_active_file_bytes"] < limits[0]):
        raise ValueError("Invalid active-file limits")
    if not 1 <= config["interval_seconds"] <= 60:
        raise ValueError("Invalid polling interval")
    return config


def _inventory_error(errors, path, exc):
    if errors is None:
        raise exc
    errors.append({"path": str(path), "error": type(exc).__name__, "operation": "inventory"})


def inventory(config, errors=None):
    files = []
    seen = set()
    for scope in config["scopes"]:
        try:
            root = Path(scope["directory"]).resolve(strict=True)
            entries = list(root.iterdir())
        except OSError as exc:
            _inventory_error(errors, scope["directory"], exc)
            continue
        for path in entries:
            name = path.name
            transcript = scope.get("include_transcripts", False) and any(
                name == base or re.fullmatch(re.escape(base) + r"\.\d+", name)
                for base in TRANSCRIPTS
            )
            if not LOG_NAME.fullmatch(name) and not transcript:
                continue
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # Concurrent rotator renamed/deleted an entry.
            except OSError as exc:
                _inventory_error(errors, path, exc)
                continue
            try:
                # No recursive traversal, symlinks, junctions, or other reparse points.
                if (
                    not stat.S_ISREG(info.st_mode)
                    or path.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & 0x400
                ):
                    continue
                if path.parent.resolve() != root:
                    raise ValueError("Unexpected file location")
                absolute = str(path.resolve())
            except (OSError, ValueError) as exc:
                _inventory_error(errors, path, exc)
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            archive = name.endswith(".gz") or bool(re.search(r"\.\d+$", name)) or "__" in name
            files.append(
                {
                    "path": absolute,
                    "bytes": info.st_size,
                    "mtime": info.st_mtime,
                    "archive": archive,
                    "scope": str(root),
                }
            )
    return files


def _checked_path(item):
    path = Path(item["path"])
    root = Path(item["scope"])
    info = path.lstat()
    if (
        path.parent.resolve() != root
        or not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or getattr(info, "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("Managed file identity changed")
    return path


def trim_tail(item, keep_bytes):
    """Keep recent complete lines using in-place truncate, preserving open writers."""
    path = _checked_path(item)
    # Bound read size even if a historical file is enormous; never copy its full body.
    with path.open("r+b") as stream:
        stream.seek(0, 2)
        original = stream.tell()
        if original <= keep_bytes:
            return 0
        if keep_bytes:
            stream.seek(original - keep_bytes)
            tail = stream.read(keep_bytes)
            newline = tail.find(b"\n")
            if newline >= 0:
                tail = tail[newline + 1 :]
        else:
            tail = b""
        stream.seek(0)
        stream.write(tail)
        stream.truncate(len(tail))
        stream.flush()
    return original - len(tail)


def enforce(config):
    actions, errors = [], []
    before = inventory(config, errors)
    before_bytes = sum(f["bytes"] for f in before)
    now = time.time()
    # Independent file guard: catches a dead rotator and legacy direct appenders.
    for item in before:
        try:
            if not item["archive"] and item["bytes"] > config["max_active_file_bytes"]:
                removed = trim_tail(item, config["active_tail_bytes"])
                actions.append(
                    {"action": "trim_oversize", "path": item["path"], "removed_bytes": removed}
                )
            elif item["archive"] and now - item["mtime"] > config["archive_max_age_days"] * 86400:
                _checked_path(item).unlink()
                actions.append(
                    {
                        "action": "expire_archive",
                        "path": item["path"],
                        "removed_bytes": item["bytes"],
                    }
                )
        except FileNotFoundError:
            pass  # Another rotator already removed it.
        except (OSError, ValueError) as exc:
            errors.append({"path": item["path"], "error": type(exc).__name__})
    current = inventory(config, errors)
    total = sum(f["bytes"] for f in current)
    cleanup_required = (
        before_bytes >= config["cleanup_trigger_bytes"] or total >= config["cleanup_trigger_bytes"]
    )
    if cleanup_required:
        # Delete oldest archives first; preserve active logs whenever possible.
        archives = sorted(
            (f for f in current if f["archive"]), key=lambda f: (f["mtime"], f["path"])
        )
        for item in archives:
            if total <= config["cleanup_target_bytes"]:
                break
            try:
                _checked_path(item).unlink()
                actions.append(
                    {
                        "action": "prune_archive",
                        "path": item["path"],
                        "removed_bytes": item["bytes"],
                    }
                )
                total -= item["bytes"]
            except FileNotFoundError:
                total -= item["bytes"]
            except (OSError, ValueError) as exc:
                errors.append({"path": item["path"], "error": type(exc).__name__})
        current = inventory(config, errors)
        total = sum(f["bytes"] for f in current)
        for item in sorted(
            (f for f in current if not f["archive"]), key=lambda f: f["bytes"], reverse=True
        ):
            if total <= config["cleanup_target_bytes"]:
                break
            keep = max(
                0,
                min(
                    config["active_tail_bytes"],
                    item["bytes"] - (total - config["cleanup_target_bytes"]),
                ),
            )
            try:
                removed = trim_tail(item, keep)
                actions.append(
                    {"action": "trim_budget", "path": item["path"], "removed_bytes": removed}
                )
                total -= removed
            except FileNotFoundError:
                total -= item["bytes"]
            except (OSError, ValueError) as exc:
                errors.append({"path": item["path"], "error": type(exc).__name__})
    final = inventory(config, errors)
    total = sum(f["bytes"] for f in final)
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "error" if errors or total >= config["aggregate_limit_bytes"] else "ok",
        "aggregate_limit_bytes": config["aggregate_limit_bytes"],
        "cleanup_trigger_bytes": config["cleanup_trigger_bytes"],
        "cleanup_target_bytes": config["cleanup_target_bytes"],
        "before_bytes": before_bytes,
        "current_bytes": total,
        "managed_file_count": len(final),
        "cleanup_required": cleanup_required,
        "inventory_complete": not any(e.get("operation") == "inventory" for e in errors),
        "action_count": len(actions),
        "actions": actions[:40],
        "errors": errors[:40],
        "files": [{k: f[k] for k in ("path", "bytes", "archive")} for f in final[:200]],
    }


def save_state(config, state):
    target = Path(config["state_file"])
    payload = json.dumps(state, indent=2)
    if len(payload.encode()) > 128 * 1024:
        raise ValueError("State report exceeded its own size bound")
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    if args.once:
        state = enforce(config)
        save_state(config, state)
        print(
            json.dumps(
                {
                    k: state[k]
                    for k in ("status", "current_bytes", "managed_file_count", "action_count")
                }
            )
        )
        return 0 if state["status"] == "ok" else 1
    print(
        "BotBridge log manager started: total budget 1 GB; bounded rotating logs and aggregate cleanup active.",
        flush=True,
    )
    last_error, last_notice = None, 0
    while True:
        try:
            state = enforce(config)
            save_state(config, state)
            signature = tuple((e["path"], e["error"]) for e in state["errors"])
            if (
                state["action_count"]
                or state["status"] != "ok"
                and (signature != last_error or time.monotonic() - last_notice >= 60)
            ):
                print(
                    f"log_budget status={state['status']} bytes={state['current_bytes']} actions={state['action_count']} errors={len(state['errors'])}",
                    flush=True,
                )
                last_error, last_notice = signature, time.monotonic()
        except (OSError, ValueError) as exc:
            signature = type(exc).__name__
            if signature != last_error or time.monotonic() - last_notice >= 60:
                print(f"log_budget scan_failed={signature}", file=sys.stderr, flush=True)
                last_error, last_notice = signature, time.monotonic()
        time.sleep(config["interval_seconds"])


if __name__ == "__main__":
    sys.exit(main())
