#!/usr/bin/env python3
"""Resolve exact GitHub Actions change ranges and classify affected KSword projects."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ZERO_SHA = "0" * 40

COMMON_RE = re.compile(
    r"(^tools/|^scripts/|^shared/|^third_party/|^\.deps/|^\.github/workflows/|"
    r"^.*\.sln$|(^|/)(Directory\.Build\..*|.*\.props|.*\.targets)$)"
)
PROJECT_PATTERNS = {
    "usermode": re.compile(
        r"^(TaskmgrHijack\.ps1$|Ksword5\.1/|Launcher/|Taskbar/|KswordHUD/|"
        r"APIMonitor_x64/|KswordCLI/)"
    ),
    "setup": re.compile(
        r"^(TaskmgrHijack\.ps1$|KswordSetup/|Ksword5\.1/|Launcher/|Taskbar/|"
        r"KswordHUD/|APIMonitor_x64/|KswordCLI/|KswordARKDriver/|KswordARKLight/)"
    ),
    "arklight": re.compile(
        r"^(KswordARKLight/|KswordARKDriver/|"
        r"Ksword5\.1/Ksword5\.1/(ArkDriverClient/|Resource/)|shared/driver/|"
        r"scripts/Sign-KswordArkDriverVariant\.ps1$)"
    ),
    "ce_plugin": re.compile(
        r"^(CheatEnginePlugin/|"
        r"Ksword5\.1/Ksword5\.1/(ArkDriverClient/|ksword/string/)|shared/driver/)"
    ),
    "ce_launcher": re.compile(
        r"^(CheatEngineExecutablePlugin/|"
        r"Ksword5\.1/Ksword5\.1/(ArkDriverClient/|ksword/string/))"
    ),
}
DRIVER_RE = re.compile(
    r"(^KswordARKDriver/|^shared/driver/|^third_party/systeminformer_dyn/|"
    r"^scripts/Sign-KswordArkDriverVariant\.ps1$|"
    r"^\.github/workflows/driver-ci\.yml$|^.*\.sln$|"
    r"(^|/)(Directory\.Build\..*|.*\.props|.*\.targets)$)"
)


class GitCommandError(RuntimeError):
    pass


@dataclass(frozen=True)
class DiffRange:
    arguments: tuple[str, ...]
    description: str


def run_git(arguments: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        ["git", *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode != 0:
        command = "git " + " ".join(arguments)
        detail = process.stderr.strip() or process.stdout.strip() or f"exit {process.returncode}"
        raise GitCommandError(f"{command} failed: {detail}")
    return process


def commit_exists(revision: str) -> bool:
    if not revision:
        return False
    return run_git(["cat-file", "-e", f"{revision}^{{commit}}"], check=False).returncode == 0


def resolve_parent(revision: str, parent_number: int) -> str | None:
    process = run_git(["rev-parse", f"{revision}^{parent_number}"], check=False)
    if process.returncode != 0:
        return None
    value = process.stdout.strip()
    return value if commit_exists(value) else None


def load_event(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        event = json.load(handle)
    if not isinstance(event, dict):
        raise ValueError("GitHub event payload must be a JSON object")
    return event


def resolve_diff_range(event_name: str, event: dict, event_sha: str) -> DiffRange | None:
    if event_name == "pull_request":
        pull_request = event.get("pull_request")
        if isinstance(pull_request, dict):
            base = pull_request.get("base")
            head = pull_request.get("head")
            base_sha = base.get("sha", "") if isinstance(base, dict) else ""
            head_sha = head.get("sha", "") if isinstance(head, dict) else ""
            if commit_exists(base_sha) and commit_exists(head_sha):
                return DiffRange((f"{base_sha}...{head_sha}",), "pull-request endpoint commits")

        first_parent = resolve_parent(event_sha, 1)
        second_parent = resolve_parent(event_sha, 2)
        if first_parent and second_parent:
            return DiffRange(
                (f"{first_parent}...{second_parent}",),
                "pull-request merge commit parents",
            )
        return None

    if event_name == "push":
        before = str(event.get("before") or "")
        after = str(event.get("after") or event_sha or "")
        if before and before != ZERO_SHA and commit_exists(before) and commit_exists(after):
            return DiffRange((before, after), "push before/after commits")
        return None

    if event_name == "workflow_dispatch":
        if commit_exists(event_sha) and commit_exists(f"{event_sha}^1"):
            return DiffRange((f"{event_sha}^1", event_sha), "manual-dispatch HEAD commit")
        return None

    return None


def changed_paths(diff_range: DiffRange | None) -> list[str] | None:
    if diff_range is None:
        return None
    process = run_git(
        ["diff", "--name-only", "--no-renames", *diff_range.arguments, "--"],
        check=False,
    )
    if process.returncode != 0:
        print(
            f"Unable to resolve {diff_range.description}: "
            f"{process.stderr.strip() or f'exit {process.returncode}'}. "
            "Treating every project as affected.",
            file=sys.stderr,
        )
        return None
    return [line for line in process.stdout.splitlines() if line]


def project_outputs(paths: list[str] | None) -> dict[str, bool]:
    if paths is None:
        return {name: True for name in PROJECT_PATTERNS}
    outputs: dict[str, bool] = {}
    for name, pattern in PROJECT_PATTERNS.items():
        outputs[name] = any(pattern.search(path) or COMMON_RE.search(path) for path in paths)
    return outputs


def driver_output(paths: list[str] | None) -> bool:
    return paths is None or any(DRIVER_RE.search(path) for path in paths)


def write_outputs(path: Path, values: dict[str, bool]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for name, value in values.items():
            handle.write(f"{name}={'true' if value else 'false'}\n")


def print_paths(paths: list[str] | None, source: str) -> None:
    print(f"Resolved range: {source}")
    print("Changed paths:")
    if paths is None:
        print("__all__")
    elif paths:
        print("\n".join(paths))
    else:
        print("<none>")


def detect(arguments: argparse.Namespace) -> int:
    event = load_event(arguments.event_path)
    diff_range = resolve_diff_range(arguments.event_name, event, arguments.event_sha)
    paths = changed_paths(diff_range)
    source = diff_range.description if diff_range is not None else "unavailable; conservative fallback"
    print_paths(paths, source)

    if arguments.mode == "projects":
        outputs = project_outputs(paths)
        write_outputs(arguments.github_output, outputs)
        summary = " ".join(f"{name}={str(value).lower()}" for name, value in outputs.items())
        print(f"Affected projects: {summary}")
    else:
        value = driver_output(paths)
        write_outputs(arguments.github_output, {"driver": value})
        print(f"Affected driver project: {str(value).lower()}")
    return 0


def check_whitespace(arguments: argparse.Namespace) -> int:
    event = load_event(arguments.event_path)
    diff_range = resolve_diff_range(arguments.event_name, event, arguments.event_sha)
    if diff_range is None:
        raise RuntimeError(
            "Cannot prove the exact change range for whitespace validation; "
            "refusing to silently validate a partial range."
        )
    print(f"Checking whitespace over {diff_range.description}: {' '.join(diff_range.arguments)}")
    process = subprocess.run(
        ["git", "diff", "--check", *diff_range.arguments, "--"],
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(f"git diff --check failed with exit code {process.returncode}")
    return 0


def validate_patterns() -> None:
    required_project_inputs = {
        "TaskmgrHijack.ps1": ("usermode", "setup"),
    }
    for path, expected_projects in required_project_inputs.items():
        outputs = project_outputs([path])
        for project in expected_projects:
            if not outputs[project]:
                raise RuntimeError(f"{path} must trigger {project}")

    required_driver_inputs = (
        "third_party/systeminformer_dyn/kphdyn.c",
        "third_party/systeminformer_dyn/kphdyn.h",
        "third_party/systeminformer_dyn/ksw_si_dynconfig.h",
        "Ksword.ReleaseOutput.props",
        ".github/workflows/driver-ci.yml",
    )
    for path in required_driver_inputs:
        if not driver_output([path]):
            raise RuntimeError(f"{path} must trigger the driver build")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--event-name", required=True)
    common.add_argument("--event-path", type=Path, required=True)
    common.add_argument("--event-sha", required=True)

    detect_parser = subparsers.add_parser("detect", parents=[common])
    detect_parser.add_argument("--mode", choices=("projects", "driver"), required=True)
    detect_parser.add_argument("--github-output", type=Path, required=True)

    subparsers.add_parser("check-whitespace", parents=[common])
    subparsers.add_parser("validate-patterns")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.command == "detect":
        return detect(arguments)
    if arguments.command == "check-whitespace":
        return check_whitespace(arguments)
    validate_patterns()
    print("CI path-classification regression checks passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GitCommandError, OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
