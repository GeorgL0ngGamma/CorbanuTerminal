#!/usr/bin/env python3
"""Bounded ASan investigation on a disposable macOS GitHub runner.

Keep the original libtest process/concurrency rather than nextest's separate
processes. Reuse ordinary-test profile isolation and native-keyring denial.
This diagnostic is neither a fix nor a regression test for issue #1367.
Rust crates are instrumented; the prebuilt standard library and native system
libraries are not. A passing run does not rule out defects in those libraries.
"""

import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "codex-rs"
FILTERS = [
    "suite::issue_506::",
    "suite::issue_584::",
    "suite::issue_620_622::",
    "suite::issue_736_740::",
    "suite::issue_747::",
    "suite::issue_748::",
]


def main():
    if platform.system() != "Darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This investigation requires a disposable macOS GitHub runner")
    out = Path(os.environ["RUNNER_TEMP"]) / "issue-1367-asan"
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    spec = importlib.util.spec_from_file_location(
        "isolation", ROOT / "scripts/isolated_rust_tests.py"
    )
    isolation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolation)
    metadata = {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "originalHead": "5cfd69e7823ac69677b74b3005e5774aa373f52e",
        "platform": platform.platform(),
        "cpuCount": os.cpu_count(),
        "image": os.environ.get("ImageVersion"),
        "compiler": subprocess.check_output(["rustc", "-Vv"], cwd=WORKSPACE, text=True),
        "rustflags": os.environ["RUSTFLAGS"],
        "stackBytes": 8388608,
        "instrumented": "Rust crates; prebuilt std and native system libraries are not instrumented",
    }
    (out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    summary = []

    def run(label, command, env, timeout):
        print(f"Starting {label}", flush=True)
        begin = time.monotonic()
        with (out / f"{label}.log").open("w") as log:
            try:
                result = subprocess.run(
                    command, cwd=WORKSPACE, env=env, stdout=log,
                    stderr=subprocess.STDOUT, timeout=timeout,
                )
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        record = {
            "label": label, "command": command, "exitCode": code,
            "seconds": round(time.monotonic() - begin, 3),
            "tmpdir": env.get("TMPDIR"),
        }
        if label.startswith("run-"):
            events = []
            for line in (out / f"{label}.log").read_text(errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and event.get("type") in ("suite", "test"):
                    events.append(event)
            record["startedTests"] = [
                e["name"] for e in events
                if e.get("type") == "test" and e.get("event") == "started"
            ]
            record["finishedTests"] = [
                e["name"] for e in events
                if e.get("type") == "test" and e.get("event") in ("ok", "failed", "ignored")
            ]
            record["suiteResults"] = [
                e for e in events
                if e.get("type") == "suite" and e.get("event") in ("ok", "failed")
            ]
            # A green tool invocation with zero/no recorded tests is not a pass.
            if code == 0 and (
                len(record["startedTests"]) != 18
                or len(record["finishedTests"]) != 18
                or not any(e.get("passed") == 18 for e in record["suiteResults"])
            ):
                code = record["exitCode"] = 125
                record["error"] = "Expected all 18 selected tests and a complete result"
        summary.append(record)
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"{label}: exit={code}, {record['seconds']}s", flush=True)
        if code:
            print((out / f"{label}.log").read_text(errors="replace")[-18000:], flush=True)
        return code

    try:
        with tempfile.TemporaryDirectory(prefix="issue-1367-profile-") as home:
            env = isolation.test_environment(os.environ, Path(home))
            isolation.validate_debug_run([], env)
            env["ASAN_OPTIONS"] = (
                "detect_leaks=0:detect_stack_use_after_return=1:abort_on_error=1:"
                f"symbolize=1:log_path={out / 'asan'}"
            )
            target_lib = Path(subprocess.check_output(
                ["rustc", "--print", "target-libdir"], cwd=WORKSPACE, text=True
            ).strip())
            symbolizer = target_lib.parent / "bin/llvm-symbolizer"
            if symbolizer.is_file():
                env["ASAN_SYMBOLIZER_PATH"] = str(symbolizer)
            cargo = [
                "cargo", "test", "--locked", "--target", "aarch64-apple-darwin",
                "-p", "codex-core", "--test", "all",
            ]
            code = run("build", cargo + ["--no-run"], env, 2700)
            if code:
                return code
            code = run("build-helpers", [
                "cargo", "build", "--locked", "--target", "aarch64-apple-darwin",
                "-p", "codex-code-mode-host", "-p", "codex-rmcp-client", "--bins",
            ], env, 600)
            if code:
                return code
            test_args = ["--", *FILTERS, "-Z", "unstable-options", "--format", "json"]
            for iteration in range(1, 4):
                for tmp in ("runner", "tmp"):
                    child_env = env.copy()
                    if tmp == "tmp":
                        child_env["TMPDIR"] = "/tmp"
                    code = run(f"run-{iteration}-{tmp}", cargo + test_args, child_env, 180)
                    if code:
                        return code
            return 0
    finally:
        # Capture reports even if ASan or the process terminates the test command.
        reports = []
        for root in (
            Path.home() / "Library/Logs/DiagnosticReports",
            Path("/Library/Logs/DiagnosticReports"),
        ):
            if root.exists():
                for path in root.rglob("*"):
                    if (
                        path.is_file()
                        and path.suffix in (".ips", ".crash")
                        and path.name.startswith("all-")
                        and path.stat().st_mtime >= started
                    ):
                        destination = out / "crash-reports" / path.name
                        destination.parent.mkdir(exist_ok=True)
                        shutil.copy2(path, destination)
                        reports.append(path.name)
        (out / "crash-reports.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
