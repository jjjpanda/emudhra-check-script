"""Run a scan in CI; exposure findings are distinct from an incomplete run."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run_scan(command, report_dir, require_wsl=False):
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    code = None
    error = None
    with (report_dir / "scan.log").open("w", encoding="utf-8") as log:
        try:
            with subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            ) as process:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    print(line, end="", flush=True)
                code = process.wait()
        except OSError as exc:
            error = str(exc)
            log.write(error + "\n")

    report = (report_dir / "scan.log").read_text(encoding="utf-8")
    report = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", report)
    complete = code in (0, 1, 2) and bool(
        re.search(r"^== SUMMARY ==\s*$", report, re.MULTILINE)
    )
    if require_wsl:
        distros = re.findall(r"^== WSL distro: .+ ==\s*$", report, re.MULTILINE)
        results = re.findall(
            r"^\[(?:OK|FAIL|WARN)\]\s+WSL .+: "
            r"(?:no issues|issues found|some checks not verified).*$",
            report,
            re.MULTILINE,
        )
        complete = complete and bool(distros) and len(distros) == len(results)

    outcome = {0: "no issues", 1: "issues found", 2: "checks not verified"}.get(
        code, "scan did not complete"
    )
    if not complete:
        outcome = "scan did not complete"
    result = {"exit_code": code, "completed": complete, "outcome": outcome}
    if error:
        result["error"] = error
    (report_dir / "result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    summary = (
        f"Scan result: **{outcome}** (script exit: `{code}`).\n\n"
        "This job checks scan execution. Exposure findings and unverified checks "
        "are reported in the artifact; a green job does not certify trust safety.\n"
    )
    (report_dir / "summary.md").write_text(summary, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
    print(summary)
    return 0 if complete else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", default="scan-reports")
    parser.add_argument("--windows-shell", choices=("powershell", "pwsh"), default="pwsh")
    parser.add_argument("--require-wsl", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if os.name == "nt":
        command = [
            args.windows_shell, "-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(root / "check-windows.ps1"),
        ]
    else:
        command = ["/bin/bash", str(root / "check-unix.sh"), "--no-docker"]
    return run_scan(command, args.report_dir, args.require_wsl)


if __name__ == "__main__":
    sys.exit(main())
