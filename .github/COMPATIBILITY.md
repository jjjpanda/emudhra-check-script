The Platform compatibility workflow runs on pull requests touching the scripts or
CI files, and can also be started with **Actions > Platform compatibility > Run
workflow** once the workflow exists on the default branch. A run tests the checked
out revision; local, unpushed edits are not included.

| Environment | Coverage |
| --- | --- |
| Ubuntu 24.04 | Native runner, system Bash |
| macOS 15, Apple Silicon and Intel | Native runners, `/bin/bash` (system Bash 3.2) |
| Windows Server 2025 | Windows PowerShell 5.1 and PowerShell 7 |
| Debian 13, Alpine, Fedora, Arch, Rocky 9, Alma 9, openSUSE Tumbleweed | Linux containers with Bash, Python, curl, Git and OpenSSL installed |
| Windows Server 2022 + Ubuntu 24.04 | WSL 1 and WSL 2; the Windows script must actually complete its delegated distro scan |

All scanner invocations are scan-only. Linux/macOS scans use `--no-docker` so they
do not scan runner image caches or recursively launch containers. Installing test
dependencies and the WSL distro changes only disposable CI environments.

Each scan uploads `scan.log`, `result.json` and `summary.md` for 14 days. The job
summary distinguishes no issues, issues found and unverified checks. Exit codes
0, 1 and 2 are valid scan outcomes; an unexpected exit or missing final SUMMARY
fails the job. WSL jobs also fail if no distro was scanned or delegation did not
finish. A green job establishes that the scan completed, not that every TLS check
passed or that the runner is protected.

This exercises the tools and bundles present in each environment. It does not
establish compatibility with every Linux release, browser, custom Python/tool
installation, desktop Windows edition, or fix command. Linux containers do not
exercise a distro's kernel, init system, or desktop trust integrations. Rolling
image tags intentionally track currently published distro images; runner image
versions and scan output are recorded in the Actions logs.
