import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from run_scan import run_scan


class ScanExecutionTests(unittest.TestCase):
    def scan(self, code, output, require_wsl=False):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-c", f"print({output!r}); raise SystemExit({code})"]
            with contextlib.redirect_stdout(io.StringIO()), patch.dict(
                os.environ, {"GITHUB_STEP_SUMMARY": str(Path(directory) / "job-summary.md")}
            ):
                result = run_scan(command, directory, require_wsl)
            metadata = json.loads((Path(directory) / "result.json").read_text())
            return result, metadata

    def test_findings_and_unverified_checks_do_not_fail_execution(self):
        for code in (0, 1, 2):
            with self.subTest(code=code):
                result, metadata = self.scan(code, "== SUMMARY ==\nreport")
                self.assertEqual(result, 0)
                self.assertEqual(metadata["exit_code"], code)

    def test_exit_one_without_summary_is_a_crash(self):
        result, metadata = self.scan(1, "Traceback: probe failed")
        self.assertEqual(result, 1)
        self.assertFalse(metadata["completed"])

    def test_unexpected_exit_fails_even_with_summary(self):
        for code in (3, 127):
            with self.subTest(code=code):
                self.assertEqual(self.scan(code, "== SUMMARY ==")[0], 1)

    def test_wsl_job_requires_an_actual_completed_distro_scan(self):
        self.assertEqual(self.scan(0, "== SUMMARY ==", True)[0], 1)
        prefix = "== WSL distro: Ubuntu-24.04 (WSL2, Running) ==\n"
        failed = prefix + "[WARN] WSL Ubuntu-24.04: check-unix.sh did not finish (code 127)\n== SUMMARY =="
        self.assertEqual(self.scan(2, failed, True)[0], 1)
        for status in ("[OK] no issues", "[FAIL] issues found", "[WARN] some checks not verified"):
            tag, text = status.split(" ", 1)
            output = prefix + f"{tag} WSL Ubuntu-24.04: {text}\n== SUMMARY =="
            self.assertEqual(self.scan(1, output, True)[0], 0)


if __name__ == "__main__":
    unittest.main()
