import json
import os
import shutil
import stat
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CLI = ROOT / "prooftrail.py"
TMP = ROOT / "tmp"


def run_cli(args, cwd=ROOT):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=cwd,
        text=True,
        capture_output=True,
    )


def load_json(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def remove_tree(path):
    def retry_with_write_bit(func, failed_path, _exc_info):
        os.chmod(failed_path, stat.S_IREAD | stat.S_IWRITE)
        func(failed_path)

    shutil.rmtree(path, onerror=retry_with_write_bit)


class ProoftrailAcceptanceTests(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(exist_ok=True)
        self.work = TMP / self._testMethodName
        if self.work.exists():
            remove_tree(self.work)
        self.work.mkdir()

    def test_run_success_writes_required_files_and_command_record(self):
        out = self.work / "proof-success"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", "print('ok')"])
        self.assertEqual(result.returncode, 0, result.stderr)

        for rel in [
            "SUMMARY.md",
            "commands.jsonl",
            "manifest.json",
            "prooftrail.log",
            "REDACTION.md",
            "artifacts/commands/cmd-001/stdout.txt",
            "artifacts/commands/cmd-001/stderr.txt",
        ]:
            self.assertTrue((out / rel).exists(), rel)

        command = json.loads((out / "commands.jsonl").read_text(encoding="utf-8").strip())
        self.assertEqual(command["exit_code"], 0)
        self.assertEqual(command["stdout_path"], "artifacts/commands/cmd-001/stdout.txt")
        self.assertIn("ok", (out / command["stdout_path"]).read_text(encoding="utf-8"))
        self.assertEqual(command["stdout_bytes"], (out / command["stdout_path"]).stat().st_size)
        self.assertEqual(command["stderr_bytes"], (out / command["stderr_path"]).stat().st_size)
        self.assertEqual(load_json(out / "manifest.json")["evidence_boundary"], "capture-only")

    def test_relative_output_path_is_supported_from_cwd(self):
        relative_out = Path("tmp") / self._testMethodName / "proof-relative"
        result = run_cli(["run", "--out", str(relative_out), "--project", "demo", "--", sys.executable, "-c", "print('relative')"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((ROOT / relative_out / "SUMMARY.md").exists())

    def test_run_failing_command_writes_proof_and_returns_wrapped_exit_code(self):
        out = self.work / "proof-fail"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", "import sys; print('bad'); sys.exit(7)"])
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertTrue((out / "SUMMARY.md").exists())

        command = json.loads((out / "commands.jsonl").read_text(encoding="utf-8").strip())
        self.assertEqual(command["exit_code"], 7)
        summary = (out / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertIn("Command exited with code `7`.", summary)
        self.assertNotIn("tests passed", summary.lower())

    def test_import_mode_copies_text_and_screenshot_artifacts(self):
        source = self.work / "import"
        source.mkdir()
        stdout = source / "stdout.txt"
        stderr = source / "stderr.txt"
        screenshot = source / "screenshot.png"
        stdout.write_text("hello from import\n", encoding="utf-8")
        stderr.write_text("warning line\n", encoding="utf-8")
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\nfake")

        out = self.work / "proof-import"
        result = run_cli([
            "import",
            "--out",
            str(out),
            "--project",
            "demo",
            "--command",
            "python tests.py",
            "--exit-code",
            "0",
            "--stdout",
            str(stdout),
            "--stderr",
            str(stderr),
            "--screenshot",
            str(screenshot),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = load_json(out / "manifest.json")
        self.assertEqual(manifest["mode"], "import")
        self.assertEqual(manifest["screenshots"][0]["path"], "screenshots/screenshot-001.png")
        self.assertTrue((out / "artifacts/commands/cmd-001/stdout.txt").exists())
        self.assertTrue((out / "screenshots/screenshot-001.png").exists())

    def test_git_available_captures_status_and_diff_artifacts(self):
        repo = self.work / "repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.email", "demo@example.invalid"], cwd=repo, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Demo"], cwd=repo, check=True, capture_output=True, text=True)
        tracked = repo / "tracked.txt"
        tracked.write_text("before\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True, capture_output=True, text=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True, text=True)
        tracked.write_text("before\nafter\n", encoding="utf-8")

        out = self.work / "proof-git"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--cwd", str(repo), "--", sys.executable, "-c", "print('git')"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for rel in [
            "git/status.before.txt",
            "git/status.after.txt",
            "git/diff.stat.txt",
            "git/diff.name-status.txt",
            "git/git.diff",
        ]:
            self.assertTrue((out / rel).exists(), rel)
        self.assertTrue(load_json(out / "manifest.json")["git"]["available"])

    def test_git_unavailable_succeeds_without_git_folder(self):
        cwd = self.work / "not-git"
        cwd.mkdir()
        out = self.work / "proof-no-git"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--cwd", str(cwd), "--", sys.executable, "-c", "print('no git')"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((out / "git").exists())
        self.assertFalse(load_json(out / "manifest.json")["git"]["available"])

    def test_high_confidence_secret_blocks_finalization(self):
        out = self.work / "proof-secret"
        secret_text = "api" + "_key=demo-secret-value-12345"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", f"print({secret_text!r})"])
        self.assertEqual(result.returncode, 66)
        self.assertTrue((out / "REDACTION_BLOCKED.md").exists())
        self.assertTrue((out / "prooftrail.log").exists())
        for rel in ["SUMMARY.md", "commands.jsonl", "manifest.json"]:
            self.assertFalse((out / rel).exists(), rel)
        blocked = (out / "REDACTION_BLOCKED.md").read_text(encoding="utf-8")
        self.assertIn("secret.api_key_assignment", blocked)
        self.assertNotIn("demo-secret-value-12345", blocked)

    def test_medium_pii_redacts_and_records_finding(self):
        out = self.work / "proof-pii"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", "print('contact user@example.com')"])
        self.assertEqual(result.returncode, 0, result.stderr)
        stdout = (out / "artifacts/commands/cmd-001/stdout.txt").read_text(encoding="utf-8")
        self.assertIn("[REDACTED:pii.email:1]", stdout)
        self.assertNotIn("user@example.com", stdout)
        self.assertIn("pii.email", (out / "REDACTION.md").read_text(encoding="utf-8"))

    def test_existing_output_requires_overwrite(self):
        out = self.work / "proof-existing"
        first = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", "print('first')"])
        self.assertEqual(first.returncode, 0, first.stderr)
        original = (out / "manifest.json").read_text(encoding="utf-8")

        second = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", "print('second')"])
        self.assertEqual(second.returncode, 64)
        self.assertEqual(original, (out / "manifest.json").read_text(encoding="utf-8"))

        third = run_cli(["run", "--out", str(out), "--project", "demo", "--overwrite", "--", sys.executable, "-c", "print('third')"])
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertIn("third", (out / "artifacts/commands/cmd-001/stdout.txt").read_text(encoding="utf-8"))

    def test_public_artifact_wording_has_no_internal_terms(self):
        out = self.work / "proof-public"
        result = run_cli(["run", "--out", str(out), "--project", "demo", "--", sys.executable, "-c", "print('public')"])
        self.assertEqual(result.returncode, 0, result.stderr)
        forbidden = [
            "SECRETARY_" + "ORCH" + "ESTRATION",
            "PORTFOLIO_" + "LEDGER",
            "work" + "er",
            "money" + "-lane",
            "bounty " + "pipeline",
            "this " + "prompt",
            "Co" + "dex",
            "AI-" + "work" + "er",
        ]
        public_text = (ROOT / "README.md").read_text(encoding="utf-8")
        public_text += "\n" + (out / "SUMMARY.md").read_text(encoding="utf-8")
        for term in forbidden:
            self.assertNotIn(term, public_text)


if __name__ == "__main__":
    unittest.main()
