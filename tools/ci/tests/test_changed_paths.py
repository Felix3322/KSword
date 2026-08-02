from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

import changed_paths  # noqa: E402


def git(repo: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(process.stderr or process.stdout)
    return process.stdout.strip()


class RepositoryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.email", "ci@example.invalid")
        git(self.repo, "config", "user.name", "CI Test")
        (self.repo / "base.txt").write_text("base\n", encoding="utf-8")
        git(self.repo, "add", "base.txt")
        git(self.repo, "commit", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.previous_cwd = Path.cwd()
        os.chdir(self.repo)

    def tearDown(self) -> None:
        os.chdir(self.previous_cwd)
        self.temp.cleanup()

    def commit_file(self, path: str, content: str, message: str) -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        git(self.repo, "add", path)
        git(self.repo, "commit", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def test_pull_request_uses_three_dot_endpoint_range(self) -> None:
        git(self.repo, "switch", "-c", "feature", self.base)
        head = self.commit_file("Ksword5.1/feature.cpp", "feature\n", "feature")

        git(self.repo, "switch", "main")
        advanced_base = self.commit_file("docs/base-only.md", "base only\n", "advance base")

        event = {
            "pull_request": {
                "base": {"sha": advanced_base},
                "head": {"sha": head},
            }
        }
        diff_range = changed_paths.resolve_diff_range("pull_request", event, head)
        self.assertIsNotNone(diff_range)
        self.assertEqual(diff_range.arguments, (f"{advanced_base}...{head}",))
        self.assertEqual(changed_paths.changed_paths(diff_range), ["Ksword5.1/feature.cpp"])

    def test_merge_parent_fallback_survives_sibling_merge(self) -> None:
        git(self.repo, "switch", "-c", "feature", self.base)
        self.commit_file("Ksword5.1/window.cpp", "window\n", "feature")
        git(self.repo, "switch", "main")
        git(self.repo, "merge", "--no-ff", "feature", "-m", "synthetic merge")
        synthetic_merge = git(self.repo, "rev-parse", "HEAD")

        git(self.repo, "reset", "--hard", self.base)
        git(self.repo, "merge", "--no-ff", "feature", "-m", "actual merge")
        actual_merge = git(self.repo, "rev-parse", "HEAD")
        self.assertNotEqual(synthetic_merge, actual_merge)

        git(self.repo, "checkout", "--detach", synthetic_merge)
        diff_range = changed_paths.resolve_diff_range("pull_request", {}, synthetic_merge)
        self.assertIsNotNone(diff_range)
        self.assertEqual(changed_paths.changed_paths(diff_range), ["Ksword5.1/window.cpp"])

    def test_rename_reports_old_and_new_paths(self) -> None:
        git(self.repo, "switch", "-c", "feature", self.base)
        self.commit_file("KswordARKDriver/driver.c", "driver\n", "add driver")
        before = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "docs").mkdir()
        git(self.repo, "mv", "KswordARKDriver/driver.c", "docs/driver.c")
        git(self.repo, "commit", "-m", "move driver")
        after = git(self.repo, "rev-parse", "HEAD")

        paths = changed_paths.changed_paths(
            changed_paths.DiffRange((before, after), "rename test")
        )
        self.assertEqual(paths, ["KswordARKDriver/driver.c", "docs/driver.c"])
        self.assertTrue(changed_paths.driver_output(paths))

    def test_unavailable_push_base_falls_back_to_all(self) -> None:
        event = {"before": "f" * 40, "after": self.base}
        diff_range = changed_paths.resolve_diff_range("push", event, self.base)
        self.assertIsNone(diff_range)
        self.assertTrue(all(changed_paths.project_outputs(None).values()))
        self.assertTrue(changed_paths.driver_output(None))

    def test_common_build_inputs_trigger_driver(self) -> None:
        for path in (
            "Ksword.ReleaseOutput.props",
            "Directory.Build.targets",
            "Ksword5.1/Ksword5.1.vcxproj.props",
            ".github/workflows/driver-ci.yml",
        ):
            with self.subTest(path=path):
                self.assertTrue(changed_paths.driver_output([path]))


if __name__ == "__main__":
    unittest.main()
