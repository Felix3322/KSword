from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import launcher_report_intake as intake


class LauncherBundleContractTests(unittest.TestCase):
    def test_bundle_copies_every_reported_module_from_inspected_set(self) -> None:
        bundle_source = (
            Path(__file__).resolve().parents[2]
            / "Launcher"
            / "Bundle.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("for (const ModuleFinding& finding : scan.inspected)", bundle_source)
        self.assertNotIn(
            "for (const ModuleFinding& finding : scan.collectionCandidates) if (finding.module.classId != 0)",
            bundle_source,
        )


class LauncherReportValidationPolicyTests(unittest.TestCase):
    def test_missing_non_required_non_collection_module_is_a_warning(self) -> None:
        errors, warnings = intake.report_validation_diagnostics(
            [
                {
                    "fileName": "lxcore.sys",
                    "compatibilityRequired": False,
                    "collectionOnly": False,
                    "errors": ["binary_missing"],
                }
            ],
            [],
        )

        self.assertEqual([], errors)
        self.assertEqual(["lxcore.sys:binary_missing_optional"], warnings)

    def test_missing_compatibility_module_remains_an_error(self) -> None:
        errors, warnings = intake.report_validation_diagnostics(
            [
                {
                    "fileName": "ntoskrnl.exe",
                    "compatibilityRequired": True,
                    "collectionOnly": False,
                    "errors": ["binary_missing"],
                }
            ],
            [],
        )

        self.assertEqual(["ntoskrnl.exe:binary_missing"], errors)
        self.assertEqual([], warnings)

    def test_publishable_modules_excludes_optional_missing_attachment(self) -> None:
        modules = intake.publishable_modules(
            [
                {"fileName": "ntoskrnl.exe", "valid": True},
                {
                    "fileName": "lxcore.sys",
                    "valid": False,
                    "compatibilityRequired": False,
                    "collectionOnly": False,
                    "errors": ["binary_missing"],
                },
            ]
        )

        self.assertEqual(["ntoskrnl.exe"], [module["fileName"] for module in modules])


class CompatibilityProfilePolicyTests(unittest.TestCase):
    def test_compatibility_modules_remain_profile_candidates(self) -> None:
        self.assertEqual(
            "ntoskrnl",
            intake.compatibility_profile_class({"classId": 0, "collectionOnly": False}),
        )
        self.assertEqual(
            "ntkrla57",
            intake.compatibility_profile_class({"classId": 1, "collectionOnly": False}),
        )

    def test_collection_only_fltmgr_is_not_a_profile_candidate(self) -> None:
        self.assertIsNone(
            intake.compatibility_profile_class({"classId": 48, "collectionOnly": True})
        )

    def test_collection_only_report_commits_only_pe_and_pdb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            report_dir = temporary_root / "report"
            corpus_root = temporary_root / "corpus"
            source = report_dir / "fltmgr.sys.bin"
            llvm_pdbutil = temporary_root / "llvm-pdbutil.exe"
            report_dir.mkdir()
            corpus_root.mkdir()
            source.write_bytes(b"test pe")
            llvm_pdbutil.write_bytes(b"test tool")

            module = {
                "fileName": "fltmgr.sys",
                "canonicalFileName": "fltmgr.sys",
                "source": str(source),
                "classId": 48,
                "valid": True,
                "collectionOnly": True,
                "arch": "amd64",
                "version": "10.0.26100.1",
                "sha256": intake.sha256_file(source),
                "pdb": {
                    "name": "fltMgr.pdb",
                    "symbolKey": "A" * 32 + "1",
                    "guid": "A" * 32,
                },
            }
            result = {
                "valid": True,
                "reportId": "collection-only-test",
                "modules": [module],
            }

            def fake_download_pdb(
                _module: dict[str, object],
                destination: Path,
                _symbol_server: str,
                _llvm_pdbutil: Path,
            ) -> None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"test pdb")

            with (
                mock.patch.object(intake, "download_pdb", side_effect=fake_download_pdb),
                mock.patch.object(
                    intake,
                    "run_profile_generator",
                    side_effect=AssertionError("collection-only module generated a profile"),
                ),
                mock.patch.object(
                    intake,
                    "validate_generated_profiles",
                    side_effect=AssertionError("collection-only report validated profiles"),
                ),
            ):
                intake.commit_report(
                    result,
                    corpus_root,
                    report_dir,
                    "https://symbols.invalid",
                    llvm_pdbutil,
                )

            self.assertTrue(Path(module["peDestination"]).is_file())
            self.assertTrue(Path(module["pdbDestination"]).is_file())
            self.assertNotIn("profileDestination", module)
            self.assertEqual(0, result["profileValidation"]["publishedProfiles"])


if __name__ == "__main__":
    unittest.main()
