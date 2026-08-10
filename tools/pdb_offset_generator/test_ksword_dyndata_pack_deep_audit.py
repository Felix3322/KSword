from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import ksword_dyndata_pack_deep_audit as audit


class DeepLibraryDiscoveryTests(unittest.TestCase):
    def test_uses_profile_directory_when_manifest_has_no_deep_library_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile_directory = Path(temporary) / "profiles"
            deep_directory = profile_directory / "pdb_deep_offsets"
            deep_directory.mkdir(parents=True)
            first = deep_directory / "ntos_deep_offsets.json"
            second = deep_directory / "win32k_deep_offsets.json"
            first.write_text("{}", encoding="utf-8")
            second.write_text("{}", encoding="utf-8")
            manifest_path = profile_directory / "ark_dyndata_manifest.json"

            discovered = audit.deep_library_paths({}, manifest_path)

            self.assertEqual([first, second], discovered)


if __name__ == "__main__":
    unittest.main()
