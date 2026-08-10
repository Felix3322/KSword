from __future__ import annotations

import unittest
from pathlib import Path


class DriverVariantSigningScriptTests(unittest.TestCase):
    def test_kernel_policy_verification_does_not_combine_all_switch(self) -> None:
        script = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "Sign-KswordArkDriverVariant.ps1"
        ).read_text(encoding="utf-8-sig")

        self.assertIn("verify /kp /v $Path", script)
        self.assertNotIn("verify /kp /all /v $Path", script)
        self.assertIn("$previousErrorPreference = $ErrorActionPreference", script)
        self.assertIn("$ErrorActionPreference = 'Continue'", script)
        self.assertIn("$ErrorActionPreference = $previousErrorPreference", script)


if __name__ == "__main__":
    unittest.main()
