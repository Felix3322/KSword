from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "i18n_language_pack.py"
SPEC = importlib.util.spec_from_file_location("i18n_language_pack", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
I18N = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = I18N
SPEC.loader.exec_module(I18N)


class CppLiteralExtractionTests(unittest.TestCase):
    def extract(self, source: str) -> list[tuple[str, int]]:
        return list(I18N.extract_cpp_literals(source))

    def test_quoted_include_is_not_ui_text(self) -> None:
        source = '#include "WindowLayerDiagnostics.inl"\nQStringLiteral("Visible UI")\n'
        self.assertEqual(self.extract(source), [("Visible UI", 2)])

    def test_indented_include_after_comment_is_not_ui_text(self) -> None:
        source = '/* generated include */   #include "GeneratedHeader.h"\nL"Real label"\n'
        self.assertEqual(self.extract(source), [("Real label", 2)])

    def test_literals_in_code_still_keep_source_lines(self) -> None:
        source = '// ignored "comment"\nconst auto first = "First label";\nconst auto second = R"(Second label)";\n'
        self.assertEqual(
            self.extract(source),
            [("First label", 2), ("Second label", 3)],
        )


if __name__ == "__main__":
    unittest.main()
