import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import i18n_language_pack as i18n


class I18nLanguagePackTests(unittest.TestCase):
    def test_extracts_compiler_concatenated_literal(self) -> None:
        source = '''
QString value = QStringLiteral(
    "第一段：%1"
    /* C++ still concatenates across comments. */
    "；第二段：%2");
'''
        self.assertIn(
            ("第一段：%1；第二段：%2", 3),
            list(i18n.extract_cpp_concatenated_literals(source)),
        )

    def test_does_not_join_literals_across_punctuation(self) -> None:
        source = 'QStringList values{QStringLiteral("甲"), QStringLiteral("乙")};'
        self.assertEqual([], list(i18n.extract_cpp_concatenated_literals(source)))

    def test_extracts_referenced_semantic_keys(self) -> None:
        source = '''
language.bindText(label,
    QStringLiteral("settings.feature.label"),
    QStringLiteral("功能"));
translated("dialog.action.accept", "确定");
'''
        self.assertEqual(
            [("settings.feature.label", 3), ("dialog.action.accept", 5)],
            list(i18n.extract_semantic_key_references(source)),
        )

    def test_audit_rejects_missing_referenced_key(self) -> None:
        occurrence = i18n.Occurrence("Page.cpp", 42)
        errors = i18n.audit(
            {},
            {"translations": {}, "context_translations": {}, "source_translations": {}},
            {"translations": {}, "context_translations": {}, "source_translations": {}},
            {"page.action.run": [occurrence]},
        )
        self.assertIn(
            "missing zh-CN referenced semantic translation: 'page.action.run' (Page.cpp:42)",
            errors,
        )
        self.assertIn(
            "missing en-US referenced semantic translation: 'page.action.run' (Page.cpp:42)",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
