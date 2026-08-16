from __future__ import annotations

import unittest
from pathlib import Path

import ksword_profile_release_sync as release_sync


class V4OnlyPackTests(unittest.TestCase):
    def make_record(
        self,
        name: str,
        field_count: int,
        typed_item_count: int,
        v4_item_count: int,
    ) -> release_sync.ProfileRecord:
        return release_sync.ProfileRecord(
            path=Path(f"{name}.json"),
            data={
                "profileName": name,
                "fields": {},
                "module": {
                    "class": "ntoskrnl",
                    "machine": 0x8664,
                    "timeDateStamp": 1,
                    "sizeOfImage": 1,
                },
            },
            identity=release_sync.ProfileIdentity("ntoskrnl", 0x8664, 1, 1),
            field_count=field_count,
            typed_items=[{"name": "EpUniqueProcessId", "kind": "StructOffset", "value": 0x440}]
            * typed_item_count,
            v4_items=[
                {
                    "itemId": 58,
                    "name": "EpUniqueProcessId",
                    "itemKind": 1,
                    "kind": "StructOffset",
                    "flags": 1,
                    "capabilityGroupId": 1,
                    "value": 0x1000,
                    "aux0": 0,
                    "aux1": 0,
                    "aux2": 0,
                    "aux3": 0,
                }
            ]
            * v4_item_count,
        )

    def test_pack_version_filters_profiles_by_supported_payload(self) -> None:
        legacy = self.make_record("legacy", 1, 0, 0)
        typed = self.make_record("typed", 0, 1, 0)
        v4_only = self.make_record("v4_only", 0, 0, 1)
        records = [legacy, typed, v4_only]

        self.assertEqual(
            release_sync.KSW_SUPPORTED_PACK_VERSIONS,
            (release_sync.KSW_PACK_VERSION_V4,),
        )
        self.assertEqual(
            [typed, v4_only],
            release_sync.records_for_pack_version(records, release_sync.KSW_PACK_VERSION_V4),
        )

    def test_v4_entry_has_no_legacy_offset_mirrors(self) -> None:
        record = self.make_record("v4", 1, 0, 1)
        entry = release_sync.build_pack_profile_entry(record, pack_version=release_sync.KSW_PACK_VERSION_V4)
        self.assertIn("items", entry)
        self.assertNotIn("fields", entry)
        self.assertNotIn("legacyItems", entry)
        self.assertNotIn("callbackItems", entry)

    def test_reserved_timer_ids_are_not_generated(self) -> None:
        self.assertNotIn(1004, release_sync.V4_SPECIAL_ITEM_IDS.values())
        self.assertNotIn(1006, release_sync.V4_SPECIAL_ITEM_IDS.values())
        self.assertEqual(
            release_sync.V4_FIXED_CAPABILITY_GROUP_COUNTS[release_sync.V4_TIMER_GROUP_ID],
            (15, 0),
        )


if __name__ == "__main__":
    unittest.main()
