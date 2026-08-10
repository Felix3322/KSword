from __future__ import annotations

import unittest
from pathlib import Path

import ksword_profile_release_sync as release_sync


class PackVersionCompatibilityTests(unittest.TestCase):
    def make_record(
        self,
        name: str,
        field_count: int,
        typed_item_count: int,
        v4_item_count: int,
    ) -> release_sync.ProfileRecord:
        return release_sync.ProfileRecord(
            path=Path(f"{name}.json"),
            data={"profileName": name, "fields": {}},
            identity=release_sync.ProfileIdentity("ntoskrnl", 0x8664, 1, 1),
            field_count=field_count,
            typed_items=[{"name": "EpUniqueProcessId", "kind": "StructOffset", "value": 0x440}]
            * typed_item_count,
            v4_items=[
                {
                    "itemId": 1201,
                    "name": "CiKernelHashBucketList",
                    "itemKind": 2,
                    "kind": "GlobalRva",
                    "flags": 1,
                    "capabilityGroupId": 4,
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
            [legacy],
            release_sync.records_for_pack_version(records, release_sync.KSW_PACK_VERSION_V1),
        )
        self.assertEqual(
            [legacy],
            release_sync.records_for_pack_version(records, release_sync.KSW_PACK_VERSION_V2),
        )
        self.assertEqual(
            [legacy, typed],
            release_sync.records_for_pack_version(records, release_sync.KSW_PACK_VERSION_V3),
        )
        self.assertEqual(
            [legacy, typed, v4_only],
            release_sync.records_for_pack_version(records, release_sync.KSW_PACK_VERSION_V4),
        )


if __name__ == "__main__":
    unittest.main()
