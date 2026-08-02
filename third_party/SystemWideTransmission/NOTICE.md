# SystemWideTransmission Reference Notice

Upstream project: <https://github.com/WindowsKin/SystemWideTransmission>

- Revision reviewed: `9b06e82bcc9e8bbdb7641c68d321979fe7fd11b5`
- Source file reviewed: `SystemWideTransmission.c`
- Revision date: 2026-08-02
- License at that revision: GNU General Public License, version 3
- License blob SHA-1: `10dc7c6ce292b21bf20b7d33173d4289a264663e`
- Archived license text: `third_party/SystemWideTransmission/LICENSE.txt`

The public project above was reviewed as a conceptual reference for locating
and controlling the Windows HAL performance-counter path. No upstream source
file is vendored in this directory, compiled by KSword, or linked into KSword.

KSword's system-time implementation is independently written for its own
R3/R0 protocol and driver lifecycle. It adds bounded signature windows,
version-aware slot selection, pointer and conflict validation, synchronized
multi-core counter state, continuity-preserving reconfiguration, guarded
rollback, unload draining, and an optional Hyper-V shared-QPC backend.

The accompanying license file records the terms of the reviewed upstream
revision for attribution and compliance tracking. It does not replace the
license that applies to independently authored KSword files. If upstream code
is later copied or vendored, its GPL terms must be evaluated and followed.
