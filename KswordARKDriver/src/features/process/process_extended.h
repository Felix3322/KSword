#pragma once

#include "ark/ark_driver.h"

EXTERN_C_START

VOID
KswordARKProcessPopulateExtendedEntry(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* Entry,
    _In_ PEPROCESS ProcessObject
    );

NTSTATUS
KswordARKProcessPatchProtectionByDynData(
    _In_ ULONG ProcessId,
    _In_ UCHAR ProtectionLevel,
    _In_ UCHAR SignatureLevel,
    _In_ UCHAR SectionSignatureLevel
    );

NTSTATUS
KswordARKProcessPatchProtectionByDynDataObject(
    _In_ PEPROCESS ProcessObject,
    _In_ UCHAR ProtectionLevel,
    _In_ UCHAR SignatureLevel,
    _In_ UCHAR SectionSignatureLevel
    );

// PP 守护巡检用：按与写入路径相同的偏移解析顺序回读当前 Protection 字节。
NTSTATUS
KswordARKProcessReadProtectionByte(
    _In_ PEPROCESS ProcessObject,
    _Out_ UCHAR* ProtectionByteOut
    );

// PP 深度加固用：清空 EPROCESS.DebugPort。
NTSTATUS
KswordARKProcessClearDebugPortByObject(
    _In_ PEPROCESS ProcessObject
    );

EXTERN_C_END
