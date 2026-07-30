/*++

Module Name:

    platform_audit.c

Abstract:

    HAL 与 KMDF 绑定表的只读、失败关闭审计。

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkPlatformAuditIoctl.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSW_PLATFORM_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE, entries))
#define KSW_PLATFORM_HAL_PUBLIC_ENTRY_COUNT 24UL
#define KSW_PLATFORM_PRIVATE_ENTRY_LIMIT 96UL

typedef struct _KSW_PLATFORM_HAL_PUBLIC_VIEW
{
    ULONG Version;
    ULONG Reserved;
    PVOID Entries[KSW_PLATFORM_HAL_PUBLIC_ENTRY_COUNT];
} KSW_PLATFORM_HAL_PUBLIC_VIEW;

typedef struct _KSW_PLATFORM_WDF_FUNCTION_DESCRIPTOR
{
    ULONG Index;
    PCWSTR Name;
} KSW_PLATFORM_WDF_FUNCTION_DESCRIPTOR;

typedef struct _KSW_PLATFORM_CALLBACK_DESCRIPTOR
{
    PVOID Address;
    PCWSTR Name;
} KSW_PLATFORM_CALLBACK_DESCRIPTOR;

static const PCWSTR g_KswHalDispatchNames[KSW_PLATFORM_HAL_PUBLIC_ENTRY_COUNT] = {
    L"HalQuerySystemInformation",
    L"HalSetSystemInformation",
    L"HalQueryBusSlots",
    L"Spare1",
    L"HalExamineMBR",
    L"HalIoReadPartitionTable",
    L"HalIoSetPartitionInformation",
    L"HalIoWritePartitionTable",
    L"HalReferenceHandlerForBus",
    L"HalReferenceBusHandler",
    L"HalDereferenceBusHandler",
    L"HalInitPnpDriver",
    L"HalInitPowerManagement",
    L"HalGetDmaAdapter",
    L"HalGetInterruptTranslator",
    L"HalStartMirroring",
    L"HalEndMirroring",
    L"HalMirrorPhysicalMemory",
    L"HalEndOfBoot",
    L"HalMirrorVerify",
    L"HalGetCachedAcpiTable",
    L"HalSetPciErrorHandlerCallback",
    L"HalGetPrmCache",
    L"HalInvokePrmFwHandler"
};

static const KSW_PLATFORM_WDF_FUNCTION_DESCRIPTOR g_KswWdfFunctions[] = {
    { WdfDriverCreateTableIndex, L"WdfDriverCreate" },
    { WdfDeviceCreateTableIndex, L"WdfDeviceCreate" },
    { WdfIoQueueCreateTableIndex, L"WdfIoQueueCreate" },
    { WdfRequestCompleteTableIndex, L"WdfRequestComplete" },
    { WdfMemoryCreateTableIndex, L"WdfMemoryCreate" },
    { WdfObjectDeleteTableIndex, L"WdfObjectDelete" }
};

static const KSW_PLATFORM_CALLBACK_DESCRIPTOR g_KswWdfCallbacks[] = {
    { (PVOID)KswordARKDriverEvtDriverUnload, L"KswordARKDriverEvtDriverUnload" },
    { (PVOID)KswordARKDriverEvtDriverContextCleanup, L"KswordARKDriverEvtDriverContextCleanup" },
    { (PVOID)KswordARKDriverEvtIoDeviceControl, L"KswordARKDriverEvtIoDeviceControl" },
    { (PVOID)KswordARKDriverEvtIoRead, L"KswordARKDriverEvtIoRead" },
    { (PVOID)KswordARKDriverEvtIoStop, L"KswordARKDriverEvtIoStop" },
    { (PVOID)KswordARKDriverEvtDevicePrepareHardware, L"KswordARKDriverEvtDevicePrepareHardware" }
};

static VOID
KswPlatformCopyWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
{
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source != NULL) {
        (VOID)RtlStringCchCopyNW(Destination, DestinationChars, Source, DestinationChars - 1UL);
    }
}

static PVOID
KswPlatformGetRoutine(
    _In_z_ PCWSTR RoutineName
    )
{
    UNICODE_STRING routineNameString;

    if (RoutineName == NULL) {
        return NULL;
    }
    RtlInitUnicodeString(&routineNameString, RoutineName);
    return MmGetSystemRoutineAddress(&routineNameString);
}

static BOOLEAN
KswPlatformModuleNameEquals(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_z_ PCSTR ExpectedName
    )
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;

    if (Module == NULL || ExpectedName == NULL) {
        return FALSE;
    }
    KswordARKHookGetModuleFileName(Module, &fileName, &fileNameBytes);
    return KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, ExpectedName);
}

static BOOLEAN
KswPlatformIsExpectedHalOwner(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module
    )
{
    return KswPlatformModuleNameEquals(Module, "ntoskrnl.exe") ||
        KswPlatformModuleNameEquals(Module, "ntkrnlmp.exe") ||
        KswPlatformModuleNameEquals(Module, "ntkrnlpa.exe") ||
        KswPlatformModuleNameEquals(Module, "ntkrpamp.exe") ||
        KswPlatformModuleNameEquals(Module, "hal.dll");
}

static VOID
KswPlatformFillModule(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module
    )
{
    if (Entry == NULL || Module == NULL) {
        return;
    }

    Entry->moduleBase = (ULONGLONG)(ULONG_PTR)Module->ImageBase;
    Entry->moduleSize = Module->ImageSize;
    Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_MODULE;
    KswordARKHookCopyBoundedAnsiToWide(
        Module->FullPathName,
        RTL_NUMBER_OF(Module->FullPathName),
        Entry->modulePath,
        RTL_NUMBER_OF(Entry->modulePath));
}

static VOID
KswPlatformSetVendorLabel(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_z_ PCWSTR ExpectedVendor
    )
{
    PCWSTR ownerLabel = L"<unknown>";
    PCWSTR cursor = NULL;

    if (Entry == NULL || ExpectedVendor == NULL) {
        return;
    }
    if ((Entry->fieldFlags & KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED) != 0UL) {
        ownerLabel = ExpectedVendor;
    }
    else if ((Entry->fieldFlags & KSWORD_ARK_PLATFORM_FIELD_MODULE) != 0UL &&
             Entry->modulePath[0] != L'\0') {
        ownerLabel = Entry->modulePath;
        for (cursor = Entry->modulePath; *cursor != L'\0'; ++cursor) {
            if (*cursor == L'\\' || *cursor == L'/') {
                ownerLabel = cursor + 1;
            }
        }
    }
    KswPlatformCopyWide(
        Entry->vendor,
        RTL_NUMBER_OF(Entry->vendor),
        ownerLabel);
    Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_VENDOR;
}

static BOOLEAN
KswPlatformAddressSectionMatches(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONG_PTR Address,
    _In_ BOOLEAN RequireExecutable
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionIndex = 0UL;
    ULONG sectionTableRva = 0UL;

    if (Module == NULL ||
        Address < (ULONG_PTR)Module->ImageBase ||
        Address >= ((ULONG_PTR)Module->ImageBase + Module->ImageSize)) {
        return FALSE;
    }
    if (!KswordARKHookReadMemorySafe(Module->ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !KswordARKHookValidateRvaRange((ULONG)dosHeader.e_lfanew, sizeof(ntHeaders), Module->ImageSize) ||
        !KswordARKHookReadMemorySafe(
            (const UCHAR*)Module->ImageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > 96U) {
        return FALSE;
    }

    sectionTableRva = (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (sectionIndex = 0UL; sectionIndex < ntHeaders.FileHeader.NumberOfSections; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG currentRva = sectionTableRva + (sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR startAddress = 0U;
        ULONG_PTR endAddress = 0U;
        BOOLEAN executable = FALSE;

        if (!KswordARKHookValidateRvaRange(currentRva, sizeof(sectionHeader), Module->ImageSize) ||
            !KswordARKHookReadMemorySafe(
                (const UCHAR*)Module->ImageBase + currentRva,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }

        span = sectionHeader.Misc.VirtualSize;
        if (span < sectionHeader.SizeOfRawData) {
            span = sectionHeader.SizeOfRawData;
        }
        if (span == 0UL ||
            !KswordARKHookValidateRvaRange(sectionHeader.VirtualAddress, span, Module->ImageSize)) {
            continue;
        }

        startAddress = (ULONG_PTR)Module->ImageBase + sectionHeader.VirtualAddress;
        endAddress = startAddress + span;
        executable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        if (Address >= startAddress &&
            Address < endAddress &&
            executable == RequireExecutable) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswPlatformDecodeDetourTarget(
    _In_ ULONG64 Address,
    _Out_ ULONG64* TargetOut
    )
{
    UCHAR codeBytes[16];
    ULONG offset = 0UL;

    if (TargetOut == NULL || Address == 0ULL) {
        return FALSE;
    }
    *TargetOut = 0ULL;
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)Address, codeBytes, sizeof(codeBytes))) {
        return FALSE;
    }

    if (codeBytes[0] == 0xF3U && codeBytes[1] == 0x0FU &&
        codeBytes[2] == 0x1EU && codeBytes[3] == 0xFAU) {
        offset = 4UL;
    }

    if (codeBytes[offset] == 0xE9U) {
        LONG displacement = 0;
        RtlCopyMemory(&displacement, &codeBytes[offset + 1UL], sizeof(displacement));
        *TargetOut = Address + offset + 5ULL + (LONGLONG)displacement;
        return TRUE;
    }
    if (codeBytes[offset] == 0xEBU) {
        CHAR displacement8 = (CHAR)codeBytes[offset + 1UL];
        *TargetOut = Address + offset + 2ULL + (LONGLONG)displacement8;
        return TRUE;
    }
    if (codeBytes[offset] == 0xFFU && codeBytes[offset + 1UL] == 0x25U) {
        LONG displacement = 0;
        ULONG64 pointerAddress = 0ULL;
        RtlCopyMemory(&displacement, &codeBytes[offset + 2UL], sizeof(displacement));
        pointerAddress = Address + offset + 6ULL + (LONGLONG)displacement;
        return KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)pointerAddress,
            TargetOut,
            sizeof(*TargetOut));
    }
    if (codeBytes[offset] == 0x48U && codeBytes[offset + 1UL] == 0xB8U &&
        codeBytes[offset + 10UL] == 0xFFU && codeBytes[offset + 11UL] == 0xE0U) {
        RtlCopyMemory(TargetOut, &codeBytes[offset + 2UL], sizeof(*TargetOut));
        return TRUE;
    }
    return FALSE;
}

typedef struct _KSW_PLATFORM_MASKED_SIGNATURE
{
    UCHAR Bytes[12];
    UCHAR Mask[12];
    ULONG Length;
    ULONG Identifier;
} KSW_PLATFORM_MASKED_SIGNATURE;

static const KSW_PLATFORM_MASKED_SIGNATURE g_KswX64PrologueSignatures[] = {
    { { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x57, 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      10UL, 1UL },
    { { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      6UL, 2UL },
    { { 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0x00 },
      4UL, 3UL },
    { { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      7UL, 4UL },
    { { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      7UL, 5UL },
    { { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      10UL, 6UL },
    { { 0x48, 0x8B, 0xC4, 0x55, 0x53, 0x56, 0x57 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
      7UL, 7UL },
    { { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
      7UL, 8UL }
};

static BOOLEAN
KswPlatformMaskedBytesMatch(
    _In_reads_(ByteCount) const UCHAR* Data,
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_reads_(ByteCount) const UCHAR* Mask,
    _In_ ULONG ByteCount
    )
{
    ULONG index = 0UL;

    if (Data == NULL || Bytes == NULL || Mask == NULL || ByteCount == 0UL) {
        return FALSE;
    }
    for (index = 0UL; index < ByteCount; ++index) {
        if ((Data[index] & Mask[index]) != (Bytes[index] & Mask[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
KswPlatformIdentifyX64Prologue(
    _In_ ULONG64 Address,
    _Out_ ULONG* SignatureIdOut
    )
{
    UCHAR bytes[20];
    ULONG codeOffset = 0UL;
    ULONG index = 0UL;
    ULONG matchedCount = 0UL;
    ULONG matchedId = 0UL;

    if (SignatureIdOut == NULL) {
        return FALSE;
    }
    *SignatureIdOut = 0UL;
    RtlZeroMemory(bytes, sizeof(bytes));
    if (Address == 0ULL ||
        !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)Address, bytes, sizeof(bytes))) {
        return FALSE;
    }
    if (bytes[0] == 0xF3U && bytes[1] == 0x0FU &&
        bytes[2] == 0x1EU && bytes[3] == 0xFAU) {
        codeOffset = 4UL;
    }

    // 中文说明：每个模式都是真实字节 + mask，且只检查函数头固定 20 字节。
    // 只有恰好一个模式命中才接受；多命中与零命中都按未知版本失败关闭。
    for (index = 0UL; index < RTL_NUMBER_OF(g_KswX64PrologueSignatures); ++index) {
        const KSW_PLATFORM_MASKED_SIGNATURE* signature =
            &g_KswX64PrologueSignatures[index];
        if (codeOffset + signature->Length > sizeof(bytes)) {
            continue;
        }
        if (KswPlatformMaskedBytesMatch(
                bytes + codeOffset,
                signature->Bytes,
                signature->Mask,
                signature->Length)) {
            matchedCount += 1UL;
            matchedId = signature->Identifier;
        }
    }
    if (matchedCount != 1UL) {
        return FALSE;
    }
    *SignatureIdOut = matchedId;
    return TRUE;
}

static VOID
KswPlatformClassifyFunction(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ BOOLEAN ExpectedHalOwner,
    _In_ BOOLEAN ExpectedWdfOwner,
    _In_ BOOLEAN ExpectedKswordOwner
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* detourOwner = NULL;
    ULONG64 detourTarget = 0ULL;
    BOOLEAN ownerExpected = FALSE;
    BOOLEAN executable = FALSE;
    ULONG prologueSignatureId = 0UL;

    if (Entry == NULL || Entry->liveAddress == 0ULL) {
        return;
    }

    owner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)Entry->liveAddress);
    KswPlatformFillModule(Entry, owner);
    executable = owner != NULL &&
        KswPlatformAddressSectionMatches(owner, (ULONG_PTR)Entry->liveAddress, TRUE);
    if (ExpectedHalOwner) {
        ownerExpected = KswPlatformIsExpectedHalOwner(owner);
    }
    else if (ExpectedWdfOwner) {
        ownerExpected = KswPlatformModuleNameEquals(owner, "Wdf01000.sys");
    }
    else if (ExpectedKswordOwner) {
        ownerExpected = KswPlatformModuleNameEquals(owner, "KswordARK.sys");
    }
    else {
        ownerExpected = owner != NULL;
    }

    if (ownerExpected) {
        Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED;
    }
    if (!ownerExpected || !executable) {
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
        return;
    }

    if (KswPlatformDecodeDetourTarget(Entry->liveAddress, &detourTarget)) {
        detourOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)detourTarget);
        if (detourOwner == NULL || detourOwner != owner) {
            Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
            Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
        }
        else {
            Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
            Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
            Entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
            Entry->lastStatus = STATUS_REVISION_MISMATCH;
        }
        return;
    }

    if (KswPlatformIdentifyX64Prologue(Entry->liveAddress, &prologueSignatureId)) {
        Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_VALIDATED;
        Entry->prologueSignatureId = prologueSignatureId;
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_CLEAN;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
    }
    else {
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_LOW;
        Entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
        Entry->lastStatus = STATUS_REVISION_MISMATCH;
    }
}

static ULONG
KswPlatformOutputCapacity(
    _In_ size_t OutputBytes
    )
{
    size_t payloadBytes = 0U;
    size_t capacity = 0U;

    if (OutputBytes <= KSW_PLATFORM_RESPONSE_HEADER_SIZE) {
        return 0UL;
    }
    payloadBytes = OutputBytes - KSW_PLATFORM_RESPONSE_HEADER_SIZE;
    capacity = payloadBytes / sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY);
    if (capacity > MAXULONG) {
        return MAXULONG;
    }
    return (ULONG)capacity;
}

static VOID
KswPlatformAppend(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry
    )
{
    if (Response == NULL || Entry == NULL) {
        return;
    }
    Response->totalCount += 1UL;
    if (Response->returnedCount >= Capacity || Response->returnedCount >= MaxRows) {
        Response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED |
            KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL;
        Response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
        Response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return;
    }
    Response->entries[Response->returnedCount] = *Entry;
    Response->returnedCount += 1UL;
    if (Entry->status != KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
        Response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL;
        if (Response->queryStatus == KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
            Response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
        }
    }
}

static VOID
KswPlatformAddDiagnostic(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ ULONG Scope,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_z_ PCWSTR Name,
    _In_z_ PCWSTR Detail
    )
{
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.scope = Scope;
    entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC;
    entry.status = Status;
    entry.hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED;
    entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_NONE;
    entry.signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY;
    entry.lastStatus = LastStatus;
    KswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), Name);
    KswPlatformCopyWide(entry.detail, RTL_NUMBER_OF(entry.detail), Detail);
    KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    Response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL |
        KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED;
    if (Response->queryStatus == KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
        Response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
    }
    Response->lastStatus = LastStatus;
}

static VOID
KswPlatformAddHalDispatch(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
{
    PVOID tableAddress = KswPlatformGetRoutine(L"HalDispatchTable");
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    KSW_PLATFORM_HAL_PUBLIC_VIEW tableView;
    ULONG index = 0UL;

    if (tableAddress == NULL) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_PROCEDURE_NOT_FOUND,
            L"HalDispatchTable",
            L"精确导出不存在；未进行全内核扫描，审计按失败关闭返回。");
        return;
    }
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)tableAddress);
    if (tableOwner == NULL ||
        !KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformAddressSectionMatches(tableOwner, (ULONG_PTR)tableAddress, FALSE) ||
        !KswPlatformAddressSectionMatches(
            tableOwner,
            (ULONG_PTR)tableAddress + sizeof(tableView) - 1U,
            FALSE) ||
        !KswordARKHookReadMemorySafe(tableAddress, &tableView, sizeof(tableView)) ||
        tableView.Version != HAL_DISPATCH_VERSION ||
        tableView.Reserved != 0UL) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_REVISION_MISMATCH,
            L"HalDispatchTable",
            L"导出地址、非执行节、公开 HAL_DISPATCH_VERSION 或保留字段校验失败；拒绝解释表项。");
        return;
    }

    for (index = 0UL; index < KSW_PLATFORM_HAL_PUBLIC_ENTRY_COUNT; ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.scope = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH;
        entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION;
        entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
        entry.fieldFlags = KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;
        entry.signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6;
        entry.entryIndex = index;
        entry.tableAddress = (ULONGLONG)(ULONG_PTR)tableAddress;
        entry.lastStatus = STATUS_SUCCESS;
        KswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), g_KswHalDispatchNames[index]);

        if (tableView.Entries[index] != NULL) {
            entry.liveAddress = (ULONGLONG)(ULONG_PTR)tableView.Entries[index];
            entry.baselineAddress = entry.liveAddress;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
                KSWORD_ARK_PLATFORM_FIELD_BASELINE_ADDRESS |
                KSWORD_ARK_PLATFORM_FIELD_RUNTIME_SNAPSHOT_BASELINE;
            KswPlatformClassifyFunction(&entry, ModuleInfo, TRUE, FALSE, FALSE);
            KswPlatformCopyWide(
                entry.detail,
                RTL_NUMBER_OF(entry.detail),
                L"原始地址列为本次只读结构快照，不冒充磁盘/PDB 基线；Hook 结论来自模块边界、执行节和保守 x64 prologue。");
        }
        else {
            entry.hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
            entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
            KswPlatformCopyWide(entry.detail, RTL_NUMBER_OF(entry.detail), L"公开表项为空；保留为可解释的只读状态。");
        }
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static BOOLEAN
KswPlatformValidateCountPrefixedTableAddress(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PVOID TableAddress,
    _In_ BOOLEAN RequireAllExpectedTargets,
    _Out_opt_ ULONG* EntryCountOut
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG header[2];
    ULONG index = 0UL;
    ULONG nonNullCount = 0UL;
    ULONG expectedTargetCount = 0UL;
    ULONG_PTR endAddress = 0U;

    if (TableAddress == NULL) {
        return FALSE;
    }
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)TableAddress);
    RtlZeroMemory(header, sizeof(header));
    if (tableOwner == NULL ||
        !KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformAddressSectionMatches(tableOwner, (ULONG_PTR)TableAddress, FALSE) ||
        !KswordARKHookReadMemorySafe(TableAddress, header, sizeof(header)) ||
        header[0] == 0UL ||
        header[0] > KSW_PLATFORM_PRIVATE_ENTRY_LIMIT) {
        return FALSE;
    }

    endAddress = (ULONG_PTR)TableAddress + sizeof(header) +
        ((ULONG_PTR)header[0] * sizeof(PVOID));
    if (endAddress <= (ULONG_PTR)TableAddress ||
        endAddress > ((ULONG_PTR)tableOwner->ImageBase + tableOwner->ImageSize) ||
        !KswPlatformAddressSectionMatches(tableOwner, endAddress - 1U, FALSE)) {
        return FALSE;
    }

    // 中文说明：精确导出只要求表结构可安全读取，越界目标留给逐项 Hook 分类，
    // 这样可疑指针仍会作为证据显示。仅在 RIP 候选消歧时要求所有目标可信，
    // 避免把恰好以小整数开头的普通 data 误识别为私有函数表。
    for (index = 0UL; index < header[0]; ++index) {
        PVOID functionAddress = NULL;
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* functionOwner = NULL;

        if (!KswordARKHookReadMemorySafe(
                (const UCHAR*)TableAddress + sizeof(header) + (index * sizeof(PVOID)),
                &functionAddress,
                sizeof(functionAddress))) {
            return FALSE;
        }
        if (functionAddress == NULL) {
            continue;
        }
        functionOwner = KswordARKHookFindModuleForAddress(
            ModuleInfo,
            (ULONG_PTR)functionAddress);
        if (KswPlatformIsExpectedHalOwner(functionOwner) &&
            KswPlatformAddressSectionMatches(
                functionOwner,
                (ULONG_PTR)functionAddress,
                TRUE)) {
            expectedTargetCount += 1UL;
        }
        else if (RequireAllExpectedTargets) {
            return FALSE;
        }
        nonNullCount += 1UL;
    }
    if (nonNullCount == 0UL ||
        (RequireAllExpectedTargets && expectedTargetCount != nonNullCount)) {
        return FALSE;
    }
    if (EntryCountOut != NULL) {
        *EntryCountOut = header[0];
    }
    return TRUE;
}

typedef struct _KSW_PLATFORM_RIP_SIGNATURE
{
    UCHAR Bytes[10];
    UCHAR Mask[10];
    ULONG Length;
    ULONG DisplacementOffset;
    ULONG InstructionLength;
    BOOLEAN Indirect;
} KSW_PLATFORM_RIP_SIGNATURE;

static const KSW_PLATFORM_RIP_SIGNATURE g_KswRipTableSignatures[] = {
    { { 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0x85, 0xC0 },
      { 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF },
      10UL, 3UL, 7UL, TRUE },
    { { 0x48, 0x8B, 0x0D, 0, 0, 0, 0, 0x48, 0x85, 0xC9 },
      { 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF },
      10UL, 3UL, 7UL, TRUE },
    { { 0x4C, 0x8B, 0x35, 0, 0, 0, 0, 0x4D, 0x85, 0xF6 },
      { 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF },
      10UL, 3UL, 7UL, TRUE },
    { { 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8 },
      { 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF },
      8UL, 3UL, 7UL, FALSE },
    { { 0x4C, 0x8D, 0x35, 0, 0, 0, 0, 0xE8 },
      { 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF },
      8UL, 3UL, 7UL, FALSE }
};

static NTSTATUS
KswPlatformLocateRipRelativeTable(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_z_ PCWSTR AnchorName,
    _Outptr_ PVOID* TableAddressOut
    )
{
    static const UCHAR wrapperBytes[14] = {
        0x48, 0x83, 0xEC, 0x00, 0xE8, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x00, 0xC3
    };
    static const UCHAR wrapperMask[14] = {
        0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x00, 0xFF
    };
    PVOID anchorAddress = NULL;
    ULONG64 scanAddress = 0ULL;
    UCHAR wrapperCode[16];
    UCHAR scanBytes[0x100];
    LONG callDisplacement = 0;
    ULONG offset = 0UL;
    ULONG signatureIndex = 0UL;
    ULONG uniqueCount = 0UL;
    PVOID uniqueCandidate = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* anchorOwner = NULL;

    if (ModuleInfo == NULL || AnchorName == NULL || TableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TableAddressOut = NULL;
    anchorAddress = KswPlatformGetRoutine(AnchorName);
    anchorOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)anchorAddress);
    if (anchorAddress == NULL ||
        !KswPlatformIsExpectedHalOwner(anchorOwner) ||
        !KswPlatformAddressSectionMatches(anchorOwner, (ULONG_PTR)anchorAddress, TRUE)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(wrapperCode, sizeof(wrapperCode));
    if (!KswordARKHookReadMemorySafe(anchorAddress, wrapperCode, sizeof(wrapperCode)) ||
        !KswPlatformMaskedBytesMatch(
            wrapperCode,
            wrapperBytes,
            wrapperMask,
            RTL_NUMBER_OF(wrapperBytes))) {
        return STATUS_REVISION_MISMATCH;
    }
    RtlCopyMemory(&callDisplacement, &wrapperCode[5], sizeof(callDisplacement));
    scanAddress = (ULONG64)(ULONG_PTR)anchorAddress + 9ULL + (LONGLONG)callDisplacement;
    if (scanAddress == 0ULL ||
        KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)scanAddress) != anchorOwner ||
        !KswPlatformAddressSectionMatches(anchorOwner, (ULONG_PTR)scanAddress, TRUE)) {
        return STATUS_INVALID_ADDRESS;
    }

    RtlZeroMemory(scanBytes, sizeof(scanBytes));
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)scanAddress,
            scanBytes,
            sizeof(scanBytes))) {
        return STATUS_PARTIAL_COPY;
    }

    // 中文说明：仅在精确导出 thunk 指向的单个函数前 0x100 字节内扫描。
    // 每个命中先解析 RIP-relative，再验证候选完整表结构；全内核无界扫描被禁止。
    for (offset = 0UL; offset < sizeof(scanBytes); ++offset) {
        for (signatureIndex = 0UL;
             signatureIndex < RTL_NUMBER_OF(g_KswRipTableSignatures);
             ++signatureIndex) {
            const KSW_PLATFORM_RIP_SIGNATURE* signature =
                &g_KswRipTableSignatures[signatureIndex];
            LONG displacement = 0;
            ULONG64 ripTarget = 0ULL;
            PVOID candidate = NULL;

            if (offset + signature->Length > sizeof(scanBytes) ||
                !KswPlatformMaskedBytesMatch(
                    scanBytes + offset,
                    signature->Bytes,
                    signature->Mask,
                    signature->Length)) {
                continue;
            }
            RtlCopyMemory(
                &displacement,
                scanBytes + offset + signature->DisplacementOffset,
                sizeof(displacement));
            ripTarget = scanAddress + offset + signature->InstructionLength +
                (LONGLONG)displacement;
            if (signature->Indirect) {
                if (!KswordARKHookReadMemorySafe(
                        (const VOID*)(ULONG_PTR)ripTarget,
                        &candidate,
                        sizeof(candidate))) {
                    continue;
                }
            }
            else {
                candidate = (PVOID)(ULONG_PTR)ripTarget;
            }
            if (!KswPlatformValidateCountPrefixedTableAddress(
                    ModuleInfo,
                    candidate,
                    TRUE,
                    NULL)) {
                continue;
            }
            if (uniqueCandidate == candidate) {
                continue;
            }
            uniqueCandidate = candidate;
            uniqueCount += 1UL;
        }
    }
    if (uniqueCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    if (uniqueCount != 1UL) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    *TableAddressOut = uniqueCandidate;
    return STATUS_SUCCESS;
}

static VOID
KswPlatformAddCountPrefixedTable(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG Scope,
    _In_z_ PCWSTR ExportName,
    _In_z_ PCWSTR EntryPrefix,
    _In_opt_z_ PCWSTR SignatureAnchorName
    )
{
    PVOID tableAddress = KswPlatformGetRoutine(ExportName);
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG header[2];
    ULONG entryCount = 0UL;
    ULONG index = 0UL;
    ULONG_PTR endAddress = 0U;
    ULONG signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_COUNT_PREFIXED_TABLE;
    NTSTATUS locateStatus = STATUS_SUCCESS;

    if (tableAddress == NULL) {
        if (SignatureAnchorName != NULL) {
            locateStatus = KswPlatformLocateRipRelativeTable(
                ModuleInfo,
                SignatureAnchorName,
                &tableAddress);
            if (NT_SUCCESS(locateStatus)) {
                signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_RIP_RELATIVE_MASKED;
            }
        }
        else {
            locateStatus = STATUS_PROCEDURE_NOT_FOUND;
        }
        if (!NT_SUCCESS(locateStatus) || tableAddress == NULL) {
            KswPlatformAddDiagnostic(
                Response, Capacity, MaxRows, Scope,
                KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
                locateStatus,
                ExportName,
                L"精确导出不存在，可信 anchor 的有界 byte/mask + RIP-relative 路径也未产生唯一结构候选；按失败关闭返回。");
            return;
        }
    }

    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)tableAddress);
    RtlZeroMemory(header, sizeof(header));
    if (tableOwner == NULL ||
        !KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformAddressSectionMatches(tableOwner, (ULONG_PTR)tableAddress, FALSE) ||
        !KswordARKHookReadMemorySafe(tableAddress, header, sizeof(header)) ||
        !KswPlatformValidateCountPrefixedTableAddress(
            ModuleInfo,
            tableAddress,
            FALSE,
            &entryCount)) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows, Scope,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            ExportName,
            L"精确导出未通过所属模块、非执行节或安全读取校验；拒绝解释私有表。");
        return;
    }

    entryCount = header[0];
    endAddress = (ULONG_PTR)tableAddress + sizeof(header) + ((ULONG_PTR)entryCount * sizeof(PVOID));
    if (endAddress <= (ULONG_PTR)tableAddress ||
        endAddress > ((ULONG_PTR)tableOwner->ImageBase + tableOwner->ImageSize)) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows, Scope,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_INVALID_ADDRESS,
            ExportName,
            L"计数前缀推导出的表范围越过已验证模块边界；拒绝读取。");
        return;
    }

    for (index = 0UL; index < entryCount; ++index) {
        PVOID functionAddress = NULL;
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        WCHAR nameText[KSWORD_ARK_PLATFORM_NAME_CHARS];

        if (!KswordARKHookReadMemorySafe(
                (const UCHAR*)tableAddress + sizeof(header) + (index * sizeof(PVOID)),
                &functionAddress,
                sizeof(functionAddress))) {
            KswPlatformAddDiagnostic(
                Response, Capacity, MaxRows, Scope,
                KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
                STATUS_PARTIAL_COPY,
                ExportName,
                L"已验证表范围内发生安全读取失败；停止该表，避免跨界访问。");
            break;
        }

        RtlZeroMemory(&entry, sizeof(entry));
        RtlZeroMemory(nameText, sizeof(nameText));
        (VOID)RtlStringCchPrintfW(
            nameText,
            RTL_NUMBER_OF(nameText),
            L"%ws[%lu]",
            EntryPrefix,
            index);
        entry.size = sizeof(entry);
        entry.scope = Scope;
        entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION;
        entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
        entry.signatureId = signatureId;
        entry.entryIndex = index;
        entry.tableAddress = (ULONGLONG)(ULONG_PTR)tableAddress;
        entry.fieldFlags = KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;
        if (signatureId == KSWORD_ARK_PLATFORM_SIGNATURE_COUNT_PREFIXED_TABLE) {
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;
        }
        entry.lastStatus = STATUS_SUCCESS;
        KswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), nameText);

        if (functionAddress != NULL) {
            entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
            entry.baselineAddress = entry.liveAddress;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
                KSWORD_ARK_PLATFORM_FIELD_BASELINE_ADDRESS |
                KSWORD_ARK_PLATFORM_FIELD_RUNTIME_SNAPSHOT_BASELINE;
            KswPlatformClassifyFunction(&entry, ModuleInfo, TRUE, FALSE, FALSE);
        }
        else {
            entry.hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
            entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
        }
        KswPlatformCopyWide(
            entry.detail,
            RTL_NUMBER_OF(entry.detail),
            L"无 PDB：仅在精确导出、唯一计数前缀、模块边界和安全读取全部成立时展示；原始地址为本次结构快照。");
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static VOID
KswPlatformAddWdfFunctions(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
{
    const WDFFUNC* functionTable = WdfFunctions;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG index = 0UL;

    if (functionTable == NULL) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"WdfFunctions",
            L"当前驱动没有可读的 KMDF 绑定表；未尝试搜索 Wdf01000 私有内存。");
        return;
    }
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)functionTable);
    if (tableOwner == NULL ||
        !KswPlatformModuleNameEquals(tableOwner, "Wdf01000.sys") ||
        !KswPlatformAddressSectionMatches(tableOwner, (ULONG_PTR)functionTable, FALSE)) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"WdfFunctions",
            L"KMDF 绑定表地址不在 Wdf01000.sys 的非执行节；拒绝读取函数指针。");
        return;
    }

    for (index = 0UL; index < RTL_NUMBER_OF(g_KswWdfFunctions); ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        WDFFUNC functionAddress = NULL;

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.scope = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS;
        entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION;
        entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
        entry.hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
        entry.signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE;
        entry.entryIndex = g_KswWdfFunctions[index].Index;
        entry.tableAddress = (ULONGLONG)(ULONG_PTR)functionTable;
        entry.fieldFlags = KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;
        entry.lastStatus = STATUS_SUCCESS;
        KswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), g_KswWdfFunctions[index].Name);
        if (g_KswWdfFunctions[index].Index >= WdfFunctionTableNumEntries ||
            !KswordARKHookReadMemorySafe(
                &functionTable[g_KswWdfFunctions[index].Index],
                &functionAddress,
                sizeof(functionAddress)) ||
            functionAddress == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
            entry.lastStatus = STATUS_REVISION_MISMATCH;
            KswPlatformCopyWide(
                entry.detail,
                RTL_NUMBER_OF(entry.detail),
                L"编译期 WDF 索引超界、指针不可读或为空；该函数按失败关闭显示。");
            KswPlatformSetVendorLabel(&entry, L"Microsoft Corporation");
            KswPlatformAppend(Response, Capacity, MaxRows, &entry);
            continue;
        }

        entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
        entry.baselineAddress = entry.liveAddress;
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_BASELINE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_RUNTIME_SNAPSHOT_BASELINE;
        KswPlatformClassifyFunction(&entry, ModuleInfo, FALSE, TRUE, FALSE);
        KswPlatformSetVendorLabel(&entry, L"Microsoft Corporation");
        KswPlatformCopyWide(
            entry.detail,
            RTL_NUMBER_OF(entry.detail),
            L"函数来自当前驱动的 WDF 版本绑定表；原始地址为只读运行时快照，Hook 结论不会冒充 PDB/disk baseline。");
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static VOID
KswPlatformAddWdfCallbacks(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(g_KswWdfCallbacks); ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.scope = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS;
        entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_CALLBACK;
        entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
        entry.signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE;
        entry.entryIndex = index;
        entry.liveAddress = (ULONGLONG)(ULONG_PTR)g_KswWdfCallbacks[index].Address;
        entry.baselineAddress = entry.liveAddress;
        entry.fieldFlags = KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_BASELINE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_RUNTIME_SNAPSHOT_BASELINE;
        entry.lastStatus = STATUS_SUCCESS;
        KswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), g_KswWdfCallbacks[index].Name);
        KswPlatformClassifyFunction(&entry, ModuleInfo, FALSE, FALSE, TRUE);
        KswPlatformSetVendorLabel(&entry, L"KSword Project");
        KswPlatformCopyWide(
            entry.detail,
            RTL_NUMBER_OF(entry.detail),
            L"回调地址来自 KswordARK 实际 WDF 配置入口，不扫描任意驱动对象；仅检查自身模块执行节与保守 prologue。");
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

NTSTATUS
KswordARKPlatformAuditIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST defaultRequest;
    const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST* requestPacket = NULL;
    KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response = NULL;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputBytes = 0U;
    size_t actualOutputBytes = 0U;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS;
    ULONG scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL;
    ULONG majorVersion = 0UL;
    ULONG minorVersion = 0UL;
    ULONG buildNumber = 0UL;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    defaultRequest.scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL;
    defaultRequest.maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputBytes,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputBytes);
    requestPacket = hasInput ?
        (const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST*)inputBuffer :
        &defaultRequest;
    if (requestPacket->size != sizeof(*requestPacket) ||
        requestPacket->version != KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION ||
        requestPacket->reserved0 != 0UL ||
        (requestPacket->scopeMask & ~KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    scopeMask = requestPacket->scopeMask == 0UL ?
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL :
        requestPacket->scopeMask;
    maxRows = requestPacket->maxRows == 0UL ?
        KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS :
        requestPacket->maxRows;
    if (maxRows > KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) {
        maxRows = KSWORD_ARK_PLATFORM_HARD_MAX_ROWS;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_PLATFORM_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, actualOutputBytes);
    response = (KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE*)outputBuffer;
    response->size = KSW_PLATFORM_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
    response->scopeMask = scopeMask;
    response->responseFlags = KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB;
    response->entrySize = sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY);
    response->signaturePolicyFlags =
        KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
        KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
        KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
        KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_VALIDATED;
    response->lastStatus = STATUS_SUCCESS;
    capacity = KswPlatformOutputCapacity(actualOutputBytes);
    (VOID)PsGetVersion(&majorVersion, &minorVersion, &buildNumber, NULL);
    UNREFERENCED_PARAMETER(majorVersion);
    UNREFERENCED_PARAMETER(minorVersion);
    response->buildNumber = buildNumber;

    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        KswPlatformAddDiagnostic(
            response, capacity, maxRows, scopeMask,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            status,
            L"LoadedModuleSnapshot",
            L"无法取得已加载模块快照；没有地址归属证据时拒绝读取 HAL/WDF 表。");
        *BytesReturned = KSW_PLATFORM_RESPONSE_HEADER_SIZE +
            ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        return STATUS_SUCCESS;
    }

    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH) != 0UL) {
        KswPlatformAddHalDispatch(response, capacity, maxRows, moduleInfo);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE) != 0UL) {
        KswPlatformAddCountPrefixedTable(
            response, capacity, maxRows, moduleInfo,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            L"HalPrivateDispatchTable",
            L"HalPrivateDispatchTable",
            NULL);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI) != 0UL) {
        KswPlatformAddCountPrefixedTable(
            response, capacity, maxRows, moduleInfo,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            L"HalAcpiDispatchTable",
            L"HalAcpiDispatchTable",
            L"HalAcpiGetTableEx");
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS) != 0UL) {
        KswPlatformAddCountPrefixedTable(
            response, capacity, maxRows, moduleInfo,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            L"HalSubComponents",
            L"HalSubComponents",
            NULL);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS) != 0UL) {
        KswPlatformAddWdfFunctions(response, capacity, maxRows, moduleInfo);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS) != 0UL) {
        KswPlatformAddWdfCallbacks(response, capacity, maxRows, moduleInfo);
    }

    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    if ((response->responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED;
    }
    *BytesReturned = KSW_PLATFORM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}
