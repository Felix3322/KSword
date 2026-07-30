/*++

Module Name:

    i8042_audit.c

Abstract:

    i8042prt 专项只读审计。只有已知 PE/RSDS/opcode/DriverObject 描述符全部
    匹配时才读取设备扩展中的端点指针；未知版本始终失败关闭。

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkI8042AuditIoctl.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSW_I8042_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE, entries))
#define KSW_I8042_POOL_TAG '24iK'
#define KSW_I8042_DEVICE_LIMIT 64UL
#define KSW_I8042_DEVICE_ENUM_RETRIES 2UL
#define KSW_I8042_STACK_DEPTH_LIMIT 32UL
#define KSW_I8042_RSDS_SIGNATURE 0x53445352UL

#define KSW_I8042_EXPECTED_TIME_DATE_STAMP 0xFD7548DDUL
#define KSW_I8042_EXPECTED_IMAGE_SIZE      0x00026000UL
#define KSW_I8042_EXPECTED_CHECKSUM        0x0002637EUL
#define KSW_I8042_EXPECTED_PDB_AGE         1UL
#define KSW_I8042_EXPECTED_INTERNAL_DISPATCH_RVA 0x00007190UL
#define KSW_I8042_EXPECTED_ADD_DEVICE_RVA       0x0001B6F0UL
#define KSW_I8042_EXPECTED_EXTENSION_SIZE        0x00000458UL

#define KSW_I8042_OFFSET_CLASS_DEVICE_OBJECT 0x1B0UL
#define KSW_I8042_OFFSET_CLASS_SERVICE       0x1B8UL
#define KSW_I8042_OFFSET_KEYBOARD_INIT       0x398UL
#define KSW_I8042_OFFSET_KEYBOARD_ISR        0x3A0UL
#define KSW_I8042_OFFSET_KEYBOARD_CONTEXT    0x3A8UL
#define KSW_I8042_OFFSET_MOUSE_ISR           0x428UL
#define KSW_I8042_OFFSET_MOUSE_CONTEXT       0x430UL

typedef struct _KSW_I8042_RSDS_HEADER
{
    ULONG Signature;
    GUID Guid;
    ULONG Age;
} KSW_I8042_RSDS_HEADER;

typedef struct _KSW_I8042_OPCODE_DESCRIPTOR
{
    ULONG Rva;
    ULONG Length;
    UCHAR Bytes[48];
} KSW_I8042_OPCODE_DESCRIPTOR;

typedef struct _KSW_I8042_ENDPOINT_VALUES
{
    PVOID ClassDeviceObject;
    PVOID ClassService;
    PVOID InitializationRoutine;
    PVOID IsrRoutine;
    PVOID Context;
} KSW_I8042_ENDPOINT_VALUES;

static const GUID g_KswI8042ExpectedPdbGuid = {
    0xEC704C63UL,
    0x3F2FU,
    0xA4E7U,
    { 0xBEU, 0xF7U, 0x86U, 0xF7U, 0x55U, 0xDCU, 0xB5U, 0x2CU }
};

// 对应磁盘文件 SHA256：
// 6BF208FF2A08DFAEA0FDEE5890FB6D96920052D00235DBE7C95212AD37D76166。
// R0 不对已重定位的内存映像伪做文件哈希，而是验证同一文件的 PE/RSDS 与
// 五个精确 opcode 窗口。
static const KSW_I8042_OPCODE_DESCRIPTOR g_KswI8042OpcodeDescriptors[] = {
    {
        0x0000758BUL,
        10UL,
        { 0x0FU, 0x10U, 0x00U, 0x0FU, 0x11U, 0x87U, 0xB0U, 0x01U, 0x00U, 0x00U }
    },
    {
        0x00007840UL,
        10UL,
        { 0x0FU, 0x10U, 0x00U, 0x0FU, 0x11U, 0x87U, 0xB0U, 0x01U, 0x00U, 0x00U }
    },
    {
        0x0000768CUL,
        46UL,
        {
            0x48U, 0x8BU, 0x4EU, 0x20U, 0x48U, 0x8BU, 0x01U,
            0x48U, 0x89U, 0x87U, 0xA8U, 0x03U, 0x00U, 0x00U,
            0x48U, 0x8BU, 0x41U, 0x08U, 0x48U, 0x85U, 0xC0U, 0x74U, 0x07U,
            0x48U, 0x89U, 0x87U, 0x98U, 0x03U, 0x00U, 0x00U,
            0x48U, 0x8BU, 0x41U, 0x10U, 0x48U, 0x85U, 0xC0U, 0x74U, 0x07U,
            0x48U, 0x89U, 0x87U, 0xA0U, 0x03U, 0x00U, 0x00U
        }
    },
    {
        0x000079E3UL,
        30UL,
        {
            0x48U, 0x8BU, 0x4EU, 0x20U, 0x48U, 0x8BU, 0x01U,
            0x48U, 0x89U, 0x87U, 0x30U, 0x04U, 0x00U, 0x00U,
            0x48U, 0x8BU, 0x41U, 0x08U, 0x48U, 0x85U, 0xC0U, 0x74U, 0x07U,
            0x48U, 0x89U, 0x87U, 0x28U, 0x04U, 0x00U, 0x00U
        }
    },
    {
        0x0001B761UL,
        31UL,
        {
            0xBFU, 0x58U, 0x04U, 0x00U, 0x00U,
            0x48U, 0x89U, 0x44U, 0x24U, 0x30U,
            0x41U, 0xB9U, 0x27U, 0x00U, 0x00U, 0x00U,
            0x44U, 0x88U, 0x7CU, 0x24U, 0x28U,
            0x45U, 0x33U, 0xC0U, 0x8BU, 0xD7U,
            0x44U, 0x89U, 0x7CU, 0x24U, 0x20U
        }
    }
};

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

extern POBJECT_TYPE* IoDriverObjectType;

static VOID
KswI8042CopyWide(
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
        (VOID)RtlStringCchCopyNW(
            Destination,
            DestinationChars,
            Source,
            DestinationChars - 1UL);
    }
}

static BOOLEAN
KswI8042ModuleNameEquals(
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
    return KswordARKHookBoundedAnsiEqualsInsensitive(
        fileName,
        fileNameBytes,
        ExpectedName);
}

static const KSW_HOOK_SYSTEM_MODULE_ENTRY*
KswI8042FindUniqueModule(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_z_ PCSTR ExpectedName
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* result = NULL;
    ULONG index = 0UL;
    ULONG matches = 0UL;

    if (ModuleInfo == NULL || ExpectedName == NULL) {
        return NULL;
    }
    for (index = 0UL; index < ModuleInfo->NumberOfModules; ++index) {
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* module = &ModuleInfo->Modules[index];
        if (!KswI8042ModuleNameEquals(module, ExpectedName)) {
            continue;
        }
        result = module;
        matches += 1UL;
    }
    return matches == 1UL ? result : NULL;
}

static BOOLEAN
KswI8042AddressExecutable(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONG_PTR Address
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionTableRva = 0UL;
    ULONG index = 0UL;

    if (Module == NULL ||
        Address < (ULONG_PTR)Module->ImageBase ||
        Address >= ((ULONG_PTR)Module->ImageBase + Module->ImageSize) ||
        !KswordARKHookReadImageBytes(Module, 0UL, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !KswordARKHookReadImageNtHeaders(Module, &ntHeaders)) {
        return FALSE;
    }
    sectionTableRva =
        (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (index = 0UL; index < ntHeaders.FileHeader.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER section;
        ULONG sectionRva = sectionTableRva +
            (index * (ULONG)sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR start = 0U;
        ULONG_PTR end = 0U;

        RtlZeroMemory(&section, sizeof(section));
        if (!KswordARKHookReadImageBytes(
                Module,
                sectionRva,
                &section,
                sizeof(section))) {
            return FALSE;
        }
        span = section.Misc.VirtualSize;
        if (span < section.SizeOfRawData) {
            span = section.SizeOfRawData;
        }
        if (span == 0UL ||
            !KswordARKHookValidateRvaRange(
                section.VirtualAddress,
                span,
                Module->ImageSize)) {
            continue;
        }
        start = (ULONG_PTR)Module->ImageBase + section.VirtualAddress;
        end = start + span;
        if (Address >= start && Address < end) {
            return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        }
    }
    return FALSE;
}

static BOOLEAN
KswI8042ValidateRsds(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ const IMAGE_NT_HEADERS* NtHeaders,
    _Out_ GUID* GuidOut,
    _Out_ ULONG* AgeOut
    )
{
    IMAGE_DATA_DIRECTORY directory;
    ULONG entryCount = 0UL;
    ULONG index = 0UL;
    ULONG rsdsCount = 0UL;
    ULONG matchingCount = 0UL;
    GUID observedGuid;
    ULONG observedAge = 0UL;
    GUID matchingGuid;
    ULONG matchingAge = 0UL;

    if (Module == NULL || NtHeaders == NULL || GuidOut == NULL || AgeOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&directory, sizeof(directory));
    RtlZeroMemory(&observedGuid, sizeof(observedGuid));
    RtlZeroMemory(&matchingGuid, sizeof(matchingGuid));
    RtlZeroMemory(GuidOut, sizeof(*GuidOut));
    *AgeOut = 0UL;
    if (!KswordARKHookGetDataDirectory(
            NtHeaders,
            IMAGE_DIRECTORY_ENTRY_DEBUG,
            &directory) ||
        directory.VirtualAddress == 0UL ||
        directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        (directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0UL ||
        !KswordARKHookValidateRvaRange(
            directory.VirtualAddress,
            directory.Size,
            Module->ImageSize)) {
        return FALSE;
    }
    entryCount = directory.Size / (ULONG)sizeof(IMAGE_DEBUG_DIRECTORY);
    if (entryCount == 0UL || entryCount > 32UL) {
        return FALSE;
    }

    for (index = 0UL; index < entryCount; ++index) {
        IMAGE_DEBUG_DIRECTORY debugEntry;
        KSW_I8042_RSDS_HEADER rsds;
        ULONG entryRva = directory.VirtualAddress +
            (index * (ULONG)sizeof(IMAGE_DEBUG_DIRECTORY));

        RtlZeroMemory(&debugEntry, sizeof(debugEntry));
        RtlZeroMemory(&rsds, sizeof(rsds));
        if (!KswordARKHookReadImageBytes(
                Module,
                entryRva,
                &debugEntry,
                sizeof(debugEntry)) ||
            debugEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            debugEntry.AddressOfRawData == 0UL ||
            debugEntry.SizeOfData < sizeof(rsds) ||
            !KswordARKHookReadImageBytes(
                Module,
                debugEntry.AddressOfRawData,
                &rsds,
                sizeof(rsds)) ||
            rsds.Signature != KSW_I8042_RSDS_SIGNATURE) {
            continue;
        }
        rsdsCount += 1UL;
        observedGuid = rsds.Guid;
        observedAge = rsds.Age;
        if (RtlCompareMemory(
                &rsds.Guid,
                &g_KswI8042ExpectedPdbGuid,
                sizeof(GUID)) == sizeof(GUID) &&
            rsds.Age == KSW_I8042_EXPECTED_PDB_AGE) {
            matchingGuid = rsds.Guid;
            matchingAge = rsds.Age;
            matchingCount += 1UL;
        }
    }
    if (rsdsCount == 1UL) {
        *GuidOut = observedGuid;
        *AgeOut = observedAge;
    }
    if (rsdsCount != 1UL || matchingCount != 1UL) {
        return FALSE;
    }
    *GuidOut = matchingGuid;
    *AgeOut = matchingAge;
    return TRUE;
}

static NTSTATUS
KswI8042ValidateImage(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _Out_ IMAGE_NT_HEADERS* NtHeadersOut,
    _Out_ GUID* PdbGuidOut,
    _Out_ ULONG* PdbAgeOut,
    _Out_ ULONG* FailedOpcodeRvaOut
    )
{
    IMAGE_NT_HEADERS ntHeaders;
    GUID pdbGuid;
    ULONG pdbAge = 0UL;
    ULONG index = 0UL;

    if (Module == NULL || NtHeadersOut == NULL || PdbGuidOut == NULL ||
        PdbAgeOut == NULL || FailedOpcodeRvaOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    RtlZeroMemory(NtHeadersOut, sizeof(*NtHeadersOut));
    RtlZeroMemory(PdbGuidOut, sizeof(*PdbGuidOut));
    *PdbAgeOut = 0UL;
    *FailedOpcodeRvaOut = 0UL;
    if (!KswI8042ModuleNameEquals(Module, "i8042prt.sys") ||
        !KswordARKHookReadImageNtHeaders(Module, &ntHeaders)) {
        return STATUS_IMAGE_CHECKSUM_MISMATCH;
    }
    *NtHeadersOut = ntHeaders;
    if (
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.FileHeader.TimeDateStamp != KSW_I8042_EXPECTED_TIME_DATE_STAMP ||
        ntHeaders.OptionalHeader.SizeOfImage != KSW_I8042_EXPECTED_IMAGE_SIZE ||
        ntHeaders.OptionalHeader.CheckSum != KSW_I8042_EXPECTED_CHECKSUM ||
        Module->ImageSize != KSW_I8042_EXPECTED_IMAGE_SIZE) {
        return STATUS_IMAGE_CHECKSUM_MISMATCH;
    }
    if (!KswI8042ValidateRsds(Module, &ntHeaders, &pdbGuid, &pdbAge)) {
        *PdbGuidOut = pdbGuid;
        *PdbAgeOut = pdbAge;
        return STATUS_REVISION_MISMATCH;
    }
    *PdbGuidOut = pdbGuid;
    *PdbAgeOut = pdbAge;
    for (index = 0UL;
         index < RTL_NUMBER_OF(g_KswI8042OpcodeDescriptors);
         ++index) {
        const KSW_I8042_OPCODE_DESCRIPTOR* descriptor =
            &g_KswI8042OpcodeDescriptors[index];
        UCHAR bytes[48];

        RtlZeroMemory(bytes, sizeof(bytes));
        if (descriptor->Length == 0UL ||
            descriptor->Length > sizeof(bytes) ||
            !KswordARKHookReadImageBytes(
                Module,
                descriptor->Rva,
                bytes,
                descriptor->Length) ||
            RtlCompareMemory(
                bytes,
                descriptor->Bytes,
                descriptor->Length) != descriptor->Length) {
            *FailedOpcodeRvaOut = descriptor->Rva;
            return STATUS_DATA_ERROR;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KswI8042ReferenceDriver(
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut
    )
{
    UNICODE_STRING name;

    if (DriverObjectOut == NULL || IoDriverObjectType == NULL ||
        *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DriverObjectOut = NULL;
    RtlInitUnicodeString(&name, L"\\Driver\\i8042prt");
    return ObReferenceObjectByName(
        &name,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0UL,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)DriverObjectOut);
}

static NTSTATUS
KswI8042ValidateDriverLayout(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _Out_ ULONG64* ObservedDispatchOut,
    _Out_ ULONG64* ObservedAddDeviceOut
    )
{
    DRIVER_OBJECT driverView;
    PDRIVER_ADD_DEVICE addDevice = NULL;
    ULONG_PTR expectedDispatch = 0U;
    ULONG_PTR expectedAddDevice = 0U;

    if (DriverObject == NULL || Module == NULL ||
        ObservedDispatchOut == NULL || ObservedAddDeviceOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ObservedDispatchOut = 0ULL;
    *ObservedAddDeviceOut = 0ULL;
    RtlZeroMemory(&driverView, sizeof(driverView));
    if (!KswordARKHookReadMemorySafe(
            DriverObject,
            &driverView,
            sizeof(driverView))) {
        return STATUS_PARTIAL_COPY;
    }
    if (driverView.Type != IO_TYPE_DRIVER ||
        driverView.Size != (CSHORT)sizeof(DRIVER_OBJECT) ||
        driverView.DriverStart != Module->ImageBase ||
        driverView.DriverSize != Module->ImageSize ||
        driverView.DriverExtension == NULL) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!KswordARKHookReadMemorySafe(
            (const UCHAR*)driverView.DriverExtension +
                FIELD_OFFSET(DRIVER_EXTENSION, AddDevice),
            &addDevice,
            sizeof(addDevice))) {
        return STATUS_PARTIAL_COPY;
    }
    expectedDispatch =
        (ULONG_PTR)Module->ImageBase + KSW_I8042_EXPECTED_INTERNAL_DISPATCH_RVA;
    expectedAddDevice =
        (ULONG_PTR)Module->ImageBase + KSW_I8042_EXPECTED_ADD_DEVICE_RVA;
    *ObservedDispatchOut =
        (ULONG64)(ULONG_PTR)driverView.MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
    *ObservedAddDeviceOut = (ULONG64)(ULONG_PTR)addDevice;
    if ((ULONG_PTR)driverView.MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] !=
            expectedDispatch ||
        (ULONG_PTR)addDevice != expectedAddDevice) {
        return STATUS_DATA_ERROR;
    }
    return STATUS_SUCCESS;
}

static ULONG
KswI8042OutputCapacity(
    _In_ size_t OutputBytes
    )
{
    size_t payloadBytes = 0U;
    size_t capacity = 0U;

    if (OutputBytes <= KSW_I8042_RESPONSE_HEADER_SIZE) {
        return 0UL;
    }
    payloadBytes = OutputBytes - KSW_I8042_RESPONSE_HEADER_SIZE;
    capacity = payloadBytes / sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY);
    return capacity > MAXULONG ? MAXULONG : (ULONG)capacity;
}

static VOID
KswI8042SetDetail(
    _Inout_ KSWORD_ARK_I8042_AUDIT_ENTRY* Entry,
    _In_ ULONG DetailCode,
    _In_ ULONGLONG Arg0,
    _In_ ULONGLONG Arg1,
    _In_ ULONGLONG Arg2,
    _In_ ULONGLONG Arg3
    )
{
    if (Entry == NULL) {
        return;
    }
    Entry->detailCode = DetailCode;
    Entry->detailArgs[0] = Arg0;
    Entry->detailArgs[1] = Arg1;
    Entry->detailArgs[2] = Arg2;
    Entry->detailArgs[3] = Arg3;
    if (DetailCode != KSWORD_ARK_I8042_DETAIL_NONE) {
        Entry->fieldFlags |= KSWORD_ARK_I8042_FIELD_DETAIL_ARGS;
    }
}

static VOID
KswI8042Append(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSWORD_ARK_I8042_AUDIT_ENTRY* Entry
    )
{
    if (Response == NULL || Entry == NULL) {
        return;
    }
    Response->totalCount += 1UL;
    if (Response->returnedCount >= Capacity ||
        Response->returnedCount >= MaxRows) {
        Response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_TRUNCATED |
            KSWORD_ARK_I8042_RESPONSE_PARTIAL;
        Response->queryStatus =
            KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED;
        Response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return;
    }
    Response->entries[Response->returnedCount] = *Entry;
    Response->returnedCount += 1UL;
    if (Entry->status != KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE) {
        Response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_PARTIAL;
        if (Response->queryStatus ==
            KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE) {
            Response->queryStatus = KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL;
        }
    }
}

static VOID
KswI8042AddDiagnostic(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_ ULONG DetailCode,
    _In_ ULONGLONG Arg0,
    _In_ ULONGLONG Arg1,
    _In_ BOOLEAN FailClosed
    )
{
    KSWORD_ARK_I8042_AUDIT_ENTRY entry;
    ULONG returnedBefore = 0UL;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.rowKind = KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC;
    entry.status = Status;
    entry.verdict = FailClosed ?
        KSWORD_ARK_I8042_VERDICT_UNSUPPORTED :
        KSWORD_ARK_I8042_VERDICT_UNKNOWN;
    entry.lastStatus = LastStatus;
    KswI8042SetDetail(&entry, DetailCode, Arg0, Arg1, 0ULL, 0ULL);
    returnedBefore = Response->returnedCount;
    KswI8042Append(Response, Capacity, MaxRows, &entry);
    Response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_PARTIAL;
    if (FailClosed) {
        Response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED;
    }
    if (Response->returnedCount == returnedBefore) {
        // KswI8042Append 已保留 BUFFER_TRUNCATED/STATUS_BUFFER_OVERFLOW。
        return;
    }
    Response->queryStatus = Status;
    Response->lastStatus = LastStatus;
}

static BOOLEAN
KswI8042WideContainsInsensitive(
    _In_reads_(TextChars) PCWSTR Text,
    _In_ ULONG TextChars,
    _In_z_ PCWSTR Needle
    )
{
    ULONG needleChars = 0UL;
    ULONG offset = 0UL;
    ULONG index = 0UL;

    if (Text == NULL || Needle == NULL) {
        return FALSE;
    }
    while (Needle[needleChars] != L'\0') {
        needleChars += 1UL;
    }
    if (needleChars == 0UL || needleChars > TextChars) {
        return FALSE;
    }
    for (offset = 0UL; offset + needleChars <= TextChars; ++offset) {
        BOOLEAN matched = TRUE;
        for (index = 0UL; index < needleChars; ++index) {
            WCHAR left = Text[offset + index];
            WCHAR right = Needle[index];
            if (left == L'\0') {
                matched = FALSE;
                break;
            }
            if (RtlUpcaseUnicodeChar(left) != RtlUpcaseUnicodeChar(right)) {
                matched = FALSE;
                break;
            }
        }
        if (matched) {
            return TRUE;
        }
    }
    return FALSE;
}

static ULONG
KswI8042ClassifyDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_writes_(PnpIdChars) PWCHAR PnpId,
    _In_ ULONG PnpIdChars
    )
{
    PDEVICE_OBJECT physicalDevice = NULL;
    WCHAR classGuid[64];
    WCHAR hardwareIds[KSWORD_ARK_I8042_PNP_ID_CHARS];
    ULONG requiredBytes = 0UL;
    NTSTATUS classStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS hardwareStatus = STATUS_UNSUCCESSFUL;

    if (PnpId == NULL || PnpIdChars == 0UL) {
        return KSWORD_ARK_I8042_DEVICE_UNKNOWN;
    }
    PnpId[0] = L'\0';
    RtlZeroMemory(classGuid, sizeof(classGuid));
    RtlZeroMemory(hardwareIds, sizeof(hardwareIds));
    physicalDevice = IoGetDeviceAttachmentBaseRef(DeviceObject);
    if (physicalDevice == NULL) {
        return KSWORD_ARK_I8042_DEVICE_UNKNOWN;
    }
    classStatus = IoGetDeviceProperty(
        physicalDevice,
        DevicePropertyClassGuid,
        sizeof(classGuid) - sizeof(WCHAR),
        classGuid,
        &requiredBytes);
    requiredBytes = 0UL;
    hardwareStatus = IoGetDeviceProperty(
        physicalDevice,
        DevicePropertyHardwareID,
        sizeof(hardwareIds) - sizeof(WCHAR),
        hardwareIds,
        &requiredBytes);
    if (NT_SUCCESS(hardwareStatus) && hardwareIds[0] != L'\0') {
        KswI8042CopyWide(PnpId, PnpIdChars, hardwareIds);
    }
    else if (NT_SUCCESS(classStatus) && classGuid[0] != L'\0') {
        KswI8042CopyWide(PnpId, PnpIdChars, classGuid);
    }

    ObDereferenceObject(physicalDevice);

    if ((NT_SUCCESS(classStatus) &&
         KswI8042WideContainsInsensitive(
             classGuid,
             RTL_NUMBER_OF(classGuid),
             L"4D36E96B-E325-11CE-BFC1-08002BE10318")) ||
        (NT_SUCCESS(hardwareStatus) &&
         KswI8042WideContainsInsensitive(
             hardwareIds,
             RTL_NUMBER_OF(hardwareIds),
             L"PNP030"))) {
        return KSWORD_ARK_I8042_DEVICE_KEYBOARD;
    }
    if ((NT_SUCCESS(classStatus) &&
         KswI8042WideContainsInsensitive(
             classGuid,
             RTL_NUMBER_OF(classGuid),
             L"4D36E96F-E325-11CE-BFC1-08002BE10318")) ||
        (NT_SUCCESS(hardwareStatus) &&
         KswI8042WideContainsInsensitive(
             hardwareIds,
             RTL_NUMBER_OF(hardwareIds),
             L"PNP0F"))) {
        return KSWORD_ARK_I8042_DEVICE_MOUSE;
    }
    return KSWORD_ARK_I8042_DEVICE_UNKNOWN;
}

static BOOLEAN
KswI8042ReadExtensionPointer(
    _In_ PVOID DeviceExtension,
    _In_ ULONG Offset,
    _Out_ PVOID* ValueOut
    )
{
    if (DeviceExtension == NULL || ValueOut == NULL ||
        Offset + sizeof(PVOID) > KSW_I8042_EXPECTED_EXTENSION_SIZE) {
        return FALSE;
    }
    *ValueOut = NULL;
    return KswordARKHookReadMemorySafe(
        (const UCHAR*)DeviceExtension + Offset,
        ValueOut,
        sizeof(*ValueOut));
}

static BOOLEAN
KswI8042ReadEndpoints(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDRIVER_OBJECT ExpectedDriverObject,
    _In_ ULONG DeviceKind,
    _Out_ KSW_I8042_ENDPOINT_VALUES* ValuesOut
    )
{
    DEVICE_OBJECT deviceView;
    BOOLEAN success = TRUE;

    if (DeviceObject == NULL || ExpectedDriverObject == NULL ||
        ValuesOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&deviceView, sizeof(deviceView));
    RtlZeroMemory(ValuesOut, sizeof(*ValuesOut));
    if (!KswordARKHookReadMemorySafe(
            DeviceObject,
            &deviceView,
            sizeof(deviceView)) ||
        deviceView.DriverObject != ExpectedDriverObject ||
        deviceView.DeviceExtension == NULL ||
        deviceView.DeviceType != FILE_DEVICE_8042_PORT) {
        return FALSE;
    }
    success = KswI8042ReadExtensionPointer(
        deviceView.DeviceExtension,
        KSW_I8042_OFFSET_CLASS_DEVICE_OBJECT,
        &ValuesOut->ClassDeviceObject) && success;
    success = KswI8042ReadExtensionPointer(
        deviceView.DeviceExtension,
        KSW_I8042_OFFSET_CLASS_SERVICE,
        &ValuesOut->ClassService) && success;
    if (DeviceKind == KSWORD_ARK_I8042_DEVICE_KEYBOARD) {
        success = KswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_KEYBOARD_INIT,
            &ValuesOut->InitializationRoutine) && success;
        success = KswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_KEYBOARD_ISR,
            &ValuesOut->IsrRoutine) && success;
        success = KswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_KEYBOARD_CONTEXT,
            &ValuesOut->Context) && success;
    }
    else if (DeviceKind == KSWORD_ARK_I8042_DEVICE_MOUSE) {
        success = KswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_MOUSE_ISR,
            &ValuesOut->IsrRoutine) && success;
        success = KswI8042ReadExtensionPointer(
            deviceView.DeviceExtension,
            KSW_I8042_OFFSET_MOUSE_CONTEXT,
            &ValuesOut->Context) && success;
    }
    else {
        success = FALSE;
    }
    return success;
}

static VOID
KswI8042InspectStack(
    _In_ PDEVICE_OBJECT BaseDevice,
    _In_opt_ PVOID ClassDeviceObject,
    _In_ ULONG64 OwnerModuleBase,
    _In_ ULONG OwnerModuleSize,
    _Out_ BOOLEAN* ClassDevicePresentOut,
    _Out_ BOOLEAN* OwnerModulePresentOut
    )
{
    PDEVICE_OBJECT current = NULL;
    ULONG depth = 0UL;

    if (ClassDevicePresentOut == NULL || OwnerModulePresentOut == NULL) {
        return;
    }
    *ClassDevicePresentOut = FALSE;
    *OwnerModulePresentOut = FALSE;
    if (BaseDevice == NULL) {
        return;
    }
    current = IoGetAttachedDeviceReference(BaseDevice);
    while (current != NULL && depth < KSW_I8042_STACK_DEPTH_LIMIT) {
        PDEVICE_OBJECT next = NULL;
        DEVICE_OBJECT deviceView;
        DRIVER_OBJECT driverView;

        RtlZeroMemory(&deviceView, sizeof(deviceView));
        RtlZeroMemory(&driverView, sizeof(driverView));
        if ((PVOID)current == ClassDeviceObject) {
            *ClassDevicePresentOut = TRUE;
        }
        if (KswordARKHookReadMemorySafe(
                current,
                &deviceView,
                sizeof(deviceView)) &&
            deviceView.DriverObject != NULL &&
            KswordARKHookReadMemorySafe(
                deviceView.DriverObject,
                &driverView,
                sizeof(driverView)) &&
            OwnerModuleBase != 0ULL &&
            OwnerModuleSize != 0UL &&
            (ULONG64)(ULONG_PTR)driverView.DriverStart == OwnerModuleBase &&
            driverView.DriverSize == OwnerModuleSize) {
            *OwnerModulePresentOut = TRUE;
        }
        next = IoGetLowerDeviceObject(current);
        ObDereferenceObject(current);
        current = next;
        depth += 1UL;
    }
    if (current != NULL) {
        ObDereferenceObject(current);
    }
}

static VOID
KswI8042FillOwnerModule(
    _Inout_ KSWORD_ARK_I8042_AUDIT_ENTRY* Entry,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module
    )
{
    if (Entry == NULL || Module == NULL) {
        return;
    }
    Entry->moduleBase = (ULONGLONG)(ULONG_PTR)Module->ImageBase;
    Entry->moduleSize = Module->ImageSize;
    Entry->fieldFlags |= KSWORD_ARK_I8042_FIELD_OWNER_MODULE;
    KswordARKHookCopyBoundedAnsiToWide(
        Module->FullPathName,
        RTL_NUMBER_OF(Module->FullPathName),
        Entry->ownerModulePath,
        RTL_NUMBER_OF(Entry->ownerModulePath));
}

static VOID
KswI8042AddEndpoint(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG DeviceKind,
    _In_ ULONG EndpointKind,
    _In_opt_ PVOID CallbackAddress,
    _In_opt_ PVOID ContextAddress,
    _In_opt_ PVOID ClassDeviceObject,
    _In_opt_z_ PCWSTR PnpId
    )
{
    KSWORD_ARK_I8042_AUDIT_ENTRY entry;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
    BOOLEAN executable = FALSE;
    BOOLEAN classDevicePresent = FALSE;
    BOOLEAN ownerModulePresent = FALSE;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.rowKind = KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT;
    entry.deviceKind = DeviceKind;
    entry.endpointKind = EndpointKind;
    entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE;
    entry.verdict = KSWORD_ARK_I8042_VERDICT_UNKNOWN;
    entry.lastStatus = STATUS_SUCCESS;
    entry.deviceObject = (ULONGLONG)(ULONG_PTR)DeviceObject;
    entry.classDeviceObject = (ULONGLONG)(ULONG_PTR)ClassDeviceObject;
    entry.callbackAddress = (ULONGLONG)(ULONG_PTR)CallbackAddress;
    entry.contextAddress = (ULONGLONG)(ULONG_PTR)ContextAddress;
    entry.fieldFlags = KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
        KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
        KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED;
    if (PnpId != NULL && PnpId[0] != L'\0') {
        KswI8042CopyWide(entry.pnpId, RTL_NUMBER_OF(entry.pnpId), PnpId);
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_PNP_ID;
    }
    if (ClassDeviceObject != NULL) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT;
    }
    if (ContextAddress != NULL) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS;
    }
    if (CallbackAddress == NULL) {
        KswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_ENDPOINT_NULL,
            EndpointKind,
            (ULONGLONG)(ULONG_PTR)DeviceObject,
            0ULL,
            0ULL);
        KswI8042Append(Response, Capacity, MaxRows, &entry);
        return;
    }

    entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS;
    owner = KswordARKHookFindModuleForAddress(
        ModuleInfo,
        (ULONG_PTR)CallbackAddress);
    KswI8042FillOwnerModule(&entry, owner);
    executable = owner != NULL &&
        KswI8042AddressExecutable(owner, (ULONG_PTR)CallbackAddress);
    if (executable) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_EXECUTABLE;
    }
    KswI8042InspectStack(
        DeviceObject,
        ClassDeviceObject,
        entry.moduleBase,
        entry.moduleSize,
        &classDevicePresent,
        &ownerModulePresent);
    if (classDevicePresent) {
        entry.fieldFlags |= KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK;
    }

    if (owner == NULL || !ownerModulePresent) {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_SUSPICIOUS;
        entry.lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        KswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_OWNER_MISMATCH,
            entry.callbackAddress,
            entry.moduleBase,
            EndpointKind,
            0ULL);
    }
    else if (!executable) {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_SUSPICIOUS;
        entry.lastStatus = STATUS_INVALID_ADDRESS;
        KswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_NON_EXECUTABLE,
            entry.callbackAddress,
            entry.moduleBase,
            EndpointKind,
            0ULL);
    }
    else if (ClassDeviceObject == NULL || !classDevicePresent) {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_SUSPICIOUS;
        entry.lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        KswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_CLASS_DO_OUTSIDE_STACK,
            entry.classDeviceObject,
            entry.deviceObject,
            EndpointKind,
            0ULL);
    }
    else {
        entry.status = KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
        entry.verdict = KSWORD_ARK_I8042_VERDICT_AVAILABLE;
        KswI8042SetDetail(
            &entry,
            KSWORD_ARK_I8042_DETAIL_ENDPOINT_AVAILABLE,
            entry.callbackAddress,
            entry.moduleBase,
            entry.classDeviceObject,
            entry.contextAddress);
    }
    KswI8042Append(Response, Capacity, MaxRows, &entry);
}

static VOID
KswI8042AuditDevice(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    KSWORD_ARK_I8042_AUDIT_ENTRY deviceEntry;
    DEVICE_OBJECT deviceView;
    KSW_I8042_ENDPOINT_VALUES values;
    WCHAR pnpId[KSWORD_ARK_I8042_PNP_ID_CHARS];
    ULONG deviceKind = KSWORD_ARK_I8042_DEVICE_UNKNOWN;

    RtlZeroMemory(&deviceEntry, sizeof(deviceEntry));
    RtlZeroMemory(&deviceView, sizeof(deviceView));
    RtlZeroMemory(&values, sizeof(values));
    RtlZeroMemory(pnpId, sizeof(pnpId));
    deviceEntry.size = sizeof(deviceEntry);
    deviceEntry.rowKind = KSWORD_ARK_I8042_AUDIT_ROW_DEVICE;
    deviceEntry.status = KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED;
    deviceEntry.verdict = KSWORD_ARK_I8042_VERDICT_UNSUPPORTED;
    deviceEntry.deviceObject = (ULONGLONG)(ULONG_PTR)DeviceObject;
    deviceEntry.fieldFlags = KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
        KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
        KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED;

    if (!KswordARKHookReadMemorySafe(
            DeviceObject,
            &deviceView,
            sizeof(deviceView)) ||
        deviceView.DriverObject != DriverObject ||
        deviceView.DeviceType != FILE_DEVICE_8042_PORT) {
        deviceEntry.lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        KswI8042SetDetail(
            &deviceEntry,
            KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH,
            deviceEntry.deviceObject,
            deviceView.DeviceType,
            FILE_DEVICE_8042_PORT,
            0ULL);
        KswI8042Append(Response, Capacity, MaxRows, &deviceEntry);
        return;
    }

    deviceKind = KswI8042ClassifyDevice(
        DeviceObject,
        pnpId,
        RTL_NUMBER_OF(pnpId));
    deviceEntry.deviceKind = deviceKind;
    if (pnpId[0] != L'\0') {
        KswI8042CopyWide(
            deviceEntry.pnpId,
            RTL_NUMBER_OF(deviceEntry.pnpId),
            pnpId);
        deviceEntry.fieldFlags |= KSWORD_ARK_I8042_FIELD_PNP_ID;
    }
    if (deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN) {
        deviceEntry.lastStatus = STATUS_NOT_SUPPORTED;
        KswI8042SetDetail(
            &deviceEntry,
            KSWORD_ARK_I8042_DETAIL_PNP_CLASS_UNKNOWN,
            deviceEntry.deviceObject,
            0ULL,
            0ULL,
            0ULL);
        KswI8042Append(Response, Capacity, MaxRows, &deviceEntry);
        return;
    }

    deviceEntry.status = KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
    deviceEntry.verdict = KSWORD_ARK_I8042_VERDICT_AVAILABLE;
    deviceEntry.lastStatus = STATUS_SUCCESS;
    KswI8042SetDetail(
        &deviceEntry,
        KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED,
        KSW_I8042_EXPECTED_EXTENSION_SIZE,
        deviceKind,
        deviceEntry.deviceObject,
        0ULL);
    KswI8042Append(Response, Capacity, MaxRows, &deviceEntry);

    if (!KswI8042ReadEndpoints(
            DeviceObject,
            DriverObject,
            deviceKind,
            &values)) {
        KswI8042AddDiagnostic(
            Response,
            Capacity,
            MaxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            KSWORD_ARK_I8042_DETAIL_EXTENSION_READ_FAILED,
            deviceEntry.deviceObject,
            deviceKind,
            FALSE);
        return;
    }

    if (deviceKind == KSWORD_ARK_I8042_DEVICE_KEYBOARD) {
        KswI8042AddEndpoint(
            Response, Capacity, MaxRows, ModuleInfo, DeviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE,
            values.ClassService, NULL, values.ClassDeviceObject, pnpId);
        KswI8042AddEndpoint(
            Response, Capacity, MaxRows, ModuleInfo, DeviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_INITIALIZATION,
            values.InitializationRoutine, values.Context,
            values.ClassDeviceObject, pnpId);
        KswI8042AddEndpoint(
            Response, Capacity, MaxRows, ModuleInfo, DeviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_ISR,
            values.IsrRoutine, values.Context,
            values.ClassDeviceObject, pnpId);
    }
    else {
        KswI8042AddEndpoint(
            Response, Capacity, MaxRows, ModuleInfo, DeviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_MOUSE_CLASS_SERVICE,
            values.ClassService, NULL, values.ClassDeviceObject, pnpId);
        KswI8042AddEndpoint(
            Response, Capacity, MaxRows, ModuleInfo, DeviceObject, deviceKind,
            KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR,
            values.IsrRoutine, values.Context,
            values.ClassDeviceObject, pnpId);
    }
}

static VOID
KswI8042ReleaseDeviceList(
    _Inout_updates_(Count) PDEVICE_OBJECT* DeviceObjects,
    _In_ ULONG Count
    )
{
    ULONG index = 0UL;

    if (DeviceObjects == NULL) {
        return;
    }
    for (index = 0UL; index < Count; ++index) {
        if (DeviceObjects[index] != NULL) {
            ObDereferenceObject(DeviceObjects[index]);
            DeviceObjects[index] = NULL;
        }
    }
}

static NTSTATUS
KswI8042EnumerateDevices(
    _Inout_ KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT* deviceObjects = NULL;
    ULONG requestedCount = 0UL;
    ULONG actualCount = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    status = IoEnumerateDeviceObjectList(
        DriverObject,
        NULL,
        0UL,
        &requestedCount);
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        return status;
    }
    if (requestedCount == 0UL) {
        KswI8042AddDiagnostic(
            Response,
            Capacity,
            MaxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE,
            STATUS_NOT_FOUND,
            KSWORD_ARK_I8042_DETAIL_NO_DEVICES,
            0ULL,
            0ULL,
            FALSE);
        return STATUS_SUCCESS;
    }

    for (attempt = 0UL; attempt < KSW_I8042_DEVICE_ENUM_RETRIES; ++attempt) {
        ULONG index = 0UL;
        if (requestedCount > KSW_I8042_DEVICE_LIMIT) {
            return STATUS_NOT_SUPPORTED;
        }
        deviceObjects = (PDEVICE_OBJECT*)KswordARKAllocateNonPagedPool(
            (SIZE_T)requestedCount * sizeof(*deviceObjects),
            KSW_I8042_POOL_TAG);
        if (deviceObjects == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(
            deviceObjects,
            (SIZE_T)requestedCount * sizeof(*deviceObjects));
        actualCount = 0UL;
        status = IoEnumerateDeviceObjectList(
            DriverObject,
            deviceObjects,
            requestedCount * (ULONG)sizeof(*deviceObjects),
            &actualCount);
        if (status == STATUS_BUFFER_TOO_SMALL) {
            KswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            deviceObjects = NULL;
            if (actualCount <= requestedCount) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            requestedCount = actualCount;
            continue;
        }
        if (!NT_SUCCESS(status)) {
            KswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            return status;
        }
        if (actualCount > requestedCount) {
            KswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            return STATUS_INVALID_BUFFER_SIZE;
        }
        if (actualCount == 0UL) {
            KswI8042ReleaseDeviceList(deviceObjects, requestedCount);
            ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
            KswI8042AddDiagnostic(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE,
                STATUS_NOT_FOUND,
                KSWORD_ARK_I8042_DETAIL_NO_DEVICES,
                0ULL,
                0ULL,
                FALSE);
            return STATUS_SUCCESS;
        }
        for (index = 0UL; index < actualCount; ++index) {
            if (deviceObjects[index] != NULL) {
                KswI8042AuditDevice(
                    Response,
                    Capacity,
                    MaxRows,
                    ModuleInfo,
                    DriverObject,
                    deviceObjects[index]);
            }
        }
        KswI8042ReleaseDeviceList(deviceObjects, requestedCount);
        ExFreePoolWithTag(deviceObjects, KSW_I8042_POOL_TAG);
        return STATUS_SUCCESS;
    }
    return STATUS_RETRY;
}

NTSTATUS
KswordARKI8042AuditIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST defaultRequest;
    const KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST* requestPacket = NULL;
    KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE* response = NULL;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* i8042Module = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputBytes = 0U;
    size_t actualOutputBytes = 0U;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS;
    ULONG failedOpcodeRva = 0UL;
    ULONG pdbAge = 0UL;
    GUID pdbGuid;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG64 observedDispatch = 0ULL;
    ULONG64 observedAddDevice = 0ULL;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION;
    defaultRequest.maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputBytes,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputBytes);
    requestPacket = hasInput ?
        (const KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST*)inputBuffer :
        &defaultRequest;
    if (requestPacket->size != sizeof(*requestPacket) ||
        requestPacket->version != KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION ||
        requestPacket->flags != 0UL ||
        requestPacket->reserved0 != 0UL ||
        requestPacket->reserved1 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    maxRows = requestPacket->maxRows == 0UL ?
        KSWORD_ARK_I8042_DEFAULT_MAX_ROWS :
        requestPacket->maxRows;
    if (maxRows > KSWORD_ARK_I8042_HARD_MAX_ROWS) {
        maxRows = KSWORD_ARK_I8042_HARD_MAX_ROWS;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_I8042_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, actualOutputBytes);
    response = (KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE*)outputBuffer;
    response->size = KSW_I8042_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
    response->entrySize = sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY);
    response->descriptorId = KSWORD_ARK_I8042_DESCRIPTOR_WIN11_26100_7934;
    response->lastStatus = STATUS_SUCCESS;
    capacity = KswI8042OutputCapacity(actualOutputBytes);

    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        if (NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }
        KswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND,
            moduleInfoBytes,
            0ULL,
            TRUE);
        goto Exit;
    }
    i8042Module = KswI8042FindUniqueModule(moduleInfo, "i8042prt.sys");
    if (i8042Module == NULL) {
        KswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND,
            0ULL,
            0ULL,
            TRUE);
        goto Exit;
    }

    status = KswI8042ValidateImage(
        i8042Module,
        &ntHeaders,
        &pdbGuid,
        &pdbAge,
        &failedOpcodeRva);
    response->imageBase = (ULONGLONG)(ULONG_PTR)i8042Module->ImageBase;
    response->imageTimeDateStamp = ntHeaders.FileHeader.TimeDateStamp;
    response->imageSize = ntHeaders.OptionalHeader.SizeOfImage;
    response->imageChecksum = ntHeaders.OptionalHeader.CheckSum;
    response->pdbAge = pdbAge;
    RtlCopyMemory(response->pdbGuid, &pdbGuid, sizeof(pdbGuid));
    if (!NT_SUCCESS(status)) {
        ULONG detailCode = KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH;
        if (status == STATUS_REVISION_MISMATCH) {
            detailCode = KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH;
        }
        else if (status == STATUS_DATA_ERROR) {
            detailCode = KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH;
        }
        KswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED,
            status,
            detailCode,
            failedOpcodeRva,
            response->imageBase,
            TRUE);
        goto Exit;
    }
    response->responseFlags |= KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED;

    status = KswI8042ReferenceDriver(&driverObject);
    if (!NT_SUCCESS(status) || driverObject == NULL) {
        if (NT_SUCCESS(status)) {
            status = STATUS_NOT_FOUND;
        }
        KswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED,
            status,
            KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND,
            0ULL,
            0ULL,
            TRUE);
        goto Exit;
    }
    status = KswI8042ValidateDriverLayout(
        driverObject,
        i8042Module,
        &observedDispatch,
        &observedAddDevice);
    if (!NT_SUCCESS(status)) {
        KswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED,
            status,
            KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH,
            observedDispatch,
            observedAddDevice,
            TRUE);
        goto Exit;
    }
    response->responseFlags |=
        KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED;

    status = KswI8042EnumerateDevices(
        response,
        capacity,
        maxRows,
        moduleInfo,
        driverObject);
    if (!NT_SUCCESS(status)) {
        KswI8042AddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_I8042_DETAIL_DEVICE_ENUM_FAILED,
            0ULL,
            0ULL,
            FALSE);
    }

Exit:
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    *BytesReturned = KSW_I8042_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
         sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}
