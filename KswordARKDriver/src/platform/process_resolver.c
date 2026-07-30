/*++

Module Name:

    process_resolver.c

Abstract:

    This file resolves optional kernel process routines dynamically.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_resolver.h"

typedef ULONG_PTR(NTAPI* KSWORD_OBJECT_ACCESSOR_FN)(
    _In_ PVOID Object
    );

typedef enum _KSWORD_ACCESSOR_LOAD_KIND
{
    KswordAccessorLoadPointer,
    KswordAccessorLoadUlong,
    KswordAccessorLoadUshort,
    KswordAccessorLoadUchar,
    KswordAccessorAddress
} KSWORD_ACCESSOR_LOAD_KIND;

typedef struct _KSWORD_ACCESSOR_DISPLACEMENT
{
    LONG Offset;
    KSWORD_ACCESSOR_LOAD_KIND LoadKind;
} KSWORD_ACCESSOR_DISPLACEMENT;

static VOID
KswordARKDriverInitializeRuntimeDynDataOffsets(
    _Out_ PKSWORD_RUNTIME_DYNDATA_OFFSETS Offsets
    )
{
    LONG* field = NULL;
    SIZE_T index = 0U;

    if (Offsets == NULL) {
        return;
    }
    field = (LONG*)Offsets;
    for (index = 0U; index < sizeof(*Offsets) / sizeof(*field); ++index) {
        field[index] = -1;
    }
}

static BOOLEAN
KswordARKDriverDecodeAccessorDisplacement(
    _In_reads_bytes_(ByteCount) const UCHAR* Bytes,
    _In_ SIZE_T ByteCount,
    _Out_ KSWORD_ACCESSOR_DISPLACEMENT* DisplacementOut
    )
{
    SIZE_T index = 0U;

    if (Bytes == NULL || DisplacementOut == NULL) {
        return FALSE;
    }
    DisplacementOut->Offset = -1;
    DisplacementOut->LoadKind = KswordAccessorLoadPointer;

    for (index = 0U; index + 7U <= ByteCount && index < 24U; ++index) {
        LONG displacement = -1;
        KSWORD_ACCESSOR_LOAD_KIND kind = KswordAccessorLoadPointer;
        SIZE_T displacementIndex = 0U;

        if (Bytes[index] == 0x48U &&
            (Bytes[index + 1U] == 0x8BU || Bytes[index + 1U] == 0x8DU) &&
            Bytes[index + 2U] == 0x81U) {
            kind = (Bytes[index + 1U] == 0x8DU)
                ? KswordAccessorAddress
                : KswordAccessorLoadPointer;
            displacementIndex = index + 3U;
        }
        else if (Bytes[index] == 0x8BU && Bytes[index + 1U] == 0x81U) {
            kind = KswordAccessorLoadUlong;
            displacementIndex = index + 2U;
        }
        else if (Bytes[index] == 0x0FU &&
                 Bytes[index + 1U] == 0xB6U &&
                 Bytes[index + 2U] == 0x81U) {
            kind = KswordAccessorLoadUchar;
            displacementIndex = index + 3U;
        }
        else if (Bytes[index] == 0x0FU &&
                 Bytes[index + 1U] == 0xB7U &&
                 Bytes[index + 2U] == 0x81U) {
            kind = KswordAccessorLoadUshort;
            displacementIndex = index + 3U;
        }
        else {
            continue;
        }

        RtlCopyMemory(
            &displacement,
            Bytes + displacementIndex,
            sizeof(displacement));
        if (displacement <= 0 || displacement > 0x00003FFF) {
            continue;
        }
        DisplacementOut->Offset = displacement;
        DisplacementOut->LoadKind = kind;
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
KswordARKDriverReadAccessorValue(
    _In_ PVOID Object,
    _In_ const KSWORD_ACCESSOR_DISPLACEMENT* Displacement,
    _Out_ ULONG_PTR* ValueOut
    )
{
    if (Object == NULL || Displacement == NULL || ValueOut == NULL ||
        Displacement->Offset <= 0) {
        return FALSE;
    }
    *ValueOut = 0U;

    __try {
        const UCHAR* address = (const UCHAR*)Object + Displacement->Offset;
        switch (Displacement->LoadKind) {
        case KswordAccessorAddress:
            *ValueOut = (ULONG_PTR)address;
            break;
        case KswordAccessorLoadPointer:
            *ValueOut = *(const ULONG_PTR*)address;
            break;
        case KswordAccessorLoadUlong:
            *ValueOut = *(const ULONG*)address;
            break;
        case KswordAccessorLoadUshort:
            *ValueOut = *(const USHORT*)address;
            break;
        case KswordAccessorLoadUchar:
            *ValueOut = *(const UCHAR*)address;
            break;
        default:
            return FALSE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static LONG
KswordARKDriverResolveValidatedAccessorOffset(
    _In_ PCWSTR RoutineName,
    _In_ PVOID ValidationObject
    )
{
    UNICODE_STRING routineName;
    KSWORD_OBJECT_ACCESSOR_FN accessor = NULL;
    UCHAR code[32] = { 0 };
    KSWORD_ACCESSOR_DISPLACEMENT displacement;
    ULONG_PTR accessorValue = 0U;
    ULONG_PTR fieldValue = 0U;

    if (RoutineName == NULL || ValidationObject == NULL) {
        return -1;
    }
    RtlInitUnicodeString(&routineName, RoutineName);
    accessor = (KSWORD_OBJECT_ACCESSOR_FN)MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }

    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor(ValidationObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    if (!KswordARKDriverDecodeAccessorDisplacement(
            code,
            sizeof(code),
            &displacement) ||
        !KswordARKDriverReadAccessorValue(
            ValidationObject,
            &displacement,
            &fieldValue) ||
        fieldValue != accessorValue) {
        return -1;
    }
    return displacement.Offset;
}

static LONG
KswordARKDriverResolveActiveProcessLinksOffset(
    _In_ PEPROCESS Process,
    _In_ LONG UniqueProcessIdOffset
    )
{
    LONG activeProcessLinksOffset = -1;
    PLIST_ENTRY link = NULL;

    if (Process == NULL || UniqueProcessIdOffset <= 0 ||
        UniqueProcessIdOffset > (LONG)(0x00003FFFU - sizeof(HANDLE))) {
        return -1;
    }
    activeProcessLinksOffset =
        UniqueProcessIdOffset + (LONG)sizeof(HANDLE);
    link = (PLIST_ENTRY)((PUCHAR)Process + activeProcessLinksOffset);

    __try {
        if (link->Flink == NULL || link->Blink == NULL ||
            link->Flink->Blink != link ||
            link->Blink->Flink != link) {
            return -1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    return activeProcessLinksOffset;
}

VOID
KswordARKDriverResolveReadOnlyDynDataOffsets(
    _Out_ PKSWORD_RUNTIME_DYNDATA_OFFSETS Offsets
    )
{
    PEPROCESS process = PsGetCurrentProcess();
    PETHREAD thread = PsGetCurrentThread();
    LONG threadProcessIdOffset = -1;
    LONG threadIdOffset = -1;

    if (Offsets == NULL) {
        return;
    }
    KswordARKDriverInitializeRuntimeDynDataOffsets(Offsets);
    if (process != NULL) {
        Offsets->EpUniqueProcessId =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessId",
                process);
        Offsets->EpActiveProcessLinks =
            KswordARKDriverResolveActiveProcessLinksOffset(
                process,
                Offsets->EpUniqueProcessId);
        Offsets->EpImageFileName =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessImageFileName",
                process);
        Offsets->EpCreateTime =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessCreateTimeQuadPart",
                process);
        Offsets->EpExitStatus =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessExitStatus",
                process);
        Offsets->EpPeb =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessPeb",
                process);
        Offsets->EpWin32Process =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessWin32Process",
                process);
        Offsets->EpWow64Process =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessWow64Process",
                process);
        Offsets->EpInheritedFromUniqueProcessId =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessInheritedFromUniqueProcessId",
                process);
        Offsets->EpSectionBaseAddress =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessSectionBaseAddress",
                process);
    }
    if (thread != NULL) {
        threadProcessIdOffset =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetThreadProcessId",
                thread);
        threadIdOffset =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetThreadId",
                thread);
        if (threadProcessIdOffset > 0 &&
            threadIdOffset ==
                threadProcessIdOffset + (LONG)sizeof(HANDLE)) {
            Offsets->EtCid = threadProcessIdOffset;
        }
        Offsets->KtProcess =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetThreadProcess",
                thread);
    }
}

// Resolve PsSuspendProcess first; this export is available on more systems.
KSWORD_PS_SUSPEND_PROCESS_FN
KswordARKDriverResolvePsSuspendProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsSuspendProcess");
    return (KSWORD_PS_SUSPEND_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

// Fallback resolver for Zw/Nt suspend APIs that use process handle input.
KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN
KswordARKDriverResolveZwOrNtSuspendProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwSuspendProcess");
    {
        KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN routineAddress =
            (KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
        if (routineAddress != NULL) {
            return routineAddress;
        }
    }

    RtlInitUnicodeString(&routineName, L"NtSuspendProcess");
    return (KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

KSWORD_PS_IS_PROTECTED_PROCESS_FN
KswordARKDriverResolvePsIsProtectedProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
    return (KSWORD_PS_IS_PROTECTED_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

KSWORD_PS_IS_PROTECTED_PROCESS_LIGHT_FN
KswordARKDriverResolvePsIsProtectedProcessLight(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcessLight");
    return (KSWORD_PS_IS_PROTECTED_PROCESS_LIGHT_FN)MmGetSystemRoutineAddress(&routineName);
}

// PPLcontrol-style parser: read the immediate displacement at +2 from PsIsProtected*.
static LONG
KswordARKDriverReadProtectedRoutineOffset(
    _In_ PVOID routineAddress
    )
{
    USHORT offsetValue = 0U;

    if (routineAddress == NULL) {
        return -1;
    }

    __try {
        RtlCopyMemory(
            &offsetValue,
            ((const UCHAR*)routineAddress) + 2U,
            sizeof(offsetValue));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    if (offsetValue == 0U || offsetValue > 0x0FFFU) {
        return -1;
    }

    return (LONG)offsetValue;
}

LONG
KswordARKDriverResolveProcessProtectionOffset(
    VOID
    )
{
    KSWORD_PS_IS_PROTECTED_PROCESS_FN psIsProtectedProcess = NULL;
    KSWORD_PS_IS_PROTECTED_PROCESS_LIGHT_FN psIsProtectedProcessLight = NULL;
    LONG protectionOffsetA = -1;
    LONG protectionOffsetB = -1;

    psIsProtectedProcess = KswordARKDriverResolvePsIsProtectedProcess();
    psIsProtectedProcessLight = KswordARKDriverResolvePsIsProtectedProcessLight();
    if (psIsProtectedProcess == NULL || psIsProtectedProcessLight == NULL) {
        return -1;
    }

    protectionOffsetA = KswordARKDriverReadProtectedRoutineOffset((PVOID)psIsProtectedProcess);
    protectionOffsetB = KswordARKDriverReadProtectedRoutineOffset((PVOID)psIsProtectedProcessLight);
    if (protectionOffsetA <= 0 ||
        protectionOffsetB <= 0 ||
        protectionOffsetA != protectionOffsetB) {
        return -1;
    }

    return protectionOffsetA;
}

LONG
KswordARKDriverResolveProcessSignatureLevelOffset(
    VOID
    )
{
    LONG protectionOffset = KswordARKDriverResolveProcessProtectionOffset();
    if (protectionOffset <= (LONG)(2U * sizeof(UCHAR))) {
        return -1;
    }

    return protectionOffset - (LONG)(2U * sizeof(UCHAR));
}

LONG
KswordARKDriverResolveProcessSectionSignatureLevelOffset(
    VOID
    )
{
    LONG protectionOffset = KswordARKDriverResolveProcessProtectionOffset();
    if (protectionOffset <= (LONG)sizeof(UCHAR)) {
        return -1;
    }

    return protectionOffset - (LONG)sizeof(UCHAR);
}

// Resolve ZwSetInformationProcess dynamically for broad WDK compatibility.
KSWORD_ZW_SET_INFORMATION_PROCESS_FN
KswordARKDriverResolveZwSetInformationProcess(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"ZwSetInformationProcess");
    return (KSWORD_ZW_SET_INFORMATION_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}
