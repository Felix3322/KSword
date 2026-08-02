/*++

Module Name:

    process_resolver.c

Abstract:

    This file resolves optional kernel process routines dynamically.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "process_resolver.h"
#include "token_layout_resolver.h"

#define KSW_RUNTIME_PROCESS_SCAN_BYTES 0x1000U
#define KSW_RUNTIME_THREAD_SCAN_BYTES 0x1000U
#define KSW_RUNTIME_THREAD_LIST_BUDGET 0x1000U

typedef ULONG_PTR(NTAPI* KSWORD_OBJECT_ACCESSOR_FN)(
    _In_ PVOID Object
    );

typedef BOOLEAN(NTAPI* KSWORD_PROCESS_BOOLEAN_ACCESSOR_FN)(
    _In_ PEPROCESS Process
    );

typedef ULONG_PTR(NTAPI* KSWORD_CURRENT_THREAD_ACCESSOR_FN)(
    VOID
    );

typedef UCHAR(NTAPI* KSWORD_PROCESS_PROTECTION_ACCESSOR_FN)(
    _In_ PEPROCESS Process
    );

typedef UCHAR(NTAPI* KSWORD_PROCESS_SIGNATURE_ACCESSOR_FN)(
    _In_ PEPROCESS Process,
    _Out_opt_ PUCHAR SectionSignatureLevel
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

static BOOLEAN
KswordARKDriverReadPointerGuarded(
    _In_ const VOID* Address,
    _Out_ ULONG_PTR* ValueOut
    );

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
KswordARKDriverResolveCurrentThreadStackOffset(
    _In_z_ PCWSTR RoutineName,
    _In_ PETHREAD CurrentThread
    )
/*++

Routine Description:

    Decode a no-argument current-thread stack accessor.  Accepted x64 code is
    deliberately narrow: load KTHREAD from gs:[188h], load one pointer field
    using disp8/disp32, then return.  The candidate must equal the live export
    result for the same current thread before it is published.

Return Value:

    Validated KTHREAD field offset, or -1 for any missing/ambiguous shape.

--*/
{
    static const UCHAR currentThreadLoad[] = {
        0x65U, 0x48U, 0x8BU, 0x04U, 0x25U,
        0x88U, 0x01U, 0x00U, 0x00U
    };
    UNICODE_STRING routineName;
    KSWORD_CURRENT_THREAD_ACCESSOR_FN accessor = NULL;
    UCHAR code[32];
    LONG offset = -1;
    SIZE_T instructionEnd = 0U;
    ULONG_PTR accessorValue = 0U;
    ULONG_PTR fieldValue = 0U;

    if (RoutineName == NULL || CurrentThread == NULL) {
        return -1;
    }
    RtlInitUnicodeString(&routineName, RoutineName);
    accessor = (KSWORD_CURRENT_THREAD_ACCESSOR_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }
    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    if (RtlCompareMemory(
            code,
            currentThreadLoad,
            sizeof(currentThreadLoad)) != sizeof(currentThreadLoad)) {
        return -1;
    }

    if (code[9] == 0x48U && code[10] == 0x8BU && code[11] == 0x40U) {
        offset = (LONG)code[12];
        instructionEnd = 13U;
    }
    else if (code[9] == 0x48U && code[10] == 0x8BU &&
        code[11] == 0x80U) {
        RtlCopyMemory(&offset, &code[12], sizeof(offset));
        instructionEnd = 16U;
    }
    if (offset <= 0 || offset > (LONG)KSW_RUNTIME_THREAD_SCAN_BYTES ||
        code[instructionEnd] != 0xC3U ||
        accessorValue < (ULONG_PTR)MmSystemRangeStart) {
        return -1;
    }
    if (!KswordARKDriverReadPointerGuarded(
            (const UCHAR*)CurrentThread + offset,
            &fieldValue) ||
        fieldValue != accessorValue) {
        return -1;
    }
    return offset;
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

LONG
KswordARKDriverResolveProcessFlagsOffset(
    _In_ PEPROCESS Process
    )
/*++

Routine Description:

    Recover EPROCESS.Flags from the exported PsGetProcessExitProcessCalled
    bit accessor.  The resolver accepts only the compact x64 sequence that
    loads one ULONG from RCX, shifts the result, and masks it to one bit.  The
    decoded bit is then compared with the live accessor result before the
    offset is published.

Arguments:

    Process - Live process object used for semantic validation.

Return Value:

    A validated EPROCESS.Flags offset, or -1 when the accessor shape or live
    value is ambiguous.

--*/
{
    UNICODE_STRING routineName;
    KSWORD_PROCESS_BOOLEAN_ACCESSOR_FN accessor = NULL;
    UCHAR code[32] = { 0 };
    ULONG index = 0UL;
    LONG resolvedOffset = -1;
    ULONG resolvedBit = MAXULONG;
    ULONG matchCount = 0UL;
    BOOLEAN accessorValue = FALSE;

    if (Process == NULL) {
        return -1;
    }

    RtlInitUnicodeString(&routineName, L"PsGetProcessExitProcessCalled");
    accessor = (KSWORD_PROCESS_BOOLEAN_ACCESSOR_FN)MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }

    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor(Process) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    for (index = 0UL; index + 11UL <= RTL_NUMBER_OF(code); ++index) {
        LONG candidateOffset = -1;
        ULONG shift = MAXULONG;
        ULONG suffix = index + 6UL;

        /* mov r32, dword ptr [rcx+disp32] */
        if (code[index] != 0x8BU || (code[index + 1UL] & 0xC7U) != 0x81U) {
            continue;
        }
        RtlCopyMemory(&candidateOffset, code + index + 2UL, sizeof(candidateOffset));
        if (candidateOffset <= 0 || candidateOffset > 0x00003FFF) {
            continue;
        }

        /* shr eax, imm8; and al/eax, 1 */
        if (code[suffix] == 0xC1U && code[suffix + 1UL] == 0xE8U) {
            shift = code[suffix + 2UL];
            suffix += 3UL;
        }
        if (shift >= 32UL) {
            continue;
        }
        if (!((code[suffix] == 0x24U && code[suffix + 1UL] == 0x01U) ||
              (code[suffix] == 0x83U && code[suffix + 1UL] == 0xE0U &&
               code[suffix + 2UL] == 0x01U))) {
            continue;
        }

        resolvedOffset = candidateOffset;
        resolvedBit = shift;
        matchCount += 1UL;
    }

    if (matchCount != 1UL || resolvedOffset <= 0 || resolvedBit >= 32UL) {
        return -1;
    }

    __try {
        const ULONG flags = *(volatile const ULONG*)((const UCHAR*)Process + resolvedOffset);
        if ((((flags >> resolvedBit) & 1UL) != 0UL) != accessorValue) {
            return -1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    return resolvedOffset;
}

static BOOLEAN
KswordARKDriverReadPointerGuarded(
    _In_ const VOID* Address,
    _Out_ ULONG_PTR* ValueOut
    )
/*++

Routine Description:

    Read one kernel pointer-sized value through an exception boundary.

Arguments:

    Address - Candidate readable kernel address.
    ValueOut - Receives the copied scalar value.

Return Value:

    TRUE when the read completed; otherwise FALSE.

--*/
{
    if (Address == NULL || ValueOut == NULL) {
        return FALSE;
    }
    *ValueOut = 0U;

    __try {
        *ValueOut = *(volatile const ULONG_PTR*)Address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKDriverReadListEntryGuarded(
    _In_ const LIST_ENTRY* Address,
    _Out_ LIST_ENTRY* EntryOut
    )
/*++

Routine Description:

    Copy one candidate LIST_ENTRY without trusting the candidate mapping.

Arguments:

    Address - Candidate list-entry address.
    EntryOut - Receives a stable scalar snapshot of both links.

Return Value:

    TRUE when both links were copied; otherwise FALSE.

--*/
{
    if (Address == NULL || EntryOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(EntryOut, sizeof(*EntryOut));

    __try {
        EntryOut->Flink = Address->Flink;
        EntryOut->Blink = Address->Blink;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKDriverAddressInsideObjectWindow(
    _In_ ULONG_PTR Address,
    _In_ ULONG_PTR ObjectBase,
    _In_ SIZE_T ObjectWindow
    )
/*++

Routine Description:

    Test whether an address lies inside one bounded live-object inspection window.

Arguments:

    Address - Address being classified.
    ObjectBase - Start of the live kernel object.
    ObjectWindow - Maximum number of bytes inspected from the object.

Return Value:

    TRUE when Address is within the non-wrapping half-open window.

--*/
{
    if (ObjectBase == 0U || ObjectWindow == 0U ||
        ObjectBase > MAXULONG_PTR - ObjectWindow) {
        return FALSE;
    }
    return (Address >= ObjectBase && Address < ObjectBase + ObjectWindow) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKDriverValidateThreadListCandidate(
    _In_ PEPROCESS Process,
    _In_ PETHREAD CurrentThread,
    _In_ LONG KthreadProcessOffset,
    _In_ ULONG ThreadListEntryOffset,
    _Out_ ULONG* ProcessThreadListHeadOffsetOut
    )
/*++

Routine Description:

    Validate one ETHREAD list-entry candidate by walking only reciprocal links
    until the list reaches a head embedded in the owning EPROCESS. Every thread
    node must expose the already validated KTHREAD.Process pointer at the same
    offset. This turns the offset search into a structural identity check rather
    than a naked pointer-pattern match.

Arguments:

    Process - Owning live process object.
    CurrentThread - Referenced live thread known to belong to Process.
    KthreadProcessOffset - Accessor-derived KTHREAD.Process offset.
    ThreadListEntryOffset - Candidate ETHREAD.ThreadListEntry offset.
    ProcessThreadListHeadOffsetOut - Receives the matching EPROCESS head offset.

Return Value:

    TRUE when a complete bounded path reaches a reciprocal EPROCESS list head.

--*/
{
    ULONG_PTR processBase = (ULONG_PTR)Process;
    ULONG_PTR currentLinkAddress = (ULONG_PTR)CurrentThread + ThreadListEntryOffset;
    LIST_ENTRY currentEntry;
    ULONG step = 0UL;

    if (Process == NULL || CurrentThread == NULL ||
        KthreadProcessOffset < 0 || ProcessThreadListHeadOffsetOut == NULL) {
        return FALSE;
    }
    *ProcessThreadListHeadOffsetOut = 0UL;
    if (!KswordARKDriverReadListEntryGuarded((const LIST_ENTRY*)currentLinkAddress, &currentEntry) ||
        currentEntry.Flink == NULL || currentEntry.Blink == NULL) {
        return FALSE;
    }

    for (step = 0UL; step < KSW_RUNTIME_THREAD_LIST_BUDGET; ++step) {
        ULONG_PTR nextAddress = (ULONG_PTR)currentEntry.Flink;
        LIST_ENTRY nextEntry;

        if (!KswordARKDriverReadListEntryGuarded((const LIST_ENTRY*)nextAddress, &nextEntry) ||
            (ULONG_PTR)nextEntry.Blink != currentLinkAddress) {
            return FALSE;
        }

        if (KswordARKDriverAddressInsideObjectWindow(
                nextAddress,
                processBase,
                KSW_RUNTIME_PROCESS_SCAN_BYTES)) {
            ULONG_PTR firstThreadLinkAddress = (ULONG_PTR)nextEntry.Flink;
            LIST_ENTRY firstThreadEntry;
            ULONG_PTR firstThreadProcess = 0U;

            if (nextAddress < processBase ||
                nextAddress - processBase > MAXULONG ||
                firstThreadLinkAddress <= ThreadListEntryOffset ||
                !KswordARKDriverReadListEntryGuarded(
                    (const LIST_ENTRY*)firstThreadLinkAddress,
                    &firstThreadEntry) ||
                (ULONG_PTR)firstThreadEntry.Blink != nextAddress ||
                !KswordARKDriverReadPointerGuarded(
                    (const UCHAR*)(firstThreadLinkAddress - ThreadListEntryOffset) + KthreadProcessOffset,
                    &firstThreadProcess) ||
                firstThreadProcess != processBase) {
                return FALSE;
            }

            *ProcessThreadListHeadOffsetOut = (ULONG)(nextAddress - processBase);
            return TRUE;
        }

        if (nextAddress <= ThreadListEntryOffset) {
            return FALSE;
        }
        {
            ULONG_PTR nextThreadAddress = nextAddress - ThreadListEntryOffset;
            ULONG_PTR nextThreadProcess = 0U;

            if (!KswordARKDriverReadPointerGuarded(
                    (const UCHAR*)nextThreadAddress + KthreadProcessOffset,
                    &nextThreadProcess) ||
                nextThreadProcess != processBase) {
                return FALSE;
            }
        }

        currentLinkAddress = nextAddress;
        currentEntry = nextEntry;
    }
    return FALSE;
}

static VOID
KswordARKDriverResolveThreadListOffsets(
    _In_opt_ PEPROCESS Process,
    _In_ PETHREAD CurrentThread,
    _In_ LONG KthreadProcessOffset,
    _Out_ LONG* ProcessThreadListHeadOffsetOut,
    _Out_ LONG* ThreadListEntryOffsetOut
    )
/*++

Routine Description:

    Find a unique reciprocal process/thread list pair in two live objects.

Arguments:

    Process - Current process object.
    CurrentThread - Current thread object.
    KthreadProcessOffset - Previously validated KTHREAD.Process offset.
    ProcessThreadListHeadOffsetOut - Receives EPROCESS.ThreadListHead.
    ThreadListEntryOffsetOut - Receives ETHREAD.ThreadListEntry.

Return Value:

    None. Both outputs remain unavailable unless exactly one pair validates.

--*/
{
    ULONG candidateOffset = 0UL;
    LONG foundProcessOffset = -1;
    LONG foundThreadOffset = -1;

    if (ProcessThreadListHeadOffsetOut == NULL || ThreadListEntryOffsetOut == NULL) {
        return;
    }
    *ProcessThreadListHeadOffsetOut = -1;
    *ThreadListEntryOffsetOut = -1;
    if (Process == NULL || CurrentThread == NULL || KthreadProcessOffset < 0) {
        return;
    }

    for (candidateOffset = 0UL;
         candidateOffset + sizeof(LIST_ENTRY) <= KSW_RUNTIME_THREAD_SCAN_BYTES;
         candidateOffset += (ULONG)sizeof(PVOID)) {
        ULONG processHeadOffset = 0UL;

        if (!KswordARKDriverValidateThreadListCandidate(
                Process,
                CurrentThread,
                KthreadProcessOffset,
                candidateOffset,
                &processHeadOffset)) {
            continue;
        }
        if (foundThreadOffset >= 0) {
            return;
        }
        foundProcessOffset = (LONG)processHeadOffset;
        foundThreadOffset = (LONG)candidateOffset;
    }

    *ProcessThreadListHeadOffsetOut = foundProcessOffset;
    *ThreadListEntryOffsetOut = foundThreadOffset;
}

VOID
KswordARKDriverResolveReadOnlyDynDataOffsets(
    _Out_ PKSWORD_RUNTIME_DYNDATA_OFFSETS Offsets
    )
{
    PEPROCESS process = PsGetCurrentProcess();
    PETHREAD thread = PsGetCurrentThread();
    PACCESS_TOKEN token = NULL;
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
        Offsets->EpJob =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessJob",
                process);
        Offsets->EpDebugPort =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessDebugPort",
                process);
        Offsets->EpPriorityClass =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessPriorityClass",
                process);
        Offsets->EpActiveThreads =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessActiveThreadCount",
                process);
        Offsets->EpWin32WindowStation =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessWin32WindowStation",
                process);
        Offsets->EpSecurityPort =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetProcessSecurityPort",
                process);

        token = PsReferencePrimaryToken(process);
        if (token != NULL) {
            Offsets->EpToken = KswordARKDriverResolveProcessTokenOffset(process, token);
            KswordARKDriverResolveTokenLayoutOffsets(
                token,
                &Offsets->TokUserAndGroupCount,
                &Offsets->TokUserAndGroups,
                &Offsets->TokIntegrityLevelIndex,
                &Offsets->TokMandatoryPolicy);
            PsDereferencePrimaryToken(token);
            token = NULL;
        }
        Offsets->EpFlags = KswordARKDriverResolveProcessFlagsOffset(process);
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
        Offsets->KtInitialStack =
            KswordARKDriverResolveCurrentThreadStackOffset(
                L"IoGetInitialStack",
                thread);
        Offsets->KtStackLimit =
            KswordARKDriverResolveCurrentThreadStackOffset(
                L"PsGetCurrentThreadStackLimit",
                thread);
        Offsets->KtStackBase =
            KswordARKDriverResolveCurrentThreadStackOffset(
                L"PsGetCurrentThreadStackBase",
                thread);
        Offsets->EtStartAddress =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetThreadStartAddress",
                thread);
        Offsets->EtWin32StartAddress =
            KswordARKDriverResolveValidatedAccessorOffset(
                L"PsGetThreadWin32StartAddress",
                thread);
        KswordARKDriverResolveThreadListOffsets(
            process,
            thread,
            Offsets->KtProcess,
            &Offsets->EpThreadListHead,
            &Offsets->EtThreadListEntry);
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

static LONG
KswordARKDriverDecodeReturnedUcharOffset(
    _In_reads_bytes_(ByteCount) const UCHAR* Bytes,
    _In_ SIZE_T ByteCount
    )
{
    LONG candidate = -1;
    SIZE_T index = 0U;

    if (Bytes == NULL) {
        return -1;
    }
    for (index = 0U; index + 7U <= ByteCount; ++index) {
        LONG offset = -1;
        SIZE_T instructionBytes = 0U;

        // mov al, byte ptr [rcx+disp32]
        if (Bytes[index] == 0x8AU && Bytes[index + 1U] == 0x81U) {
            RtlCopyMemory(&offset, Bytes + index + 2U, sizeof(offset));
            instructionBytes = 6U;
        }
        // movzx eax, byte ptr [rcx+disp32]
        else if (index + 8U <= ByteCount &&
            Bytes[index] == 0x0FU && Bytes[index + 1U] == 0xB6U &&
            Bytes[index + 2U] == 0x81U) {
            RtlCopyMemory(&offset, Bytes + index + 3U, sizeof(offset));
            instructionBytes = 7U;
        }
        else {
            continue;
        }
        if (offset <= 0 || offset > 0x0FFF ||
            index + instructionBytes >= ByteCount ||
            Bytes[index + instructionBytes] != 0xC3U) {
            continue;
        }
        if (candidate >= 0 && candidate != offset) {
            return -1;
        }
        candidate = offset;
    }
    return candidate;
}

static BOOLEAN
KswordARKDriverResolveProcessSignatureOffsets(
    _Out_ LONG* SignatureLevelOffsetOut,
    _Out_ LONG* SectionSignatureLevelOffsetOut
    )
{
    UNICODE_STRING routineName;
    KSWORD_PROCESS_SIGNATURE_ACCESSOR_FN accessor = NULL;
    PEPROCESS process = PsGetCurrentProcess();
    UCHAR code[32];
    UCHAR signatureValue = 0U;
    UCHAR sectionValue = 0U;
    UCHAR signatureField = 0U;
    UCHAR sectionField = 0U;
    LONG signatureOffset = -1;
    LONG sectionOffset = -1;
    SIZE_T index = 0U;

    if (SignatureLevelOffsetOut == NULL ||
        SectionSignatureLevelOffsetOut == NULL || process == NULL) {
        return FALSE;
    }
    *SignatureLevelOffsetOut = -1;
    *SectionSignatureLevelOffsetOut = -1;
    RtlInitUnicodeString(&routineName, L"PsGetProcessSignatureLevel");
    accessor = (KSWORD_PROCESS_SIGNATURE_ACCESSOR_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return FALSE;
    }
    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        signatureValue = accessor(process, &sectionValue);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    for (index = 0U; index + 8U <= sizeof(code); ++index) {
        LONG offset = -1;

        if (code[index] != 0x8AU || code[index + 1U] != 0x81U) {
            continue;
        }
        RtlCopyMemory(&offset, code + index + 2U, sizeof(offset));
        if (offset <= 0 || offset > 0x0FFF) {
            continue;
        }
        // The optional section-signing output is copied through RDX.
        if (code[index + 6U] == 0x88U && code[index + 7U] == 0x02U) {
            if (sectionOffset >= 0 && sectionOffset != offset) {
                return FALSE;
            }
            sectionOffset = offset;
        }
        // The signature level itself is returned in AL.
        if (code[index + 6U] == 0xC3U) {
            if (signatureOffset >= 0 && signatureOffset != offset) {
                return FALSE;
            }
            signatureOffset = offset;
        }
    }
    if (signatureOffset <= 0 || sectionOffset <= 0 ||
        signatureOffset == sectionOffset) {
        return FALSE;
    }
    __try {
        signatureField = *((volatile const UCHAR*)process + signatureOffset);
        sectionField = *((volatile const UCHAR*)process + sectionOffset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    if (signatureField != signatureValue || sectionField != sectionValue) {
        return FALSE;
    }
    *SignatureLevelOffsetOut = signatureOffset;
    *SectionSignatureLevelOffsetOut = sectionOffset;
    return TRUE;
}

LONG
KswordARKDriverResolveProcessProtectionOffset(
    VOID
    )
{
    UNICODE_STRING routineName;
    KSWORD_PROCESS_PROTECTION_ACCESSOR_FN accessor = NULL;
    PEPROCESS process = PsGetCurrentProcess();
    UCHAR code[32];
    UCHAR accessorValue = 0U;
    UCHAR fieldValue = 0U;
    LONG offset = -1;

    if (process == NULL) {
        return -1;
    }
    RtlInitUnicodeString(&routineName, L"PsGetProcessProtection");
    accessor = (KSWORD_PROCESS_PROTECTION_ACCESSOR_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (accessor == NULL) {
        return -1;
    }
    RtlZeroMemory(code, sizeof(code));
    __try {
        RtlCopyMemory(code, (const VOID*)accessor, sizeof(code));
        accessorValue = accessor(process);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    offset = KswordARKDriverDecodeReturnedUcharOffset(code, sizeof(code));
    if (offset <= 0) {
        return -1;
    }
    __try {
        fieldValue = *((volatile const UCHAR*)process + offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    return fieldValue == accessorValue ? offset : -1;
}

LONG
KswordARKDriverResolveProcessSignatureLevelOffset(
    VOID
    )
{
    LONG signatureOffset = -1;
    LONG sectionOffset = -1;
    LONG protectionOffset = KswordARKDriverResolveProcessProtectionOffset();

    if (protectionOffset <= 0 ||
        !KswordARKDriverResolveProcessSignatureOffsets(
            &signatureOffset,
            &sectionOffset) ||
        sectionOffset + (LONG)sizeof(UCHAR) != protectionOffset ||
        signatureOffset + (LONG)sizeof(UCHAR) != sectionOffset) {
        return -1;
    }
    return signatureOffset;
}

LONG
KswordARKDriverResolveProcessSectionSignatureLevelOffset(
    VOID
    )
{
    LONG signatureOffset = -1;
    LONG sectionOffset = -1;
    LONG protectionOffset = KswordARKDriverResolveProcessProtectionOffset();

    if (protectionOffset <= 0 ||
        !KswordARKDriverResolveProcessSignatureOffsets(
            &signatureOffset,
            &sectionOffset) ||
        sectionOffset + (LONG)sizeof(UCHAR) != protectionOffset ||
        signatureOffset + (LONG)sizeof(UCHAR) != sectionOffset) {
        return -1;
    }
    return sectionOffset;
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
