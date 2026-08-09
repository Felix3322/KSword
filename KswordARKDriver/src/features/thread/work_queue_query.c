/*++

Module Name:

    work_queue_query.c

Abstract:

    Read-only, identity-matched Ex work-queue enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_thread.h"
#include "driver/KswordArkWorkQueueIoctl.h"
#include "../dyndata/dyndata_v4_internal.h"
#include "work_queue_fallback.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntimage.h>

#define KSW_WORK_QUEUE_MAX_PE_SECTIONS 96UL
#define KSW_WORK_QUEUE_MAX_EX_POOL_INDEX 8UL

typedef struct _KSW_WORK_QUEUE_BUILDER
{
    KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE* Response;
    ULONG Capacity;
    ULONG MaxEntries;
    BOOLEAN Stop;
    KSW_DYN_V4_WORK_QUEUE_LAYOUT Layout;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* Modules;
} KSW_WORK_QUEUE_BUILDER;

static BOOLEAN
KswordARKWorkQueueIsKernelAddress(
    _In_ ULONG64 Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFULL;
#else
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
KswordARKWorkQueueAddAddress(
    _In_ ULONG64 Base,
    _In_ ULONG64 Offset,
    _Out_ ULONG64* AddressOut
    )
{
    if (AddressOut == NULL || Base > MAXULONGLONG - Offset) {
        return FALSE;
    }
    *AddressOut = Base + Offset;
    return KswordARKWorkQueueIsKernelAddress(*AddressOut);
}

static BOOLEAN
KswordARKWorkQueueRead(
    _In_ ULONG64 Address,
    _Out_writes_bytes_(BytesToRead) PVOID Destination,
    _In_ SIZE_T BytesToRead
    )
{
    if (Destination == NULL || BytesToRead == 0U ||
        !KswordARKWorkQueueIsKernelAddress(Address) ||
        Address > MAXULONGLONG - (ULONG64)(BytesToRead - 1U) ||
        !KswordARKWorkQueueIsKernelAddress(Address + (ULONG64)(BytesToRead - 1U))) {
        return FALSE;
    }
    return KswordARKHookReadMemorySafe(
        (const VOID*)(ULONG_PTR)Address,
        Destination,
        BytesToRead);
}

static BOOLEAN
KswordARKWorkQueueReadField(
    _In_ ULONG64 Base,
    _In_ ULONG Offset,
    _Out_writes_bytes_(BytesToRead) PVOID Destination,
    _In_ SIZE_T BytesToRead
    )
{
    ULONG64 address = 0ULL;

    return KswordARKWorkQueueAddAddress(Base, Offset, &address) &&
        KswordARKWorkQueueRead(address, Destination, BytesToRead);
}

static BOOLEAN
KswordARKWorkQueueListHeadIsPlausible(
    _In_ ULONG64 ListHeadAddress,
    _In_ const LIST_ENTRY* Head
    )
{
    ULONG64 forward = 0ULL;
    ULONG64 backward = 0ULL;

    if (Head == NULL || !KswordARKWorkQueueIsKernelAddress(ListHeadAddress)) {
        return FALSE;
    }
    forward = (ULONG64)(ULONG_PTR)Head->Flink;
    backward = (ULONG64)(ULONG_PTR)Head->Blink;

    // An empty list is valid only when both links point back to the head.
    if (forward == ListHeadAddress || backward == ListHeadAddress) {
        return forward == ListHeadAddress && backward == ListHeadAddress;
    }
    return KswordARKWorkQueueIsKernelAddress(forward) &&
        KswordARKWorkQueueIsKernelAddress(backward);
}

static BOOLEAN
KswordARKWorkQueueFieldFits(
    _In_ ULONG Offset,
    _In_ ULONG FieldBytes,
    _In_ ULONG TypeSize
    )
{
    return FieldBytes != 0UL &&
        TypeSize >= FieldBytes &&
        Offset <= TypeSize - FieldBytes;
}

static BOOLEAN
KswordARKWorkQueueLayoutValid(
    _In_ const KSW_DYN_V4_WORK_QUEUE_LAYOUT* Layout,
    _In_ ULONG RequestFlags
    )
{
    const ULONG listArrayBytes =
        KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT * (ULONG)sizeof(LIST_ENTRY);
    const BOOLEAN runtimeLayout = Layout != NULL &&
        (Layout->RuntimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) != 0UL;

    if (runtimeLayout) {
        const BOOLEAN itemsRequested =
            (RequestFlags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORK_ITEMS) != 0UL;
        const BOOLEAN threadsRequested =
            (RequestFlags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORKER_THREADS) != 0UL;
        const BOOLEAN itemsAvailable =
            (Layout->RuntimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS) != 0UL;
        const BOOLEAN threadsAvailable =
            (Layout->RuntimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) != 0UL;

        if (!KswordARKWorkQueueIsKernelAddress(Layout->ModuleBase) ||
            Layout->ModuleSize < sizeof(PVOID) ||
            Layout->PspSystemPartitionRva == 0UL ||
            Layout->PspSystemPartitionRva > Layout->ModuleSize - sizeof(PVOID) ||
            Layout->ExPoolUntrusted >= KSW_WORK_QUEUE_MAX_EX_POOL_INDEX ||
            !itemsAvailable ||
            (threadsRequested && !threadsAvailable && !itemsRequested) ||
            Layout->RuntimePriorityIndexes[0] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
            Layout->RuntimePriorityIndexes[1] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
            Layout->RuntimePriorityIndexes[2] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
            Layout->RuntimePriorityIndexes[0] == Layout->RuntimePriorityIndexes[1] ||
            Layout->RuntimePriorityIndexes[0] == Layout->RuntimePriorityIndexes[2] ||
            Layout->RuntimePriorityIndexes[1] == Layout->RuntimePriorityIndexes[2] ||
            !KswordARKWorkQueueFieldFits(
                Layout->EpartitionExPartition,
                sizeof(PVOID),
                Layout->EpartitionTypeSize) ||
            !KswordARKWorkQueueFieldFits(
                Layout->ExPartitionWorkQueues,
                sizeof(PVOID),
                Layout->ExPartitionTypeSize) ||
            !KswordARKWorkQueueFieldFits(
                Layout->KpriQueueEntryListHead,
                listArrayBytes,
                Layout->KpriQueueTypeSize) ||
            !KswordARKWorkQueueFieldFits(
                Layout->WorkItemList,
                sizeof(LIST_ENTRY),
                Layout->WorkItemTypeSize) ||
            !KswordARKWorkQueueFieldFits(
                Layout->WorkItemRoutine,
                sizeof(PVOID),
                Layout->WorkItemTypeSize) ||
            !KswordARKWorkQueueFieldFits(
                Layout->WorkItemParameter,
                sizeof(PVOID),
                Layout->WorkItemTypeSize)) {
            return FALSE;
        }
        if (threadsRequested && threadsAvailable) {
            return KswordARKWorkQueueFieldFits(
                    Layout->KthreadQueue,
                    sizeof(PVOID),
                    Layout->KthreadTypeSize) &&
                KswordARKWorkQueueFieldFits(
                    Layout->EthreadStartAddress,
                    sizeof(PVOID),
                    Layout->EthreadTypeSize);
        }
        return TRUE;
    }

    if (Layout == NULL ||
        !KswordARKWorkQueueIsKernelAddress(Layout->ModuleBase) ||
        Layout->ModuleSize < sizeof(PVOID) ||
        Layout->PspSystemPartitionRva == 0UL ||
        Layout->ExpBuiltinPrioritiesRva == 0UL ||
        Layout->PspSystemPartitionRva > Layout->ModuleSize - sizeof(PVOID) ||
        Layout->ModuleSize < 3UL * sizeof(ULONG) ||
        Layout->ExpBuiltinPrioritiesRva >
            Layout->ModuleSize - (3UL * sizeof(ULONG)) ||
        Layout->ExPoolUntrusted >= KSW_WORK_QUEUE_MAX_EX_POOL_INDEX ||
        Layout->EpartitionTypeSize == 0UL ||
        Layout->ExPartitionTypeSize == 0UL ||
        Layout->ExWorkQueueTypeSize == 0UL ||
        Layout->KpriQueueTypeSize == 0UL ||
        Layout->KthreadTypeSize == 0UL ||
        Layout->EthreadTypeSize == 0UL ||
        Layout->WorkItemTypeSize == 0UL) {
        return FALSE;
    }

    return
        KswordARKWorkQueueFieldFits(
            Layout->EpartitionExPartition,
            sizeof(PVOID),
            Layout->EpartitionTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->ExPartitionWorkQueues,
            sizeof(PVOID),
            Layout->ExPartitionTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->ExWorkQueueWorkPriQueue,
            Layout->KpriQueueTypeSize,
            Layout->ExWorkQueueTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->ExWorkQueueQueueIndex,
            sizeof(ULONG),
            Layout->ExWorkQueueTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->KpriQueueEntryListHead,
            listArrayBytes,
            Layout->KpriQueueTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->KpriQueueThreadListHead,
            sizeof(LIST_ENTRY),
            Layout->KpriQueueTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->KthreadQueue,
            sizeof(PVOID),
            Layout->KthreadTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->KthreadQueueListEntry,
            sizeof(LIST_ENTRY),
            Layout->KthreadTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->EthreadTcb,
            Layout->KthreadTypeSize,
            Layout->EthreadTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->EthreadStartAddress,
            sizeof(PVOID),
            Layout->EthreadTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->WorkItemList,
            sizeof(LIST_ENTRY),
            Layout->WorkItemTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->WorkItemRoutine,
            sizeof(PVOID),
            Layout->WorkItemTypeSize) &&
        KswordARKWorkQueueFieldFits(
            Layout->WorkItemParameter,
            sizeof(PVOID),
            Layout->WorkItemTypeSize);
}

static VOID
KswordARKWorkQueueCopyBoundedAnsi(
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ SIZE_T DestinationBytes,
    _In_reads_bytes_(SourceBytes) const UCHAR* Source,
    _In_ ULONG SourceBytes
    )
{
    SIZE_T index = 0U;

    if (Destination == NULL || DestinationBytes == 0U) {
        return;
    }
    Destination[0] = '\0';
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }
    while (index + 1U < DestinationBytes &&
           index < (SIZE_T)SourceBytes &&
           Source[index] != 0U) {
        Destination[index] = (CHAR)Source[index];
        ++index;
    }
    Destination[index] = '\0';
}

static BOOLEAN
KswordARKWorkQueueRoutineInExecutableSection(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONG64 RoutineAddress
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG64 routineRva64 = 0ULL;
    ULONG64 sectionTableRva64 = 0ULL;
    ULONG sectionIndex = 0UL;

    if (Module == NULL || Module->ImageBase == NULL ||
        Module->ImageSize == 0UL ||
        RoutineAddress < (ULONG64)(ULONG_PTR)Module->ImageBase) {
        return FALSE;
    }
    routineRva64 = RoutineAddress - (ULONG64)(ULONG_PTR)Module->ImageBase;
    if (routineRva64 >= Module->ImageSize ||
        !KswordARKHookReadMemorySafe(Module->ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !KswordARKHookReadImageNtHeaders(Module, &ntHeaders) ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSW_WORK_QUEUE_MAX_PE_SECTIONS) {
        return FALSE;
    }

    sectionTableRva64 =
        (ULONG64)(ULONG)dosHeader.e_lfanew +
        (ULONG64)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        (ULONG64)ntHeaders.FileHeader.SizeOfOptionalHeader;
    if (sectionTableRva64 > MAXULONG) {
        return FALSE;
    }

    for (sectionIndex = 0UL;
         sectionIndex < (ULONG)ntHeaders.FileHeader.NumberOfSections;
         ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG64 sectionHeaderRva64 =
            sectionTableRva64 +
            ((ULONG64)sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG64 sectionStart = 0ULL;
        ULONG64 sectionSpan = 0ULL;
        ULONG64 sectionEnd = 0ULL;

        if (sectionHeaderRva64 > MAXULONG ||
            !KswordARKHookReadImageBytes(
                Module,
                (ULONG)sectionHeaderRva64,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }
        sectionStart = sectionHeader.VirtualAddress;
        sectionSpan = sectionHeader.Misc.VirtualSize != 0UL
            ? sectionHeader.Misc.VirtualSize
            : sectionHeader.SizeOfRawData;
        if (sectionSpan == 0ULL ||
            sectionStart > MAXULONGLONG - sectionSpan) {
            continue;
        }
        sectionEnd = sectionStart + sectionSpan;
        if (routineRva64 >= sectionStart && routineRva64 < sectionEnd) {
            return (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        }
    }
    return FALSE;
}

static VOID
KswordARKWorkQueueFillModule(
    _In_ KSW_WORK_QUEUE_BUILDER* Builder,
    _In_ ULONG64 RoutineAddress,
    _Inout_ KSWORD_ARK_WORK_QUEUE_ENTRY* Entry
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* module = NULL;
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;

    if (Builder == NULL || Entry == NULL) {
        return;
    }
    if (RoutineAddress == 0ULL) {
        Entry->status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_UNRESOLVED;
        return;
    }
    Entry->flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT;
    module = KswordARKHookFindModuleForAddress(
        Builder->Modules,
        (ULONG_PTR)RoutineAddress);
    if (module == NULL) {
        Entry->status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_UNRESOLVED;
        return;
    }

    Entry->flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED;
    Entry->moduleBase = (ULONG64)(ULONG_PTR)module->ImageBase;
    Entry->moduleSize = module->ImageSize;
    KswordARKHookGetModuleFileName(module, &fileName, &fileNameBytes);
    KswordARKWorkQueueCopyBoundedAnsi(
        Entry->moduleName,
        sizeof(Entry->moduleName),
        fileName,
        fileNameBytes);
    KswordARKWorkQueueCopyBoundedAnsi(
        Entry->modulePath,
        sizeof(Entry->modulePath),
        module->FullPathName,
        sizeof(module->FullPathName));

    if (!KswordARKWorkQueueRoutineInExecutableSection(module, RoutineAddress)) {
        Entry->status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_NOT_EXECUTABLE;
        return;
    }
    Entry->flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION;
}

static VOID
KswordARKWorkQueueMarkPartial(
    _Inout_ KSW_WORK_QUEUE_BUILDER* Builder,
    _In_ ULONG StatusFlag,
    _In_ NTSTATUS LastStatus
    )
{
    if (Builder == NULL || Builder->Response == NULL) {
        return;
    }
    Builder->Response->statusFlags |=
        KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL | StatusFlag;
    Builder->Response->lastStatus = LastStatus;
}

static VOID
KswordARKWorkQueueAppendEntry(
    _Inout_ KSW_WORK_QUEUE_BUILDER* Builder,
    _In_ const KSWORD_ARK_WORK_QUEUE_ENTRY* Entry
    )
{
    KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE* response = NULL;

    if (Builder == NULL || Entry == NULL || Builder->Response == NULL ||
        Builder->Stop) {
        return;
    }
    response = Builder->Response;
    response->totalCount += 1UL;
    if (response->returnedCount < Builder->Capacity &&
        response->returnedCount < Builder->MaxEntries) {
        response->entries[response->returnedCount] = *Entry;
        response->returnedCount += 1UL;
    }
    else {
        KswordARKWorkQueueMarkPartial(
            Builder,
            KSWORD_ARK_WORK_QUEUE_STATUS_TRUNCATED,
            STATUS_BUFFER_OVERFLOW);
        Builder->Stop = TRUE;
        return;
    }

}

static VOID
KswordARKWorkQueueEnumerateItems(
    _Inout_ KSW_WORK_QUEUE_BUILDER* Builder,
    _In_ ULONG NodeIndex,
    _In_ ULONG QueueType,
    _In_ ULONG PriorityIndex,
    _In_ ULONG64 WorkQueueAddress,
    _In_ ULONG64 ListHeadAddress
    )
{
    LIST_ENTRY headBefore;
    LIST_ENTRY headAfter;
    ULONG64 currentLink = 0ULL;
    ULONG64 previousLink = ListHeadAddress;
    ULONG iteration = 0UL;

    if (Builder == NULL || Builder->Stop) {
        return;
    }
    if (!KswordARKWorkQueueRead(ListHeadAddress, &headBefore, sizeof(headBefore))) {
        Builder->Response->readFailureCount += 1UL;
        KswordARKWorkQueueMarkPartial(
            Builder,
            KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
            STATUS_PARTIAL_COPY);
        return;
    }
    if (!KswordARKWorkQueueListHeadIsPlausible(ListHeadAddress, &headBefore)) {
        Builder->Response->corruptListCount += 1UL;
        KswordARKWorkQueueMarkPartial(
            Builder,
            KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST,
            STATUS_DATA_ERROR);
        return;
    }

    currentLink = (ULONG64)(ULONG_PTR)headBefore.Flink;
    while (currentLink != ListHeadAddress && !Builder->Stop) {
        LIST_ENTRY currentLinks;
        ULONG64 workItemAddress = 0ULL;
        ULONG64 routineAddress = 0ULL;
        ULONG64 parameterAddress = 0ULL;
        KSWORD_ARK_WORK_QUEUE_ENTRY entry;

        if (iteration >= Builder->MaxEntries) {
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_TRUNCATED,
                STATUS_BUFFER_OVERFLOW);
            Builder->Stop = TRUE;
            break;
        }
        ++iteration;
        if (!KswordARKWorkQueueIsKernelAddress(currentLink) ||
            currentLink < Builder->Layout.WorkItemList ||
            !KswordARKWorkQueueRead(currentLink, &currentLinks, sizeof(currentLinks)) ||
            (ULONG64)(ULONG_PTR)currentLinks.Blink != previousLink) {
            Builder->Response->corruptListCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST,
                STATUS_DATA_ERROR);
            break;
        }
        workItemAddress = currentLink - Builder->Layout.WorkItemList;
        if (!KswordARKWorkQueueReadField(
                workItemAddress,
                Builder->Layout.WorkItemRoutine,
                &routineAddress,
                sizeof(routineAddress)) ||
            !KswordARKWorkQueueReadField(
                workItemAddress,
                Builder->Layout.WorkItemParameter,
                &parameterAddress,
                sizeof(parameterAddress))) {
            Builder->Response->readFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
            previousLink = currentLink;
            currentLink = (ULONG64)(ULONG_PTR)currentLinks.Flink;
            continue;
        }

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.rowKind = KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM;
        entry.queueType = QueueType;
        entry.priorityIndex = PriorityIndex;
        entry.nodeIndex = NodeIndex;
        entry.flags = KSWORD_ARK_WORK_QUEUE_ENTRY_QUEUE_VALIDATED;
        entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK;
        entry.queueAddress = WorkQueueAddress;
        entry.workItemAddress = workItemAddress;
        entry.routineAddress = routineAddress;
        entry.parameterAddress = parameterAddress;
        if (parameterAddress != 0ULL) {
            entry.flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_PARAMETER_PRESENT;
        }
        KswordARKWorkQueueFillModule(Builder, routineAddress, &entry);
        if (entry.status != KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK) {
            KswordARKWorkQueueMarkPartial(
                Builder,
                0UL,
                STATUS_INVALID_IMAGE_FORMAT);
        }
        KswordARKWorkQueueAppendEntry(Builder, &entry);

        previousLink = currentLink;
        currentLink = (ULONG64)(ULONG_PTR)currentLinks.Flink;
    }

    if (!Builder->Stop) {
        if (!KswordARKWorkQueueRead(ListHeadAddress, &headAfter, sizeof(headAfter))) {
            Builder->Response->readFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
        }
        else if (previousLink != (ULONG64)(ULONG_PTR)headBefore.Blink ||
                 !KswordARKWorkQueueListHeadIsPlausible(ListHeadAddress, &headAfter) ||
                 headAfter.Flink != headBefore.Flink ||
                 headAfter.Blink != headBefore.Blink) {
            Builder->Response->corruptListCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST,
                STATUS_RETRY);
        }
    }
}

static VOID
KswordARKWorkQueueEnumerateThreads(
    _Inout_ KSW_WORK_QUEUE_BUILDER* Builder,
    _In_ ULONG NodeIndex,
    _In_ ULONG64 WorkQueueAddress,
    _In_ ULONG64 PriQueueAddress,
    _In_opt_ const KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* SystemThreads
    )
{
    KSW_WORK_QUEUE_THREAD_WALKER walker;
    PETHREAD threadCursor = NULL;

    if (Builder == NULL || Builder->Stop) {
        return;
    }

    /*
     * ThreadListHead is a private, lockless queue list and cannot establish
     * that an arbitrary list-derived address is an object. Walk the System
     * process with the shared thread cursor instead; whether it comes from the
     * public walker or from the TID snapshot plus PsLookupThreadByThreadId,
     * every cursor is an Object Manager referenced ETHREAD. DynData is used
     * only to read the referenced ETHREAD's embedded KTHREAD.Queue and
     * reverse-match it to the target KPRIQUEUE.
     */
    RtlZeroMemory(&walker, sizeof(walker));
    KswordARKWorkQueueInitializeThreadWalker(&walker, SystemThreads);
    if (!KswordARKWorkQueueThreadWalkerUsable(&walker)) {
        return;
    }

    threadCursor = KswordARKWorkQueueThreadWalkerNext(&walker);
    while (threadCursor != NULL && !Builder->Stop) {
        ULONG64 ethreadAddress = 0ULL;
        ULONG64 kthreadAddress = 0ULL;
        ULONG64 queuePointer = 0ULL;
        ULONG64 verifiedQueuePointer = 0ULL;
        ULONG64 startAddress = 0ULL;
        ULONG threadProcessId = 0UL;
        KSWORD_ARK_WORK_QUEUE_ENTRY entry;

        ethreadAddress = (ULONG64)(ULONG_PTR)threadCursor;
        if (!KswordARKWorkQueueAddAddress(
                ethreadAddress,
                Builder->Layout.EthreadTcb,
                &kthreadAddress) ||
            !KswordARKWorkQueueReadField(
                kthreadAddress,
                Builder->Layout.KthreadQueue,
                &queuePointer,
                sizeof(queuePointer))) {
            Builder->Response->readFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
            goto AdvanceThread;
        }
        if (queuePointer != PriQueueAddress) {
            goto AdvanceThread;
        }

        RtlZeroMemory(&entry, sizeof(entry));
        entry.size = sizeof(entry);
        entry.rowKind = KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD;
        entry.queueType = KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER;
        entry.priorityIndex = MAXULONG;
        entry.nodeIndex = NodeIndex;
        entry.flags =
            KSWORD_ARK_WORK_QUEUE_ENTRY_QUEUE_VALIDATED |
            KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_REFERENCED;
        entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK;
        entry.queueAddress = WorkQueueAddress;
        entry.threadObject = ethreadAddress;

        __try {
            entry.threadId = HandleToULong(PsGetThreadId(threadCursor));
            threadProcessId = HandleToULong(PsGetThreadProcessId(threadCursor));
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
            entry.threadCreateTime100ns =
                (ULONG64)PsGetThreadCreateTime(threadCursor);
#endif
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            threadProcessId = 0UL;
        }
        if (entry.threadId == 0UL ||
            entry.threadCreateTime100ns == 0ULL ||
            threadProcessId != 4UL) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED;
            Builder->Response->referenceFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_OBJECT_NAME_NOT_FOUND);
        }
        else if (!KswordARKWorkQueueReadField(
                ethreadAddress,
                Builder->Layout.EthreadStartAddress,
                &startAddress,
                sizeof(startAddress))) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_READ_FAILED;
            Builder->Response->readFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
        }
        else if (startAddress == 0ULL) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED;
            Builder->Response->referenceFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_OBJECT_NAME_NOT_FOUND);
        }
        else if (!KswordARKWorkQueueReadField(
                kthreadAddress,
                Builder->Layout.KthreadQueue,
                &verifiedQueuePointer,
                sizeof(verifiedQueuePointer))) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_READ_FAILED;
            Builder->Response->readFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
        }
        else if (verifiedQueuePointer != PriQueueAddress) {
            entry.threadId = 0UL;
            entry.threadCreateTime100ns = 0ULL;
            entry.status = KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED;
            Builder->Response->referenceFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                Builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_RETRY);
        }
        else {
            entry.flags |= KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_IDENTITY_VALID;
            entry.routineAddress = startAddress;
            KswordARKWorkQueueFillModule(Builder, startAddress, &entry);
            if (entry.status != KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK) {
                KswordARKWorkQueueMarkPartial(
                    Builder,
                    0UL,
                    STATUS_INVALID_IMAGE_FORMAT);
            }
        }

        KswordARKWorkQueueAppendEntry(Builder, &entry);

AdvanceThread:
        if (Builder->Stop) {
            break;
        }
        threadCursor = KswordARKWorkQueueThreadWalkerNext(&walker);
    }
    KswordARKWorkQueueThreadWalkerClose(&walker);
}

static NTSTATUS
KswordARKDriverEnumerateWorkQueues(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ SIZE_T OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST* Request,
    _Out_ SIZE_T* BytesWrittenOut
    )
{
    KSW_WORK_QUEUE_BUILDER builder;
    ULONG moduleBytes = 0UL;
    ULONG priorityIndexes[3] = { 0UL, 0UL, 0UL };
    ULONG queueTypes[3] = {
        KSWORD_ARK_WORK_QUEUE_TYPE_CRITICAL,
        KSWORD_ARK_WORK_QUEUE_TYPE_DELAYED,
        KSWORD_ARK_WORK_QUEUE_TYPE_HYPERCRITICAL
    };
    KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT systemThreads;
    BOOLEAN workerThreadsUsable = FALSE;
    ULONG64 pspSystemPartitionAddress = 0ULL;
    ULONG64 prioritiesAddress = 0ULL;
    ULONG64 epartitionAddress = 0ULL;
    ULONG64 exPartitionAddress = 0ULL;
    ULONG64 workQueuesAddress = 0ULL;
    ULONG nodeCount = 0UL;
    ULONG nodeIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL ||
        OutputBufferLength < KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    RtlZeroMemory(&builder, sizeof(builder));
    RtlZeroMemory(&systemThreads, sizeof(systemThreads));
    builder.Response = (KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE*)OutputBuffer;
    builder.Capacity = (ULONG)(
        (OutputBufferLength - KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
    builder.MaxEntries = Request->maxEntries;

    builder.Response->size = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
    builder.Response->version = KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION;
    builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK;
    builder.Response->entrySize = sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY);

#if !defined(_M_AMD64) && !defined(_M_X64)
    builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
    builder.Response->lastStatus = STATUS_NOT_SUPPORTED;
    *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
    return STATUS_SUCCESS;
#else
    status = KswordARKDynDataV4SnapshotWorkQueueLayout(&builder.Layout);
    if (!NT_SUCCESS(status)) {
        status = KswordARKWorkQueueResolveRuntimeLayout(&builder.Layout);
        if (!NT_SUCCESS(status)) {
            builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
            builder.Response->lastStatus = status;
            *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
            return STATUS_SUCCESS;
        }
    }
    builder.Response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_IDENTITY_MATCHED;
    if (!KswordARKWorkQueueLayoutValid(&builder.Layout, Request->flags)) {
        builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT;
        builder.Response->lastStatus = STATUS_DATA_ERROR;
        *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    builder.Response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_LAYOUT_VALIDATED;

    if ((Request->flags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORKER_THREADS) != 0UL) {
        if ((builder.Layout.RuntimeFlags &
             KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) != 0UL &&
            (builder.Layout.RuntimeFlags &
             KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) == 0UL) {
            // 运行期布局没能描述线程字段，工作项仍可枚举，线程行显式降级。
            builder.Response->referenceFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                &builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                STATUS_NOT_SUPPORTED);
        }
        else {
            KSW_WORK_QUEUE_THREAD_WALKER probeWalker;

            /*
             * ntoskrnl 并不导出 PsGetNextProcessThread，因此线程来源以
             * System 进程 TID 快照为主：每个 TID 都经 PsLookupThreadByThreadId
             * 取回被引用的 ETHREAD，身份强度与公开遍历例程一致。
             */
            (VOID)KswordARKWorkQueueCaptureSystemThreads(&systemThreads);
            RtlZeroMemory(&probeWalker, sizeof(probeWalker));
            KswordARKWorkQueueInitializeThreadWalker(&probeWalker, &systemThreads);
            workerThreadsUsable =
                KswordARKWorkQueueThreadWalkerUsable(&probeWalker);
            KswordARKWorkQueueThreadWalkerClose(&probeWalker);
            if (!workerThreadsUsable) {
                builder.Response->referenceFailureCount += 1UL;
                KswordARKWorkQueueMarkPartial(
                    &builder,
                    KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE,
                    STATUS_PROCEDURE_NOT_FOUND);
            }
        }
    }

    status = KswordARKHookBuildModuleSnapshot(&builder.Modules, &moduleBytes);
    if (!NT_SUCCESS(status)) {
        builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED;
        builder.Response->lastStatus = status;
        *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }

    if ((builder.Layout.RuntimeFlags &
         KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) != 0UL) {
        RtlCopyMemory(
            priorityIndexes,
            builder.Layout.RuntimePriorityIndexes,
            sizeof(priorityIndexes));
    }
    else if (!KswordARKWorkQueueAddAddress(
                 builder.Layout.ModuleBase,
                 builder.Layout.ExpBuiltinPrioritiesRva,
                 &prioritiesAddress) ||
             !KswordARKWorkQueueRead(
                 prioritiesAddress,
                 priorityIndexes,
                 sizeof(priorityIndexes))) {
        builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED;
        builder.Response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE;
        builder.Response->readFailureCount += 1UL;
        builder.Response->lastStatus = STATUS_DATA_ERROR;
        *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(builder.Modules, KSW_HOOK_SCAN_TAG);
        builder.Modules = NULL;
        KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }

    if (!KswordARKWorkQueueAddAddress(
            builder.Layout.ModuleBase,
            builder.Layout.PspSystemPartitionRva,
            &pspSystemPartitionAddress) ||
        !KswordARKWorkQueueRead(
            pspSystemPartitionAddress,
            &epartitionAddress,
            sizeof(epartitionAddress)) ||
        !KswordARKWorkQueueIsKernelAddress(epartitionAddress) ||
        !KswordARKWorkQueueReadField(
            epartitionAddress,
            builder.Layout.EpartitionExPartition,
            &exPartitionAddress,
            sizeof(exPartitionAddress)) ||
        !KswordARKWorkQueueIsKernelAddress(exPartitionAddress) ||
        !KswordARKWorkQueueReadField(
            exPartitionAddress,
            builder.Layout.ExPartitionWorkQueues,
            &workQueuesAddress,
            sizeof(workQueuesAddress)) ||
        !KswordARKWorkQueueIsKernelAddress(workQueuesAddress) ||
        priorityIndexes[0] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
        priorityIndexes[1] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
        priorityIndexes[2] >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
        priorityIndexes[0] == priorityIndexes[1] ||
        priorityIndexes[0] == priorityIndexes[2] ||
        priorityIndexes[1] == priorityIndexes[2]) {
        builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED;
        builder.Response->statusFlags |= KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE;
        builder.Response->readFailureCount += 1UL;
        builder.Response->lastStatus = STATUS_DATA_ERROR;
        *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(builder.Modules, KSW_HOOK_SCAN_TAG);
        builder.Modules = NULL;
        KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }

    nodeCount = (ULONG)KeQueryHighestNodeNumber() + 1UL;
    if (nodeCount == 0UL || nodeCount > KSWORD_ARK_WORK_QUEUE_MAX_NODES) {
        builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT;
        builder.Response->lastStatus = STATUS_DATA_ERROR;
        *BytesWrittenOut = KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(builder.Modules, KSW_HOOK_SCAN_TAG);
        builder.Modules = NULL;
        KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_SUCCESS;
    }
    builder.Response->nodeCount = nodeCount;

    for (nodeIndex = 0UL; nodeIndex < nodeCount && !builder.Stop; ++nodeIndex) {
        ULONG64 nodeQueuePointerAddress = 0ULL;
        ULONG64 nodeQueueArrayAddress = 0ULL;
        ULONG64 workQueuePointerAddress = 0ULL;
        ULONG64 workQueueAddress = 0ULL;
        ULONG64 priQueueAddress = 0ULL;
        ULONG liveQueueIndex = MAXULONG;
        ULONG queueTypeIndex = 0UL;

        if (!KswordARKWorkQueueAddAddress(
                workQueuesAddress,
                (ULONG64)nodeIndex * sizeof(PVOID),
                &nodeQueuePointerAddress) ||
            !KswordARKWorkQueueRead(
                nodeQueuePointerAddress,
                &nodeQueueArrayAddress,
                sizeof(nodeQueueArrayAddress)) ||
            !KswordARKWorkQueueIsKernelAddress(nodeQueueArrayAddress) ||
            !KswordARKWorkQueueAddAddress(
                nodeQueueArrayAddress,
                (ULONG64)builder.Layout.ExPoolUntrusted * sizeof(PVOID),
                &workQueuePointerAddress) ||
            !KswordARKWorkQueueRead(
                workQueuePointerAddress,
                &workQueueAddress,
                sizeof(workQueueAddress)) ||
            !KswordARKWorkQueueIsKernelAddress(workQueueAddress) ||
            (((builder.Layout.RuntimeFlags &
               KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE) == 0UL) &&
             (!KswordARKWorkQueueReadField(
                 workQueueAddress,
                 builder.Layout.ExWorkQueueQueueIndex,
                 &liveQueueIndex,
                 sizeof(liveQueueIndex)) ||
              liveQueueIndex != builder.Layout.ExPoolUntrusted)) ||
            !KswordARKWorkQueueAddAddress(
                workQueueAddress,
                builder.Layout.ExWorkQueueWorkPriQueue,
                &priQueueAddress)) {
            builder.Response->readFailureCount += 1UL;
            KswordARKWorkQueueMarkPartial(
                &builder,
                KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                STATUS_PARTIAL_COPY);
            continue;
        }

        builder.Response->queuesVisited += 1UL;
        if ((Request->flags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORK_ITEMS) != 0UL) {
            for (queueTypeIndex = 0UL;
                 queueTypeIndex < RTL_NUMBER_OF(priorityIndexes) && !builder.Stop;
                 ++queueTypeIndex) {
                ULONG64 listHeadOffset =
                    (ULONG64)builder.Layout.KpriQueueEntryListHead +
                    ((ULONG64)priorityIndexes[queueTypeIndex] * sizeof(LIST_ENTRY));
                ULONG64 listHeadAddress = 0ULL;

                if (!KswordARKWorkQueueAddAddress(
                        priQueueAddress,
                        listHeadOffset,
                        &listHeadAddress)) {
                    builder.Response->readFailureCount += 1UL;
                    KswordARKWorkQueueMarkPartial(
                        &builder,
                        KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE,
                        STATUS_INTEGER_OVERFLOW);
                    continue;
                }
                KswordARKWorkQueueEnumerateItems(
                    &builder,
                    nodeIndex,
                    queueTypes[queueTypeIndex],
                    priorityIndexes[queueTypeIndex],
                    workQueueAddress,
                    listHeadAddress);
            }
        }

        if ((Request->flags & KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_WORKER_THREADS) != 0UL &&
            !builder.Stop &&
            workerThreadsUsable) {
            KswordARKWorkQueueEnumerateThreads(
                &builder,
                nodeIndex,
                workQueueAddress,
                priQueueAddress,
                &systemThreads);
        }
    }

    if ((builder.Response->statusFlags &
         (KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL |
          KSWORD_ARK_WORK_QUEUE_STATUS_TRUNCATED |
          KSWORD_ARK_WORK_QUEUE_STATUS_CORRUPT_LIST |
          KSWORD_ARK_WORK_QUEUE_STATUS_READ_FAILURE |
          KSWORD_ARK_WORK_QUEUE_STATUS_REFERENCE_FAILURE)) != 0UL) {
        builder.Response->queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL;
    }
    else {
        builder.Response->lastStatus = STATUS_SUCCESS;
    }

    *BytesWrittenOut =
        KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE +
        ((SIZE_T)builder.Response->returnedCount *
         sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
    ExFreePoolWithTag(builder.Modules, KSW_HOOK_SCAN_TAG);
    builder.Modules = NULL;
    KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS
KswordARKWorkQueueIoctlEnum(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST requestCopy;
    const KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST* requestPacket = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    SIZE_T actualInputLength = 0U;
    SIZE_T actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (InputBufferLength != sizeof(KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST) ||
        OutputBufferLength < KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualInputLength != sizeof(KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    requestPacket = (const KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST*)inputBuffer;
    requestCopy = *requestPacket;
    if (requestCopy.size != sizeof(requestCopy) ||
        requestCopy.version != KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION ||
        requestCopy.flags == 0UL ||
        (requestCopy.flags & ~KSWORD_ARK_WORK_QUEUE_FLAG_VALID_MASK) != 0UL ||
        requestCopy.maxEntries == 0UL ||
        requestCopy.maxEntries > KSWORD_ARK_WORK_QUEUE_MAX_ENTRIES ||
        requestCopy.reserved0 != 0UL ||
        requestCopy.reserved1 != 0UL ||
        requestCopy.reserved2 != 0UL ||
        requestCopy.reserved3 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualOutputLength != OutputBufferLength) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    return KswordARKDriverEnumerateWorkQueues(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        BytesReturned);
}
