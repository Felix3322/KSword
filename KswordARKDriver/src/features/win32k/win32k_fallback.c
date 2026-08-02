/*++

Module Name:

    win32k_fallback.c

Abstract:

    PDB-independent tagWND and tagQ layout discovery.  Stable win32k exports
    are used only as bounded disassembly anchors.  A decoded layout is not
    trusted until live HWND generation values, object back-pointers, and the
    public PsGetThreadWin32Thread map agree in an attached GUI session.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query paths.

--*/

#include "win32k_fallback.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

#define KSW_WIN32K_HANDLE_SCAN_BYTES       0x0300UL
#define KSW_WIN32K_MAX_SESSION_HANDLES     0x00010000UL
#define KSW_WIN32K_MAX_SILO_OFFSET         0x00010000UL
#define KSW_WIN32K_WINDOW_HEAD_BYTES       0x20UL
#define KSW_WIN32K_OFFSET_UNKNOWN          MAXULONG

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_DATA_ERROR
#define STATUS_DATA_ERROR ((NTSTATUS)0xC000003EL)
#endif

typedef PVOID(NTAPI* KSW_USER_GET_SILO_GLOBALS_FN)(VOID);

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID Process,
    _Out_ PVOID ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID ApcState
    );

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

static BOOLEAN
KswordARKWin32kFallbackIsKernelAddress(
    _In_ ULONG_PTR Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (((ULONG64)Address >> 48U) == 0xFFFFULL);
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
KswordARKWin32kFallbackRead(
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    if (Buffer == NULL || Size == 0U ||
        !KswordARKWin32kFallbackIsKernelAddress(Address) ||
        Address > MAXULONG_PTR - (Size - 1U) ||
        !KswordARKWin32kFallbackIsKernelAddress(Address + Size - 1U)) {
        return FALSE;
    }
    return KswordARKRuntimeReadMemory((const VOID*)Address, Buffer, Size);
}

static BOOLEAN
KswordARKWin32kFallbackReadUlong(
    _In_reads_bytes_(ByteCount) const UCHAR* Bytes,
    _In_ ULONG ByteCount,
    _In_ ULONG Offset,
    _Out_ ULONG* ValueOut
    )
{
    if (Bytes == NULL || ValueOut == NULL ||
        Offset > ByteCount || sizeof(*ValueOut) > ByteCount - Offset) {
        return FALSE;
    }
    RtlCopyMemory(ValueOut, Bytes + Offset, sizeof(*ValueOut));
    return TRUE;
}

static BOOLEAN
KswordARKWin32kFallbackSetUniqueOffset(
    _Inout_ ULONG* Destination,
    _In_ ULONG Candidate,
    _In_ ULONG Maximum
    )
{
    if (Destination == NULL || Candidate > Maximum) {
        return FALSE;
    }
    if (*Destination == KSW_WIN32K_OFFSET_UNKNOWN) {
        *Destination = Candidate;
        return TRUE;
    }
    return *Destination == Candidate;
}

static BOOLEAN
KswordARKWin32kFallbackDecodeDirectBranch(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Instruction,
    _Out_ ULONG_PTR* TargetOut
    )
{
    UCHAR bytes[5];
    LONG displacement = 0L;
    ULONG_PTR target = 0U;

    if (View == NULL || TargetOut == NULL ||
        !KswordARKRuntimeAddressIsExecutable(View, Instruction, sizeof(bytes)) ||
        !KswordARKRuntimeReadMemory((const VOID*)Instruction, bytes, sizeof(bytes)) ||
        (bytes[0] != 0xE8U && bytes[0] != 0xE9U)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + 1U, sizeof(displacement));
    target = Instruction + sizeof(bytes) + (LONG_PTR)displacement;
    if (!KswordARKRuntimeAddressIsExecutable(View, target, 1U)) {
        return FALSE;
    }
    *TargetOut = target;
    return TRUE;
}

static BOOLEAN
KswordARKWin32kFallbackDecodeHandleLayoutAt(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR RoutineAddress,
    _Out_ KSW_WIN32K_FALLBACK_LAYOUT* LayoutOut
    )
/*++

Routine Description:

    Decode the private handle-table path used by ValidateHwnd.  The compound
    instruction relationships intentionally match semantics, not an entire
    build-specific byte string.

--*/
{
    UCHAR code[KSW_WIN32K_HANDLE_SCAN_BYTES];
    KSW_WIN32K_FALLBACK_LAYOUT layout;
    ULONG index = 0UL;
    ULONG flagsInstruction = KSW_WIN32K_OFFSET_UNKNOWN;
    BOOLEAN foundTableSequence = FALSE;
    BOOLEAN foundObjectScale = FALSE;
    BOOLEAN foundHandleMetadata = FALSE;

    if (View == NULL || LayoutOut == NULL ||
        !KswordARKRuntimeAddressIsExecutable(View, RoutineAddress, sizeof(code)) ||
        !KswordARKRuntimeReadMemory((const VOID*)RoutineAddress, code, sizeof(code))) {
        return FALSE;
    }
    RtlZeroMemory(&layout, sizeof(layout));
    layout.SiloServerInfo = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.SiloHandleEntrySize = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.SiloHandleEntries = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.SiloObjectSlots = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.ServerHandleCount = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.HandleEntryShift = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.ObjectSlotStride = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.HandleGeneration = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.HandleType = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.HandleFlags = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagWndHandle = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagWndThreadInfo = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagThreadInfoQueue = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagQActiveWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagQFocusWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagQCaptureWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    layout.TagQCaretWindow = KSW_WIN32K_OFFSET_UNKNOWN;

    for (index = 0UL; index + 11UL < sizeof(code); ++index) {
        ULONG siloOffset = 0UL;

        if (code[index] == 0x4CU && code[index + 1UL] == 0x8BU &&
            code[index + 2UL] == 0x88U &&
            code[index + 7UL] == 0x49U && code[index + 8UL] == 0x3BU &&
            (code[index + 9UL] & 0xC7U) == 0x41U &&
            KswordARKWin32kFallbackReadUlong(
                code, sizeof(code), index + 3UL, &siloOffset) &&
            !KswordARKWin32kFallbackSetUniqueOffset(
                &layout.SiloServerInfo, siloOffset, KSW_WIN32K_MAX_SILO_OFFSET)) {
            return FALSE;
        }
        if (code[index] == 0x4CU && code[index + 1UL] == 0x8BU &&
            code[index + 2UL] == 0x88U &&
            code[index + 7UL] == 0x49U && code[index + 8UL] == 0x3BU &&
            (code[index + 9UL] & 0xC7U) == 0x41U) {
            if (!KswordARKWin32kFallbackSetUniqueOffset(
                    &layout.ServerHandleCount,
                    code[index + 10UL],
                    0x40UL)) {
                return FALSE;
            }
        }
    }

    for (index = 0UL; index + 45UL < sizeof(code); ++index) {
        ULONG sizeOffset = 0UL;
        ULONG entriesOffset = 0UL;
        ULONG objectsOffset = 0UL;
        ULONG entriesIndex = 0UL;
        ULONG objectsIndex = 0UL;
        ULONG search = 0UL;

        if (code[index] != 0x0FU || code[index + 1UL] != 0xAFU ||
            code[index + 2UL] != 0xB8U ||
            !KswordARKWin32kFallbackReadUlong(
                code, sizeof(code), index + 3UL, &sizeOffset)) {
            continue;
        }
        for (search = index + 7UL; search <= index + 24UL; ++search) {
            if (code[search] == 0x4CU && code[search + 1UL] == 0x03U &&
                code[search + 2UL] == 0xB3U) {
                entriesIndex = search;
                break;
            }
        }
        if (entriesIndex == 0UL ||
            !KswordARKWin32kFallbackReadUlong(
                code, sizeof(code), entriesIndex + 3UL, &entriesOffset)) {
            continue;
        }
        for (search = entriesIndex + 7UL;
            search + 2UL < sizeof(code) && search <= entriesIndex + 36UL;
            ++search) {
            if (code[search] == 0x48U && code[search + 1UL] == 0x8BU &&
                code[search + 2UL] == 0x80U) {
                objectsIndex = search;
                break;
            }
        }
        if (objectsIndex == 0UL ||
            !KswordARKWin32kFallbackReadUlong(
                code, sizeof(code), objectsIndex + 3UL, &objectsOffset)) {
            continue;
        }
        if (!KswordARKWin32kFallbackSetUniqueOffset(
                &layout.SiloHandleEntrySize, sizeOffset, KSW_WIN32K_MAX_SILO_OFFSET) ||
            !KswordARKWin32kFallbackSetUniqueOffset(
                &layout.SiloHandleEntries, entriesOffset, KSW_WIN32K_MAX_SILO_OFFSET) ||
            !KswordARKWin32kFallbackSetUniqueOffset(
                &layout.SiloObjectSlots, objectsOffset, KSW_WIN32K_MAX_SILO_OFFSET)) {
            return FALSE;
        }
        foundTableSequence = TRUE;

        for (search = objectsIndex + 7UL; search + 12UL < sizeof(code) &&
            search <= objectsIndex + 52UL; ++search) {
            if (code[search] == 0x48U && code[search + 1UL] == 0xC1U &&
                code[search + 2UL] == 0xF9U &&
                code[search + 4UL] == 0x8BU && code[search + 5UL] == 0xC9U &&
                code[search + 6UL] == 0x48U && code[search + 7UL] == 0x8DU &&
                code[search + 8UL] == 0x14U && code[search + 9UL] == 0x89U) {
                ULONG scaleSearch = 0UL;

                if (!KswordARKWin32kFallbackSetUniqueOffset(
                        &layout.HandleEntryShift,
                        code[search + 3UL],
                        6UL)) {
                    return FALSE;
                }
                for (scaleSearch = search + 10UL;
                    scaleSearch + 3UL < sizeof(code) && scaleSearch <= search + 28UL;
                    ++scaleSearch) {
                    if (code[scaleSearch] == 0x48U &&
                        code[scaleSearch + 1UL] == 0x8DU &&
                        code[scaleSearch + 2UL] == 0x3CU &&
                        code[scaleSearch + 3UL] == 0xD0U) {
                        layout.ObjectSlotStride = 5UL * sizeof(ULONG64);
                        foundObjectScale = TRUE;
                        break;
                    }
                }
            }
        }
    }

    for (index = 0UL; index + 80UL < sizeof(code); ++index) {
        ULONG typeIndex = 0UL;
        ULONG flagIndex = 0UL;
        ULONG search = 0UL;

        if (code[index] != 0x66U || code[index + 1UL] != 0x41U ||
            code[index + 2UL] != 0x3BU || code[index + 3UL] != 0x46U) {
            continue;
        }
        for (search = index + 5UL;
            search + 4UL < sizeof(code) && search <= index + 64UL;
            ++search) {
            if (code[search] == 0x41U && code[search + 1UL] == 0x80U &&
                code[search + 2UL] == 0x7EU && code[search + 4UL] == 0x01U) {
                typeIndex = search;
                break;
            }
        }
        if (typeIndex == 0UL) {
            continue;
        }
        for (search = typeIndex + 5UL;
            search + 4UL < sizeof(code) && search <= typeIndex + 64UL;
            ++search) {
            if (code[search] == 0x41U && code[search + 1UL] == 0xF6U &&
                code[search + 2UL] == 0x46U && code[search + 4UL] == 0x01U) {
                flagIndex = search;
                break;
            }
        }
        if (flagIndex == 0UL ||
            !KswordARKWin32kFallbackSetUniqueOffset(
                &layout.HandleGeneration, code[index + 4UL], 0x80UL) ||
            !KswordARKWin32kFallbackSetUniqueOffset(
                &layout.HandleType, code[typeIndex + 3UL], 0x80UL) ||
            !KswordARKWin32kFallbackSetUniqueOffset(
                &layout.HandleFlags, code[flagIndex + 3UL], 0x80UL)) {
            return FALSE;
        }
        flagsInstruction = flagIndex;
        foundHandleMetadata = TRUE;
    }

    if (flagsInstruction != KSW_WIN32K_OFFSET_UNKNOWN) {
        for (index = flagsInstruction + 5UL;
            index + 3UL < sizeof(code) && index <= flagsInstruction + 32UL;
            ++index) {
            if (code[index] == 0x48U && code[index + 1UL] == 0x8BU &&
                code[index + 2UL] == 0x77U &&
                !KswordARKWin32kFallbackSetUniqueOffset(
                    &layout.TagWndThreadInfo,
                    code[index + 3UL],
                    0x100UL)) {
                return FALSE;
            }
        }
    }

    if (!foundTableSequence || !foundObjectScale || !foundHandleMetadata ||
        layout.SiloServerInfo == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.ServerHandleCount == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.HandleEntryShift == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.HandleEntryShift < 3UL || layout.HandleEntryShift > 6UL ||
        layout.ObjectSlotStride == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.TagWndThreadInfo == KSW_WIN32K_OFFSET_UNKNOWN ||
        layout.HandleGeneration == layout.HandleType ||
        layout.HandleGeneration == layout.HandleFlags ||
        layout.HandleType == layout.HandleFlags) {
        return FALSE;
    }
    *LayoutOut = layout;
    return TRUE;
}

static BOOLEAN
KswordARKWin32kFallbackDecodeHandleLayout(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _Out_ KSW_WIN32K_FALLBACK_LAYOUT* LayoutOut
    )
{
    ULONG_PTR exportAddress = 0U;
    ULONG_PTR target = 0U;
    ULONG index = 0UL;

    exportAddress = (ULONG_PTR)KswordARKRuntimeFindExport(View, "ValidateHwnd");
    if (exportAddress == 0U) {
        return FALSE;
    }
    if (KswordARKWin32kFallbackDecodeHandleLayoutAt(View, exportAddress, LayoutOut)) {
        return TRUE;
    }
    for (index = 0UL; index < 0x40UL; ++index) {
        if (KswordARKWin32kFallbackDecodeDirectBranch(
                View, exportAddress + index, &target) &&
            KswordARKWin32kFallbackDecodeHandleLayoutAt(View, target, LayoutOut)) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
KswordARKWin32kFallbackReferenceSessionProcess(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ ULONG SessionId,
    _Outptr_ PEPROCESS* ProcessOut
    )
{
    ULONG index = 0UL;

    if (Context == NULL || ProcessOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessOut = NULL;
    for (index = 0UL; index < Context->ThreadMapCount; ++index) {
        if (Context->ThreadMap[index].SessionId == SessionId) {
            NTSTATUS status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)Context->ThreadMap[index].ProcessId,
                ProcessOut);
            if (NT_SUCCESS(status) && *ProcessOut != NULL) {
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_NOT_FOUND;
}

static const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY*
KswordARKWin32kFallbackFindThreadInfo(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ ULONG64 ThreadInfo,
    _In_ ULONG SessionId
    )
{
    ULONG index = 0UL;

    if (Context == NULL || ThreadInfo == 0ULL) {
        return NULL;
    }
    for (index = 0UL; index < Context->ThreadMapCount; ++index) {
        if (Context->ThreadMap[index].ThreadInfo == ThreadInfo &&
            Context->ThreadMap[index].SessionId == SessionId) {
            return &Context->ThreadMap[index];
        }
    }
    return NULL;
}

static BOOLEAN
KswordARKWin32kFallbackRequestMatchesSession(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _In_ ULONG SessionId
    )
{
    ULONG index = 0UL;
    KSWORD_WIN32K_PS_GET_PROCESS_SESSION_ID_FN getSessionId = NULL;

    if (Request == NULL) {
        return TRUE;
    }
    if (Request->sessionId == 0UL &&
        (Request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL) {
        getSessionId = KswordARKWin32kResolvePsGetProcessSessionId();
        if (getSessionId == NULL ||
            getSessionId(PsGetCurrentProcess()) != SessionId) {
            return FALSE;
        }
    }
    if (Request->sessionId != 0UL && Request->sessionId != SessionId) {
        return FALSE;
    }
    if (Request->processId == 0UL && Request->threadId == 0UL) {
        return TRUE;
    }
    for (index = 0UL; index < Context->ThreadMapCount; ++index) {
        const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* entry =
            &Context->ThreadMap[index];
        if (entry->SessionId == SessionId &&
            (Request->processId == 0UL || Request->processId == entry->ProcessId) &&
            (Request->threadId == 0UL || Request->threadId == entry->ThreadId)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswordARKWin32kFallbackSessionAlreadyVisited(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ ULONG MapIndex
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < MapIndex; ++index) {
        if (Context->ThreadMap[index].SessionId ==
            Context->ThreadMap[MapIndex].SessionId) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswordARKWin32kFallbackInferHandleOffset(
    _In_ ULONG_PTR TagWnd,
    _In_ ULONG64 Hwnd,
    _Out_ ULONG* OffsetOut
    )
{
    UCHAR head[KSW_WIN32K_WINDOW_HEAD_BYTES];
    ULONG matchCount = 0UL;
    ULONG matchOffset = 0UL;
    ULONG offset = 0UL;

    if (OffsetOut == NULL ||
        !KswordARKWin32kFallbackRead(TagWnd, head, sizeof(head))) {
        return FALSE;
    }
    for (offset = 0UL; offset + sizeof(ULONG64) <= sizeof(head);
        offset += sizeof(ULONG64)) {
        ULONG64 value = 0ULL;
        RtlCopyMemory(&value, head + offset, sizeof(value));
        if (value == Hwnd) {
            matchOffset = offset;
            matchCount += 1UL;
        }
    }
    if (matchCount != 1UL) {
        return FALSE;
    }
    *OffsetOut = matchOffset;
    return TRUE;
}

NTSTATUS
KswordARKWin32kFallbackInitialize(
    _Out_ KSW_WIN32K_FALLBACK_CONTEXT* Context
    )
{
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleBytes = 0UL;
    KSW_RUNTIME_IMAGE_VIEW baseView;
    KSW_RUNTIME_IMAGE_VIEW fullView;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Context, sizeof(*Context));
    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    if (!KswordARKWin32kFindModuleByName(
            moduleInfo, "win32kbase.sys", &Context->Win32kbase) ||
        !KswordARKWin32kFindModuleByName(
            moduleInfo, "win32kfull.sys", &Context->Win32kfull)) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        return STATUS_NOT_FOUND;
    }
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    UNREFERENCED_PARAMETER(moduleBytes);

    if (!KswordARKRuntimeInitializeImageView(
            Context->Win32kbase.ImageBase,
            Context->Win32kbase.ImageSize,
            &baseView) ||
        !KswordARKRuntimeInitializeImageView(
            Context->Win32kfull.ImageBase,
            Context->Win32kfull.ImageSize,
            &fullView)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    Context->UserGetSiloGlobals = (ULONG_PTR)KswordARKRuntimeFindExport(
        &baseView,
        "UserGetSiloGlobals");
    Context->HandleLayoutResolved =
        Context->UserGetSiloGlobals != 0U &&
        KswordARKWin32kFallbackDecodeHandleLayout(&baseView, &Context->Layout);
    if (!Context->HandleLayoutResolved) {
        RtlZeroMemory(&Context->Layout, sizeof(Context->Layout));
        Context->Layout.TagWndHandle = KSW_WIN32K_OFFSET_UNKNOWN;
        Context->Layout.TagQCaretWindow = KSW_WIN32K_OFFSET_UNKNOWN;
    }
    Context->QueueLayoutResolved = KswordARKWin32kFallbackDecodeQueueLayout(
        &fullView,
        &Context->Layout);
    if (!Context->HandleLayoutResolved && !Context->QueueLayoutResolved) {
        return STATUS_NOT_SUPPORTED;
    }

    status = KswordARKWin32kBuildGuiThreadMap(
        KSW_WIN32K_FALLBACK_MAP_LIMIT,
        KSW_WIN32K_FALLBACK_POOL_TAG,
        &Context->ThreadMap,
        &Context->ThreadMapCount,
        &Context->ThreadMapTruncated);
    if (!NT_SUCCESS(status) || Context->ThreadMap == NULL ||
        Context->ThreadMapCount == 0UL) {
        KswordARKWin32kFallbackCleanup(Context);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    return STATUS_SUCCESS;
}

VOID
KswordARKWin32kFallbackCleanup(
    _Inout_ KSW_WIN32K_FALLBACK_CONTEXT* Context
    )
{
    if (Context == NULL) {
        return;
    }
    if (Context->ThreadMap != NULL) {
        ExFreePoolWithTag(Context->ThreadMap, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    RtlZeroMemory(Context, sizeof(*Context));
}

NTSTATUS
KswordARKWin32kFallbackEnumerateWindows(
    _Inout_ KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _Out_writes_(WindowCapacity) KSW_WIN32K_FALLBACK_WINDOW* Windows,
    _In_ ULONG WindowCapacity,
    _Out_ ULONG* WindowCountOut,
    _Out_ ULONG* TotalCountOut,
    _Out_ BOOLEAN* TruncatedOut
    )
{
    ULONG mapIndex = 0UL;
    ULONG windowCount = 0UL;
    ULONG totalCount = 0UL;
    ULONG inferredHandleOffset = KSW_WIN32K_OFFSET_UNKNOWN;
    BOOLEAN truncated = FALSE;
    BOOLEAN validatedSession = FALSE;

    if (Context == NULL || Windows == NULL || WindowCapacity == 0UL ||
        WindowCountOut == NULL || TotalCountOut == NULL || TruncatedOut == NULL ||
        !Context->HandleLayoutResolved || Context->ThreadMap == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    *WindowCountOut = 0UL;
    *TotalCountOut = 0UL;
    *TruncatedOut = FALSE;
    RtlZeroMemory(Windows, sizeof(*Windows) * WindowCapacity);

    for (mapIndex = 0UL; mapIndex < Context->ThreadMapCount; ++mapIndex) {
        const ULONG sessionId = Context->ThreadMap[mapIndex].SessionId;
        PEPROCESS sessionProcess = NULL;
        DECLSPEC_ALIGN(16) UCHAR attachState[128];
        BOOLEAN attached = FALSE;
        PVOID siloGlobals = NULL;
        ULONG_PTR serverInfo = 0U;
        ULONG_PTR handleEntries = 0U;
        ULONG_PTR objectSlots = 0U;
        ULONG_PTR handleCountValue = 0U;
        ULONG handleEntrySize = 0UL;
        ULONG handleCount = 0UL;
        ULONG handleIndex = 0UL;
        NTSTATUS status = STATUS_SUCCESS;

        if (KswordARKWin32kFallbackSessionAlreadyVisited(Context, mapIndex) ||
            !KswordARKWin32kFallbackRequestMatchesSession(Context, Request, sessionId)) {
            continue;
        }
        status = KswordARKWin32kFallbackReferenceSessionProcess(
            Context,
            sessionId,
            &sessionProcess);
        if (!NT_SUCCESS(status) || sessionProcess == NULL) {
            truncated = TRUE;
            continue;
        }
        RtlZeroMemory(attachState, sizeof(attachState));
        KeStackAttachProcess((PVOID)sessionProcess, attachState);
        attached = TRUE;
        __try {
            siloGlobals = ((KSW_USER_GET_SILO_GLOBALS_FN)
                Context->UserGetSiloGlobals)();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            siloGlobals = NULL;
        }
        if (siloGlobals == NULL ||
            !KswordARKWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + Context->Layout.SiloServerInfo,
                &serverInfo,
                sizeof(serverInfo)) ||
            !KswordARKWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + Context->Layout.SiloHandleEntrySize,
                &handleEntrySize,
                sizeof(handleEntrySize)) ||
            !KswordARKWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + Context->Layout.SiloHandleEntries,
                &handleEntries,
                sizeof(handleEntries)) ||
            !KswordARKWin32kFallbackRead(
                (ULONG_PTR)siloGlobals + Context->Layout.SiloObjectSlots,
                &objectSlots,
                sizeof(objectSlots)) ||
            !KswordARKWin32kFallbackRead(
                serverInfo + Context->Layout.ServerHandleCount,
                &handleCountValue,
                sizeof(handleCountValue)) ||
            !KswordARKWin32kFallbackIsKernelAddress(serverInfo) ||
            !KswordARKWin32kFallbackIsKernelAddress(handleEntries) ||
            !KswordARKWin32kFallbackIsKernelAddress(objectSlots) ||
            handleEntrySize != (1UL << Context->Layout.HandleEntryShift) ||
            handleEntrySize < 8UL || handleEntrySize > 0x40UL ||
            handleCountValue == 0U) {
            truncated = TRUE;
            goto DetachSession;
        }
        handleCount = handleCountValue > KSW_WIN32K_MAX_SESSION_HANDLES
            ? KSW_WIN32K_MAX_SESSION_HANDLES
            : (ULONG)handleCountValue;
        if (handleCountValue > KSW_WIN32K_MAX_SESSION_HANDLES) {
            truncated = TRUE;
        }

        for (handleIndex = 0UL; handleIndex < handleCount; ++handleIndex) {
            ULONG_PTR entryAddress = 0U;
            ULONG_PTR slotAddress = 0U;
            ULONG_PTR tagWnd = 0U;
            ULONG64 threadInfo = 0ULL;
            ULONG64 hwnd = 0ULL;
            USHORT generation = 0U;
            UCHAR type = 0U;
            UCHAR flags = 0U;
            ULONG handleOffset = 0UL;
            const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* owner = NULL;

            if (handleEntries > MAXULONG_PTR -
                    ((ULONG_PTR)handleIndex * handleEntrySize) ||
                objectSlots > MAXULONG_PTR -
                    ((ULONG_PTR)handleIndex * Context->Layout.ObjectSlotStride)) {
                truncated = TRUE;
                break;
            }
            entryAddress = handleEntries + ((ULONG_PTR)handleIndex * handleEntrySize);
            slotAddress = objectSlots +
                ((ULONG_PTR)handleIndex * Context->Layout.ObjectSlotStride);
            if (!KswordARKWin32kFallbackRead(
                    entryAddress + Context->Layout.HandleType,
                    &type,
                    sizeof(type)) ||
                !KswordARKWin32kFallbackRead(
                    entryAddress + Context->Layout.HandleFlags,
                    &flags,
                    sizeof(flags)) ||
                !KswordARKWin32kFallbackRead(
                    entryAddress + Context->Layout.HandleGeneration,
                    &generation,
                    sizeof(generation)) ||
                type != 1U || (flags & 1U) != 0U ||
                !KswordARKWin32kFallbackRead(
                    slotAddress,
                    &tagWnd,
                    sizeof(tagWnd)) ||
                !KswordARKWin32kFallbackIsKernelAddress(tagWnd) ||
                !KswordARKWin32kFallbackRead(
                    tagWnd + Context->Layout.TagWndThreadInfo,
                    &threadInfo,
                    sizeof(threadInfo))) {
                continue;
            }
            owner = KswordARKWin32kFallbackFindThreadInfo(
                Context,
                threadInfo,
                sessionId);
            if (owner == NULL) {
                continue;
            }
            hwnd = (ULONG64)((handleIndex & 0xFFFFUL) |
                (((ULONG)generation & 0x7FFFUL) << 16U));
            if (!KswordARKWin32kFallbackInferHandleOffset(
                    tagWnd,
                    hwnd,
                    &handleOffset)) {
                continue;
            }
            if (inferredHandleOffset == KSW_WIN32K_OFFSET_UNKNOWN) {
                inferredHandleOffset = handleOffset;
            }
            else if (inferredHandleOffset != handleOffset) {
                if (attached) {
                    KeUnstackDetachProcess(attachState);
                }
                ObDereferenceObject(sessionProcess);
                RtlZeroMemory(Windows, sizeof(*Windows) * WindowCapacity);
                return STATUS_DATA_ERROR;
            }
            validatedSession = TRUE;
            if (Request != NULL &&
                ((Request->processId != 0UL && Request->processId != owner->ProcessId) ||
                 (Request->threadId != 0UL && Request->threadId != owner->ThreadId))) {
                continue;
            }
            totalCount += 1UL;
            if (windowCount >= WindowCapacity) {
                truncated = TRUE;
                continue;
            }
            Windows[windowCount].Hwnd = hwnd;
            Windows[windowCount].TagWnd = (ULONG64)tagWnd;
            Windows[windowCount].ThreadInfo = threadInfo;
            Windows[windowCount].ProcessId = owner->ProcessId;
            Windows[windowCount].ThreadId = owner->ThreadId;
            Windows[windowCount].SessionId = owner->SessionId;
            windowCount += 1UL;
        }

DetachSession:
        if (attached) {
            KeUnstackDetachProcess(attachState);
        }
        ObDereferenceObject(sessionProcess);
    }

    if (!validatedSession || inferredHandleOffset == KSW_WIN32K_OFFSET_UNKNOWN) {
        RtlZeroMemory(Windows, sizeof(*Windows) * WindowCapacity);
        return STATUS_NOT_FOUND;
    }
    Context->Layout.TagWndHandle = inferredHandleOffset;
    *WindowCountOut = windowCount;
    *TotalCountOut = totalCount;
    *TruncatedOut = truncated || Context->ThreadMapTruncated;
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKWin32kFallbackResolveWindowPointer(
    _In_ ULONG64 WindowPointer,
    _In_ ULONG SessionId,
    _In_reads_(WindowCount) const KSW_WIN32K_FALLBACK_WINDOW* Windows,
    _In_ ULONG WindowCount,
    _Out_ ULONG64* HwndOut
    )
{
    ULONG index = 0UL;

    if (HwndOut == NULL) {
        return FALSE;
    }
    *HwndOut = 0ULL;
    if (WindowPointer == 0ULL) {
        return TRUE;
    }
    for (index = 0UL; index < WindowCount; ++index) {
        if (Windows[index].TagWnd == WindowPointer &&
            Windows[index].SessionId == SessionId) {
            *HwndOut = Windows[index].Hwnd;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
KswordARKWin32kFallbackReadQueue(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* ThreadEntry,
    _In_reads_(WindowCount) const KSW_WIN32K_FALLBACK_WINDOW* Windows,
    _In_ ULONG WindowCount,
    _Out_ KSW_WIN32K_FALLBACK_QUEUE* QueueOut
    )
{
    PEPROCESS sessionProcess = NULL;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    ULONG_PTR queue = 0U;
    ULONG64 active = 0ULL;
    ULONG64 focus = 0ULL;
    ULONG64 capture = 0ULL;
    ULONG64 caret = 0ULL;
    BOOLEAN result = FALSE;

    if (Context == NULL || ThreadEntry == NULL || Windows == NULL ||
        QueueOut == NULL || !Context->QueueLayoutResolved ||
        Context->Layout.TagThreadInfoQueue == KSW_WIN32K_OFFSET_UNKNOWN ||
        KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !NT_SUCCESS(KswordARKWin32kFallbackReferenceSessionProcess(
            Context, ThreadEntry->SessionId, &sessionProcess)) ||
        sessionProcess == NULL) {
        return FALSE;
    }
    RtlZeroMemory(QueueOut, sizeof(*QueueOut));
    RtlZeroMemory(attachState, sizeof(attachState));
    KeStackAttachProcess((PVOID)sessionProcess, attachState);

    if (KswordARKWin32kFallbackRead(
            (ULONG_PTR)ThreadEntry->ThreadInfo + Context->Layout.TagThreadInfoQueue,
            &queue,
            sizeof(queue)) &&
        KswordARKWin32kFallbackIsKernelAddress(queue) &&
        KswordARKWin32kFallbackRead(
            queue + Context->Layout.TagQActiveWindow,
            &active,
            sizeof(active)) &&
        KswordARKWin32kFallbackRead(
            queue + Context->Layout.TagQFocusWindow,
            &focus,
            sizeof(focus)) &&
        KswordARKWin32kFallbackRead(
            queue + Context->Layout.TagQCaptureWindow,
            &capture,
            sizeof(capture)) &&
        KswordARKWin32kFallbackResolveWindowPointer(
            active, ThreadEntry->SessionId, Windows, WindowCount,
            &QueueOut->ActiveHwnd) &&
        KswordARKWin32kFallbackResolveWindowPointer(
            focus, ThreadEntry->SessionId, Windows, WindowCount,
            &QueueOut->FocusHwnd) &&
        KswordARKWin32kFallbackResolveWindowPointer(
            capture, ThreadEntry->SessionId, Windows, WindowCount,
            &QueueOut->CaptureHwnd)) {
        if (Context->Layout.TagQCaretWindow != KSW_WIN32K_OFFSET_UNKNOWN) {
            if (!KswordARKWin32kFallbackRead(
                    queue + Context->Layout.TagQCaretWindow,
                    &caret,
                    sizeof(caret)) ||
                !KswordARKWin32kFallbackResolveWindowPointer(
                    caret, ThreadEntry->SessionId, Windows, WindowCount,
                    &QueueOut->CaretHwnd)) {
                QueueOut->CaretHwnd = 0ULL;
            }
        }
        QueueOut->QueueObject = (ULONG64)queue;
        result = TRUE;
    }
    KeUnstackDetachProcess(attachState);
    ObDereferenceObject(sessionProcess);
    return result;
}

VOID
KswordARKWin32kFallbackPublishOffsets(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _Out_ KSWORD_ARK_WIN32K_FIELD_OFFSETS* Offsets
    )
{
    if (Offsets == NULL) {
        return;
    }
    KswordARKWin32kInitializeOffsets(Offsets);
    if (Context == NULL) {
        return;
    }
    if (Context->HandleLayoutResolved) {
        Offsets->tagWndThreadInfo = Context->Layout.TagWndThreadInfo;
    }
    if (Context->QueueLayoutResolved) {
        Offsets->tagThreadInfoQueue = Context->Layout.TagThreadInfoQueue;
        Offsets->tagQActiveWindow = Context->Layout.TagQActiveWindow;
        Offsets->tagQFocusWindow = Context->Layout.TagQFocusWindow;
        Offsets->tagQCaptureWindow = Context->Layout.TagQCaptureWindow;
        if (Context->Layout.TagQCaretWindow != KSW_WIN32K_OFFSET_UNKNOWN) {
            Offsets->tagQCaretWindow = Context->Layout.TagQCaretWindow;
        }
    }
}

ULONG64
KswordARKWin32kFallbackProbeCapabilityMask(
    VOID
    )
{
    KSW_WIN32K_FALLBACK_CONTEXT context;
    NTSTATUS status = KswordARKWin32kFallbackInitialize(&context);
    ULONG64 mask = 0ULL;

    if (!NT_SUCCESS(status)) {
        return 0ULL;
    }
    if (context.HandleLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGWND_SIGNATURE;
    }
    if (context.QueueLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGQ_SIGNATURE;
    }
    KswordARKWin32kFallbackCleanup(&context);
    return mask;
}
