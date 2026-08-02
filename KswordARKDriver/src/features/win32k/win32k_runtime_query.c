/*++

Module Name:

    win32k_runtime_query.c

Abstract:

    Protocol adapters for the validated Win32k signature fallback.  Only
    identity fields whose live relationships were proved are returned;
    PDB-only text, class, desktop, style, and rectangle fields remain marked
    unavailable instead of being guessed.

Environment:

    Kernel mode, PASSIVE_LEVEL IOCTL query paths.

--*/

#include "win32k_fallback.h"
#include "win32k_query.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

#define KSW_WIN32K_WINDOW_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE) - \
        sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY))
#define KSW_WIN32K_GUI_THREAD_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE) - \
        sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY))

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Outptr_ PETHREAD* Thread
    );

typedef struct _KSW_WIN32K_PROFILE_ONE_ENTRY_RESPONSE
{
    KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE Header;
    KSWORD_ARK_WIN32K_SESSION_ENTRY ExtraEntry;
} KSW_WIN32K_PROFILE_ONE_ENTRY_RESPONSE, *PKSW_WIN32K_PROFILE_ONE_ENTRY_RESPONSE;

static ULONG64
KswordARKWin32kFallbackCapabilityMask(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ BOOLEAN EnumerationValidated
    )
{
    ULONG64 mask = KSWORD_ARK_WIN32K_CAP_WIN32KBASE_LOADED |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_LOADED |
        KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC;

    if (Context == NULL) {
        return 0ULL;
    }
    if (Context->UserGetSiloGlobals != 0U) {
        mask |= KSWORD_ARK_WIN32K_CAP_USER_GET_SILO_GLOBALS;
    }
    if (Context->HandleLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGWND_SIGNATURE;
    }
    if (Context->QueueLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGQ_SIGNATURE;
    }
    if (EnumerationValidated) {
        mask |= KSWORD_ARK_WIN32K_CAP_WINDOW_ENUM;
    }
    return mask;
}

static ULONG
KswordARKWin32kFallbackEntryCapacity(
    _In_ size_t OutputLength,
    _In_ size_t HeaderLength,
    _In_ size_t EntryLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request
    )
{
    size_t capacity = 0U;
    ULONG maximum = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;

    if (OutputLength < HeaderLength || EntryLength == 0U) {
        return 0UL;
    }
    capacity = (OutputLength - HeaderLength) / EntryLength;
    if (Request != NULL) {
        maximum = KswordARKWin32kNormalizeMaxEntries(Request->maxEntries);
    }
    if (capacity > (size_t)maximum) {
        capacity = maximum;
    }
    if (capacity > KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES) {
        capacity = KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES;
    }
    return (ULONG)capacity;
}

static VOID
KswordARKWin32kFallbackSetWindowFailure(
    _Inout_ KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE* Response,
    _In_ NTSTATUS Status
    )
{
    Response->status = (Status == STATUS_NOT_FOUND)
        ? KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING
        : KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
    Response->lastStatus = Status;
    Response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
}

NTSTATUS
KswordARKWin32kFallbackQueryWindowSnapshot(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE* response =
        (KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE*)OutputBuffer;
    KSW_WIN32K_FALLBACK_CONTEXT context;
    KSW_WIN32K_FALLBACK_WINDOW* windows = NULL;
    ULONG capacity = 0UL;
    ULONG count = 0UL;
    ULONG total = 0UL;
    ULONG index = 0UL;
    BOOLEAN truncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBuffer == NULL || OutputBufferLength < KSW_WIN32K_WINDOW_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY);
    response->flags = Request != NULL ? Request->flags : 0UL;
    response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    response->lastStatus = STATUS_NOT_FOUND;
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
    KswordARKWin32kInitializeOffsets(&response->fieldOffsets);
    *BytesWrittenOut = KSW_WIN32K_WINDOW_HEADER_SIZE;

    if (Request != NULL && Request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }
    capacity = KswordARKWin32kFallbackEntryCapacity(
        OutputBufferLength,
        KSW_WIN32K_WINDOW_HEADER_SIZE,
        sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY),
        Request);
    if (capacity == 0UL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return STATUS_SUCCESS;
    }
    status = KswordARKWin32kFallbackInitialize(&context);
    if (!NT_SUCCESS(status)) {
        KswordARKWin32kFallbackSetWindowFailure(response, status);
        return STATUS_SUCCESS;
    }
    windows = (KSW_WIN32K_FALLBACK_WINDOW*)KswordARKAllocateNonPagedPool(
        sizeof(*windows) * capacity,
        KSW_WIN32K_FALLBACK_POOL_TAG);
    if (windows == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    status = KswordARKWin32kFallbackEnumerateWindows(
        &context,
        Request,
        windows,
        capacity,
        &count,
        &total,
        &truncated);
    if (!NT_SUCCESS(status)) {
        KswordARKWin32kFallbackSetWindowFailure(response, status);
        goto Cleanup;
    }

    response->capabilityMask = KswordARKWin32kFallbackCapabilityMask(
        &context,
        TRUE);
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
    response->status = truncated
        ? KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED
        : KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    response->lastStatus = truncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    response->totalCount = total;
    response->returnedCount = count;
    KswordARKWin32kFallbackPublishOffsets(&context, &response->fieldOffsets);

    for (index = 0UL; index < count; ++index) {
        KSWORD_ARK_WIN32K_WINDOW_ENTRY* entry = &response->entries[index];

        entry->fieldFlags = KSWORD_ARK_WIN32K_FIELD_HWND_PRESENT |
            KSWORD_ARK_WIN32K_FIELD_TAGWND_PRESENT |
            KSWORD_ARK_WIN32K_FIELD_THREADINFO_PRESENT;
        entry->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        entry->processId = windows[index].ProcessId;
        entry->threadId = windows[index].ThreadId;
        entry->sessionId = windows[index].SessionId;
        entry->titleStatus = KSWORD_ARK_WIN32K_READ_STATUS_PROFILE_MISSING;
        entry->classStatus = KSWORD_ARK_WIN32K_READ_STATUS_PROFILE_MISSING;
        entry->lastStatus = STATUS_SUCCESS;
        entry->hwnd = windows[index].Hwnd;
        entry->tagWnd = windows[index].TagWnd;
        entry->threadInfo = windows[index].ThreadInfo;
        KswordARKWin32kCopyWideText(
            entry->detail,
            KSWORD_ARK_WIN32K_DETAIL_CHARS,
            L"HWND identity was recovered by a validated ValidateHwnd signature; PDB-only text and geometry fields remain unavailable.");
    }
    *BytesWrittenOut = KSW_WIN32K_WINDOW_HEADER_SIZE +
        ((size_t)count * sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY));

Cleanup:
    if (windows != NULL) {
        ExFreePoolWithTag(windows, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    KswordARKWin32kFallbackCleanup(&context);
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKWin32kFallbackThreadMatchesRequest(
    _In_ const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* Entry,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request
    )
{
    KSWORD_WIN32K_PS_GET_PROCESS_SESSION_ID_FN getSessionId = NULL;

    if (Entry == NULL) {
        return FALSE;
    }
    if (Request != NULL && Request->sessionId == 0UL &&
        (Request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL) {
        getSessionId = KswordARKWin32kResolvePsGetProcessSessionId();
        if (getSessionId == NULL ||
            getSessionId(PsGetCurrentProcess()) != Entry->SessionId) {
            return FALSE;
        }
    }
    return Request == NULL ||
        ((Request->sessionId == 0UL || Request->sessionId == Entry->SessionId) &&
         (Request->processId == 0UL || Request->processId == Entry->ProcessId) &&
         (Request->threadId == 0UL || Request->threadId == Entry->ThreadId));
}

NTSTATUS
KswordARKWin32kFallbackQueryGuiThreadSnapshot(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE* response =
        (KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE*)OutputBuffer;
    KSW_WIN32K_FALLBACK_CONTEXT context;
    KSW_WIN32K_FALLBACK_WINDOW* windows = NULL;
    KSWORD_ARK_WIN32K_QUERY_REQUEST windowRequest;
    ULONG capacity = 0UL;
    ULONG windowCount = 0UL;
    ULONG windowTotal = 0UL;
    ULONG mapIndex = 0UL;
    BOOLEAN windowsTruncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBuffer == NULL || OutputBufferLength < KSW_WIN32K_GUI_THREAD_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY);
    response->flags = Request != NULL ? Request->flags : 0UL;
    response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    response->lastStatus = STATUS_NOT_FOUND;
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    KswordARKWin32kInitializeOffsets(&response->fieldOffsets);
    *BytesWrittenOut = KSW_WIN32K_GUI_THREAD_HEADER_SIZE;

    if (Request != NULL && Request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }
    capacity = KswordARKWin32kFallbackEntryCapacity(
        OutputBufferLength,
        KSW_WIN32K_GUI_THREAD_HEADER_SIZE,
        sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY),
        Request);
    if (capacity == 0UL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return STATUS_SUCCESS;
    }
    status = KswordARKWin32kFallbackInitialize(&context);
    if (!NT_SUCCESS(status) || !context.HandleLayoutResolved ||
        !context.QueueLayoutResolved) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        if (NT_SUCCESS(status)) {
            KswordARKWin32kFallbackCleanup(&context);
        }
        return STATUS_SUCCESS;
    }
    windows = (KSW_WIN32K_FALLBACK_WINDOW*)KswordARKAllocateNonPagedPool(
        sizeof(*windows) * KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        KSW_WIN32K_FALLBACK_POOL_TAG);
    if (windows == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(&windowRequest, sizeof(windowRequest));
    windowRequest.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    if (Request != NULL) {
        windowRequest.flags = Request->flags;
        windowRequest.sessionId = Request->sessionId;
    }
    windowRequest.maxEntries = KSW_WIN32K_FALLBACK_WINDOW_LIMIT;
    status = KswordARKWin32kFallbackEnumerateWindows(
        &context,
        &windowRequest,
        windows,
        KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        &windowCount,
        &windowTotal,
        &windowsTruncated);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
        response->lastStatus = status;
        goto Cleanup;
    }

    response->capabilityMask = KswordARKWin32kFallbackCapabilityMask(
        &context,
        TRUE);
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    response->lastStatus = windowsTruncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    KswordARKWin32kFallbackPublishOffsets(&context, &response->fieldOffsets);

    for (mapIndex = 0UL; mapIndex < context.ThreadMapCount; ++mapIndex) {
        const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* thread =
            &context.ThreadMap[mapIndex];
        KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY* entry = NULL;
        KSW_WIN32K_FALLBACK_QUEUE queue;
        PETHREAD threadObject = NULL;

        if (!KswordARKWin32kFallbackThreadMatchesRequest(thread, Request)) {
            continue;
        }
        response->totalCount += 1UL;
        if (response->returnedCount >= capacity) {
            response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
            response->lastStatus = STATUS_BUFFER_OVERFLOW;
            continue;
        }
        entry = &response->entries[response->returnedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->fieldFlags = KSWORD_ARK_WIN32K_FIELD_THREADINFO_PRESENT;
        entry->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        entry->processId = thread->ProcessId;
        entry->threadId = thread->ThreadId;
        entry->sessionId = thread->SessionId;
        entry->threadInfo = thread->ThreadInfo;
        entry->lastStatus = STATUS_SUCCESS;
        if (NT_SUCCESS(PsLookupThreadByThreadId(
                (HANDLE)(ULONG_PTR)thread->ThreadId,
                &threadObject)) && threadObject != NULL) {
            entry->ethread = (ULONG64)(ULONG_PTR)threadObject;
            ObDereferenceObject(threadObject);
        }

        RtlZeroMemory(&queue, sizeof(queue));
        if (KswordARKWin32kFallbackReadQueue(
                &context,
                thread,
                windows,
                windowCount,
                &queue)) {
            entry->fieldFlags |= KSWORD_ARK_WIN32K_FIELD_QUEUE_PRESENT;
            entry->queueStatus = KSWORD_ARK_WIN32K_READ_STATUS_OK;
            entry->queueObject = queue.QueueObject;
            entry->activeHwnd = queue.ActiveHwnd;
            entry->focusHwnd = queue.FocusHwnd;
            entry->captureHwnd = queue.CaptureHwnd;
            entry->caretHwnd = queue.CaretHwnd;
            KswordARKWin32kCopyWideText(
                entry->detail,
                KSWORD_ARK_WIN32K_DETAIL_CHARS,
                L"tagQ core window fields were decoded from a validated NtUserGetGUIThreadInfo signature.");
        }
        else {
            entry->queueStatus = windowsTruncated
                ? KSWORD_ARK_WIN32K_READ_STATUS_TRUNCATED
                : KSWORD_ARK_WIN32K_READ_STATUS_READ_FAILED;
            entry->lastStatus = windowsTruncated
                ? STATUS_BUFFER_OVERFLOW
                : STATUS_PARTIAL_COPY;
            KswordARKWin32kCopyWideText(
                entry->detail,
                KSWORD_ARK_WIN32K_DETAIL_CHARS,
                L"The tagQ signature candidate failed live window-pointer validation and was not published.");
        }
        response->returnedCount += 1UL;
    }
    *BytesWrittenOut = KSW_WIN32K_GUI_THREAD_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY));
    UNREFERENCED_PARAMETER(windowTotal);

Cleanup:
    if (windows != NULL) {
        ExFreePoolWithTag(windows, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    KswordARKWin32kFallbackCleanup(&context);
    return STATUS_SUCCESS;
}

static const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY*
KswordARKWin32kFallbackFindDetailThread(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ const KSW_WIN32K_FALLBACK_WINDOW* Window
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < Context->ThreadMapCount; ++index) {
        if (Context->ThreadMap[index].ThreadInfo == Window->ThreadInfo &&
            Context->ThreadMap[index].SessionId == Window->SessionId) {
            return &Context->ThreadMap[index];
        }
    }
    return NULL;
}

NTSTATUS
KswordARKWin32kFallbackQueryWindowDetail(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSW_WIN32K_PROFILE_ONE_ENTRY_RESPONSE profileResponse;
    KSWORD_ARK_WIN32K_QUERY_REQUEST profileRequest;
    KSW_WIN32K_FALLBACK_CONTEXT context;
    KSW_WIN32K_FALLBACK_WINDOW* windows = NULL;
    KSWORD_ARK_WIN32K_QUERY_REQUEST windowRequest;
    const KSW_WIN32K_FALLBACK_WINDOW* match = NULL;
    const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* thread = NULL;
    KSW_WIN32K_FALLBACK_QUEUE queue;
    size_t profileBytes = 0U;
    ULONG windowCount = 0UL;
    ULONG windowTotal = 0UL;
    ULONG index = 0UL;
    ULONG targetSession = 0UL;
    BOOLEAN targetSessionFound = FALSE;
    BOOLEAN truncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutputBufferLength < sizeof(*Response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWrittenOut = sizeof(*Response);
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    Response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    Response->processId = Request->processId;
    Response->threadId = Request->threadId;
    Response->flags = Request->flags;
    Response->hwnd = Request->hwnd;
    Response->lastStatus = STATUS_NOT_FOUND;
    Response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    KswordARKWin32kInitializeOffsets(&Response->fieldOffsets);

    if (Request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION ||
        Request->hwnd == 0ULL) {
        Response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        Response->lastStatus = Request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION
            ? STATUS_REVISION_MISMATCH
            : STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&profileRequest, sizeof(profileRequest));
    profileRequest.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    profileRequest.maxEntries = 1UL;
    RtlZeroMemory(&profileResponse, sizeof(profileResponse));
    status = KswordARKWin32kQueryProfileStatus(
        &profileResponse,
        sizeof(profileResponse),
        &profileRequest,
        &profileBytes);
    if (NT_SUCCESS(status)) {
        Response->win32k = profileResponse.Header.win32k;
        Response->win32kbase = profileResponse.Header.win32kbase;
        Response->win32kfull = profileResponse.Header.win32kfull;
    }

    status = KswordARKWin32kFallbackInitialize(&context);
    if (!NT_SUCCESS(status) || !context.HandleLayoutResolved) {
        Response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        if (NT_SUCCESS(status)) {
            KswordARKWin32kFallbackCleanup(&context);
        }
        return STATUS_SUCCESS;
    }
    for (index = 0UL; index < context.ThreadMapCount; ++index) {
        const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* candidate =
            &context.ThreadMap[index];
        if ((Request->processId == 0UL || Request->processId == candidate->ProcessId) &&
            (Request->threadId == 0UL || Request->threadId == candidate->ThreadId)) {
            if (targetSessionFound && targetSession != candidate->SessionId) {
                Response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
                Response->lastStatus = STATUS_OBJECT_NAME_COLLISION;
                goto Cleanup;
            }
            targetSession = candidate->SessionId;
            targetSessionFound = TRUE;
        }
    }
    if (!targetSessionFound &&
        (Request->processId != 0UL || Request->threadId != 0UL)) {
        Response->lastStatus = STATUS_NOT_FOUND;
        goto Cleanup;
    }
    windows = (KSW_WIN32K_FALLBACK_WINDOW*)KswordARKAllocateNonPagedPool(
        sizeof(*windows) * KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        KSW_WIN32K_FALLBACK_POOL_TAG);
    if (windows == NULL) {
        Response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
        Response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(&windowRequest, sizeof(windowRequest));
    windowRequest.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    windowRequest.sessionId = targetSession;
    windowRequest.maxEntries = KSW_WIN32K_FALLBACK_WINDOW_LIMIT;
    status = KswordARKWin32kFallbackEnumerateWindows(
        &context,
        &windowRequest,
        windows,
        KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        &windowCount,
        &windowTotal,
        &truncated);
    if (!NT_SUCCESS(status)) {
        Response->lastStatus = status;
        goto Cleanup;
    }
    for (index = 0UL; index < windowCount; ++index) {
        if (windows[index].Hwnd == Request->hwnd &&
            (Request->processId == 0UL || Request->processId == windows[index].ProcessId) &&
            (Request->threadId == 0UL || Request->threadId == windows[index].ThreadId)) {
            if (match != NULL) {
                Response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
                Response->lastStatus = STATUS_OBJECT_NAME_COLLISION;
                goto Cleanup;
            }
            match = &windows[index];
        }
    }
    if (match == NULL) {
        Response->lastStatus = truncated ? STATUS_BUFFER_OVERFLOW : STATUS_NOT_FOUND;
        goto Cleanup;
    }

    Response->processId = match->ProcessId;
    Response->threadId = match->ThreadId;
    Response->hwnd = match->Hwnd;
    Response->tagWnd = match->TagWnd;
    Response->threadInfo = match->ThreadInfo;
    Response->fieldFlags = KSWORD_ARK_WIN32K_FIELD_HWND_PRESENT |
        KSWORD_ARK_WIN32K_FIELD_TAGWND_PRESENT |
        KSWORD_ARK_WIN32K_FIELD_THREADINFO_PRESENT |
        KSWORD_ARK_WIN32K_FIELD_DETAIL_IDENTITY |
        KSWORD_ARK_WIN32K_FIELD_DETAIL_OFFSETS;
    Response->capabilityMask = KswordARKWin32kFallbackCapabilityMask(
        &context,
        TRUE);
    KswordARKWin32kFallbackPublishOffsets(&context, &Response->fieldOffsets);
    Response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    Response->lastStatus = truncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;

    thread = KswordARKWin32kFallbackFindDetailThread(&context, match);
    RtlZeroMemory(&queue, sizeof(queue));
    if (thread != NULL && KswordARKWin32kFallbackReadQueue(
            &context,
            thread,
            windows,
            windowCount,
            &queue)) {
        Response->fieldFlags |= KSWORD_ARK_WIN32K_FIELD_QUEUE_PRESENT;
        Response->queueObject = queue.QueueObject;
    }
    KswordARKWin32kCopyWideText(
        Response->detail,
        KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS,
        L"The HWND, tagWND, tagTHREADINFO, and optional tagQ identity passed signature and live relationship validation; PDB-only text and class fields remain unavailable.");
    UNREFERENCED_PARAMETER(windowTotal);
    UNREFERENCED_PARAMETER(profileBytes);

Cleanup:
    if (windows != NULL) {
        ExFreePoolWithTag(windows, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    KswordARKWin32kFallbackCleanup(&context);
    return STATUS_SUCCESS;
}
