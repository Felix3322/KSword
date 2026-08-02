#pragma once

#include "win32k_support.h"
#include "../../platform/runtime_signature_scan.h"

EXTERN_C_START

#define KSW_WIN32K_FALLBACK_MAP_LIMIT       8192UL
#define KSW_WIN32K_FALLBACK_WINDOW_LIMIT    8192UL
#define KSW_WIN32K_FALLBACK_POOL_TAG        'fWkW'

typedef struct _KSW_WIN32K_FALLBACK_LAYOUT
{
    ULONG SiloServerInfo;
    ULONG SiloHandleEntrySize;
    ULONG SiloHandleEntries;
    ULONG SiloObjectSlots;
    ULONG ServerHandleCount;
    ULONG HandleEntryShift;
    ULONG ObjectSlotStride;
    ULONG HandleGeneration;
    ULONG HandleType;
    ULONG HandleFlags;
    ULONG TagWndHandle;
    ULONG TagWndThreadInfo;
    ULONG TagThreadInfoQueue;
    ULONG TagQActiveWindow;
    ULONG TagQFocusWindow;
    ULONG TagQCaptureWindow;
    ULONG TagQCaretWindow;
} KSW_WIN32K_FALLBACK_LAYOUT, *PKSW_WIN32K_FALLBACK_LAYOUT;

typedef struct _KSW_WIN32K_FALLBACK_WINDOW
{
    ULONG64 Hwnd;
    ULONG64 TagWnd;
    ULONG64 ThreadInfo;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG SessionId;
} KSW_WIN32K_FALLBACK_WINDOW, *PKSW_WIN32K_FALLBACK_WINDOW;

typedef struct _KSW_WIN32K_FALLBACK_CONTEXT
{
    KSW_HOOK_SYSTEM_MODULE_ENTRY Win32kbase;
    KSW_HOOK_SYSTEM_MODULE_ENTRY Win32kfull;
    ULONG_PTR UserGetSiloGlobals;
    KSW_WIN32K_FALLBACK_LAYOUT Layout;
    KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* ThreadMap;
    ULONG ThreadMapCount;
    BOOLEAN ThreadMapTruncated;
    BOOLEAN HandleLayoutResolved;
    BOOLEAN QueueLayoutResolved;
} KSW_WIN32K_FALLBACK_CONTEXT, *PKSW_WIN32K_FALLBACK_CONTEXT;

typedef struct _KSW_WIN32K_FALLBACK_QUEUE
{
    ULONG64 QueueObject;
    ULONG64 ActiveHwnd;
    ULONG64 FocusHwnd;
    ULONG64 CaptureHwnd;
    ULONG64 CaretHwnd;
} KSW_WIN32K_FALLBACK_QUEUE, *PKSW_WIN32K_FALLBACK_QUEUE;

NTSTATUS
KswordARKWin32kFallbackInitialize(
    _Out_ KSW_WIN32K_FALLBACK_CONTEXT* Context
    );

VOID
KswordARKWin32kFallbackCleanup(
    _Inout_ KSW_WIN32K_FALLBACK_CONTEXT* Context
    );

NTSTATUS
KswordARKWin32kFallbackEnumerateWindows(
    _Inout_ KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _Out_writes_(WindowCapacity) KSW_WIN32K_FALLBACK_WINDOW* Windows,
    _In_ ULONG WindowCapacity,
    _Out_ ULONG* WindowCountOut,
    _Out_ ULONG* TotalCountOut,
    _Out_ BOOLEAN* TruncatedOut
    );

BOOLEAN
KswordARKWin32kFallbackReadQueue(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _In_ const KSWORD_ARK_WIN32K_GUI_THREAD_MAP_ENTRY* ThreadEntry,
    _In_reads_(WindowCount) const KSW_WIN32K_FALLBACK_WINDOW* Windows,
    _In_ ULONG WindowCount,
    _Out_ KSW_WIN32K_FALLBACK_QUEUE* QueueOut
    );

VOID
KswordARKWin32kFallbackPublishOffsets(
    _In_ const KSW_WIN32K_FALLBACK_CONTEXT* Context,
    _Out_ KSWORD_ARK_WIN32K_FIELD_OFFSETS* Offsets
    );

BOOLEAN
KswordARKWin32kFallbackDecodeQueueLayout(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _Inout_ KSW_WIN32K_FALLBACK_LAYOUT* Layout
    );

ULONG64
KswordARKWin32kFallbackProbeCapabilityMask(
    VOID
    );

NTSTATUS
KswordARKWin32kFallbackQueryWindowSnapshot(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKWin32kFallbackQueryGuiThreadSnapshot(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKWin32kFallbackQueryWindowDetail(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

EXTERN_C_END
