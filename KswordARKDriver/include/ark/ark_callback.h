#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkCallbackIoctl.h"

EXTERN_C_START

// 返回 STATUS_SUCCESS 表示全部回调都注册成功；返回失败状态表示回调层已经
// 降级运行，调用方必须继续加载驱动而不是把它当成致命错误。
NTSTATUS
KswordARKCallbackInitialize(
    _In_ WDFDEVICE Device
    );

// 当前实际注册成功的 KSWORD_ARK_CALLBACK_REGISTERED_* 能力位。
ULONG
KswordARKCallbackGetRegisteredMask(
    VOID
    );

VOID
KswordARKCallbackUninitialize(
    VOID
    );

NTSTATUS
KswordARKCallbackIoctlSetRules(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlGetRuntimeState(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlWaitEvent(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlAnswerEvent(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlCancelAllPending(
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlRemoveExternalCallback(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlRemoveExternalCallbackEx(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlEnumCallbacks(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlSetMinifilterBypassPids(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlQueryMinifilterBypassPids(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

BOOLEAN
KswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG ProcessId
    );

EXTERN_C_END
