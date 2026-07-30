#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkUnloadedDriverIoctl.h"

EXTERN_C_START

// 只读枚举一个指定来源，并把来源不支持/布局缺失写入协议业务状态。
NTSTATUS
KswordARKQueryUnloadedDrivers(
    _In_ const KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST* Request,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWritten)
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE* Response,
    _In_ SIZE_T OutputBufferLength,
    _Out_ SIZE_T* BytesWritten
    );

// WDF 适配器只负责取出 METHOD_BUFFERED 缓冲区并调用功能实现。
NTSTATUS
KswordARKKernelIoctlQueryUnloadedDrivers(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

EXTERN_C_END
