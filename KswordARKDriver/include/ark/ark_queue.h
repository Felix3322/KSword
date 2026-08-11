#pragma once

#include <wdf.h>

EXTERN_C_START

// This is the context that can be placed per queue
// and would contain per queue information.
typedef struct _QUEUE_CONTEXT {

    ULONG PrivateDeviceData;  // just a placeholder

} QUEUE_CONTEXT, *PQUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_CONTEXT, QueueGetContext)

NTSTATUS
KswordARKDriverQueueInitialize(
    _In_ WDFDEVICE Device,
    _In_ BOOLEAN PowerManaged
    );

VOID
KswordARKDriverDispatchDeviceControl(
    _In_ WDFDEVICE Device,
    _In_opt_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    );

// Events from the IoQueue object
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL KswordARKDriverEvtIoDeviceControl;
EVT_WDF_IO_IN_CALLER_CONTEXT KswordARKDriverEvtIoInCallerContext;
EVT_WDF_IO_QUEUE_IO_READ KswordARKDriverEvtIoRead;
EVT_WDF_IO_QUEUE_IO_STOP KswordARKDriverEvtIoStop;

EXTERN_C_END
