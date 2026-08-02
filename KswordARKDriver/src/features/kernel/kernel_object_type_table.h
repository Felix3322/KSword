#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkKernelObjectIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKKernelObjectIoctlEnumTypeTable(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

EXTERN_C_END
