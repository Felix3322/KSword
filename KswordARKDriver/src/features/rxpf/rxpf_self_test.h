#pragma once

#include <ntddk.h>

EXTERN_C_START

_Must_inspect_result_
NTSTATUS
KswRxpfRunConcurrentExecutionTest(
    _In_ PVOID PageAddress,
    _In_ ULONGLONG ExpectedValue,
    _Out_ ULONGLONG* ReturnedValueOut,
    _Out_ ULONG* WorkerCountOut
    );

EXTERN_C_END
