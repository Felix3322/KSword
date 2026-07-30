#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkKernelBaselineIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKIdtBaselineInitialize(
    VOID
    );

VOID
KswordARKIdtBaselineUninitialize(
    VOID
    );

BOOLEAN
KswordARKIdtBaselineQuery(
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber,
    _In_ UCHAR Vector,
    _Out_opt_ ULONGLONG* TableBaseOut,
    _Out_opt_ ULONG* TableLimitOut,
    _Out_opt_ ULONGLONG* EntryAddressOut,
    _Out_opt_ ULONGLONG* RawLowOut,
    _Out_opt_ ULONGLONG* RawHighOut,
    _Out_opt_ ULONGLONG* HandlerOut,
    _Out_opt_ ULONG* GenerationOut
    );

NTSTATUS
KswordARKIdtBaselineRestore(
    _In_ const KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST* Request,
    _Out_ KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE* Response
    );

EXTERN_C_END
