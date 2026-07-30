#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkHvmIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKHvmInitialize(
    VOID
    );

VOID
KswordARKHvmUninitialize(
    VOID
    );

NTSTATUS
KswordARKHvmQuery(
    _Out_ KSWORD_ARK_QUERY_HVM_RESPONSE* Response
    );

NTSTATUS
KswordARKHvmControl(
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request,
    _Out_ KSWORD_ARK_CONTROL_HVM_RESPONSE* Response
    );

EXTERN_C_END
