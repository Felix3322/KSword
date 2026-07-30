#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkPiDdbIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKPiDdbQuery(
    _In_ const KSWORD_ARK_QUERY_PIDDB_REQUEST* Request,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWritten)
        KSWORD_ARK_QUERY_PIDDB_RESPONSE* Response,
    _In_ SIZE_T OutputBufferLength,
    _Out_ SIZE_T* BytesWritten
    );

NTSTATUS
KswordARKPiDdbDelete(
    _In_ const KSWORD_ARK_DELETE_PIDDB_REQUEST* Request,
    _Out_ KSWORD_ARK_DELETE_PIDDB_RESPONSE* Response
    );

EXTERN_C_END
