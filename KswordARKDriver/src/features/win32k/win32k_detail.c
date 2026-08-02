/*++

Module Name:

    win32k_detail.c

Abstract:

    Read-only single-window detail adapter.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_query.h"
#include "win32k_fallback.h"

NTSTATUS
KswordARKWin32kQueryWindowDetail(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Resolve one HWND through the validated runtime-signature fallback.  The
    backend rejects ambiguous identities and never trusts a caller-supplied
    tagWND address.

--*/
{
    if (Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return KswordARKWin32kFallbackQueryWindowDetail(
        Response,
        OutputBufferLength,
        Request,
        BytesWrittenOut);
}
