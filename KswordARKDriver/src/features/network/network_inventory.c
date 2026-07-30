/*++

Module Name:

    network_inventory.c

Abstract:

    Shared bounded-copy helpers for the read-only network inventory collectors.

Environment:

    Kernel mode

--*/

#include "network_inventory_internal.h"

VOID
KswordARKNetworkInventoryCopyWideText(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* Destination,
    _In_opt_z_ PCWSTR Source
    )
/*++

Routine Description:

    有界复制 BFE 名称或设备接口名称，确保共享协议文本始终 NUL 终止。

--*/
{
    RtlZeroMemory(Destination, sizeof(WCHAR) * KSWORD_ARK_NETWORK_NAME_CHARS);
    if (Source != NULL) {
        (VOID)RtlStringCchCopyW(Destination, KSWORD_ARK_NETWORK_NAME_CHARS, Source);
    }
}

VOID
KswordARKNetworkInventoryCopyUnicodeString(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* Destination,
    _In_opt_ const UNICODE_STRING* Source
    )
/*++

Routine Description:

    从 WDK UNICODE_STRING 有界复制驱动对象名称，不依赖源字符串 NUL 终止。

--*/
{
    ULONG sourceChars = 0UL;
    ULONG copyChars = 0UL;

    RtlZeroMemory(Destination, sizeof(WCHAR) * KSWORD_ARK_NETWORK_NAME_CHARS);
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }

    sourceChars = Source->Length / sizeof(WCHAR);
    copyChars = sourceChars;
    if (copyChars >= KSWORD_ARK_NETWORK_NAME_CHARS) {
        copyChars = KSWORD_ARK_NETWORK_NAME_CHARS - 1UL;
    }
    RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
}
