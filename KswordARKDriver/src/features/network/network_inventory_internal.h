#pragma once

#include "network_inventory.h"

EXTERN_C_START

// 中文说明：公共有界复制函数供 WFP/NDIS collector 使用，输出始终 NUL 终止。
VOID
KswordARKNetworkInventoryCopyWideText(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* Destination,
    _In_opt_z_ PCWSTR Source
    );

// 中文说明：复制非 NUL 终止的内核 UNICODE_STRING，避免越界读取驱动对象名称。
VOID
KswordARKNetworkInventoryCopyUnicodeString(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* Destination,
    _In_opt_ const UNICODE_STRING* Source
    );

EXTERN_C_END
