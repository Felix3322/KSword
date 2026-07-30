#pragma once

#include "network_internal.h"

EXTERN_C_START

// 中文说明：通过 netio NSI 只读快照返回 TCP/UDP endpoint；不猜测 tcpip 私有链表。
NTSTATUS
KswordARKNetworkCollectNsiEndpoints(
    _In_ BOOLEAN TcpTable,
    _In_ ULONG QueryFlags,
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_ENDPOINT_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Out_ ULONG* TotalRowsOut,
    _Out_ ULONG* ReturnedRowsOut
    );

// 中文说明：通过 BFE/WFP 官方管理接口枚举全局 provider/sublayer/callout/filter。
NTSTATUS
KswordARKNetworkCollectWfpInventory(
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Out_ ULONG* TotalRowsOut,
    _Out_ ULONG* ReturnedRowsOut
    );

// 中文说明：通过启用的 NDIS 接口与引用计数安全的设备栈遍历返回诊断链。
NTSTATUS
KswordARKNetworkCollectNdisDeviceStacks(
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Out_ ULONG* TotalRowsOut,
    _Out_ ULONG* ReturnedRowsOut
    );

EXTERN_C_END
