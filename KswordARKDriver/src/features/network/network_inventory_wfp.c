/*++

Module Name:

    network_inventory_wfp.c

Abstract:

    Read-only global BFE/WFP provider, sublayer, callout and filter inventory.

Environment:

    Kernel mode, PASSIVE_LEVEL only

--*/

#include <ntddk.h>
#include <fwpmk.h>
#include "network_inventory_internal.h"

#define KSWORD_ARK_WFP_ENUM_PAGE_ROWS 128UL
#define KSWORD_ARK_WFP_ENUM_MAX_ROWS 65536UL

typedef struct _KSWORD_ARK_WFP_ENUM_BUILDER
{
    HANDLE EngineHandle;
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* Rows;
    ULONG RowCapacity;
    ULONG TotalRows;
    ULONG ReturnedRows;
} KSWORD_ARK_WFP_ENUM_BUILDER;

static VOID
KswordARKNetworkWfpCopyGuid(
    _Out_writes_(16) UCHAR Destination[16],
    _In_opt_ const GUID* Source
    )
{
    RtlZeroMemory(Destination, 16U);
    if (Source != NULL) {
        RtlCopyMemory(Destination, Source, sizeof(GUID));
    }
}

static ULONG64
KswordARKNetworkWfpReadWeight(
    _In_ const FWP_VALUE0* Value
    )
{
    if (Value == NULL) {
        return 0ULL;
    }

    switch (Value->type) {
    case FWP_UINT8:
        return Value->uint8;
    case FWP_UINT16:
        return Value->uint16;
    case FWP_UINT32:
        return Value->uint32;
    case FWP_UINT64:
        return (Value->uint64 != NULL) ? *Value->uint64 : 0ULL;
    case FWP_EMPTY:
    default:
        return 0ULL;
    }
}

static ULONG
KswordARKNetworkWfpResolveLayerId(
    _In_ HANDLE EngineHandle,
    _In_ const GUID* LayerKey
    )
/*++

Routine Description:

    用官方 BFE 查询把 layer GUID 转换为运行时 layerId。查询失败时保持为零，
    调用行已有 FIELD_MISSING 标志，不根据 GUID 猜测编号。

--*/
{
    FWPM_LAYER0* layer = NULL;
    ULONG layerId = 0UL;
    NTSTATUS status = FwpmLayerGetByKey0(EngineHandle, LayerKey, &layer);

    if (NT_SUCCESS(status) && layer != NULL) {
        layerId = layer->layerId;
    }
    if (layer != NULL) {
        FwpmFreeMemory0((VOID**)&layer);
    }
    return layerId;
}

static KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW*
KswordARKNetworkWfpReserveRow(
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (Builder == NULL || Builder->TotalRows >= KSWORD_ARK_WFP_ENUM_MAX_ROWS) {
        return NULL;
    }

    Builder->TotalRows += 1UL;
    if (Builder->Rows != NULL && Builder->ReturnedRows < Builder->RowCapacity) {
        row = &Builder->Rows[Builder->ReturnedRows];
        RtlZeroMemory(row, sizeof(*row));
        row->rowId = Builder->ReturnedRows;
        Builder->ReturnedRows += 1UL;
    }
    return row;
}

static VOID
KswordARKNetworkWfpAppendProvider(
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder,
    _In_opt_ const FWPM_PROVIDER0* Provider
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (Provider == NULL) {
        return;
    }
    row = KswordARKNetworkWfpReserveRow(Builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    KswordARKNetworkWfpCopyGuid(row->objectKey, &Provider->providerKey);
    KswordARKNetworkInventoryCopyWideText(
        row->ownerModule,
        (Provider->serviceName != NULL) ? Provider->serviceName : Provider->displayData.name);
}

static VOID
KswordARKNetworkWfpAppendSubLayer(
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder,
    _In_opt_ const FWPM_SUBLAYER0* SubLayer
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (SubLayer == NULL) {
        return;
    }
    row = KswordARKNetworkWfpReserveRow(Builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    row->weight = SubLayer->weight;
    KswordARKNetworkWfpCopyGuid(row->providerKey, SubLayer->providerKey);
    KswordARKNetworkWfpCopyGuid(row->objectKey, &SubLayer->subLayerKey);
    KswordARKNetworkInventoryCopyWideText(row->ownerModule, SubLayer->displayData.name);
}

static VOID
KswordARKNetworkWfpAppendCallout(
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder,
    _In_opt_ const FWPM_CALLOUT0* Callout
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (Callout == NULL) {
        return;
    }
    row = KswordARKNetworkWfpReserveRow(Builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    row->layerId = KswordARKNetworkWfpResolveLayerId(
        Builder->EngineHandle,
        &Callout->applicableLayer);
    row->calloutId = Callout->calloutId;
    KswordARKNetworkWfpCopyGuid(row->providerKey, Callout->providerKey);
    KswordARKNetworkWfpCopyGuid(row->objectKey, &Callout->calloutKey);
    KswordARKNetworkInventoryCopyWideText(row->ownerModule, Callout->displayData.name);
}

static VOID
KswordARKNetworkWfpAppendFilter(
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder,
    _In_opt_ const FWPM_FILTER0* Filter
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (Filter == NULL) {
        return;
    }
    row = KswordARKNetworkWfpReserveRow(Builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    row->layerId = KswordARKNetworkWfpResolveLayerId(
        Builder->EngineHandle,
        &Filter->layerKey);
    row->filterId = Filter->filterId;
    row->weight = KswordARKNetworkWfpReadWeight(&Filter->effectiveWeight);
    if (row->weight == 0ULL) {
        row->weight = KswordARKNetworkWfpReadWeight(&Filter->weight);
    }
    KswordARKNetworkWfpCopyGuid(row->providerKey, Filter->providerKey);
    KswordARKNetworkWfpCopyGuid(row->subLayerKey, &Filter->subLayerKey);
    KswordARKNetworkWfpCopyGuid(row->objectKey, &Filter->filterKey);
    KswordARKNetworkInventoryCopyWideText(row->ownerModule, Filter->displayData.name);
}

static NTSTATUS
KswordARKNetworkWfpEnumProviders(
    _In_ HANDLE EngineHandle,
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmProviderCreateEnumHandle0(EngineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_PROVIDER0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - Builder->TotalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmProviderEnum0(EngineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            KswordARKNetworkWfpAppendProvider(Builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmProviderDestroyEnumHandle0(EngineHandle, enumHandle);
    return status;
}

static NTSTATUS
KswordARKNetworkWfpEnumSubLayers(
    _In_ HANDLE EngineHandle,
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmSubLayerCreateEnumHandle0(EngineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_SUBLAYER0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - Builder->TotalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmSubLayerEnum0(EngineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            KswordARKNetworkWfpAppendSubLayer(Builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmSubLayerDestroyEnumHandle0(EngineHandle, enumHandle);
    return status;
}

static NTSTATUS
KswordARKNetworkWfpEnumCallouts(
    _In_ HANDLE EngineHandle,
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmCalloutCreateEnumHandle0(EngineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_CALLOUT0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - Builder->TotalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmCalloutEnum0(EngineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            KswordARKNetworkWfpAppendCallout(Builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmCalloutDestroyEnumHandle0(EngineHandle, enumHandle);
    return status;
}

static NTSTATUS
KswordARKNetworkWfpEnumFilters(
    _In_ HANDLE EngineHandle,
    _Inout_ KSWORD_ARK_WFP_ENUM_BUILDER* Builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmFilterCreateEnumHandle0(EngineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_FILTER0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - Builder->TotalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmFilterEnum0(EngineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            KswordARKNetworkWfpAppendFilter(Builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmFilterDestroyEnumHandle0(EngineHandle, enumHandle);
    return status;
}

NTSTATUS
KswordARKNetworkCollectWfpInventory(
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Out_ ULONG* TotalRowsOut,
    _Out_ ULONG* ReturnedRowsOut
    )
/*++

Routine Description:

    通过 WDK fwpmk.h 声明的官方管理接口枚举系统 BFE provider、sublayer、
    callout 和 filter。枚举只读，不访问 netio/BFE 私有链表。

Return Value:

    STATUS_SUCCESS 表示四类对象均完整枚举；STATUS_BUFFER_OVERFLOW 表示触及硬上限；
    STATUS_PARTIAL_COPY 表示至少一类成功但另有 API 失败；其它失败表示没有任何完整类。

--*/
{
    KSWORD_ARK_WFP_ENUM_BUILDER builder;
    HANDLE engineHandle = NULL;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG completedClasses = 0UL;

    if (TotalRowsOut == NULL || ReturnedRowsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TotalRowsOut = 0UL;
    *ReturnedRowsOut = 0UL;
    if (Rows == NULL && RowCapacity != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&builder, sizeof(builder));
    builder.Rows = Rows;
    builder.RowCapacity = RowCapacity;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    builder.EngineHandle = engineHandle;

    status = KswordARKNetworkWfpEnumProviders(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    status = KswordARKNetworkWfpEnumSubLayers(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    status = KswordARKNetworkWfpEnumCallouts(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    status = KswordARKNetworkWfpEnumFilters(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    (VOID)FwpmEngineClose0(engineHandle);

    if (builder.TotalRows > builder.ReturnedRows && builder.Rows != NULL) {
        ULONG index = 0UL;
        for (index = 0UL; index < builder.ReturnedRows; ++index) {
            builder.Rows[index].flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED;
        }
    }

    *TotalRowsOut = builder.TotalRows;
    *ReturnedRowsOut = builder.ReturnedRows;
    if (completedClasses == 4UL) {
        return STATUS_SUCCESS;
    }
    if (firstFailure == STATUS_BUFFER_OVERFLOW) {
        return STATUS_BUFFER_OVERFLOW;
    }
    if (completedClasses != 0UL) {
        return STATUS_PARTIAL_COPY;
    }
    return NT_SUCCESS(firstFailure) ? STATUS_UNSUCCESSFUL : firstFailure;
}
