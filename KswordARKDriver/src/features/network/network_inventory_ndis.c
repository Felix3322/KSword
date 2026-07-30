/*++

Module Name:

    network_inventory_ndis.c

Abstract:

    Read-only NDIS LAN interface device-stack inventory.

Environment:

    Kernel mode, PASSIVE_LEVEL only

--*/

#include <ntifs.h>
#include "network_inventory_internal.h"

#define KSWORD_ARK_NDIS_STACK_MAX_DEPTH 64UL
#define KSWORD_ARK_NDIS_ENUM_MAX_ROWS 8192UL

// {AD498944-762F-11D0-8DCB-00C04FC3358C}，即 WDK GUID_NDIS_LAN_CLASS。
static const GUID KSWORD_ARK_NDIS_LAN_INTERFACE_CLASS =
{ 0xad498944, 0x762f, 0x11d0, { 0x8d, 0xcb, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c } };

static VOID
KswordARKNetworkNdisAppendDevice(
    _In_ PCWSTR InterfaceName,
    _In_reads_(StackCount) PDEVICE_OBJECT const* Stack,
    _In_ ULONG StackCount,
    _In_ ULONG StackIndex,
    _In_ ULONG ObjectKind,
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Inout_ ULONG* TotalRows,
    _Inout_ ULONG* ReturnedRows
    )
{
    PDEVICE_OBJECT deviceObject = Stack[StackIndex];
    PDRIVER_OBJECT driverObject = (deviceObject != NULL) ? deviceObject->DriverObject : NULL;
    KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* row = NULL;

    if (*TotalRows >= KSWORD_ARK_NDIS_ENUM_MAX_ROWS) {
        return;
    }

    *TotalRows += 1UL;
    if (Rows == NULL || *ReturnedRows >= RowCapacity) {
        return;
    }

    row = &Rows[*ReturnedRows];
    RtlZeroMemory(row, sizeof(*row));
    row->rowId = *ReturnedRows;
    row->objectKind = ObjectKind;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
    row->filterOrder = StackIndex;
    row->objectAddress = (ULONG64)(ULONG_PTR)deviceObject;
    row->parentObjectAddress =
        (StackIndex + 1UL < StackCount) ?
        (ULONG64)(ULONG_PTR)Stack[StackIndex + 1UL] :
        0ULL;

    if (driverObject != NULL) {
        row->driverObject = (ULONG64)(ULONG_PTR)driverObject;
        row->imageBase = (ULONG64)(ULONG_PTR)driverObject->DriverStart;
        KswordARKNetworkInventoryCopyUnicodeString(row->ownerModule, &driverObject->DriverName);
    }
    else {
        row->flags |=
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    }

    if (ObjectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT ||
        ObjectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN) {
        KswordARKNetworkInventoryCopyWideText(row->componentName, InterfaceName);
    }
    else if (driverObject != NULL) {
        KswordARKNetworkInventoryCopyUnicodeString(row->componentName, &driverObject->DriverName);
    }

    *ReturnedRows += 1UL;
}

NTSTATUS
KswordARKNetworkCollectNdisDeviceStacks(
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Out_ ULONG* TotalRowsOut,
    _Out_ ULONG* ReturnedRowsOut
    )
/*++

Routine Description:

    枚举 GUID_NDIS_LAN_CLASS 的启用接口，并按 IoGetAttachedDeviceReference /
    IoGetLowerDeviceObject 的引用规则取得只读设备栈。选择栈中最深的
    FILE_DEVICE_PHYSICAL_NETCARD 作为唯一可证明的 miniport 设备边界。其上对象
    只能证明已附加，objectKind 保持 UNKNOWN；无法找到边界时顶层对象也保持
    UNKNOWN，不伪造 NDIS 私有 LWF、protocol 或 binding。

Return Value:

    STATUS_SUCCESS 表示所有接口完整遍历；STATUS_BUFFER_OVERFLOW 表示深度/总数硬
    上限；STATUS_PARTIAL_COPY 表示部分接口成功、部分接口打开失败。

--*/
{
    PWSTR symbolicLinks = NULL;
    PWSTR currentLink = NULL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    ULONG successfulInterfaces = 0UL;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

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

    status = IoGetDeviceInterfaces(
        &KSWORD_ARK_NDIS_LAN_INTERFACE_CLASS,
        NULL,
        0UL,
        &symbolicLinks);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (symbolicLinks == NULL) {
        return STATUS_DATA_ERROR;
    }

    currentLink = symbolicLinks;
    while (currentLink != NULL && *currentLink != L'\0') {
        UNICODE_STRING interfaceName;
        PFILE_OBJECT fileObject = NULL;
        PDEVICE_OBJECT deviceObject = NULL;
        PDEVICE_OBJECT stack[KSWORD_ARK_NDIS_STACK_MAX_DEPTH];
        ULONG stackCount = 0UL;
        ULONG miniportIndex = MAXULONG;
        ULONG includedCount = 0UL;
        ULONG index = 0UL;

        RtlZeroMemory(stack, sizeof(stack));
        RtlInitUnicodeString(&interfaceName, currentLink);
        status = IoGetDeviceObjectPointer(
            &interfaceName,
            FILE_READ_ATTRIBUTES,
            &fileObject,
            &deviceObject);
        if (!NT_SUCCESS(status)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
            currentLink += (interfaceName.Length / sizeof(WCHAR)) + 1UL;
            continue;
        }

        stack[0] = IoGetAttachedDeviceReference(deviceObject);
        if (stack[0] == NULL) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = STATUS_NOT_FOUND;
            }
            ObDereferenceObject(fileObject);
            currentLink += (interfaceName.Length / sizeof(WCHAR)) + 1UL;
            continue;
        }
        stackCount = 1UL;

        while (stackCount < KSWORD_ARK_NDIS_STACK_MAX_DEPTH) {
            PDEVICE_OBJECT lowerObject = IoGetLowerDeviceObject(stack[stackCount - 1UL]);
            if (lowerObject == NULL) {
                break;
            }
            stack[stackCount] = lowerObject;
            stackCount += 1UL;
        }

        if (stackCount == KSWORD_ARK_NDIS_STACK_MAX_DEPTH) {
            PDEVICE_OBJECT extraObject = IoGetLowerDeviceObject(stack[stackCount - 1UL]);
            if (extraObject != NULL) {
                ObDereferenceObject(extraObject);
                if (NT_SUCCESS(firstFailure)) {
                    firstFailure = STATUS_BUFFER_OVERFLOW;
                }
            }
        }

        for (index = 0UL; index < stackCount; ++index) {
            if (stack[index]->DeviceType == FILE_DEVICE_PHYSICAL_NETCARD) {
                // 取最深匹配作为唯一可证明的 miniport 边界；其上对象仅证明已附加。
                miniportIndex = index;
            }
        }

        if (miniportIndex != MAXULONG) {
            includedCount = miniportIndex + 1UL;
            for (index = 0UL; index < includedCount; ++index) {
                const ULONG kind = (index == miniportIndex) ?
                    KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT :
                    KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN;
                KswordARKNetworkNdisAppendDevice(
                    currentLink,
                    stack,
                    includedCount,
                    index,
                    kind,
                    Rows,
                    RowCapacity,
                    &totalRows,
                    &returnedRows);
            }
        }
        else {
            KswordARKNetworkNdisAppendDevice(
                currentLink,
                stack,
                1UL,
                0UL,
                KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN,
                Rows,
                RowCapacity,
                &totalRows,
                &returnedRows);
        }

        for (index = 0UL; index < stackCount; ++index) {
            ObDereferenceObject(stack[index]);
        }
        ObDereferenceObject(fileObject);
        successfulInterfaces += 1UL;

        if (totalRows >= KSWORD_ARK_NDIS_ENUM_MAX_ROWS) {
            firstFailure = STATUS_BUFFER_OVERFLOW;
            break;
        }
        currentLink += (interfaceName.Length / sizeof(WCHAR)) + 1UL;
    }

    ExFreePool(symbolicLinks);

    if (totalRows > returnedRows && Rows != NULL) {
        ULONG index = 0UL;
        for (index = 0UL; index < returnedRows; ++index) {
            Rows[index].flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED;
        }
    }

    *TotalRowsOut = totalRows;
    *ReturnedRowsOut = returnedRows;
    if (NT_SUCCESS(firstFailure)) {
        return STATUS_SUCCESS;
    }
    if (successfulInterfaces == 0UL) {
        return firstFailure;
    }
    return (firstFailure == STATUS_BUFFER_OVERFLOW) ?
        STATUS_BUFFER_OVERFLOW :
        STATUS_PARTIAL_COPY;
}
