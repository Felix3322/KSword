/*++

Module Name:

    callback_extended_system.c

Abstract:

    枚举文件系统注册变化、登录会话终止和驱动 Shutdown 回调。

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"

#define KSWORD_ARK_CALLBACK_SYSTEM_CODE_SCAN_BYTES 0x300UL
#define KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES (16UL * 1024UL)
#define KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_LIMIT 4096UL
#define KSWORD_ARK_CALLBACK_SYSTEM_DEVICE_LIMIT 4096UL
#define KSWORD_ARK_CALLBACK_SYSTEM_TAG 'sCbK'

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

typedef struct _KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_INFORMATION;

typedef struct _KSWORD_ARK_CALLBACK_FS_REGISTRATION
{
    LIST_ENTRY Link;
    PDRIVER_OBJECT DriverObject;
    PVOID NotificationRoutine;
} KSWORD_ARK_CALLBACK_FS_REGISTRATION;

typedef struct _KSWORD_ARK_CALLBACK_LOGON_REGISTRATION
{
    PVOID Next;
    PVOID CallbackRoutine;
} KSWORD_ARK_CALLBACK_LOGON_REGISTRATION;

typedef struct _KSWORD_ARK_CALLBACK_LOGON_EX_REGISTRATION
{
    PVOID Next;
    PVOID CallbackRoutine;
    PVOID CallbackContext;
} KSWORD_ARK_CALLBACK_LOGON_EX_REGISTRATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

extern POBJECT_TYPE* IoDriverObjectType;

static NTSTATUS
KswordArkCallbackExtendedLocateFsListHead(
    _Out_ ULONG64* ListHeadAddressOut
    )
/*++

Routine Description:

    从 IoRegisterFsRegistrationChangeMountAware 中定位 IopFsNotifyChangeQueueHead。
    中文说明：要求相邻 LEA/CMP 两条 RIP-relative 指令解析到同一地址，避免把
    锁、事件或其它全局误识别为链表头。

Arguments:

    ListHeadAddressOut - 输出 LIST_ENTRY 地址。

Return Value:

    成功返回 STATUS_SUCCESS；导出或特征不可用返回对应状态。

--*/
{
    UCHAR codeBytes[KSWORD_ARK_CALLBACK_SYSTEM_CODE_SCAN_BYTES];
    ULONG offset = 0UL;
    ULONG64 routineAddress = (ULONG64)(ULONG_PTR)
        KswordArkCallbackExtendedGetSystemRoutine(L"IoRegisterFsRegistrationChangeMountAware");

    if (ListHeadAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ListHeadAddressOut = 0ULL;
    if (routineAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return STATUS_ACCESS_VIOLATION;
    }

    for (offset = 0UL; offset + 14UL <= sizeof(codeBytes); ++offset) {
        ULONG64 leaTarget = 0ULL;
        ULONG64 compareTarget = 0ULL;

        if (codeBytes[offset] != 0x4CU ||
            codeBytes[offset + 1UL] != 0x8DU ||
            codeBytes[offset + 2UL] != 0x3DU ||
            codeBytes[offset + 7UL] != 0x4CU ||
            codeBytes[offset + 8UL] != 0x39U ||
            codeBytes[offset + 9UL] != 0x3DU) {
            continue;
        }
        if (!KswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset,
                3UL,
                7UL,
                &leaTarget) ||
            !KswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset + 7UL,
                3UL,
                7UL,
                &compareTarget)) {
            continue;
        }
        if (leaTarget == compareTarget && leaTarget != 0ULL) {
            *ListHeadAddressOut = leaTarget;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

static VOID
KswordArkCallbackExtendedAddFsRegistrationCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    遍历 IopFsNotifyChangeQueueHead 并展示文件系统注册变化回调。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 listHeadAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    LIST_ENTRY listHead;

    status = KswordArkCallbackExtendedLocateFsListHead(&listHeadAddress);
    if (!NT_SUCCESS(status)) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"IopFsNotifyChangeQueueHead",
            L"未能从 IoRegisterFsRegistrationChangeMountAware 公开入口定位文件系统注册变化链。");
        return;
    }

    RtlZeroMemory(&listHead, sizeof(listHead));
    if (!KswordArkCallbackExtendedReadListEntry(listHeadAddress, &listHead)) {
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT) {
        KSWORD_ARK_CALLBACK_FS_REGISTRATION registration;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&registration, sizeof(registration));
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration))) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)registration.Link.Flink;

        if (registration.NotificationRoutine != NULL &&
            KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                (ULONG64)(ULONG_PTR)registration.NotificationRoutine)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"IoFsRegistrationChange[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"IopFsNotifyChangeQueueHead 私有链只读项；Node=0x%p，DriverObject=0x%p，NotificationRoutine=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                registration.DriverObject,
                registration.NotificationRoutine);
            KswordArkCallbackExtendedAddRow(
                Builder,
                ModuleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE,
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)registration.NotificationRoutine,
                (ULONG64)(ULONG_PTR)registration.DriverObject,
                currentAddress,
                0UL,
                nameText,
                detailText);
            ++addedCount;
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }

    if (addedCount == 0UL) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
            STATUS_SUCCESS,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE,
            0UL,
            0UL,
            0ULL,
            0ULL,
            listHeadAddress,
            0UL,
            L"IopFsNotifyChangeQueueHead empty",
            L"已定位文件系统注册变化链，但当前未发现可验证到已加载模块的回调。");
    }
}

static NTSTATUS
KswordArkCallbackExtendedLocatePairedPointerGlobal(
    _In_z_ PCWSTR RoutineName,
    _Out_ ULONG64* GlobalAddressOut
    )
/*++

Routine Description:

    定位“读取旧头指针后写回新头指针”的单链全局变量。

Arguments:

    RoutineName - 注册例程导出名称。
    GlobalAddressOut - 输出全局指针变量地址。

Return Value:

    成功返回 STATUS_SUCCESS；未命中返回 STATUS_NOT_FOUND。

--*/
{
    UCHAR codeBytes[0x100];
    ULONG readOffset = 0UL;
    ULONG64 routineAddress = (ULONG64)(ULONG_PTR)
        KswordArkCallbackExtendedGetSystemRoutine(RoutineName);

    if (GlobalAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *GlobalAddressOut = 0ULL;
    if (routineAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return STATUS_ACCESS_VIOLATION;
    }

    for (readOffset = 0UL; readOffset + 7UL <= sizeof(codeBytes); ++readOffset) {
        ULONG writeOffset = 0UL;
        ULONG64 readTarget = 0ULL;

        if (codeBytes[readOffset] != 0x48U ||
            codeBytes[readOffset + 1UL] != 0x8BU ||
            codeBytes[readOffset + 2UL] != 0x05U) {
            continue;
        }
        if (!KswordArkCallbackExtendedResolveRipRelative(
                routineAddress + readOffset,
                3UL,
                7UL,
                &readTarget)) {
            continue;
        }

        for (writeOffset = readOffset + 7UL;
            writeOffset + 7UL <= sizeof(codeBytes) &&
                writeOffset <= readOffset + 40UL;
            ++writeOffset) {
            ULONG64 writeTarget = 0ULL;

            if (codeBytes[writeOffset] != 0x48U ||
                codeBytes[writeOffset + 1UL] != 0x89U ||
                codeBytes[writeOffset + 2UL] != 0x1DU) {
                continue;
            }
            if (KswordArkCallbackExtendedResolveRipRelative(
                    routineAddress + writeOffset,
                    3UL,
                    7UL,
                    &writeTarget) &&
                writeTarget == readTarget) {
                *GlobalAddressOut = readTarget;
                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_NOT_FOUND;
}

static ULONG
KswordArkCallbackExtendedWalkLogonList(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 GlobalAddress,
    _In_ BOOLEAN ExtendedList
    )
/*++

Routine Description:

    遍历 Legacy 或 Ex 登录会话终止单链。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。
    GlobalAddress - 单链头指针变量地址。
    ExtendedList - TRUE 表示节点含 Context。

Return Value:

    返回成功验证的回调数量。

--*/
{
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 currentAddress = 0ULL;

    if (!KswordArkCallbackExtendedReadPointer(
            GlobalAddress,
            &currentAddress)) {
        return 0UL;
    }

    while (currentAddress != 0ULL &&
        index < KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT) {
        ULONG64 nextAddress = 0ULL;
        ULONG64 callbackAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;

        if (ExtendedList) {
            KSWORD_ARK_CALLBACK_LOGON_EX_REGISTRATION registration;

            RtlZeroMemory(&registration, sizeof(registration));
            if (!KswordArkCallbackEnumReadMemory(
                    (const VOID*)(ULONG_PTR)currentAddress,
                    &registration,
                    sizeof(registration))) {
                break;
            }
            nextAddress = (ULONG64)(ULONG_PTR)registration.Next;
            callbackAddress = (ULONG64)(ULONG_PTR)registration.CallbackRoutine;
            contextAddress = (ULONG64)(ULONG_PTR)registration.CallbackContext;
        }
        else {
            KSWORD_ARK_CALLBACK_LOGON_REGISTRATION registration;

            RtlZeroMemory(&registration, sizeof(registration));
            if (!KswordArkCallbackEnumReadMemory(
                    (const VOID*)(ULONG_PTR)currentAddress,
                    &registration,
                    sizeof(registration))) {
                break;
            }
            nextAddress = (ULONG64)(ULONG_PTR)registration.Next;
            callbackAddress = (ULONG64)(ULONG_PTR)registration.CallbackRoutine;
        }

        if (callbackAddress != 0ULL &&
            KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                callbackAddress)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                ExtendedList
                    ? L"SeLogonSessionTerminatedEx[%lu]"
                    : L"SeLogonSessionTerminated[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                ExtendedList
                    ? L"SeRegisterLogonSessionTerminatedRoutineEx 私有单链项；Node=0x%p，Function=0x%p，Context=0x%p。"
                    : L"SeRegisterLogonSessionTerminatedRoutine 私有单链项；Node=0x%p，Function=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                (PVOID)(ULONG_PTR)callbackAddress,
                (PVOID)(ULONG_PTR)contextAddress);
            KswordArkCallbackExtendedAddRow(
                Builder,
                ModuleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_LOGON_SESSION,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                ExtendedList
                    ? KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_EX
                    : KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_LEGACY,
                0UL,
                0UL,
                callbackAddress,
                contextAddress,
                currentAddress,
                0UL,
                nameText,
                detailText);
            ++addedCount;
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }

    return addedCount;
}

static VOID
KswordArkCallbackExtendedAddLogonCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    定位并遍历 Legacy 与 Ex 两条登录会话终止回调链。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    NTSTATUS legacyStatus = STATUS_SUCCESS;
    NTSTATUS extendedStatus = STATUS_SUCCESS;
    ULONG addedCount = 0UL;
    ULONG64 legacyGlobal = 0ULL;
    ULONG64 extendedGlobal = 0ULL;

    legacyStatus = KswordArkCallbackExtendedLocatePairedPointerGlobal(
        L"SeRegisterLogonSessionTerminatedRoutine",
        &legacyGlobal);
    if (NT_SUCCESS(legacyStatus)) {
        addedCount += KswordArkCallbackExtendedWalkLogonList(
            Builder,
            ModuleCache,
            legacyGlobal,
            FALSE);
    }

    extendedStatus = KswordArkCallbackExtendedLocatePairedPointerGlobal(
        L"SeRegisterLogonSessionTerminatedRoutineEx",
        &extendedGlobal);
    if (NT_SUCCESS(extendedStatus)) {
        addedCount += KswordArkCallbackExtendedWalkLogonList(
            Builder,
            ModuleCache,
            extendedGlobal,
            TRUE);
    }

    if (addedCount == 0UL) {
        const NTSTATUS combinedStatus = !NT_SUCCESS(legacyStatus)
            ? legacyStatus
            : (!NT_SUCCESS(extendedStatus) ? extendedStatus : STATUS_SUCCESS);
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LOGON_SESSION,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST,
            NT_SUCCESS(combinedStatus)
                ? KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED
                : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            combinedStatus,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
            0UL,
            0UL,
            0ULL,
            0ULL,
            NT_SUCCESS(legacyStatus) ? legacyGlobal : extendedGlobal,
            0UL,
            L"Se logon-session callback lists",
            NT_SUCCESS(combinedStatus)
                ? L"已定位 Legacy/Ex 登录会话终止链，但当前没有可验证回调。"
                : L"未能从 SeRegisterLogonSessionTerminatedRoutine/Ex 公开入口定位回调链。");
    }
}

static NTSTATUS
KswordArkCallbackExtendedOpenObjectDirectory(
    _In_z_ PCWSTR DirectoryName,
    _Out_ HANDLE* DirectoryHandleOut
    )
/*++

Routine Description:

    打开 \Driver 或 \FileSystem 对象目录。

Arguments:

    DirectoryName - 完整目录路径。
    DirectoryHandleOut - 输出内核句柄。

Return Value:

    返回 ZwOpenDirectoryObject 的 NTSTATUS。

--*/
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;

    if (DirectoryName == NULL || DirectoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DirectoryHandleOut = NULL;
    RtlInitUnicodeString(&directoryName, DirectoryName);
    InitializeObjectAttributes(
        &objectAttributes,
        &directoryName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    return ZwOpenDirectoryObject(
        DirectoryHandleOut,
        DIRECTORY_QUERY,
        &objectAttributes);
}

static BOOLEAN
KswordArkCallbackExtendedBuildObjectName(
    _In_z_ PCWSTR DirectoryName,
    _In_ PCUNICODE_STRING LeafName,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    拼接对象目录与叶名称。

Arguments:

    DirectoryName - 目录路径。
    LeafName - 对象叶名称。
    Destination - 输出完整路径。
    DestinationChars - 输出字符容量。

Return Value:

    成功返回 TRUE；参数或字符串越界返回 FALSE。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (DirectoryName == NULL ||
        LeafName == NULL ||
        LeafName->Buffer == NULL ||
        LeafName->Length == 0U ||
        Destination == NULL ||
        DestinationChars == 0UL) {
        return FALSE;
    }

    Destination[0] = L'\0';
    status = RtlStringCchPrintfW(
        Destination,
        DestinationChars,
        L"%ws\\",
        DirectoryName);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    status = RtlStringCchCatNW(
        Destination,
        DestinationChars,
        LeafName->Buffer,
        LeafName->Length / sizeof(WCHAR));
    return NT_SUCCESS(status);
}

static VOID
KswordArkCallbackExtendedAddDriverShutdownRows(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_z_ PCWSTR DriverName
    )
/*++

Routine Description:

    枚举一个 DriverObject 的 DO_SHUTDOWN_REGISTERED 设备对象。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。
    DriverObject - 已引用驱动对象。
    DriverName - 完整对象名。

Return Value:

    无返回值。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0UL;
    ULONG deviceCount = 0UL;
    ULONG actualCount = 0UL;
    PDEVICE_OBJECT* deviceObjects = NULL;

    if (DriverObject == NULL || DriverName == NULL) {
        return;
    }

    status = IoEnumerateDeviceObjectList(
        DriverObject,
        NULL,
        0UL,
        &deviceCount);
    if (deviceCount == 0UL ||
        deviceCount > KSWORD_ARK_CALLBACK_SYSTEM_DEVICE_LIMIT) {
        return;
    }

    deviceObjects = (PDEVICE_OBJECT*)KswordArkAllocateNonPaged(
        (SIZE_T)deviceCount * sizeof(PDEVICE_OBJECT),
        KSWORD_ARK_CALLBACK_SYSTEM_TAG);
    if (deviceObjects == NULL) {
        return;
    }
    RtlZeroMemory(
        deviceObjects,
        (SIZE_T)deviceCount * sizeof(PDEVICE_OBJECT));

    status = IoEnumerateDeviceObjectList(
        DriverObject,
        deviceObjects,
        deviceCount * sizeof(PDEVICE_OBJECT),
        &actualCount);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(deviceObjects, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
        return;
    }
    if (actualCount > deviceCount) {
        actualCount = deviceCount;
    }

    for (index = 0UL; index < actualCount; ++index) {
        PDEVICE_OBJECT deviceObject = deviceObjects[index];

        if (deviceObject != NULL &&
            (deviceObject->Flags & DO_SHUTDOWN_REGISTERED) != 0UL &&
            DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] != NULL) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"%ws/Device[%lu]",
                DriverName,
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"IoRegisterShutdownNotification/LastChance 的公开 DeviceObject 标志证据；DriverObject=0x%p，DeviceObject=0x%p。公开结构不区分常规与 LastChance 队列。",
                DriverObject,
                deviceObject);
            KswordArkCallbackExtendedAddRow(
                Builder,
                ModuleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_SHUTDOWN,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_SHUTDOWN,
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)DriverObject->MajorFunction[IRP_MJ_SHUTDOWN],
                (ULONG64)(ULONG_PTR)DriverObject,
                (ULONG64)(ULONG_PTR)deviceObject,
                0UL,
                nameText,
                detailText);
        }

        if (deviceObject != NULL) {
            ObDereferenceObject(deviceObject);
        }
    }

    ExFreePoolWithTag(deviceObjects, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
}

static VOID
KswordArkCallbackExtendedScanShutdownDirectory(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_z_ PCWSTR DirectoryName
    )
/*++

Routine Description:

    扫描一个驱动对象目录并检查 Shutdown 注册设备。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。
    DirectoryName - \Driver 或 \FileSystem。

Return Value:

    无返回值。

--*/
{
    HANDLE directoryHandle = NULL;
    KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_INFORMATION* entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    NTSTATUS status = STATUS_SUCCESS;

    status = KswordArkCallbackExtendedOpenObjectDirectory(
        DirectoryName,
        &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        ZwClose(directoryHandle);
        return;
    }

    entry = (KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_INFORMATION*)KswordArkAllocateNonPaged(
        KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES,
        KSWORD_ARK_CALLBACK_SYSTEM_TAG);
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return;
    }

    while (scannedEntries < KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_LIMIT) {
        WCHAR objectName[KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS];
        UNICODE_STRING objectNameString;
        PDRIVER_OBJECT driverObject = NULL;

        RtlZeroMemory(entry, KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES,
            TRUE,
            restartScan,
            &queryContext,
            &returnLength);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            break;
        }
        if (!NT_SUCCESS(status)) {
            break;
        }

        ++scannedEntries;
        RtlZeroMemory(objectName, sizeof(objectName));
        if (!KswordArkCallbackExtendedBuildObjectName(
                DirectoryName,
                &entry->Name,
                objectName,
                RTL_NUMBER_OF(objectName))) {
            continue;
        }

        RtlInitUnicodeString(&objectNameString, objectName);
        status = ObReferenceObjectByName(
            &objectNameString,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject);
        if (!NT_SUCCESS(status) || driverObject == NULL) {
            continue;
        }

        KswordArkCallbackExtendedAddDriverShutdownRows(
            Builder,
            ModuleCache,
            driverObject,
            objectName);
        ObDereferenceObject(driverObject);
    }

    ExFreePoolWithTag(entry, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
    ZwClose(directoryHandle);
}

static VOID
KswordArkCallbackExtendedAddShutdownCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    扫描 \Driver 与 \FileSystem 目录中的 Shutdown 注册设备。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    KswordArkCallbackExtendedScanShutdownDirectory(
        Builder,
        ModuleCache,
        L"\\Driver");
    KswordArkCallbackExtendedScanShutdownDirectory(
        Builder,
        ModuleCache,
        L"\\FileSystem");
}

VOID
KswordArkCallbackExtendedAddSystemCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    聚合 FS、LogonSession 与 Shutdown 三类遗漏回调。

Arguments:

    Builder - 响应构建器。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;

    if (Builder == NULL) {
        return;
    }

    KswordArkCallbackEnumInitModuleCache(&moduleCache);
    if (!NT_SUCCESS(KswordArkCallbackEnumEnsureModuleCache(&moduleCache))) {
        KswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }

    KswordArkCallbackExtendedAddFsRegistrationCallbacks(Builder, &moduleCache);
    KswordArkCallbackExtendedAddLogonCallbacks(Builder, &moduleCache);
    KswordArkCallbackExtendedAddShutdownCallbacks(Builder, &moduleCache);
    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
