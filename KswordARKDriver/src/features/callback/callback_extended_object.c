/*++

Module Name:

    callback_extended_object.c

Abstract:

    枚举命名 CallbackObject 注册项与 Image Verification 回调对象。

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"

#define KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES (16UL * 1024UL)
#define KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_LIMIT 4096UL
#define KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_OBJECT_CODE_SCAN_BYTES 0x80UL
#define KSWORD_ARK_CALLBACK_OBJECT_TAG 'oCbK'
#define KSWORD_ARK_CALLBACK_OBJECT_SIGNATURE 0x6C6C6143UL

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

typedef struct _KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_INFORMATION;

typedef struct _KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION
{
    LIST_ENTRY Link;
    PVOID CallbackObject;
    PVOID CallbackFunction;
    PVOID CallbackContext;
} KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION;

typedef struct _KSWORD_ARK_CALLBACK_OBJECT_SNAPSHOT
{
    ULONG TraversalIndex;
    ULONG64 RegistrationAddress;
    ULONG64 CallbackFunction;
    ULONG64 CallbackContext;
} KSWORD_ARK_CALLBACK_OBJECT_SNAPSHOT;

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
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

static NTSTATUS
KswordArkCallbackExtendedOpenCallbackDirectory(
    _Out_ HANDLE* DirectoryHandleOut
    )
/*++

Routine Description:

    打开 \Callback 对象目录。

Arguments:

    DirectoryHandleOut - 输出内核句柄。

Return Value:

    返回 ZwOpenDirectoryObject 的 NTSTATUS。

--*/
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;

    if (DirectoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DirectoryHandleOut = NULL;
    RtlInitUnicodeString(&directoryName, L"\\Callback");
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
KswordArkCallbackExtendedBuildCallbackObjectName(
    _In_ PCUNICODE_STRING LeafName,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    拼接 \Callback\叶名称。

Arguments:

    LeafName - 对象目录返回的叶名称。
    Destination - 输出完整 NT 对象路径。
    DestinationChars - 输出缓冲字符数。

Return Value:

    成功返回 TRUE；参数或字符串越界返回 FALSE。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (LeafName == NULL ||
        LeafName->Buffer == NULL ||
        LeafName->Length == 0U ||
        Destination == NULL ||
        DestinationChars == 0UL) {
        return FALSE;
    }

    Destination[0] = L'\0';
    status = RtlStringCchCopyW(
        Destination,
        DestinationChars,
        L"\\Callback\\");
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

static ULONG
KswordArkCallbackExtendedEnumerateCallbackObject(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 CallbackObjectAddress,
    _In_ ULONG CallbackClass,
    _In_ ULONG Source,
    _In_ ULONG RegistrationType,
    _In_z_ PCWSTR ObjectName
    )
/*++

Routine Description:

    遍历一个 CallbackObject 内部注册链。中文说明：当前结构由 ExRegisterCallback
    公开入口的对象布局恢复；持有对象自旋锁复制标量快照，避免并发注销释放节点，
    并在释放自旋锁后完成模块判断、字符串格式化与响应构建。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。
    CallbackObjectAddress - CallbackObject 对象体地址。
    CallbackClass - 通用或 Image Verification 类别。
    Source - 枚举来源。
    RegistrationType - 注册子类型。
    ObjectName - 展示名称。

Return Value:

    返回成功验证的注册节点数量。

--*/
{
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG snapshotCount = 0UL;
    ULONG snapshotIndex = 0UL;
    ULONG objectSignature = 0UL;
    ULONG64 listHeadAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    LIST_ENTRY listHead;
    PKSPIN_LOCK objectLock = NULL;
    KIRQL oldIrql = PASSIVE_LEVEL;
    KSWORD_ARK_CALLBACK_OBJECT_SNAPSHOT* snapshots = NULL;

    // 验证调用方提供的响应构建器、模块缓存、对象地址与展示名称。
    if (Builder == NULL ||
        ModuleCache == NULL ||
        CallbackObjectAddress == 0ULL ||
        ObjectName == NULL) {
        return 0UL;
    }
    // 验证对象签名，避免对并非 CallbackObject 的地址获取私有锁。
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)CallbackObjectAddress,
            &objectSignature,
            sizeof(objectSignature)) ||
        objectSignature != KSWORD_ARK_CALLBACK_OBJECT_SIGNATURE) {
        return 0UL;
    }

    // 计算注册链表头地址；x64 CALLBACK_OBJECT 的锁位于 +0x08，链表位于 +0x10。
    listHeadAddress = CallbackObjectAddress + (2ULL * sizeof(ULONG_PTR));
    // 在进入自旋锁前分配非分页快照，锁内不进行任何内存分配或字符串处理。
    snapshots = (KSWORD_ARK_CALLBACK_OBJECT_SNAPSHOT*)KswordArkAllocateNonPaged(
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT,
        KSWORD_ARK_CALLBACK_OBJECT_TAG);
    // 内存不足时安全放弃本对象，避免在持锁状态进入失败恢复路径。
    if (snapshots == NULL) {
        return 0UL;
    }
    // 清零快照数组，确保任何提前结束路径都不会暴露未初始化字段。
    RtlZeroMemory(
        snapshots,
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT);

    // CALLBACK_OBJECT 的 +0x08 字段由 ExRegisterCallback 以 KSPIN_LOCK 方式保护。
    objectLock = (PKSPIN_LOCK)(ULONG_PTR)(CallbackObjectAddress + sizeof(ULONG_PTR));
    // 获取对象自旋锁并保存原 IRQL，阻止并发注销释放当前注册节点。
    KeAcquireSpinLock(objectLock, &oldIrql);
    // 在锁内读取链表头，确保首节点来自同一个一致性窗口。
    RtlZeroMemory(&listHead, sizeof(listHead));
    if (!KswordArkCallbackExtendedReadListEntry(listHeadAddress, &listHead)) {
        // 读取失败时先恢复 IRQL，再释放预分配快照。
        KeReleaseSpinLock(objectLock, oldIrql);
        // 快照来自本函数的非分页分配，失败路径必须对称释放。
        ExFreePoolWithTag(snapshots, KSWORD_ARK_CALLBACK_OBJECT_TAG);
        return 0UL;
    }

    // 从锁保护下的首节点开始遍历，最多复制固定数量的标量快照。
    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT) {
        KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION registration;
        ULONG64 nextAddress = 0ULL;

        // 每个节点读取前清零本地结构，避免异常读取留下栈残值。
        RtlZeroMemory(&registration, sizeof(registration));
        // 在对象锁保护下复制注册节点，注销路径不能同时释放该节点。
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration))) {
            break;
        }
        // 保存下一节点地址，后续只在当前锁保护窗口内使用。
        nextAddress = (ULONG64)(ULONG_PTR)registration.Link.Flink;

        // 仅接受属于当前对象且具有非空回调函数的注册节点。
        if ((ULONG64)(ULONG_PTR)registration.CallbackObject == CallbackObjectAddress &&
            registration.CallbackFunction != NULL) {
            // 快照只保存锁外构建响应所需的标量，不保留可失效的节点指针。
            snapshots[snapshotCount].TraversalIndex = index;
            snapshots[snapshotCount].RegistrationAddress = currentAddress;
            snapshots[snapshotCount].CallbackFunction =
                (ULONG64)(ULONG_PTR)registration.CallbackFunction;
            snapshots[snapshotCount].CallbackContext =
                (ULONG64)(ULONG_PTR)registration.CallbackContext;
            // 记录已填充快照数量，容量与遍历上限完全一致。
            ++snapshotCount;
        }

        // 自环表示链表损坏；继续遍历会在持锁状态无限循环。
        if (nextAddress == currentAddress) {
            break;
        }
        // 推进到下一节点并记录原始遍历序号。
        currentAddress = nextAddress;
        ++index;
    }

    // 完成节点复制后立即释放对象自旋锁并恢复调用方 IRQL。
    KeReleaseSpinLock(objectLock, oldIrql);

    // 锁外逐条验证模块归属并构建响应，避免在 DISPATCH_LEVEL 执行复杂逻辑。
    for (snapshotIndex = 0UL; snapshotIndex < snapshotCount; ++snapshotIndex) {
        WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];
        const KSWORD_ARK_CALLBACK_OBJECT_SNAPSHOT* snapshot = &snapshots[snapshotIndex];

        // 非模块地址不进入结果集，但不会影响其余稳定快照。
        if (!KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                snapshot->CallbackFunction)) {
            continue;
        }

        // 预清零展示缓冲，保证格式化失败时仍保持确定内容。
        RtlZeroMemory(nameText, sizeof(nameText));
        RtlZeroMemory(detailText, sizeof(detailText));
        // 使用锁内记录的遍历序号维持现有名称语义。
        (VOID)RtlStringCbPrintfW(
            nameText,
            sizeof(nameText),
            L"%ws[%lu]",
            ObjectName,
            (unsigned long)snapshot->TraversalIndex);
        // 详情只引用标量地址，不会解引用已经注销的注册节点。
        (VOID)RtlStringCbPrintfW(
            detailText,
            sizeof(detailText),
            L"CallbackObject 注册项；Object=0x%p，Registration=0x%p，Function=0x%p，Context=0x%p。",
            (PVOID)(ULONG_PTR)CallbackObjectAddress,
            (PVOID)(ULONG_PTR)snapshot->RegistrationAddress,
            (PVOID)(ULONG_PTR)snapshot->CallbackFunction,
            (PVOID)(ULONG_PTR)snapshot->CallbackContext);
        // 将已验证快照写入统一回调枚举响应。
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            CallbackClass,
            Source,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
            STATUS_SUCCESS,
            RegistrationType,
            0UL,
            0UL,
            snapshot->CallbackFunction,
            snapshot->CallbackContext,
            snapshot->RegistrationAddress,
            0UL,
            nameText,
            detailText);
        // 统计成功加入结果集的注册项数量。
        ++addedCount;
    }

    // 释放本函数分配的非分页快照数组。
    ExFreePoolWithTag(snapshots, KSWORD_ARK_CALLBACK_OBJECT_TAG);
    return addedCount;
}

static VOID
KswordArkCallbackExtendedAddNamedCallbackObjects(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    枚举 \Callback 目录中的命名 CallbackObject 及其注册函数。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    HANDLE directoryHandle = NULL;
    KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_INFORMATION* entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING callbackTypeName;

    status = KswordArkCallbackExtendedOpenCallbackDirectory(&directoryHandle);
    if (!NT_SUCCESS(status)) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_GENERIC_KERNEL,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_GENERIC_CALLBACK_OBJECT,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"\\Callback directory",
            L"打开命名 CallbackObject 目录失败。");
        return;
    }

    entry = (KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_INFORMATION*)KswordArkAllocateNonPaged(
        KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES,
        KSWORD_ARK_CALLBACK_OBJECT_TAG);
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return;
    }

    RtlInitUnicodeString(&callbackTypeName, L"Callback");
    while (scannedEntries < KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_LIMIT) {
        WCHAR objectName[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        UNICODE_STRING fullObjectName;
        PVOID callbackObject = NULL;

        RtlZeroMemory(entry, KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES,
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
        if (!RtlEqualUnicodeString(
                &entry->TypeName,
                &callbackTypeName,
                TRUE)) {
            continue;
        }

        RtlZeroMemory(objectName, sizeof(objectName));
        if (!KswordArkCallbackExtendedBuildCallbackObjectName(
                &entry->Name,
                objectName,
                RTL_NUMBER_OF(objectName))) {
            continue;
        }

        RtlInitUnicodeString(&fullObjectName, objectName);
        status = ObReferenceObjectByName(
            &fullObjectName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            NULL,
            KernelMode,
            NULL,
            &callbackObject);
        if (!NT_SUCCESS(status) || callbackObject == NULL) {
            continue;
        }

        (VOID)KswordArkCallbackExtendedEnumerateCallbackObject(
            Builder,
            ModuleCache,
            (ULONG64)(ULONG_PTR)callbackObject,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_GENERIC_KERNEL,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_GENERIC_CALLBACK_OBJECT,
            objectName);
        ObDereferenceObject(callbackObject);
    }

    ExFreePoolWithTag(entry, KSWORD_ARK_CALLBACK_OBJECT_TAG);
    ZwClose(directoryHandle);
}

static ULONG
KswordArkCallbackExtendedLocateImageCallbackGlobals(
    _Out_writes_(GlobalCapacity) ULONG64* GlobalAddresses,
    _In_ ULONG GlobalCapacity
    )
/*++

Routine Description:

    从 SeRegisterImageVerificationCallback 中提取两个 CallbackObject 全局指针。

Arguments:

    GlobalAddresses - 输出全局指针变量地址。
    GlobalCapacity - 输出槽容量。

Return Value:

    返回去重后的全局地址数量。

--*/
{
    UCHAR codeBytes[KSWORD_ARK_CALLBACK_OBJECT_CODE_SCAN_BYTES];
    ULONG offset = 0UL;
    ULONG foundCount = 0UL;
    ULONG64 routineAddress = (ULONG64)(ULONG_PTR)
        KswordArkCallbackExtendedGetSystemRoutine(L"SeRegisterImageVerificationCallback");

    if (GlobalAddresses == NULL || GlobalCapacity == 0UL || routineAddress == 0ULL) {
        return 0UL;
    }

    RtlZeroMemory(GlobalAddresses, sizeof(ULONG64) * GlobalCapacity);
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return 0UL;
    }

    for (offset = 0UL;
        offset + 7UL <= sizeof(codeBytes) && foundCount < GlobalCapacity;
        ++offset) {
        ULONG64 globalAddress = 0ULL;
        ULONG existingIndex = 0UL;
        BOOLEAN duplicate = FALSE;

        if (codeBytes[offset] != 0x48U ||
            codeBytes[offset + 1UL] != 0x8BU ||
            codeBytes[offset + 2UL] != 0x0DU) {
            continue;
        }
        if (!KswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset,
                3UL,
                7UL,
                &globalAddress)) {
            continue;
        }

        for (existingIndex = 0UL; existingIndex < foundCount; ++existingIndex) {
            if (GlobalAddresses[existingIndex] == globalAddress) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            GlobalAddresses[foundCount] = globalAddress;
            ++foundCount;
        }
    }

    return foundCount;
}

static VOID
KswordArkCallbackExtendedAddImageVerificationCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    枚举 Informational 与 Block 两个 Image Verification CallbackObject。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 模块缓存。

Return Value:

    无返回值。

--*/
{
    ULONG index = 0UL;
    ULONG globalCount = 0UL;
    ULONG64 globalAddresses[2] = { 0ULL, 0ULL };

    globalCount = KswordArkCallbackExtendedLocateImageCallbackGlobals(
        globalAddresses,
        RTL_NUMBER_OF(globalAddresses));
    if (globalCount == 0UL) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE_VERIFICATION,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"SeImageVerification callback objects",
            L"未能从 SeRegisterImageVerificationCallback 公开入口恢复 CallbackObject 全局指针。");
        return;
    }

    for (index = 0UL; index < globalCount; ++index) {
        ULONG64 callbackObject = 0ULL;
        const ULONG registrationType = (index == 0UL)
            ? KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_INFORMATIONAL
            : KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_BLOCK;
        PCWSTR objectName = (index == 0UL)
            ? L"SeImageVerification/Informational"
            : L"SeImageVerification/Block";

        if (!KswordArkCallbackExtendedReadPointer(
                globalAddresses[index],
                &callbackObject) ||
            callbackObject == 0ULL) {
            continue;
        }

        (VOID)KswordArkCallbackExtendedEnumerateCallbackObject(
            Builder,
            ModuleCache,
            callbackObject,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE_VERIFICATION,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT,
            registrationType,
            objectName);
    }
}

VOID
KswordArkCallbackExtendedAddObjectCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    聚合命名 CallbackObject 与 Image Verification 回调枚举。

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

    KswordArkCallbackExtendedAddNamedCallbackObjects(Builder, &moduleCache);
    KswordArkCallbackExtendedAddImageVerificationCallbacks(Builder, &moduleCache);
    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
