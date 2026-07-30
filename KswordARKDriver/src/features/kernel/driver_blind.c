/*++

Module Name:

    driver_blind.c

Abstract:

    Reversible DriverObject MajorFunction communication blocking.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "ark/ark_driver.h"
#include "driver_blind_internal.h"
#include "driver_integrity.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* 中文说明：五个协议槽保持稳定顺序，便于事务回滚和 R3 mask 展示。 */
const KSW_DRIVER_COMMUNICATION_SLOT g_KswordArkDriverCommunicationSlots[
    KSW_DRIVER_COMMUNICATION_SLOT_COUNT] = {
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_CREATE, IRP_MJ_CREATE },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_READ, IRP_MJ_READ },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_WRITE, IRP_MJ_WRITE },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_DEVICE_CONTROL, IRP_MJ_DEVICE_CONTROL },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_INTERNAL_DEVICE_CONTROL, IRP_MJ_INTERNAL_DEVICE_CONTROL }
};

/* 中文说明：静态状态位于驱动非分页映像，初始化完成前不允许 IOCTL 使用。 */
KSW_DRIVER_COMMUNICATION_STATE g_KswordArkDriverCommunicationState;

/* 中文说明：编译期确认协议槽数和 WDK 的 MajorFunction 数组边界保持一致。 */
C_ASSERT(KSW_DRIVER_COMMUNICATION_SLOT_COUNT == 5U);
/* 中文说明：编译期确认最高目标 major 一定落在 DRIVER_OBJECT 公开数组中。 */
C_ASSERT(IRP_MJ_INTERNAL_DEVICE_CONTROL <= IRP_MJ_MAXIMUM_FUNCTION);
/* 中文说明：锁定 v1 的 x64 ABI 大小，防止 R0/R3 编译选项漂移。 */
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST) == 552U);
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE) == 592U);
/* 中文说明：锁定请求基址、预检对象地址和响应 reject 地址的固定偏移。 */
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST,
    targetModuleBase) == 16U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST,
    expectedDriverObjectAddress) == 24U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE,
    driverObjectAddress) == 48U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE,
    rejectDispatchAddress) == 64U);

/* 中文说明：设备快照固定上限避免恶意或病态 DriverObject 消耗无界池内存。 */
#define KSW_DRIVER_COMMUNICATION_DEVICE_LIMIT 64UL
/* 中文说明：设备数量在枚举竞态中最多重试三次。 */
#define KSW_DRIVER_COMMUNICATION_DEVICE_ENUM_RETRY_LIMIT 3UL
/* 中文说明：非分页设备指针数组使用独立可识别池标签。 */
#define KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG 'lBcK'

/* 中文说明：使用指针 CAS 原子读取当前 dispatch，不对目标内容做任何修改。 */
PDRIVER_DISPATCH
KswordARKDriverCommunicationReadDispatch(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ UCHAR MajorFunction
    )
{
    PVOID currentDispatch = NULL;

    /* 中文说明：用 NULL/NULL compare-exchange 得到与写入路径一致的原子快照。 */
    currentDispatch = InterlockedCompareExchangePointer(
        (PVOID volatile*)&DriverObject->MajorFunction[MajorFunction],
        NULL,
        NULL);
    /* 中文说明：把公开函数指针类型恢复后交给调用方比较。 */
    return (PDRIVER_DISPATCH)currentDispatch;
}

/* 中文说明：仅当槽仍等于 expected 时才替换，绝不覆盖并发的第三方改写。 */
PDRIVER_DISPATCH
KswordARKDriverCommunicationCompareExchangeDispatch(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ UCHAR MajorFunction,
    _In_ PDRIVER_DISPATCH Exchange,
    _In_ PDRIVER_DISPATCH Expected
    )
{
    PVOID previousDispatch = NULL;

    /* 中文说明：指针 CAS 同时提供原子条件更新和跨处理器内存顺序。 */
    previousDispatch = InterlockedCompareExchangePointer(
        (PVOID volatile*)&DriverObject->MajorFunction[MajorFunction],
        (PVOID)Exchange,
        (PVOID)Expected);
    /* 中文说明：返回写入前的实际入口，供事务判定成功或 foreign change。 */
    return (PDRIVER_DISPATCH)previousDispatch;
}

/* 中文说明：规范对象名必须位于 \Driver\，文件系统对象明确拒绝。 */
static BOOLEAN
KswordARKDriverCommunicationIsCanonicalDriverName(
    _In_z_ const WCHAR* CanonicalName
    )
{
    UNICODE_STRING candidateName;
    UNICODE_STRING requiredPrefix;

    /* 中文说明：空字符串不能作为可修改 DriverObject 的身份。 */
    if (CanonicalName == NULL || CanonicalName[0] == L'\0') {
        /* 中文说明：缺少规范名时按失败关闭。 */
        return FALSE;
    }

    /* 中文说明：构造只读 UNICODE_STRING 以进行不区分大小写的前缀比较。 */
    RtlInitUnicodeString(&candidateName, CanonicalName);
    /* 中文说明：末尾反斜线阻止把 \DriverLike 误判为 \Driver。 */
    RtlInitUnicodeString(&requiredPrefix, L"\\Driver\\");
    /* 中文说明：只有真正位于 \Driver\ 目录中的对象才可进入替换事务。 */
    return RtlPrefixUnicodeString(&requiredPrefix, &candidateName, TRUE);
}

/* 中文说明：检查捕获的 I/O 管理器默认 dispatch 是否由 ntos/HAL 映像拥有。 */
static NTSTATUS
KswordARKDriverCommunicationValidateKernelReject(
    _In_ PDRIVER_DISPATCH RejectDispatch
    )
{
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule = NULL;
    ULONG moduleInfoBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：空入口永远不能作为跨驱动拒绝函数。 */
    if (RejectDispatch == NULL) {
        /* 中文说明：用稳定状态指出 DriverEntry 初始表不符合预期。 */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 中文说明：读取一次系统模块快照，用公开模块归属工具验证入口所有者。 */
    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    /* 中文说明：无法证明入口属于内核时拒绝启用功能。 */
    if (!NT_SUCCESS(status) || moduleInfo == NULL) {
        /* 中文说明：异常成功但空结果也归一为不可用。 */
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    /* 中文说明：按入口地址找到唯一覆盖它的已加载模块。 */
    ownerModule = KswordARKDriverIntegrityFindModuleForAddress(
        moduleInfo,
        (ULONGLONG)(ULONG_PTR)RejectDispatch);
    /* 中文说明：仅接受 ntoskrnl、ntkrnl 或 HAL 的稳定内核映像。 */
    if (ownerModule == NULL ||
        !KswordARKDriverIntegrityIsCoreKernelModule(ownerModule)) {
        /* 中文说明：释放模块快照后返回明确的所有者不匹配。 */
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        /* 中文说明：非内核入口不能跨越 KSword 自身卸载生命周期。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：验证完成后释放临时模块快照。 */
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    /* 中文说明：入口归属和非空条件均满足。 */
    return STATUS_SUCCESS;
}

/* 中文说明：生成非零单调 generation，并写入发生状态变化的记录。 */
VOID
KswordARKDriverCommunicationAdvanceGenerationLocked(
    _Inout_opt_ KSW_DRIVER_COMMUNICATION_RECORD* Record
    )
{
    /* 中文说明：每次可观察状态变化只推进一次全局代数。 */
    ++g_KswordArkDriverCommunicationState.Generation;
    /* 中文说明：零值保留给尚未创建记录的响应。 */
    if (g_KswordArkDriverCommunicationState.Generation == 0UL) {
        /* 中文说明：自然回绕时跳过保留的零值。 */
        ++g_KswordArkDriverCommunicationState.Generation;
    }
    /* 中文说明：存在目标记录时同步它的最后变化代数。 */
    if (Record != NULL) {
        /* 中文说明：记录代数供 R3 判断查询结果是否刷新。 */
        Record->Generation = g_KswordArkDriverCommunicationState.Generation;
    }
}

/* 中文说明：按唯一模块基址查找已经持有引用的状态记录。 */
KSW_DRIVER_COMMUNICATION_RECORD*
KswordARKDriverCommunicationFindRecordLocked(
    _In_ ULONGLONG TargetModuleBase
    )
{
    ULONG recordIndex = 0UL;

    /* 中文说明：线性扫描固定小表，避免动态容器和分页依赖。 */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KSW_DRIVER_COMMUNICATION_RECORD* record =
            &g_KswordArkDriverCommunicationState.Records[recordIndex];

        /* 中文说明：只比较记录创建时锁存的不可变请求模块基址。 */
        if (record->InUse != FALSE &&
            record->TargetModuleBase == TargetModuleBase) {
            /* 中文说明：模块基址命中即返回唯一记录。 */
            return record;
        }
    }

    /* 中文说明：未命中表示目标当前没有 KSword blind 状态。 */
    return NULL;
}

/* 中文说明：从固定表取得一个清零的空记录。 */
KSW_DRIVER_COMMUNICATION_RECORD*
KswordARKDriverCommunicationAllocateRecordLocked(
    VOID
    )
{
    ULONG recordIndex = 0UL;

    /* 中文说明：按固定顺序选择首个空槽，确保行为可重复。 */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KSW_DRIVER_COMMUNICATION_RECORD* record =
            &g_KswordArkDriverCommunicationState.Records[recordIndex];

        /* 中文说明：空槽可以安全重置并交给当前事务。 */
        if (record->InUse == FALSE) {
            /* 中文说明：清除上一代残留地址和 mask。 */
            RtlZeroMemory(record, sizeof(*record));
            /* 中文说明：调用方只有提交事务后才把 InUse 设为 TRUE。 */
            return record;
        }
    }

    /* 中文说明：固定容量耗尽时不覆盖现有可恢复状态。 */
    return NULL;
}

/* 中文说明：刷新当前 owned 槽的 active/conflict mask，不写目标表。 */
VOID
KswordARKDriverCommunicationRefreshRecordLocked(
    _Inout_ KSW_DRIVER_COMMUNICATION_RECORD* Record
    )
{
    ULONG slotIndex = 0UL;
    ULONG activeMask = 0UL;
    ULONG taintedMask = 0UL;
    ULONG previousOwnedMask = 0UL;
    ULONG previousActiveMask = 0UL;
    ULONG previousTaintedMask = 0UL;

    /* 中文说明：空记录没有可刷新状态。 */
    if (Record == NULL || Record->InUse == FALSE || Record->DriverObject == NULL) {
        /* 中文说明：无效记录按无操作返回。 */
        return;
    }
    /* 中文说明：保存旧 mask，仅在所有权或外部可观察状态变化时推进 generation。 */
    previousOwnedMask = Record->OwnedMask;
    previousActiveMask = Record->ActiveMask;
    previousTaintedMask = Record->ConflictMask;
    /* 中文说明：刷新只允许增加 taint，绝不按当前指针把历史冲突清掉。 */
    taintedMask = Record->ConflictMask;
    /* 中文说明：逐槽原子读取，避免把普通读与本模块 CAS 写入混用。 */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KSW_DRIVER_COMMUNICATION_SLOT* slot =
            &g_KswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH currentDispatch = NULL;
        /* 中文说明：取得目标槽的实时原子快照。 */
        currentDispatch = KswordARKDriverCommunicationReadDispatch(
            Record->DriverObject,
            slot->MajorFunction);
        /* 中文说明：active 只描述当前通信是否被 reject，不授予恢复所有权。 */
        if (currentDispatch == g_KswordArkDriverCommunicationState.RejectDispatch) {
            activeMask |= slot->Mask;
        }
        /* 中文说明：未由本功能实际安装的槽永远没有自动恢复资格。 */
        if ((Record->OwnedMask & slot->Mask) == 0UL) {
            /* 中文说明：仅监控曾成功安装的槽，forward CAS 失败槽不落持久 taint。 */
            if ((Record->InstalledMask & slot->Mask) != 0UL &&
                currentDispatch != Record->OriginalDispatch[slotIndex]) {
                /* 中文说明：覆盖安全外部恢复后 A->reject/foreign 的二次 ABA。 */
                taintedMask |= slot->Mask;
            }
            continue;
        }
        /* 中文说明：已 taint 槽必须立即撤销恢复所有权，防止 B->reject ABA。 */
        if ((taintedMask & slot->Mask) != 0UL) {
            Record->OwnedMask &= ~slot->Mask;
            continue;
        }
        /* 中文说明：仍为本功能安装的 reject 时保持实际所有权。 */
        if (currentDispatch == g_KswordArkDriverCommunicationState.RejectDispatch) {
            continue;
        }
        /* 中文说明：第三方安全恢复到捕获原入口时直接释放所有权。 */
        if (currentDispatch == Record->OriginalDispatch[slotIndex]) {
            Record->OwnedMask &= ~slot->Mask;
            continue;
        }
        /* 中文说明：观察到其它入口后永久 taint 并撤销自动恢复资格。 */
        taintedMask |= slot->Mask;
        Record->OwnedMask &= ~slot->Mask;
    }
    /* 中文说明：提交全部五槽的实时 reject 可见性。 */
    Record->ActiveMask = activeMask;
    /* 中文说明：提交只能单调增加的永久 foreign/ABA taint。 */
    Record->ConflictMask = taintedMask;
    /* 中文说明：只有所有权或可见 mask 真正变化时才更新查询代数。 */
    if (previousOwnedMask != Record->OwnedMask ||
        previousActiveMask != Record->ActiveMask ||
        previousTaintedMask != Record->ConflictMask) {
        /* 中文说明：把外部改写导致的状态变化暴露给 R3。 */
        KswordARKDriverCommunicationAdvanceGenerationLocked(Record);
    }
}

/* 中文说明：把当前记录或无记录状态转换成稳定协议响应。 */
VOID
KswordARKDriverCommunicationFillResponse(
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response,
    _In_ ULONG Action,
    _In_ NTSTATUS LastStatus,
    _In_ ULONG ChangedMask,
    _In_opt_ const KSW_DRIVER_COMMUNICATION_RECORD* Record,
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_opt_z_ const WCHAR* CanonicalName
    )
{
    /* 中文说明：固定响应必须完全初始化，避免泄露内核栈内容。 */
    RtlZeroMemory(Response, sizeof(*Response));
    /* 中文说明：回填协议版本供 R3 拒绝不兼容布局。 */
    Response->version = KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
    /* 中文说明：回显实际执行的动作。 */
    Response->action = Action;
    /* 中文说明：五个固定通信槽始终是本功能目标集合。 */
    Response->targetedMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
    /* 中文说明：changedMask 只表示本次 CAS 真正改变的槽。 */
    Response->changedMask = ChangedMask;
    /* 中文说明：底层状态通过 lastStatus 保持精确信息。 */
    Response->lastStatus = LastStatus;
    /* 中文说明：返回已验证的 ntos/HAL reject 入口供 R3 精确证据对比。 */
    Response->rejectDispatchAddress = (ULONGLONG)(ULONG_PTR)
        g_KswordArkDriverCommunicationState.RejectDispatch;

    /* 中文说明：优先使用持久记录填充活动和冲突状态。 */
    if (Record != NULL && Record->InUse != FALSE) {
        /* 中文说明：active mask 表示五个目标槽中当前指向内核 reject 的集合。 */
        Response->activeMask = Record->ActiveMask;
        /* 中文说明：owned mask 只表示本功能实际安装且仍有恢复资格的槽。 */
        Response->ownedMask = Record->OwnedMask;
        /* 中文说明：conflict mask 表示记录生命周期内永久锁存的 foreign taint。 */
        Response->conflictMask = Record->ConflictMask;
        /* 中文说明：记录代数在 blind、restore 或外部变化时更新。 */
        Response->generation = Record->Generation;
        /* 中文说明：冲突优先于 active 状态展示。 */
        Response->state = Record->ConflictMask != 0UL
            ? KSWORD_ARK_DRIVER_COMMUNICATION_STATE_CONFLICT
            : KSWORD_ARK_DRIVER_COMMUNICATION_STATE_ACTIVE;
        /* 中文说明：存在 foreign change 时设置稳定响应标志。 */
        if (Record->ConflictMask != 0UL) {
            /* 中文说明：R3 不需要从 NTSTATUS 猜测冲突语义。 */
            Response->responseFlags |=
                KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE_FLAG_FOREIGN_CHANGE;
        }
        /* 中文说明：返回被持有引用保护的 DriverObject 地址用于诊断。 */
        Response->driverObjectAddress =
            (ULONGLONG)(ULONG_PTR)Record->DriverObject;
        /* 中文说明：返回记录创建时验证并锁存的不可变模块基址身份。 */
        Response->driverStart = Record->TargetModuleBase;
        /* 中文说明：返回解析得到的 \Driver\ 规范名。 */
        (VOID)RtlStringCchCopyW(
            Response->driverName,
            RTL_NUMBER_OF(Response->driverName),
            Record->CanonicalName);
        /* 中文说明：记录路径已经完整填充响应。 */
        return;
    }

    /* 中文说明：无记录表示目标未被本功能接管。 */
    Response->state = KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE;
    /* 中文说明：无记录查询仍返回当前全局 generation。 */
    Response->generation = g_KswordArkDriverCommunicationState.Generation;
    /* 中文说明：解析成功时返回临时引用对应的诊断地址。 */
    if (DriverObject != NULL) {
        /* 中文说明：地址只作响应展示，R3 不能把它作为后续输入。 */
        Response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject;
        /* 中文说明：DriverStart 是后续控制动作的唯一身份。 */
        Response->driverStart = (ULONGLONG)(ULONG_PTR)DriverObject->DriverStart;
    }
    /* 中文说明：解析成功时返回规范对象名。 */
    if (CanonicalName != NULL) {
        /* 中文说明：有界复制确保固定数组始终以 NUL 结尾。 */
        (VOID)RtlStringCchCopyW(
            Response->driverName,
            RTL_NUMBER_OF(Response->driverName),
            CanonicalName);
    }
}

/* 中文说明：释放 IoEnumerateDeviceObjectList 为每个非空条目取得的引用。 */
static VOID
KswordARKDriverCommunicationReleaseDeviceSnapshot(
    _Inout_updates_(Capacity) PDEVICE_OBJECT* DeviceObjects,
    _In_ ULONG Capacity
    )
{
    ULONG deviceIndex = 0UL;

    /* 中文说明：空数组不包含可释放的 DeviceObject 引用。 */
    if (DeviceObjects == NULL) {
        /* 中文说明：允许所有失败清理路径幂等调用。 */
        return;
    }
    /* 中文说明：遍历分配容量而非返回总数，兼容 BUFFER_TOO_SMALL 的部分填充。 */
    for (deviceIndex = 0UL; deviceIndex < Capacity; ++deviceIndex) {
        /* 中文说明：零初始化数组中的空槽没有引用。 */
        if (DeviceObjects[deviceIndex] == NULL) {
            /* 中文说明：跳过未被枚举 API 填充的条目。 */
            continue;
        }
        /* 中文说明：每个已填充条目都由 IoEnumerateDeviceObjectList 增加过引用。 */
        ObDereferenceObject(DeviceObjects[deviceIndex]);
        /* 中文说明：清空槽位防止重试清理时重复 dereference。 */
        DeviceObjects[deviceIndex] = NULL;
    }
}

/* 中文说明：用带引用的 DeviceObject 快照验证目标是独立 legacy control driver。 */
static NTSTATUS
KswordARKDriverCommunicationValidateDeviceSnapshot(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT* deviceObjects = NULL;
    ULONG requestedCount = 0UL;
    ULONG actualCount = 0UL;
    ULONG attemptIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    /* 中文说明：先按官方两次调用模式只查询当前设备对象数量。 */
    status = IoEnumerateDeviceObjectList(
        DriverObject,
        NULL,
        0UL,
        &requestedCount);
    /* 中文说明：零长度探测通常返回 BUFFER_TOO_SMALL，其它失败直接关闭功能。 */
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        /* 中文说明：保留内核 API 的精确失败状态。 */
        return status;
    }
    /* 中文说明：无设备对象时没有可验证的通信面。 */
    if (requestedCount == 0UL) {
        /* 中文说明：禁止在缺少设备证据时直接改 MajorFunction。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 中文说明：设备创建竞态可能让第二次枚举容量不足，因此有界重试。 */
    for (attemptIndex = 0UL;
        attemptIndex < KSW_DRIVER_COMMUNICATION_DEVICE_ENUM_RETRY_LIMIT;
        ++attemptIndex) {
        ULONG deviceIndex = 0UL;
        NTSTATUS validationStatus = STATUS_SUCCESS;
        /* 中文说明：超过固定设备上限的复杂驱动不属于本功能支持范围。 */
        if (requestedCount > KSW_DRIVER_COMMUNICATION_DEVICE_LIMIT) {
            /* 中文说明：复杂设备拓扑必须使用专用栈治理。 */
            return STATUS_NOT_SUPPORTED;
        }
        /* 中文说明：按当前所需数量分配非分页指针数组。 */
        deviceObjects = (PDEVICE_OBJECT*)KswordARKAllocateNonPagedPool(
            (SIZE_T)requestedCount * sizeof(*deviceObjects),
            KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
        /* 中文说明：无法取得快照存储时不触碰目标。 */
        if (deviceObjects == NULL) {
            /* 中文说明：把池分配失败报告给 R3。 */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* 中文说明：零初始化允许所有枚举结果按非空槽统一释放引用。 */
        RtlZeroMemory(
            deviceObjects,
            (SIZE_T)requestedCount * sizeof(*deviceObjects));
        /* 中文说明：每次重试都从零取得 API 返回的实际总数。 */
        actualCount = 0UL;
        /* 中文说明：取得带引用的稳定 DeviceObject 指针快照。 */
        status = IoEnumerateDeviceObjectList(
            DriverObject,
            deviceObjects,
            requestedCount * (ULONG)sizeof(*deviceObjects),
            &actualCount);
        /* 中文说明：容量竞态时 API 会填满可容纳条目并为它们增加引用。 */
        if (status == STATUS_BUFFER_TOO_SMALL) {
            /* 中文说明：先释放本次部分快照中的全部引用。 */
            KswordARKDriverCommunicationReleaseDeviceSnapshot(
                deviceObjects,
                requestedCount);
            /* 中文说明：释放旧容量数组后再按新数量重试。 */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* 中文说明：清空局部指针避免失败路径重复释放。 */
            deviceObjects = NULL;
            /* 中文说明：API 回填的实际总数必须增长才构成有效重试依据。 */
            if (actualCount <= requestedCount) {
                /* 中文说明：不一致返回表示目标设备链正在异常变化。 */
                return STATUS_INVALID_DEVICE_STATE;
            }
            /* 中文说明：下一轮使用 API 返回的新容量。 */
            requestedCount = actualCount;
            /* 中文说明：继续有界重试而不检查不完整快照。 */
            continue;
        }
        /* 中文说明：其它枚举失败不包含可接受的完整快照。 */
        if (!NT_SUCCESS(status)) {
            /* 中文说明：防御性释放 API 可能写入的任何带引用非空条目。 */
            KswordARKDriverCommunicationReleaseDeviceSnapshot(
                deviceObjects,
                requestedCount);
            /* 中文说明：释放本次非分页数组。 */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* 中文说明：返回精确枚举失败状态。 */
            return status;
        }
        /* 中文说明：成功结果不得超过调用方提供的容量。 */
        if (actualCount > requestedCount) {
            /* 中文说明：先释放成功调用取得的全部可见引用。 */
            KswordARKDriverCommunicationReleaseDeviceSnapshot(
                deviceObjects,
                requestedCount);
            /* 中文说明：释放异常快照数组。 */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* 中文说明：拒绝不一致的 API 结果。 */
            return STATUS_INVALID_DEVICE_STATE;
        }
        /* 中文说明：成功但空快照表示设备在两次调用之间消失。 */
        if (actualCount == 0UL) {
            /* 中文说明：空数组没有 DeviceObject 引用，但仍需释放池内存。 */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* 中文说明：没有稳定通信面时按不支持处理。 */
            return STATUS_NOT_SUPPORTED;
        }
        /* 中文说明：逐个检查带引用快照中的公开设备属性。 */
        for (deviceIndex = 0UL; deviceIndex < actualCount; ++deviceIndex) {
            PDEVICE_OBJECT deviceObject = deviceObjects[deviceIndex];
            PDEVICE_OBJECT topDevice = NULL;
            /* 中文说明：成功快照中的空条目表示内核返回不一致。 */
            if (deviceObject == NULL) {
                /* 中文说明：记录失败后由统一清理释放其它引用。 */
                validationStatus = STATUS_INVALID_DEVICE_STATE;
                /* 中文说明：无需继续读取不完整快照。 */
                break;
            }
            /* 中文说明：每个枚举对象必须仍属于目标 DriverObject。 */
            if (deviceObject->DriverObject != DriverObject) {
                /* 中文说明：跨驱动对象身份不一致。 */
                validationStatus = STATUS_OBJECT_TYPE_MISMATCH;
                /* 中文说明：停止进一步设备属性检查。 */
                break;
            }
            /* 中文说明：本功能仅支持 FILE_DEVICE_UNKNOWN 的独立控制设备。 */
            if (deviceObject->DeviceType != FILE_DEVICE_UNKNOWN) {
                /* 中文说明：专用设备类型全部交给其专用治理路径。 */
                validationStatus = STATUS_NOT_SUPPORTED;
                /* 中文说明：停止进一步设备属性检查。 */
                break;
            }
            /* 中文说明：仍在初始化的设备不能接受全局 dispatch 切换。 */
            if ((deviceObject->Flags & DO_DEVICE_INITIALIZING) != 0UL) {
                /* 中文说明：要求目标设备完成初始化。 */
                validationStatus = STATUS_DEVICE_NOT_READY;
                /* 中文说明：停止进一步设备属性检查。 */
                break;
            }
            /* 中文说明：StackSize 非一表示存在下层栈关系或对象状态异常。 */
            if (deviceObject->StackSize != 1U) {
                /* 中文说明：拒绝在跨驱动栈中制造通信断点。 */
                validationStatus = STATUS_DEVICE_BUSY;
                /* 中文说明：停止进一步设备属性检查。 */
                break;
            }
            /* 中文说明：取得带引用的当前栈顶对象，安全检查上层附加关系。 */
            topDevice = IoGetAttachedDeviceReference(deviceObject);
            /* 中文说明：公开 API 正常应返回至少输入对象自身。 */
            if (topDevice == NULL) {
                /* 中文说明：空栈顶按目标状态异常处理。 */
                validationStatus = STATUS_INVALID_DEVICE_STATE;
                /* 中文说明：没有额外引用需要释放。 */
                break;
            }
            /* 中文说明：栈顶不同表示存在上层附加设备。 */
            if (topDevice != deviceObject) {
                /* 中文说明：先记录 busy，再统一释放本次栈顶引用。 */
                validationStatus = STATUS_DEVICE_BUSY;
            }
            /* 中文说明：配对释放 IoGetAttachedDeviceReference 的栈顶引用。 */
            ObDereferenceObject(topDevice);
            /* 中文说明：发现附加栈后不再检查其它设备。 */
            if (!NT_SUCCESS(validationStatus)) {
                /* 中文说明：统一快照清理将在循环外执行。 */
                break;
            }
        }
        /* 中文说明：成功枚举的每个非空条目都在这里统一 dereference。 */
        KswordARKDriverCommunicationReleaseDeviceSnapshot(
            deviceObjects,
            requestedCount);
        /* 中文说明：释放非分页指针数组。 */
        ExFreePoolWithTag(
            deviceObjects,
            KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
        /* 中文说明：数组释放后清空局部指针。 */
        deviceObjects = NULL;
        /* 中文说明：返回完整快照的首个失败或全部通过状态。 */
        return validationStatus;
    }
    /* 中文说明：连续设备增长耗尽重试预算时要求调用方稍后重试。 */
    return STATUS_RETRY;
}

/* 中文说明：验证目标引用属于 \Driver\ 且绝不是 KSword 自身。 */
NTSTATUS
KswordARKDriverCommunicationValidateTarget(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_z_ const WCHAR* CanonicalName
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    /* 中文说明：模块基址解析必须返回真实 DriverObject。 */
    if (DriverObject == NULL) {
        /* 中文说明：空对象不能进入任何 CAS 路径。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：文件系统目录对象不属于本功能允许范围。 */
    if (!KswordARKDriverCommunicationIsCanonicalDriverName(CanonicalName)) {
        /* 中文说明：稳定拒绝 \FileSystem 和其它对象目录。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 中文说明：禁止致盲 KSword 自身，否则 R3 会失去恢复控制通道。 */
    if (DriverObject == g_KswordArkDriverCommunicationState.SelfDriverObject ||
        (g_KswordArkDriverCommunicationState.SelfDriverObject != NULL &&
        DriverObject->DriverStart ==
            g_KswordArkDriverCommunicationState.SelfDriverObject->DriverStart)) {
        /* 中文说明：使用核心驱动拒绝状态突出不可绕过的自保护。 */
        return STATUS_DRIVER_BLOCKED_CRITICAL;
    }
    /* 中文说明：模块基址解析后仍要求非空 DriverStart。 */
    if (DriverObject->DriverStart == NULL) {
        /* 中文说明：缺失加载身份时按失效对象处理。 */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* 中文说明：公开 AddDevice 表示 PnP 生命周期，禁止只改通信槽破坏 PnP 心智模型。 */
    if (DriverObject->DriverExtension != NULL &&
        DriverObject->DriverExtension->AddDevice != NULL) {
        /* 中文说明：PnP 驱动必须通过完整设备栈治理，本功能失败关闭。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 中文说明：StartIo 驱动含独立队列生命周期，不能只替换五个 dispatch 槽。 */
    if (DriverObject->DriverStartIo != NULL) {
        /* 中文说明：避免让已排队 IRP 与新拒绝入口形成半切换状态。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 中文说明：通过内核带引用枚举取得稳定设备快照并执行栈预检。 */
    status = KswordARKDriverCommunicationValidateDeviceSnapshot(DriverObject);
    /* 中文说明：保留快照预检的精确失败原因。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：任何设备生命周期或栈风险都失败关闭。 */
        return status;
    }
    /* 中文说明：目标满足目录、自身、稳定 legacy control device 和加载身份约束。 */
    return status;
}

NTSTATUS
KswordARKDriverCommunicationInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDRIVER_DISPATCH rejectDispatch = NULL;
    ULONG majorIndex = 0UL;
    ULONG_PTR selfStart = 0U;
    ULONG_PTR rejectAddress = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：该初始化必须在 WdfDriverCreate 改写 dispatch 表前执行。 */
    if (DriverObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* 中文说明：错误调用阶段无法安全验证初始 DriverObject。 */
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：重复初始化只允许同一个驱动对象幂等成功。 */
    if (InterlockedCompareExchange(
        &g_KswordArkDriverCommunicationState.Initialized,
        0L,
        0L) != 0L) {
        /* 中文说明：不同对象重复调用表示初始化顺序错误。 */
        return g_KswordArkDriverCommunicationState.SelfDriverObject == DriverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }

    /* 中文说明：I/O 管理器在 DriverEntry 前把所有槽预填为同一个 invalid dispatch。 */
    rejectDispatch = DriverObject->MajorFunction[0];
    /* 中文说明：逐项验证初始表完全一致且非空。 */
    for (majorIndex = 0UL;
        majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
        ++majorIndex) {
        /* 中文说明：任一差异表示调用已经晚于框架 dispatch 安装。 */
        if (rejectDispatch == NULL ||
            DriverObject->MajorFunction[majorIndex] != rejectDispatch) {
            /* 中文说明：不捕获不确定入口，功能按失败关闭。 */
            return STATUS_INVALID_DEVICE_STATE;
        }
    }

    /* 中文说明：额外拒绝落在 KSword 自身映像范围内的入口。 */
    selfStart = (ULONG_PTR)DriverObject->DriverStart;
    /* 中文说明：把函数入口转换为仅用于范围比较的整数地址。 */
    rejectAddress = (ULONG_PTR)rejectDispatch;
    /* 中文说明：用减法比较避免 selfStart + DriverSize 溢出。 */
    if (DriverObject->DriverSize != 0UL &&
        rejectAddress >= selfStart &&
        (rejectAddress - selfStart) < (ULONG_PTR)DriverObject->DriverSize) {
        /* 中文说明：自身函数不能作为跨越 KSword 卸载的拒绝入口。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：通过已加载模块快照证明入口真正属于 ntos/HAL。 */
    status = KswordARKDriverCommunicationValidateKernelReject(rejectDispatch);
    /* 中文说明：不能完成内核归属证明时拒绝启用功能。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：把精确验证失败返回 DriverEntry。 */
        return status;
    }

    /* 中文说明：验证成功后清空并初始化全局状态。 */
    RtlZeroMemory(
        &g_KswordArkDriverCommunicationState,
        sizeof(g_KswordArkDriverCommunicationState));
    /* 中文说明：FAST_MUTEX 只保护控制路径和记录表。 */
    ExInitializeFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：保存自身对象用于永久 self-target 拒绝。 */
    g_KswordArkDriverCommunicationState.SelfDriverObject = DriverObject;
    /* 中文说明：保存内核拥有的默认 invalid dispatch。 */
    g_KswordArkDriverCommunicationState.RejectDispatch = rejectDispatch;
    /* 中文说明：generation 从一开始，零值留给未初始化。 */
    g_KswordArkDriverCommunicationState.Generation = 1UL;
    /* 中文说明：所有状态字段就绪后发布 Initialized。 */
    InterlockedExchange(
        &g_KswordArkDriverCommunicationState.Initialized,
        1L);
    /* 中文说明：通信阻断后端可以接受 IOCTL。 */
    return STATUS_SUCCESS;
}

VOID
KswordARKDriverCommunicationUninitialize(
    VOID
    )
{
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_COMMUNICATION_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG recordIndex = 0UL;

    /* 中文说明：未初始化状态没有任何目标引用或替换需要恢复。 */
    if (InterlockedCompareExchange(
        &g_KswordArkDriverCommunicationState.Initialized,
        0L,
        0L) == 0L) {
        /* 中文说明：重复清理按幂等无操作返回。 */
        return;
    }

    /* 中文说明：串行等待正在进行的 control 操作完成。 */
    ExAcquireFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：先阻止任何后续 blind 请求创建新记录。 */
    g_KswordArkDriverCommunicationState.ShuttingDown = TRUE;

    /* 中文说明：逐记录恢复仍由本功能实际持有且未污染的槽。 */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KSW_DRIVER_COMMUNICATION_RECORD* record =
            &g_KswordArkDriverCommunicationState.Records[recordIndex];
        ULONG slotIndex = 0UL;

        /* 中文说明：空记录不包含对象引用。 */
        if (record->InUse == FALSE || record->DriverObject == NULL) {
            /* 中文说明：跳过未用槽。 */
            continue;
        }

        /* 中文说明：先锁存 foreign 观察并撤销 taint 槽的恢复所有权。 */
        KswordARKDriverCommunicationRefreshRecordLocked(record);
        /* 中文说明：卸载恢复仍坚持 compare-exchange，不覆盖 foreign change。 */
        for (slotIndex = 0UL;
            slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
            ++slotIndex) {
            const KSW_DRIVER_COMMUNICATION_SLOT* slot =
                &g_KswordArkDriverCommunicationSlots[slotIndex];

            /* 中文说明：只处理实际安装且从未 taint 的槽。 */
            if ((record->OwnedMask & slot->Mask) == 0UL ||
                (record->ConflictMask & slot->Mask) != 0UL) {
                /* 中文说明：未拥有或 taint 槽即使回到 reject 也绝不写。 */
                continue;
            }

            /* 中文说明：当前仍为内核 reject 时恢复捕获的原入口。 */
            (VOID)KswordARKDriverCommunicationCompareExchangeDispatch(
                record->DriverObject,
                slot->MajorFunction,
                record->OriginalDispatch[slotIndex],
                g_KswordArkDriverCommunicationState.RejectDispatch);
        }

        /* 中文说明：暂存引用，解锁后统一 dereference。 */
        releaseObjects[releaseCount] = record->DriverObject;
        /* 中文说明：固定容量保证 releaseCount 不会越界。 */
        ++releaseCount;
        /* 中文说明：清空记录避免卸载期间再次被查询。 */
        RtlZeroMemory(record, sizeof(*record));
    }

    /* 中文说明：所有记录已移除后撤销初始化发布状态。 */
    InterlockedExchange(
        &g_KswordArkDriverCommunicationState.Initialized,
        0L);
    /* 中文说明：目标表不引用 KSword 代码，解锁后即可释放对象引用。 */
    ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);

    /* 中文说明：在锁外释放所有目标 DriverObject 引用。 */
    for (recordIndex = 0UL; recordIndex < releaseCount; ++recordIndex) {
        /* 中文说明：数组只保存真实记录中的非空引用。 */
        ObDereferenceObject(releaseObjects[recordIndex]);
    }
}

NTSTATUS
KswordARKDriverControlCommunication(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    )
{
    const ULONG allowedFlags =
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_TARGET_MODULE_BASE_PRESENT |
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_UI_CONFIRMED |
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;

    /* 中文说明：后端只接受完整固定请求和响应指针。 */
    if (Request == NULL || Response == NULL) {
        /* 中文说明：缺少固定缓冲时不能形成协议响应。 */
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：先清零响应，确保所有失败路径都不泄露数据。 */
    RtlZeroMemory(Response, sizeof(*Response));
    /* 中文说明：填入失败路径也必须返回的协议版本。 */
    Response->version = KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
    /* 中文说明：回显请求动作便于 R3 关联并发任务。 */
    Response->action = Request->action;
    /* 中文说明：固定目标 mask 在任何结果中保持一致。 */
    Response->targetedMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;

    /* 中文说明：所有对象目录和 FAST_MUTEX 操作都要求 PASSIVE_LEVEL。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* 中文说明：记录不可执行状态供 R3 展示。 */
        Response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        /* 中文说明：错误 IRQL 不进入任何共享状态。 */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* 中文说明：DriverEntry 初始化失败或卸载后不允许控制。 */
    if (InterlockedCompareExchange(
        &g_KswordArkDriverCommunicationState.Initialized,
        0L,
        0L) == 0L) {
        /* 中文说明：未初始化状态明确报告设备后端不可用。 */
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* 中文说明：调用方可以据此禁用 UI 动作。 */
        return STATUS_DEVICE_NOT_READY;
    }
    /* 中文说明：协议版本必须精确匹配 v1 固定布局。 */
    if (Request->version != KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION) {
        /* 中文说明：版本不匹配不尝试兼容猜测。 */
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        /* 中文说明：把稳定版本错误返回调用方。 */
        return STATUS_REVISION_MISMATCH;
    }
    /* 中文说明：reserved 和未知 flags 必须为零。 */
    if (Request->reserved != 0UL || (Request->flags & ~allowedFlags) != 0UL) {
        /* 中文说明：拒绝未来字段被旧 R0 误解释。 */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* 中文说明：无效 flags 不进入对象目录。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：所有三个动作都以明确模块基址作为唯一身份。 */
    if ((Request->flags &
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
        Request->targetModuleBase == 0ULL) {
        /* 中文说明：显示名绝不能替代模块基址身份。 */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* 中文说明：缺少身份时立即失败。 */
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：按动作路由到独立、可审计的状态转换。 */
    switch (Request->action) {
    case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY:
        /* 中文说明：查询只读取状态，不受危险策略阻断。 */
        return KswordARKDriverCommunicationQuery(Request, Response);
    case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND:
        /* 中文说明：handler 已完成 safety gate，后端只执行事务。 */
        return KswordARKDriverCommunicationBlind(Request, Response);
    case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE:
        /* 中文说明：恢复是风险降低动作，不受危险策略阻断。 */
        return KswordARKDriverCommunicationRestore(Request, Response);
    default:
        /* 中文说明：未知 action 不猜测执行语义。 */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* 中文说明：返回固定参数错误。 */
        return STATUS_INVALID_PARAMETER;
    }
}
