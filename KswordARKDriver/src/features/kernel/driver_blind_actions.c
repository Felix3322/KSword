/*++

Module Name:

    driver_blind_actions.c

Abstract:

    QUERY, BLIND, and RESTORE actions for DriverObject communication control.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver_blind_internal.h"

#include <ntstrsafe.h>

/* 中文说明：BLIND 把 UI 预检时确认的规范对象名绑定到本次模块基址解析。 */
static BOOLEAN
KswordARKDriverCommunicationMatchesCanonicalName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* RequestName,
    _In_z_ const WCHAR* CanonicalName
    )
{
    SIZE_T requestLength = 0U;
    UNICODE_STRING requestString;
    UNICODE_STRING canonicalString;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：空显示名不能证明 UI 证据仍对应当前 DriverObject。 */
    if (RequestName == NULL || CanonicalName == NULL || RequestName[0] == L'\0') {
        /* 中文说明：BLIND 对缺失的证据身份失败关闭。 */
        return FALSE;
    }
    /* 中文说明：固定数组必须在 ABI 边界内终止，禁止越界字符串扫描。 */
    status = RtlStringCchLengthW(
        RequestName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
        &requestLength);
    /* 中文说明：拒绝未终止或空规范名。 */
    if (!NT_SUCCESS(status) || requestLength == 0U) {
        /* 中文说明：无效名称不进入不安全的宽字符串 API。 */
        return FALSE;
    }

    /* 中文说明：两个已终止短字符串可安全构造成 UNICODE_STRING。 */
    RtlInitUnicodeString(&requestString, RequestName);
    /* 中文说明：resolver 返回的规范 \Driver\ 名是当前内核身份。 */
    RtlInitUnicodeString(&canonicalString, CanonicalName);
    /* 中文说明：对象目录大小写不敏感，但长度和全部字符必须精确匹配。 */
    return RtlEqualUnicodeString(&requestString, &canonicalString, TRUE);
}

/* 中文说明：显式 RESTORE 只在所有 taint 槽已由外部恢复到捕获原入口时退休记录。 */
static BOOLEAN
KswordARKDriverCommunicationTaintedSlotsMatchOriginalLocked(
    _In_ const KSW_DRIVER_COMMUNICATION_RECORD* Record
    )
{
    ULONG slotIndex = 0UL;

    /* 中文说明：无记录无法证明 taint 已被外部安全解决。 */
    if (Record == NULL || Record->InUse == FALSE || Record->DriverObject == NULL) {
        /* 中文说明：失败关闭，保留任何现有诊断记录。 */
        return FALSE;
    }

    /* 中文说明：只读验证永久 taint 槽，绝不尝试写回旧入口。 */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KSW_DRIVER_COMMUNICATION_SLOT* slot =
            &g_KswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH currentDispatch = NULL;

        /* 中文说明：未 taint 槽不参与显式冲突确认。 */
        if ((Record->ConflictMask & slot->Mask) == 0UL) {
            /* 中文说明：继续检查下一个永久 taint 位。 */
            continue;
        }
        /* 中文说明：原子读取避免普通加载与 CAS 控制路径语义不一致。 */
        currentDispatch = KswordARKDriverCommunicationReadDispatch(
            Record->DriverObject,
            slot->MajorFunction);
        /* 中文说明：只有第三方已恢复到事务前原入口才允许退休记录。 */
        if (currentDispatch != Record->OriginalDispatch[slotIndex]) {
            /* 中文说明：foreign 或重新回到 reject 都必须继续保持 conflict。 */
            return FALSE;
        }
    }

    /* 中文说明：所有永久 taint 槽均已由外部恢复，RESTORE 可只清记录不写槽。 */
    return TRUE;
}

/* 中文说明：查询只读取持久记录；无记录时直接返回 inactive。 */
NTSTATUS
KswordARKDriverCommunicationQuery(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    )
{
    KSW_DRIVER_COMMUNICATION_RECORD* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_OBJECT releasedObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONGLONG targetModuleBase = 0ULL;

    /* 中文说明：先在持久表中按模块基址查找，支持对象名已从目录消失的状态。 */
    ExAcquireFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：模块基址是记录的唯一身份。 */
    record = KswordARKDriverCommunicationFindRecordLocked(Request->targetModuleBase);
    /* 中文说明：命中记录时刷新 foreign change 后直接返回。 */
    if (record != NULL) {
        /* 中文说明：查询实时读取五个槽但不修改目标入口。 */
        KswordARKDriverCommunicationRefreshRecordLocked(record);
        /* 中文说明：若外部已完整恢复，则释放不再需要的记录。 */
        if (record->OwnedMask == 0UL && record->ConflictMask == 0UL) {
            /* 中文说明：暂存对象引用，解锁后再执行 dereference。 */
            releasedObject = record->DriverObject;
            /* 中文说明：响应仍使用记录中的目标地址和名称。 */
            driverObject = record->DriverObject;
            /* 中文说明：保存不可变记录键，禁止响应从当前 DriverStart 重新派生。 */
            targetModuleBase = record->TargetModuleBase;
            /* 中文说明：保存规范名供清零记录后回填。 */
            (VOID)RtlStringCchCopyW(
                canonicalName,
                RTL_NUMBER_OF(canonicalName),
                record->CanonicalName);
            /* 中文说明：清空记录表示 blind 所有权已经结束。 */
            RtlZeroMemory(record, sizeof(*record));
            /* 中文说明：记录移除本身也是可观察状态变化。 */
            KswordARKDriverCommunicationAdvanceGenerationLocked(NULL);
            /* 中文说明：用 inactive 结果报告外部已恢复。 */
            KswordARKDriverCommunicationFillResponse(
                Response,
                Request->action,
                STATUS_SUCCESS,
                0UL,
                NULL,
                driverObject,
                canonicalName);
            /* 中文说明：inactive 响应仍返回记录锁存的原始模块基址。 */
            Response->driverStart = targetModuleBase;
        }
        else {
            /* 中文说明：活动或冲突记录按实时 mask 返回。 */
            KswordARKDriverCommunicationFillResponse(
                Response,
                Request->action,
                STATUS_SUCCESS,
                0UL,
                record,
                NULL,
                NULL);
        }
        /* 中文说明：完成记录读取后释放全局串行锁。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：仅在记录被清除时释放原持有引用。 */
        if (releasedObject != NULL) {
            /* 中文说明：响应已复制地址和名称，不再访问对象字段。 */
            ObDereferenceObject(releasedObject);
        }
        /* 中文说明：查询协议本身成功，操作状态位于响应。 */
        return STATUS_SUCCESS;
    }
    /* 中文说明：未命中记录时立即释放锁，不扫描对象目录或重新做目标预检。 */
    ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：inactive QUERY 不触碰目标，供每模块证据扫描安全轮询。 */
    KswordARKDriverCommunicationFillResponse(
        Response,
        Request->action,
        STATUS_SUCCESS,
        0UL,
        NULL,
        NULL,
        NULL);
    /* 中文说明：无记录查询是协议成功，状态明确为 inactive。 */
    return STATUS_SUCCESS;
}

/* 中文说明：对五个槽执行全有或全无的 blind CAS 事务。 */
NTSTATUS
KswordARKDriverCommunicationBlind(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    )
{
    KSW_DRIVER_COMMUNICATION_RECORD* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_DISPATCH originalDispatch[KSW_DRIVER_COMMUNICATION_SLOT_COUNT] = { 0 };
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONG slotIndex = 0UL;
    ULONG changedMask = 0UL;
    ULONG captureInvalidMask = 0UL;
    ULONG externalDispatchMask = 0UL;
    ULONG forwardConflictMask = 0UL;
    ULONG rollbackTaintMask = 0UL;
    ULONG targetImageSize = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：对象目录解析在获取 FAST_MUTEX 前完成，保持 PASSIVE_LEVEL 合约。 */
    status = KswordARKDriverReferenceObjectByModuleBase(
        Request->targetModuleBase,
        &driverObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName));
    /* 中文说明：解析失败时返回确定的 inactive 响应。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：不把未验证显示名当成规范对象名。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            status,
            0UL,
            NULL,
            NULL,
            canonicalName);
        /* 中文说明：把对象目录失败传给 IOCTL handler。 */
        return status;
    }

    /* 中文说明：BLIND 必须携带 UI 证据扫描观察到的 DriverObject 地址。 */
    if ((Request->flags &
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) == 0UL ||
        Request->expectedDriverObjectAddress == 0ULL) {
        /* 中文说明：缺少对象地址证据时返回结构完整的业务失败响应。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_INVALID_PARAMETER,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：临时 resolver 引用未进入持久记录。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：不允许只靠可能复用的模块基址执行 BLIND。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：resolver 当前对象地址必须与 UI 证据逐位相等。 */
    if (Request->expectedDriverObjectAddress !=
        (ULONGLONG)(ULONG_PTR)driverObject) {
        /* 中文说明：地址身份漂移时返回当前 resolver 结果供重新预检。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：拒绝在 X 卸载、Y 复用基址后误致盲 Y。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：对象地址不匹配是稳定身份冲突。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：绑定 UI 预检规范名，防止旧证据命中复用同模块基址的新驱动。 */
    if (!KswordARKDriverCommunicationMatchesCanonicalName(
        Request->driverName,
        canonicalName)) {
        /* 中文说明：返回当前 resolver 身份供 R3 重新执行证据预检。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：规范名不匹配时绝不进入 target preflight 或 dispatch 写入。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：用稳定身份错误拒绝陈旧 BLIND 请求。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：拒绝 \FileSystem、空 DriverStart 和 KSword 自身。 */
    status = KswordARKDriverCommunicationValidateTarget(driverObject, canonicalName);
    /* 中文说明：校验失败不保留刚取得的目标引用。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：失败响应包含已验证读取的目标诊断字段。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            status,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：事务尚未开始，可以直接释放目标引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：把自保护或目录拒绝状态返回上层。 */
        return status;
    }

    /* 中文说明：锁前再次确认 resolver 对象当前 DriverStart 仍等于不可变请求基址。 */
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        Request->targetModuleBase) {
        /* 中文说明：目标身份在预检期间漂移时形成无写入失败响应。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：漂移对象引用未进入状态表。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：不允许从目标当前可写字段派生或更新记录键。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：所有 blind/restore 状态转移由一个 FAST_MUTEX 串行化。 */
    ExAcquireFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：卸载开始后禁止创建任何新记录。 */
    if (g_KswordArkDriverCommunicationState.ShuttingDown != FALSE) {
        /* 中文说明：解锁后释放本次临时目标引用。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：卸载期间目标状态不再可变。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_DELETE_PENDING,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：临时引用未进入状态表。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：返回稳定的卸载中状态。 */
        return STATUS_DELETE_PENDING;
    }

    /* 中文说明：持锁开始事务前再次读取 DriverStart，缩小身份漂移竞态窗口。 */
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        Request->targetModuleBase) {
        /* 中文说明：锁内身份复核失败时保持全部 dispatch 槽不变。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：先释放状态锁再释放临时对象引用。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：请求尚未创建或命中任何记录。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：返回稳定身份漂移错误。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：重复 blind 先查现有模块基址记录。 */
    record = KswordARKDriverCommunicationFindRecordLocked(Request->targetModuleBase);
    /* 中文说明：命中记录时验证对象身份并刷新实时 mask。 */
    if (record != NULL) {
        /* 中文说明：同一模块基址解析到不同对象时按身份冲突关闭。 */
        if (record->DriverObject != driverObject ||
            record->TargetModuleBase != Request->targetModuleBase) {
            /* 中文说明：保留旧记录，避免错误覆盖新加载对象。 */
            KswordARKDriverCommunicationFillResponse(
                Response,
                Request->action,
                STATUS_OBJECT_TYPE_MISMATCH,
                0UL,
                record,
                NULL,
                NULL);
            /* 中文说明：完成响应后释放串行锁。 */
            ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
            /* 中文说明：释放本次额外解析引用，旧记录引用仍保留。 */
            ObDereferenceObject(driverObject);
            /* 中文说明：模块身份冲突要求先解决旧记录。 */
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* 中文说明：读取第三方可能造成的实时变化。 */
        KswordARKDriverCommunicationRefreshRecordLocked(record);
        /* 中文说明：仅五槽均由本功能实际持有、active 且无 taint 时幂等成功。 */
        if (record->OwnedMask == KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL &&
            record->ActiveMask == KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL &&
            record->ConflictMask == 0UL) {
            /* 中文说明：changedMask 为零明确表示没有二次改写。 */
            KswordARKDriverCommunicationFillResponse(
                Response,
                Request->action,
                STATUS_SUCCESS,
                0UL,
                record,
                NULL,
                NULL);
            /* 中文说明：完成幂等查询后释放串行锁。 */
            ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
            /* 中文说明：新取得的额外引用不替换记录持有引用。 */
            ObDereferenceObject(driverObject);
            /* 中文说明：重复 blind 返回成功。 */
            return STATUS_SUCCESS;
        }

        /* 中文说明：存在 partial/foreign 状态时禁止覆盖并要求先恢复。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_DEVICE_BUSY,
            0UL,
            record,
            NULL,
            NULL);
        /* 中文说明：保留冲突记录并释放串行锁。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：释放本次额外解析引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：显式返回忙状态，防止 blind 堆叠。 */
        return STATUS_DEVICE_BUSY;
    }

    /* 中文说明：预留一个空记录，但提交前保持 InUse=FALSE。 */
    record = KswordARKDriverCommunicationAllocateRecordLocked();
    /* 中文说明：容量耗尽时不启动任何目标写入。 */
    if (record == NULL) {
        /* 中文说明：释放串行锁后再释放临时对象引用。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：形成无记录的容量失败响应。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_INSUFFICIENT_RESOURCES,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：临时引用未转移给状态表。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：返回固定容量耗尽状态。 */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 中文说明：锁内快照目标映像大小，后续原入口只能落在该不可变范围。 */
    targetImageSize = driverObject->DriverSize;
    /* 中文说明：零映像大小无法证明任何可恢复入口的 owner 生命周期。 */
    if (targetImageSize == 0UL) {
        /* 中文说明：清除尚未提交的预留记录。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：形成无写入的目标状态失败响应。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_INVALID_DEVICE_STATE,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：先释放控制锁再释放临时 resolver 引用。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：失败路径没有持久记录接管引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：拒绝缺少稳定映像范围的目标。 */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 中文说明：事务前一次性捕获五个 expected 原入口。 */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KSW_DRIVER_COMMUNICATION_SLOT* slot =
            &g_KswordArkDriverCommunicationSlots[slotIndex];
        ULONGLONG originalAddress = 0ULL;

        /* 中文说明：原子读取确保后续 CAS 能检测捕获后的第三方变化。 */
        originalDispatch[slotIndex] =
            KswordARKDriverCommunicationReadDispatch(
                driverObject,
                slot->MajorFunction);
        /* 中文说明：公开 MajorFunction 槽不应为空，异常对象按失败关闭。 */
        if (originalDispatch[slotIndex] == NULL) {
            /* 中文说明：标记对应槽失败并跳过全部写入事务。 */
            captureInvalidMask |= slot->Mask;
            /* 中文说明：空入口没有可执行 owner 地址可验证。 */
            continue;
        }
        /* 中文说明：内核 reject 是唯一允许位于目标映像外的原入口。 */
        if (originalDispatch[slotIndex] ==
            g_KswordArkDriverCommunicationState.RejectDispatch) {
            /* 中文说明：该精确入口由初始化阶段证明属于 ntos/HAL。 */
            continue;
        }
        /* 中文说明：把函数指针转换为整数，仅用于已验证映像范围比较。 */
        originalAddress = (ULONGLONG)(ULONG_PTR)originalDispatch[slotIndex];
        /* 中文说明：减法范围检查避免 base+size 溢出。 */
        if (originalAddress < Request->targetModuleBase ||
            (originalAddress - Request->targetModuleBase) >=
                (ULONGLONG)targetImageSize) {
            /* 中文说明：外部 hook owner 未被目标引用 pin，禁止保存为恢复入口。 */
            externalDispatchMask |= slot->Mask;
        }
    }

    /* 中文说明：捕获到目标映像外入口时不执行任何 CAS 或持久记录写入。 */
    if (externalDispatchMask != 0UL) {
        /* 中文说明：清除尚未提交的预留记录内容。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：释放控制锁后形成外部 owner 拒绝响应。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：外部 hook 不能作为未来 RESTORE 的稳定原入口。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：失败路径没有记录接管目标引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：返回稳定 owner 不匹配状态。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：捕获阶段发现空入口时不执行任何 CAS。 */
    if (captureInvalidMask != 0UL) {
        /* 中文说明：清除尚未提交的临时记录内容。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：释放串行锁后形成失败响应。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：空入口视为目标对象状态无效。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_INVALID_DEVICE_STATE,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：释放未转移的对象引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：返回目标 dispatch 表异常。 */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 中文说明：CAS 前最后复核目标映像身份和大小未在捕获期间漂移。 */
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        Request->targetModuleBase ||
        driverObject->DriverSize != targetImageSize) {
        /* 中文说明：身份漂移时清除预留记录并保持全部槽不变。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：形成最终无写入身份失败响应。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：先释放控制锁。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：无记录接管 resolver 引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：调用方必须重新采集目标证据。 */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* 中文说明：逐槽 CAS；任一失败后进入反向回滚。 */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KSW_DRIVER_COMMUNICATION_SLOT* slot =
            &g_KswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH previousDispatch = NULL;

        /* 中文说明：原入口已经是内核 reject 时无需写入且不取得恢复所有权。 */
        if (originalDispatch[slotIndex] ==
            g_KswordArkDriverCommunicationState.RejectDispatch) {
            /* 中文说明：该槽保持外部既有状态，继续处理其它槽。 */
            continue;
        }

        /* 中文说明：只有捕获值未变化时才发布内核 reject。 */
        previousDispatch = KswordARKDriverCommunicationCompareExchangeDispatch(
            driverObject,
            slot->MajorFunction,
            g_KswordArkDriverCommunicationState.RejectDispatch,
            originalDispatch[slotIndex]);
        /* 中文说明：CAS 不匹配表示第三方在事务窗口内改写。 */
        if (previousDispatch != originalDispatch[slotIndex]) {
            /* 中文说明：只记录一次性 forward 冲突，不把未写槽持久 taint。 */
            forwardConflictMask |= slot->Mask;
            /* 中文说明：后续统一反向恢复已经替换的槽。 */
            break;
        }

        /* 中文说明：记录本次真正写入成功的槽。 */
        changedMask |= slot->Mask;
    }

    /* 中文说明：出现事务冲突时仅恢复当前仍等于 reject 的已改槽。 */
    if (forwardConflictMask != 0UL) {
        ULONG rollbackIndex = 0UL;

        /* 中文说明：反向顺序降低观察到部分提交的时间窗口。 */
        for (rollbackIndex = slotIndex;
            rollbackIndex > 0UL;
            --rollbackIndex) {
            const ULONG completedIndex = rollbackIndex - 1UL;
            const KSW_DRIVER_COMMUNICATION_SLOT* completedSlot =
                &g_KswordArkDriverCommunicationSlots[completedIndex];
            PDRIVER_DISPATCH rollbackPrevious = NULL;

            /* 中文说明：只回滚本事务确实写入的槽。 */
            if ((changedMask & completedSlot->Mask) == 0UL) {
                /* 中文说明：天然 reject 或未处理槽不需要回滚。 */
                continue;
            }

            /* 中文说明：foreign change 优先，回滚绝不覆盖它。 */
            rollbackPrevious = KswordARKDriverCommunicationCompareExchangeDispatch(
                driverObject,
                completedSlot->MajorFunction,
                originalDispatch[completedIndex],
                g_KswordArkDriverCommunicationState.RejectDispatch);
            /* 中文说明：成功回滚或第三方已恢复原入口时都不再由本事务拥有。 */
            if (rollbackPrevious ==
                g_KswordArkDriverCommunicationState.RejectDispatch) {
                /* 中文说明：CAS 已把本功能安装的 reject 恢复为捕获原入口。 */
            }
            else if (rollbackPrevious == originalDispatch[completedIndex]) {
                /* 中文说明：第三方已经安全恢复，无需再次写入。 */
            }
            /* 中文说明：回滚期间出现其它入口时永久锁存 taint。 */
            else if (rollbackPrevious != originalDispatch[completedIndex]) {
                /* 中文说明：foreign change 不被覆盖且永不取得恢复所有权。 */
                rollbackTaintMask |= completedSlot->Mask;
            }
            /* 中文说明：回滚结束后该槽无论当前值如何都不再属于 net changed。 */
            changedMask &= ~completedSlot->Mask;
        }

        /* 中文说明：只有已写槽在回滚时观察 foreign 才创建 sticky 记录。 */
        if (rollbackTaintMask != 0UL) {
            /* 中文说明：记录取得本次 resolver DriverObject 引用的长期所有权。 */
            record->DriverObject = driverObject;
            /* 中文说明：锁存请求中已验证的不可变模块基址。 */
            record->TargetModuleBase = Request->targetModuleBase;
            /* 中文说明：回滚后没有任何槽仍具备自动恢复所有权。 */
            record->OwnedMask = 0UL;
            /* 中文说明：刷新前先以零初始化实时 reject 可见性。 */
            record->ActiveMask = 0UL;
            /* 中文说明：persistent conflict 只包含回滚已写槽观察到的 foreign。 */
            record->ConflictMask = rollbackTaintMask;
            /* 中文说明：只跟踪真实安装后发生回滚 taint 的槽，不含 forward 失败槽。 */
            record->InstalledMask = rollbackTaintMask;
            /* 中文说明：复制五个事务前原入口用于只读冲突解决确认。 */
            RtlCopyMemory(
                record->OriginalDispatch,
                originalDispatch,
                sizeof(record->OriginalDispatch));
            /* 中文说明：保存规范 \Driver\ 名用于后续无目录恢复。 */
            (VOID)RtlStringCchCopyW(
                record->CanonicalName,
                RTL_NUMBER_OF(record->CanonicalName),
                canonicalName);
            /* 中文说明：最后发布 InUse，避免半初始化记录被查询。 */
            record->InUse = TRUE;
            /* 中文说明：发布回滚 taint 记录的创建代数。 */
            KswordARKDriverCommunicationAdvanceGenerationLocked(record);
            /* 中文说明：刷新实时 reject 可见性且不吸收 forward 失败槽。 */
            KswordARKDriverCommunicationRefreshRecordLocked(record);
            /* 中文说明：响应只暴露真实 rollback taint。 */
            KswordARKDriverCommunicationFillResponse(
                Response,
                Request->action,
                STATUS_OBJECT_TYPE_MISMATCH,
                0UL,
                record,
                NULL,
                NULL);
            /* 中文说明：完成 sticky 记录提交后释放全局锁。 */
            ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
            /* 中文说明：记录继续持有 DriverObject 引用直到显式安全解决。 */
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* 中文说明：全部已写槽安全回滚时 forward 冲突不形成持久记录。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：一次性 STATUS_RETRY 响应保持 inactive 且无持久 conflict。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_RETRY,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：事务已完整回滚，释放状态锁。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：无记录接管本次 resolver 引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：调用方可重新完成证据扫描后重试。 */
        return STATUS_RETRY;
    }

    /* 中文说明：五槽原本全是 reject 时没有实际安装，也绝不创建假 active 记录。 */
    if (changedMask == 0UL) {
        /* 中文说明：清除未提交的预留槽，保持 OwnedMask 语义纯净。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：形成 inactive success，明确本次没有可改变的通信入口。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_SUCCESS,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* 中文说明：无持久记录时先释放控制锁。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：本次 resolver 引用没有转移到状态表。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：业务成功但 state 保持 inactive。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：五槽事务成功后提交完整可恢复记录。 */
    record->DriverObject = driverObject;
    /* 中文说明：锁存请求中已验证的不可变模块基址。 */
    record->TargetModuleBase = Request->targetModuleBase;
    /* 中文说明：只有本次 CAS 实际安装且未回滚的槽取得恢复所有权。 */
    record->OwnedMask = changedMask;
    /* 中文说明：事务完成后五槽均等于内核 reject。 */
    record->ActiveMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
    /* 中文说明：成功事务没有 foreign change。 */
    record->ConflictMask = 0UL;
    /* 中文说明：锁存本次真实安装槽，用于所有权释放后的 ABA 监控。 */
    record->InstalledMask = changedMask;
    /* 中文说明：保存每个槽的原始函数地址。 */
    RtlCopyMemory(
        record->OriginalDispatch,
        originalDispatch,
        sizeof(record->OriginalDispatch));
    /* 中文说明：保存模块解析得到的规范对象名。 */
    (VOID)RtlStringCchCopyW(
        record->CanonicalName,
        RTL_NUMBER_OF(record->CanonicalName),
        canonicalName);
    /* 中文说明：所有字段就绪后原子控制域内发布记录。 */
    record->InUse = TRUE;
    /* 中文说明：成功 blind 推进目标 generation。 */
    KswordARKDriverCommunicationAdvanceGenerationLocked(record);
    /* 中文说明：形成包含本次 changed mask 的 active 响应。 */
    KswordARKDriverCommunicationFillResponse(
        Response,
        Request->action,
        STATUS_SUCCESS,
        changedMask,
        record,
        NULL,
        NULL);
    /* 中文说明：提交完成后释放串行锁，记录继续持有对象引用。 */
    ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：blind 事务成功。 */
    return STATUS_SUCCESS;
}

/* 中文说明：按记录原入口恢复五槽，仅替换当前仍等于 reject 的入口。 */
NTSTATUS
KswordARKDriverCommunicationRestore(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    )
{
    KSW_DRIVER_COMMUNICATION_RECORD* record = NULL;
    PDRIVER_OBJECT releasedObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONG slotIndex = 0UL;
    ULONG changedMask = 0UL;
    ULONGLONG targetModuleBase = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：恢复只依赖持久模块基址记录，不重新解析可能已消失的对象名。 */
    ExAcquireFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：模块基址是恢复动作唯一查找键。 */
    record = KswordARKDriverCommunicationFindRecordLocked(Request->targetModuleBase);
    /* 中文说明：无记录表示没有可由本功能恢复的状态。 */
    if (record == NULL) {
        /* 中文说明：形成稳定 inactive/not-found 响应。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            STATUS_NOT_FOUND,
            0UL,
            NULL,
            NULL,
            NULL);
        /* 中文说明：无记录路径立即释放锁。 */
        ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
        /* 中文说明：向 R3 明确报告不存在恢复记录。 */
        return STATUS_NOT_FOUND;
    }

    /* 中文说明：先观察并永久锁存 foreign，防止 B->reject ABA 后覆盖旧入口。 */
    KswordARKDriverCommunicationRefreshRecordLocked(record);
    /* 中文说明：逐槽恢复当前记录仍实际拥有且从未 taint 的入口。 */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KSW_DRIVER_COMMUNICATION_SLOT* slot =
            &g_KswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH previousDispatch = NULL;

        /* 中文说明：未拥有或永久 taint 的槽不再参与任何恢复写入。 */
        if ((record->OwnedMask & slot->Mask) == 0UL ||
            (record->ConflictMask & slot->Mask) != 0UL) {
            /* 中文说明：taint 槽即使再次等于 reject 也只能只读诊断。 */
            continue;
        }

        /* 中文说明：只有当前仍为内核 reject 时才写回捕获原入口。 */
        previousDispatch = KswordARKDriverCommunicationCompareExchangeDispatch(
            record->DriverObject,
            slot->MajorFunction,
            record->OriginalDispatch[slotIndex],
            g_KswordArkDriverCommunicationState.RejectDispatch);
        /* 中文说明：CAS 命中表示本次确实恢复了该槽。 */
        if (previousDispatch ==
            g_KswordArkDriverCommunicationState.RejectDispatch) {
            /* 中文说明：记录本次恢复成功的协议位。 */
            changedMask |= slot->Mask;
            /* 中文说明：该槽不再需要记录持有恢复责任。 */
            record->OwnedMask &= ~slot->Mask;
        }
        /* 中文说明：第三方已恢复到相同原入口时视为安全完成。 */
        else if (previousDispatch == record->OriginalDispatch[slotIndex]) {
            /* 中文说明：无需覆盖，直接释放该槽所有权。 */
            record->OwnedMask &= ~slot->Mask;
        }
        else {
            /* 中文说明：foreign change 不被覆盖并永久锁存 taint。 */
            record->ConflictMask |= slot->Mask;
            /* 中文说明：观察 foreign 后永久撤销该槽自动恢复资格。 */
            record->OwnedMask &= ~slot->Mask;
        }
    }

    /* 中文说明：再次只读刷新，捕获恢复 CAS 窗口内出现的 foreign change。 */
    KswordARKDriverCommunicationRefreshRecordLocked(record);
    /* 中文说明：显式 RESTORE 尝试本身推进可观察 generation。 */
    KswordARKDriverCommunicationAdvanceGenerationLocked(record);

    /* 中文说明：无 owned 且无 taint 时可直接退休；taint 必须由外部恢复后显式确认。 */
    if (record->OwnedMask == 0UL &&
        (record->ConflictMask == 0UL ||
        KswordARKDriverCommunicationTaintedSlotsMatchOriginalLocked(record))) {
        /* 中文说明：暂存对象和名称，清记录后形成完整 inactive 响应。 */
        releasedObject = record->DriverObject;
        /* 中文说明：保存不可变记录键，禁止退休响应读取目标当前 DriverStart。 */
        targetModuleBase = record->TargetModuleBase;
        /* 中文说明：保存规范名供响应在记录清零后使用。 */
        (VOID)RtlStringCchCopyW(
            canonicalName,
            RTL_NUMBER_OF(canonicalName),
            record->CanonicalName);
        /* 中文说明：记录删除是永久 taint 唯一清除点，且不写任何 taint 槽。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：发布记录退休后的全局 generation。 */
        KswordARKDriverCommunicationAdvanceGenerationLocked(NULL);
        /* 中文说明：显式确认完成后返回成功 inactive，而不是残留 foreign flag。 */
        status = STATUS_SUCCESS;
        /* 中文说明：使用仍持有引用的对象填充诊断地址后再解锁释放。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            status,
            changedMask,
            NULL,
            releasedObject,
            canonicalName);
        /* 中文说明：inactive 响应仍回填记录创建时锁存的模块基址。 */
        Response->driverStart = targetModuleBase;
    }
    else {
        /* 中文说明：任何永久 taint 都保持 conflict 并阻塞 force-unload。 */
        status = record->ConflictMask != 0UL
            ? STATUS_OBJECT_TYPE_MISMATCH
            : STATUS_SUCCESS;
        /* 中文说明：未退休记录返回实时 active 与永久 conflict mask。 */
        KswordARKDriverCommunicationFillResponse(
            Response,
            Request->action,
            status,
            changedMask,
            record,
            NULL,
            NULL);
    }

    /* 中文说明：完成状态提交后释放串行锁。 */
    ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：完整恢复后释放目标 DriverObject 引用。 */
    if (releasedObject != NULL) {
        /* 中文说明：没有任何槽再依赖该对象寿命。 */
        ObDereferenceObject(releasedObject);
    }
    /* 中文说明：返回成功或 foreign-change 状态。 */
    return status;
}
