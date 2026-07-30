/*++

Module Name:

    driver_blind_gate.c

Abstract:

    Force-unload identity gate for DriverObject communication records.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver_blind_internal.h"

BOOLEAN
KswordARKDriverCommunicationHasBlockingRecord(
    _In_ PDRIVER_OBJECT TargetDriverObject,
    _In_ ULONGLONG OriginalRequestModuleBase
    )
{
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_COMMUNICATION_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG recordIndex = 0UL;
    BOOLEAN blocked = FALSE;

    /* 中文说明：force-unload 已持有的真实 DriverObject 是不可省略的主身份。 */
    if (TargetDriverObject == NULL) {
        /* 中文说明：缺少引用对象时无法证明没有阻塞记录，按失败关闭。 */
        return TRUE;
    }
    /* 中文说明：功能未初始化时不存在由它创建的记录。 */
    if (InterlockedCompareExchange(
        &g_KswordArkDriverCommunicationState.Initialized,
        0L,
        0L) == 0L) {
        /* 中文说明：未初始化状态不会阻塞其它卸载逻辑。 */
        return FALSE;
    }
    /* 中文说明：FAST_MUTEX 要求调用方位于可等待 IRQL。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* 中文说明：错误 IRQL 无法证明安全，按存在阻塞记录处理。 */
        return TRUE;
    }

    /* 中文说明：串行扫描全部记录，避免只用一个可能被目标改写的字段作键。 */
    ExAcquireFastMutex(&g_KswordArkDriverCommunicationState.Lock);
    /* 中文说明：固定小表完整扫描可发现指针或不可变请求基址任一身份命中。 */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KSW_DRIVER_COMMUNICATION_RECORD* record =
            &g_KswordArkDriverCommunicationState.Records[recordIndex];
        BOOLEAN identityMatch = FALSE;

        /* 中文说明：空记录不持有目标身份或引用。 */
        if (record->InUse == FALSE) {
            /* 中文说明：继续检查其它记录。 */
            continue;
        }
        /* 中文说明：已引用 DriverObject 指针命中时不信任目标当前 DriverStart。 */
        if (record->DriverObject == TargetDriverObject) {
            /* 中文说明：对象身份命中即纳入门禁。 */
            identityMatch = TRUE;
        }
        /* 中文说明：原始 force-unload 请求基址提供第二条不可变身份线索。 */
        else if (OriginalRequestModuleBase != 0ULL &&
            record->TargetModuleBase == OriginalRequestModuleBase) {
            /* 中文说明：任一身份记录都必须先解决，不能被当前字段漂移绕过。 */
            identityMatch = TRUE;
        }
        /* 中文说明：无任一身份命中的记录与本次卸载无关。 */
        if (identityMatch == FALSE) {
            /* 中文说明：继续完整扫描。 */
            continue;
        }

        /* 中文说明：刷新实时 owned 和永久 taint 后作最终门禁判断。 */
        KswordARKDriverCommunicationRefreshRecordLocked(record);
        /* 中文说明：任一 owned 或 sticky taint 位都要求先执行 RESTORE。 */
        if (record->OwnedMask != 0UL || record->ConflictMask != 0UL) {
            /* 中文说明：发现阻塞记录后保留它及其 DriverObject 引用。 */
            blocked = TRUE;
            /* 中文说明：仍需在解锁后释放先前清理的过期记录引用。 */
            break;
        }

        /* 中文说明：无 owned/taint 的身份记录已经安全过期，可在门禁内退休。 */
        if (record->DriverObject != NULL) {
            /* 中文说明：暂存记录引用，避免在 FAST_MUTEX 内触发对象删除路径。 */
            releaseObjects[releaseCount] = record->DriverObject;
            /* 中文说明：固定表容量保证释放数组不会越界。 */
            ++releaseCount;
        }
        /* 中文说明：清除安全过期记录，不保留可变目标字段。 */
        RtlZeroMemory(record, sizeof(*record));
        /* 中文说明：记录退休推进全局 generation。 */
        KswordARKDriverCommunicationAdvanceGenerationLocked(NULL);
    }
    /* 中文说明：身份扫描完成后释放全局状态锁。 */
    ExReleaseFastMutex(&g_KswordArkDriverCommunicationState.Lock);

    /* 中文说明：在锁外释放所有安全过期记录持有的 DriverObject 引用。 */
    for (recordIndex = 0UL; recordIndex < releaseCount; ++recordIndex) {
        /* 中文说明：数组只保存非空记录引用。 */
        ObDereferenceObject(releaseObjects[recordIndex]);
    }
    /* 中文说明：返回双身份扫描得到的失败关闭门禁结果。 */
    return blocked;
}
