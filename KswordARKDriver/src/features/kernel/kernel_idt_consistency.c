/*++

Module Name:

    kernel_idt_consistency.c

Abstract:

    只读采集每个活动逻辑处理器的 IDTR，计算「多数派」IDT 表，并与驱动启动期
    抓取的 IDT 基线比对。它回答两个问题：某个核心是否被单独换了 IDT（典型的
    lidt 接管手法只改当前核），以及整机 IDT 表是否被搬到了启动期以外的地址。

    本文件只执行 SIDT 与结构比较，不写 IDTR、不改任何描述符。

Environment:

    Kernel mode, PASSIVE_LEVEL（采集过程需要切换线程组亲和性）。

--*/

#include "kernel_idt_consistency.h"

#include "kernel_idt_baseline.h"
#include "src/platform/pool_compat.h"

#include <intrin.h>

// 本模块私有的池标签。
#define KSW_IDT_CONSISTENCY_TAG 'cIsK'

#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS 0xFFFFU
#endif

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__sidt)
#endif

#pragma pack(push, 1)
// SIDT 写回的 10 字节伪描述符布局。
typedef struct _KSW_IDT_CONSISTENCY_REGISTER
{
    USHORT Limit;
    ULONG_PTR Base;
} KSW_IDT_CONSISTENCY_REGISTER, *PKSW_IDT_CONSISTENCY_REGISTER;
#pragma pack(pop)

#if defined(_M_AMD64) || defined(_M_X64)

static VOID
KswordARKIdtConsistencyComputeMajority(
    _Inout_ KSW_IDT_CONSISTENCY_VIEW* View
    )
/*++

Routine Description:

    在已采集的样本中找出出现次数最多的 (Base, Limit) 组合作为多数派。

Arguments:

    View - 已填好 Cpus[] 的采集结果。

Return Value:

    None. 结果写入 View 的 Majority* 字段。

--*/
{
    ULONG outerIndex = 0UL;

    /* 没有任何有效样本时保持全零，调用方据此判定不可用。 */
    if (View == NULL || View->CapturedCount == 0UL) {
        return;
    }

    /* 处理器数量最多几百个，直接做 O(n^2) 计票即可，无需额外分配。 */
    for (outerIndex = 0UL; outerIndex < View->CpuCount; ++outerIndex) {
        const KSW_IDT_CONSISTENCY_CPU* candidate = &View->Cpus[outerIndex];
        ULONG innerIndex = 0UL;
        ULONG votes = 0UL;

        /* 采集失败的行不参与计票。 */
        if (candidate->Captured == 0UL) {
            continue;
        }

        /* 统计与候选值完全相同的处理器数量。 */
        for (innerIndex = 0UL; innerIndex < View->CpuCount; ++innerIndex) {
            const KSW_IDT_CONSISTENCY_CPU* other = &View->Cpus[innerIndex];

            /* 同样跳过无效样本，避免把零值算成一票。 */
            if (other->Captured == 0UL) {
                continue;
            }

            /* Base 与 Limit 都相同才算同一张表。 */
            if (other->Base == candidate->Base && other->Limit == candidate->Limit) {
                votes += 1UL;
            }
        }

        /* 票数更高者胜出，平票时保留先出现的候选，保证结果稳定。 */
        if (votes > View->MajorityCount) {
            View->MajorityCount = votes;
            View->MajorityBase = candidate->Base;
            View->MajorityLimit = candidate->Limit;
        }
    }
}

static VOID
KswordARKIdtConsistencyScoreRows(
    _Inout_ KSW_IDT_CONSISTENCY_VIEW* View
    )
/*++

Routine Description:

    按多数派与启动期基线统计偏离处理器的数量。

Arguments:

    View - 已完成多数派计算的采集结果。

Return Value:

    None. 结果写入 View 的 DivergedCount / RelocatedCount。

--*/
{
    ULONG index = 0UL;

    /* 多数派不成立时不做任何判定，避免输出无依据的告警。 */
    if (View == NULL || View->MajorityCount == 0UL) {
        return;
    }

    /* 逐行比对，分别累计「偏离多数派」和「偏离启动期基线」。 */
    for (index = 0UL; index < View->CpuCount; ++index) {
        const KSW_IDT_CONSISTENCY_CPU* row = &View->Cpus[index];

        /* 采集失败的行不产生任何结论。 */
        if (row->Captured == 0UL) {
            continue;
        }

        /* 与多数派表地址或长度不同即视为分化。 */
        if (row->Base != View->MajorityBase || row->Limit != View->MajorityLimit) {
            View->DivergedCount += 1UL;
        }

        /* 只有拿到基线的行才允许判定重定位。 */
        if (row->BaselineAvailable != 0UL &&
            (row->Base != row->BaselineBase || row->Limit != row->BaselineLimit)) {
            View->RelocatedCount += 1UL;
        }
    }
}

#endif

NTSTATUS
KswordARKIdtConsistencyCollect(
    _Outptr_result_maybenull_ KSW_IDT_CONSISTENCY_VIEW** ViewOut
    )
/*++

Routine Description:

    遍历所有活动处理器执行 SIDT，构建跨 CPU 的 IDTR 一致性视图。

Arguments:

    ViewOut - 成功时接收调用方需释放的视图指针。

Return Value:

    STATUS_SUCCESS 或分配/拓扑/架构相关的失败状态。

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONG activeCount = 0UL;
    ULONG globalIndex = 0UL;
    ULONG rowCount = 0UL;
    SIZE_T allocationBytes = 0U;
    KSW_IDT_CONSISTENCY_VIEW* view = NULL;

    /* 参数校验：调用方必须提供输出槽位。 */
    if (ViewOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 先清空输出，保证失败路径上调用方看到的是 NULL。 */
    *ViewOut = NULL;

    /* 查询全组活动处理器总数作为数组上界。 */
    activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCount == 0UL) {
        return STATUS_NOT_SUPPORTED;
    }

    /* 计算变长结构大小并防止乘法溢出。 */
    if (activeCount > (MAXULONG_PTR - sizeof(KSW_IDT_CONSISTENCY_VIEW)) / sizeof(KSW_IDT_CONSISTENCY_CPU)) {
        return STATUS_NOT_SUPPORTED;
    }
    allocationBytes = sizeof(KSW_IDT_CONSISTENCY_VIEW) +
        ((SIZE_T)activeCount * sizeof(KSW_IDT_CONSISTENCY_CPU));

    /* 采集在切换亲和性的过程中进行，使用非分页池承载结果。 */
    view = (KSW_IDT_CONSISTENCY_VIEW*)KswordARKAllocateNonPagedPool(
        allocationBytes,
        KSW_IDT_CONSISTENCY_TAG);
    if (view == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 归零后所有未采集行的 Captured 自然为 0。 */
    RtlZeroMemory(view, allocationBytes);

    /* 逐个处理器采样 IDTR，并顺带取回该处理器的启动期基线。 */
    for (globalIndex = 0UL; globalIndex < activeCount; ++globalIndex) {
        PROCESSOR_NUMBER processor;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        KSW_IDT_CONSISTENCY_REGISTER idtr;
        KSW_IDT_CONSISTENCY_CPU* row = &view->Cpus[rowCount];
        ULONGLONG baselineBase = 0ULL;
        ULONG baselineLimit = 0UL;

        /* 把稳定的全局索引解析成 组:核 标识。 */
        RtlZeroMemory(&processor, sizeof(processor));
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(globalIndex, &processor))) {
            continue;
        }

        /* 亲和性掩码是按位构造的，超出位宽的核心号直接跳过。 */
        if (processor.Number >= sizeof(KAFFINITY) * 8UL) {
            continue;
        }

        /* 构造只包含目标处理器的组亲和性。 */
        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processor.Group;
        targetAffinity.Mask = ((KAFFINITY)1) << processor.Number;

        /* 切到目标处理器执行 SIDT，随即恢复原亲和性。 */
        RtlZeroMemory(&idtr, sizeof(idtr));
        KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
        __sidt(&idtr);
        KeRevertToUserGroupAffinityThread(&previousAffinity);

        /* Base 为零说明取到的不是有效描述符，丢弃该样本。 */
        if (idtr.Base == 0U) {
            continue;
        }

        /* 记录本次采样的身份与 IDTR 值。 */
        row->Group = processor.Group;
        row->Number = processor.Number;
        row->Base = (ULONGLONG)idtr.Base;
        row->Limit = (ULONG)idtr.Limit;
        row->Captured = 1UL;

        /* 向量 0 的基线查询只用于取回该 CPU 的启动期表地址与长度。 */
        if (KswordARKIdtBaselineQuery(
                (USHORT)processor.Group,
                (UCHAR)processor.Number,
                0U,
                &baselineBase,
                &baselineLimit,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL)) {
            row->BaselineBase = baselineBase;
            row->BaselineLimit = baselineLimit;
            row->BaselineAvailable = 1UL;
        }

        /* 只有成功写入的行才推进下标。 */
        rowCount += 1UL;
        view->CapturedCount += 1UL;
    }

    /* 记录实际使用的行数，后续遍历都以它为界。 */
    view->CpuCount = rowCount;

    /* 一个有效样本都没有时视为不可用，释放后返回错误。 */
    if (view->CapturedCount == 0UL) {
        ExFreePoolWithTag(view, KSW_IDT_CONSISTENCY_TAG);
        return STATUS_NOT_FOUND;
    }

    /* 先算多数派，再据此统计偏离数量。 */
    KswordARKIdtConsistencyComputeMajority(view);
    KswordARKIdtConsistencyScoreRows(view);

    /* 所有权移交调用方。 */
    *ViewOut = view;
    return STATUS_SUCCESS;
#else
    /* 非 x64 平台没有可读的 IDTR，直接报告不支持。 */
    if (ViewOut != NULL) {
        *ViewOut = NULL;
    }
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
KswordARKIdtConsistencyRelease(
    _In_opt_ KSW_IDT_CONSISTENCY_VIEW* View
    )
/*++

Routine Description:

    释放 KswordARKIdtConsistencyCollect 返回的视图。

Arguments:

    View - 可选的视图指针。

Return Value:

    None.

--*/
{
    /* 允许传入 NULL，简化调用方的失败清理路径。 */
    if (View == NULL) {
        return;
    }

    /* 用采集时相同的标签归还内存。 */
    ExFreePoolWithTag(View, KSW_IDT_CONSISTENCY_TAG);
}

ULONG
KswordARKIdtConsistencyClassify(
    _In_opt_ const KSW_IDT_CONSISTENCY_VIEW* View,
    _In_ ULONG ProcessorGroup,
    _In_ ULONG ProcessorNumber
    )
/*++

Routine Description:

    返回指定处理器相对多数派与启动期基线的偏离标志。

Arguments:

    View - 可选的采集结果。
    ProcessorGroup - 处理器组号。
    ProcessorNumber - 组内处理器号。

Return Value:

    KSW_IDT_CONSISTENCY_RISK_* 的按位组合；无依据时返回 0。

--*/
{
    ULONG index = 0UL;
    ULONG riskFlags = 0UL;

    /* 视图缺失或多数派不成立时不产生任何结论。 */
    if (View == NULL || View->MajorityCount == 0UL) {
        return 0UL;
    }

    /* 线性查找目标处理器对应的采样行。 */
    for (index = 0UL; index < View->CpuCount; ++index) {
        const KSW_IDT_CONSISTENCY_CPU* row = &View->Cpus[index];

        /* 跳过无效行与非目标处理器。 */
        if (row->Captured == 0UL ||
            row->Group != ProcessorGroup ||
            row->Number != ProcessorNumber) {
            continue;
        }

        /* 与多数派表不同：可能只有本核心被换了 IDT。 */
        if (row->Base != View->MajorityBase || row->Limit != View->MajorityLimit) {
            riskFlags |= KSW_IDT_CONSISTENCY_RISK_DIVERGED;
        }

        /* 与启动期基线不同：整表被搬到了新的地址。 */
        if (row->BaselineAvailable != 0UL &&
            (row->Base != row->BaselineBase || row->Limit != row->BaselineLimit)) {
            riskFlags |= KSW_IDT_CONSISTENCY_RISK_RELOCATED;
        }

        /* 每个处理器只会出现一行，命中后即可结束查找。 */
        break;
    }

    return riskFlags;
}
