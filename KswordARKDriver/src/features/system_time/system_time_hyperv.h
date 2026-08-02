/*
 * 参考机制的许可证与归档说明：
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "ark/ark_system_time.h"

/* Hyper-V 诊断快照只在 system_time 功能内部流转。 */
typedef struct _KSWORD_ARK_SYSTEM_TIME_HYPERV_DIAGNOSTICS
{
    ULONG StateFlags;
    PVOID SharedUserVa;
    ULONGLONG TimeUpdateLock;
    ULONGLONG OriginalMultiplier;
    ULONGLONG OriginalBias;
    ULONGLONG CurrentMultiplier;
    ULONGLONG CurrentBias;
} KSWORD_ARK_SYSTEM_TIME_HYPERV_DIAGNOSTICS;

/* 初始化共享页同步状态，不查询或修改 Hyper-V。 */
VOID
KswordARKSystemTimeHypervInitialize(
    VOID
    );

/* 只读探测 Hyper-V 共享 QPC 页并返回有限诊断证据。 */
NTSTATUS
KswordARKSystemTimeHypervQuery(
    _Out_ KSWORD_ARK_SYSTEM_TIME_HYPERV_DIAGNOSTICS* Diagnostics
    );

/* 激活前固定共享页物理映射并保存可恢复的倍率与偏置快照。 */
NTSTATUS
KswordARKSystemTimeHypervPrepare(
    VOID
    );

/* 在 HAL 钩子就绪后按其连续 QPC 快照发布首个 Hyper-V 倍率。 */
NTSTATUS
KswordARKSystemTimeHypervActivate(
    _In_ ULONG Command,
    _In_ ULONG Factor
    );

/* 活跃状态下保持连续性并原子切换 Hyper-V 倍率。 */
NTSTATUS
KswordARKSystemTimeHypervReconfigure(
    _In_ ULONG Command,
    _In_ ULONG Factor
    );

/* 周期验证共享页仍属于本功能，并在系统恢复原值时重新发布。 */
NTSTATUS
KswordARKSystemTimeHypervMaintain(
    VOID
    );

/* 仅在共享页仍为原值或本功能值时恢复快照并解除物理映射。 */
NTSTATUS
KswordARKSystemTimeHypervRestore(
    VOID
    );