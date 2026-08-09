#pragma once

//
// kernel_idt_consistency.h
//
// 跨 CPU 的 IDTR 一致性视图。只读采集每个逻辑处理器的 IDTR，找出「多数派」表，
// 并把偏离多数派或偏离启动期基线的处理器标出来。用于识别只在个别核心上换表
// （lidt 接管）以及整表重定位这两类篡改。
//

#include "ark/ark_driver.h"

EXTERN_C_START

// 本处理器 IDTR 与多数派处理器不一致。
#define KSW_IDT_CONSISTENCY_RISK_DIVERGED 0x00000001UL
// 本处理器 IDTR 与驱动启动期抓取的基线不一致。
#define KSW_IDT_CONSISTENCY_RISK_RELOCATED 0x00000002UL

// 单个处理器的 IDTR 采样。
typedef struct _KSW_IDT_CONSISTENCY_CPU
{
    ULONG Group;
    ULONG Number;
    ULONG Captured;
    ULONG Limit;
    ULONGLONG Base;
    ULONGLONG BaselineBase;
    ULONG BaselineLimit;
    ULONG BaselineAvailable;
} KSW_IDT_CONSISTENCY_CPU, *PKSW_IDT_CONSISTENCY_CPU;

// 一次全机采集结果。Cpus 为变长数组，长度为 CpuCount。
typedef struct _KSW_IDT_CONSISTENCY_VIEW
{
    ULONG CpuCount;
    ULONG CapturedCount;
    ULONG MajorityCount;
    ULONG MajorityLimit;
    ULONG DivergedCount;
    ULONG RelocatedCount;
    ULONGLONG MajorityBase;
    KSW_IDT_CONSISTENCY_CPU Cpus[1];
} KSW_IDT_CONSISTENCY_VIEW, *PKSW_IDT_CONSISTENCY_VIEW;

NTSTATUS
KswordARKIdtConsistencyCollect(
    _Outptr_result_maybenull_ KSW_IDT_CONSISTENCY_VIEW** ViewOut
    );

VOID
KswordARKIdtConsistencyRelease(
    _In_opt_ KSW_IDT_CONSISTENCY_VIEW* View
    );

ULONG
KswordARKIdtConsistencyClassify(
    _In_opt_ const KSW_IDT_CONSISTENCY_VIEW* View,
    _In_ ULONG ProcessorGroup,
    _In_ ULONG ProcessorNumber
    );

EXTERN_C_END
