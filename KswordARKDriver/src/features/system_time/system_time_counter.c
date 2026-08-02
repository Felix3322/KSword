/*++

Module Name:

    system_time_counter.c

Abstract:

    多核安全的连续虚拟性能计数器与 HAL 回调入口。

Third-Party Notice:

    参考机制的许可证与归档说明位于：
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_counter.h"

#include <intrin.h>

/* HAL 计数器回调在当前 x64 Windows 上不接收参数并返回 64 位计数。 */
typedef LONGLONG
(*KSW_SYSTEM_TIME_COUNTER_ROUTINE)(
    VOID
    );

/* 一个原子 LONG 同时发布命令与倍率，防止钩子读取混合配置。 */
#define KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK   0x0000FFFFUL
#define KSW_SYSTEM_TIME_CONTROL_COMMAND_SHIFT 16UL

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(_InterlockedCompareExchange128)
#endif

/* 时间对按 16 字节对齐，分别保存 lastReal 与 virtualCounter。 */
__declspec(align(16))
static volatile LONG64 g_KswordArkSystemTimePair[2] = { 0LL, 0LL };

/* 钩子只读取三个原子状态，不依赖 runtime 控制锁。 */
static PVOID volatile g_KswordArkSystemTimeOriginalCounter = NULL;
static volatile LONG g_KswordArkSystemTimeControlWord = 0L;
static volatile LONG g_KswordArkSystemTimeInFlight = 0L;

/* 编码控制字，Command 位于高 16 位，Factor 位于低 16 位。 */
static
LONG
KswordARKSystemTimeMakeControlWord(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    const ULONG encoded =
        ((Command & KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK)
            << KSW_SYSTEM_TIME_CONTROL_COMMAND_SHIFT) |
        (Factor & KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK);
    return (LONG)encoded;
}

/* 提取命令字段，返回协议定义的加速、减速或恢复值。 */
static
ULONG
KswordARKSystemTimeCommandFromControlWord(
    _In_ LONG ControlWord
    )
{
    return ((ULONG)ControlWord >>
        KSW_SYSTEM_TIME_CONTROL_COMMAND_SHIFT) &
        KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK;
}

/* 提取倍率字段；零值按 1 处理，保证故障状态仍可单调前进。 */
static
ULONG
KswordARKSystemTimeFactorFromControlWord(
    _In_ LONG ControlWord
    )
{
    const ULONG factor =
        (ULONG)ControlWord &
        KSW_SYSTEM_TIME_CONTROL_FACTOR_MASK;
    return factor == 0UL ? 1UL : factor;
}

/* 对虚拟计数加法做饱和处理，避免极端停顿后回绕为负值。 */
static
ULONGLONG
KswordARKSystemTimeSaturatingAdd(
    _In_ ULONGLONG Left,
    _In_ ULONGLONG Right
    )
{
    if (Left >= (ULONGLONG)MAXLONGLONG ||
        (ULONGLONG)MAXLONGLONG - Left < Right) {
        return MAXLONGLONG;
    }
    return Left + Right;
}

/* 按 N 或 1/N 缩放真实增量，倍率上限由共享协议限制。 */
static
ULONGLONG
KswordARKSystemTimeScaleDelta(
    _In_ ULONGLONG Delta,
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    if (Command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP) {
        if (Delta > (ULONGLONG)MAXLONGLONG / Factor) {
            return MAXLONGLONG;
        }
        return Delta * Factor;
    }
    if (Command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN) {
        return Delta / Factor;
    }
    return Delta;
}

/*
 * 用 CMPXCHG16B 原子提交 lastReal/virtualCounter。
 * CAS 失败时 comparand 会被硬件更新，循环据此重新计算本次增量。
 */
static
LONGLONG
KswordARKSystemTimeAdvanceCounter(
    _In_ LONGLONG RealCounter
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    LONG64 comparand[2] = { 0LL, 0LL };
    const LONG controlWord = InterlockedCompareExchange(
        &g_KswordArkSystemTimeControlWord,
        0L,
        0L);
    const ULONG command =
        KswordARKSystemTimeCommandFromControlWord(controlWord);
    const ULONG factor =
        KswordARKSystemTimeFactorFromControlWord(controlWord);

    comparand[0] = g_KswordArkSystemTimePair[0];
    comparand[1] = g_KswordArkSystemTimePair[1];
    for (;;) {
        const ULONGLONG lastReal =
            (ULONGLONG)comparand[0];
        const ULONGLONG virtualCounter =
            (ULONGLONG)comparand[1];
        const ULONGLONG currentReal =
            RealCounter > 0LL
            ? (ULONGLONG)RealCounter
            : lastReal;
        const ULONGLONG realDelta =
            currentReal > lastReal
            ? currentReal - lastReal
            : 0ULL;
        const ULONGLONG scaledDelta =
            KswordARKSystemTimeScaleDelta(
                realDelta,
                command,
                factor);
        const ULONGLONG nextVirtual =
            KswordARKSystemTimeSaturatingAdd(
                virtualCounter,
                scaledDelta);
        const CHAR exchanged =
            _InterlockedCompareExchange128(
                g_KswordArkSystemTimePair,
                (LONG64)nextVirtual,
                (LONG64)currentReal,
                comparand);
        if (exchanged != 0) {
            return (LONGLONG)nextVirtual;
        }
    }
#else
    return RealCounter;
#endif
}

/*
 * HAL 槽进入本钩子后只调用已保存的真实计数器并执行原子缩放。
 * 入口和所有依赖均不分页，也不获取可能阻塞的锁。
 */
static
LONGLONG
KswordARKSystemTimeCounterHook(
    VOID
    )
{
    KSW_SYSTEM_TIME_COUNTER_ROUTINE originalCounter = NULL;
    LONGLONG virtualCounter = 0LL;

    InterlockedIncrement(
        &g_KswordArkSystemTimeInFlight);
    originalCounter =
        (KSW_SYSTEM_TIME_COUNTER_ROUTINE)
            InterlockedCompareExchangePointer(
                (PVOID volatile*)
                    &g_KswordArkSystemTimeOriginalCounter,
                NULL,
                NULL);
    if (originalCounter != NULL &&
        (PVOID)originalCounter !=
            (PVOID)KswordARKSystemTimeCounterHook) {
        virtualCounter = KswordARKSystemTimeAdvanceCounter(
            originalCounter());
    }
    InterlockedDecrement(
        &g_KswordArkSystemTimeInFlight);
    return virtualCounter;
}

VOID
KswordARKSystemTimeCounterInitialize(
    VOID
    )
{
    g_KswordArkSystemTimePair[0] = 0LL;
    g_KswordArkSystemTimePair[1] = 0LL;
    InterlockedExchangePointer(
        (PVOID volatile*)&g_KswordArkSystemTimeOriginalCounter,
        NULL);
    InterlockedExchange(
        &g_KswordArkSystemTimeInFlight,
        0L);
    InterlockedExchange(
        &g_KswordArkSystemTimeControlWord,
        KswordARKSystemTimeMakeControlWord(
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
            1UL));
}

VOID
KswordARKSystemTimeCounterActivate(
    _In_ PVOID OriginalCounter,
    _In_ LONGLONG InitialCounter,
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    InterlockedExchangePointer(
        (PVOID volatile*)&g_KswordArkSystemTimeOriginalCounter,
        OriginalCounter);
    g_KswordArkSystemTimePair[0] = InitialCounter;
    g_KswordArkSystemTimePair[1] = InitialCounter;
    KeMemoryBarrier();
    InterlockedExchange(
        &g_KswordArkSystemTimeControlWord,
        KswordARKSystemTimeMakeControlWord(
            Command,
            Factor));
}

NTSTATUS
KswordARKSystemTimeCounterReconfigure(
    _In_ ULONG Command,
    _In_ ULONG Factor
    )
{
    KSW_SYSTEM_TIME_COUNTER_ROUTINE originalCounter = NULL;

    originalCounter =
        (KSW_SYSTEM_TIME_COUNTER_ROUTINE)
            InterlockedCompareExchangePointer(
                (PVOID volatile*)
                    &g_KswordArkSystemTimeOriginalCounter,
                NULL,
                NULL);
    if (originalCounter == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    (void)KswordARKSystemTimeAdvanceCounter(
        originalCounter());
    InterlockedExchange(
        &g_KswordArkSystemTimeControlWord,
        KswordARKSystemTimeMakeControlWord(
            Command,
            Factor));
    return STATUS_SUCCESS;
}

VOID
KswordARKSystemTimeCounterReset(
    VOID
    )
{
    InterlockedExchange(
        &g_KswordArkSystemTimeControlWord,
        KswordARKSystemTimeMakeControlWord(
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
            1UL));
}

PVOID
KswordARKSystemTimeCounterHookAddress(
    VOID
    )
{
    return (PVOID)KswordARKSystemTimeCounterHook;
}

LONG
KswordARKSystemTimeCounterInFlight(
    VOID
    )
{
    return InterlockedCompareExchange(
        &g_KswordArkSystemTimeInFlight,
        0L,
        0L);
}
