/*
 * 参考机制的许可证与归档说明：
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "ark/ark_system_time.h"

/* 初始化独立的原子时间对与控制字，不触碰任何 HAL 指针。 */
VOID
KswordARKSystemTimeCounterInitialize(
    VOID
    );

/* 激活时发布原始计数器、起始值、命令和倍率。 */
VOID
KswordARKSystemTimeCounterActivate(
    _In_ PVOID OriginalCounter,
    _In_ LONGLONG InitialCounter,
    _In_ ULONG Command,
    _In_ ULONG Factor
    );

/* 活跃状态下连续结算旧倍率并切换到新命令。 */
NTSTATUS
KswordARKSystemTimeCounterReconfigure(
    _In_ ULONG Command,
    _In_ ULONG Factor
    );

/* 恢复路径把控制字切回 1x，原始函数地址保留到在途调用排空。 */
VOID
KswordARKSystemTimeCounterReset(
    VOID
    );

/* 返回可写入 HAL 槽的非分页钩子地址。 */
PVOID
KswordARKSystemTimeCounterHookAddress(
    VOID
    );

/* 返回当前已进入钩子但尚未离开的调用数。 */
LONG
KswordARKSystemTimeCounterInFlight(
    VOID
    );
