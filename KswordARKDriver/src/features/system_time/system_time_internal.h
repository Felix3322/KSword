/*
 * 参考机制的许可证与归档说明：
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "ark/ark_system_time.h"

/*
 * 解析结果只在驱动内部使用。
 * primarySlot/secondarySlot 指向 HAL 计数器函数指针槽，而不是函数本身。
 */
typedef struct _KSWORD_ARK_SYSTEM_TIME_RESOLUTION
{
    volatile PVOID* PrimarySlot;
    volatile PVOID* SecondarySlot;
    volatile LONG* InternalFlags;
    PVOID CounterDescriptor;
    ULONG OsBuildNumber;
    BOOLEAN UsesHandlerTable;
    UCHAR Reserved[3];
} KSWORD_ARK_SYSTEM_TIME_RESOLUTION, *PKSWORD_ARK_SYSTEM_TIME_RESOLUTION;

/*
 * 解析 KeQueryPerformanceCounter 内的 RIP 相对引用。
 * ResolutionMode 选择兼容定位或增强校验定位。
 */
NTSTATUS
KswordARKSystemTimeResolve(
    _In_ ULONG ResolutionMode,
    _Out_ KSWORD_ARK_SYSTEM_TIME_RESOLUTION* Resolution
    );
