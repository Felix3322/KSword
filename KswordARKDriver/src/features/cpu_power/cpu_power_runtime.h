#pragma once

#include <ntddk.h>
#include "driver/KswordArkCpuPowerIoctl.h"

EXTERN_C_START

// KswordARKCpuPowerQuerySnapshot：读取 CPUID 与白名单 Intel 电源 MSR，并生成固定响应。
NTSTATUS
KswordARKCpuPowerQuerySnapshot(
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* Response
    );

// KswordARKCpuPowerApply：校验请求、跨逻辑处理器修改白名单字段并执行写后回读。
NTSTATUS
KswordARKCpuPowerApply(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* Response
    );

EXTERN_C_END
