/*
 * 参考机制的许可证与归档说明：
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkSystemTimeIoctl.h"

EXTERN_C_START

/* 初始化全局变速的同步对象和周期维护 DPC，不在加载时修改计时源。 */
VOID
KswordARKSystemTimeInitialize(
    VOID
    );

/* 驱动卸载前停止维护、恢复原始计时指针并等待在途调用离开。 */
VOID
KswordARKSystemTimeUninitialize(
    VOID
    );

/* 查询当前解析结果、倍率、接管状态和有限诊断地址。 */
NTSTATUS
KswordARKSystemTimeQuery(
    _Out_ KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE* Response
    );

/* 执行一条经过版本、代次和安全确认校验的变速控制命令。 */
NTSTATUS
KswordARKSystemTimeControl(
    _In_ const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST* Request,
    _Out_ KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE* Response
    );

EXTERN_C_END
