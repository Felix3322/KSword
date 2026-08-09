#pragma once

#include <ntddk.h>
#include "driver/KswordArkFileIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKDriverDeletePath(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ BOOLEAN isDirectory
    );

NTSTATUS
KswordARKDriverQueryFileInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_QUERY_FILE_INFO_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

// KswordARKDriverEnumerateDirectory：分页返回 R0 文件系统目录行，不解析私有 FS 内核结构。
// 连续分页（下一页 startIndex 等于上一页 nextIndex）会复用上一次的目录句柄续扫，
// 避免每页重新打开目录并跳过前 N 项；非连续请求自动退回重新打开。
NTSTATUS
KswordARKDriverEnumerateDirectory(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_DIRECTORY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

// KswordARKDriverResetDirectoryScanCache：释放目录续扫缓存持有的目录句柄。
// 驱动卸载路径必须调用，否则会带着一个未关闭的句柄退出。
VOID
KswordARKDriverResetDirectoryScanCache(
    VOID
    );

/*
 * KswordARKDriverSetFileIntegrity
 * Inputs:
 * - Request contains a kernel/NT-style path and target S-1-16-* RID.
 * Processing:
 * - Opens the file object and calls ZwSetSecurityObject with
 *   LABEL_SECURITY_INFORMATION. It does not patch filesystem/private objects.
 * Return behavior:
 * - Returns the NTSTATUS from path open, security descriptor construction, or
 *   ZwSetSecurityObject.
 */
NTSTATUS
KswordARKDriverSetFileIntegrity(
    _In_ const KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST* Request
    );

EXTERN_C_END
