#pragma once

// ============================================================
// KernelDumpParser.h
// 作用：
// - 声明内核转储（蓝屏 DMP）解析函数；
// - 支持 64 位 PAGEDU64 头（含小型转储的 TRIAGE 驱动列表）
//   与 32 位 PAGEDUMP 头（仅头部关键信息）；
// - 产出 BugCheck 代码、参数、系统版本、驱动列表等展示数据。
// 调用方式：
// - 仅由 MinidumpParser.cpp 的 ParseDumpFile 在识别出 PAGE 签名后调用；
// - view 为映射好的只读文件视图，result 由调用方预置 filePath/fileSize。
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // ParseKernelDump64 作用：解析 64 位内核转储（签名 PAGEDU64）。
    // 传入 view 只读文件视图与 result 输出结构；返回后 result.success 指示成败。
    void ParseKernelDump64(const DumpFileView& view, DumpParseResult& result);

    // ParseKernelDump32 作用：解析 32 位内核转储（签名 PAGEDUMP），仅头部信息。
    // 传入 view 只读文件视图与 result 输出结构；返回后 result.success 指示成败。
    void ParseKernelDump32(const DumpFileView& view, DumpParseResult& result);
}
