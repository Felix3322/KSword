#pragma once

// ============================================================
// DumpByteView.h
// 作用：
// - 把转储文件中已验证的连续原始字节格式化成固定宽度十六进制文本；
// - 输出同时含目标机地址、十六进制字节和 ASCII 预览，供 TRIAGE 数据块
//   原始查看页使用；
// - 只处理调用方已经按文件范围验证过的数据，不承担文件 I/O。
// 调用方式：
// - KernelDumpParser 读取受限预览并填入 DumpByteBlock；
// - MinidumpDock 渲染页签时调用 FormatDumpBytes 生成只读文本。
// ============================================================

#include <QString>

#include <cstdint>

namespace ks::minidump
{
    // FormatDumpBytes 作用：把原始字节渲染为每行 16 字节的十六进制视图。
    // 参数 baseAddress：第一字节的目标机虚拟地址。
    // 参数 bytes/byteCount：已验证的原始字节范围。
    // 参数 omittedBytes：未放入预览的剩余字节数，用于尾部提示。
    // 返回：可直接放入只读文本控件的原始文本。
    QString FormatDumpBytes(
        std::uint64_t baseAddress,
        const unsigned char* bytes,
        std::uint64_t byteCount,
        std::uint64_t omittedBytes = 0);
}
