#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace KswordEtwArchiveCompression
{
    enum class BlockMethod : std::uint32_t
    {
        Stored = 0,
        Zstandard = 1
    };

    struct EncodedBlock
    {
        BlockMethod method = BlockMethod::Stored;
        std::vector<char> payload;
    };

    // ETW 归档以约 1 MiB 的跨记录数据块压缩。Zstandard level 3 在实时写入吞吐
    // 与重复文本/JSON 压缩率之间提供稳定平衡；不可压缩数据自动退回原样存储。
    bool compressBlock(std::span<const char> source, EncodedBlock* encodedOut);

    // expectedSize 必须来自经过上层边界校验的归档块头，避免损坏文件触发无界分配。
    bool decompressBlock(
        BlockMethod method,
        std::span<const char> encoded,
        std::size_t expectedSize,
        std::vector<char>* decodedOut);
}
