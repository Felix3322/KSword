#include <MonitorDock/EtwArchiveCompression.h>

#include <new>
#include <stdexcept>
#include <utility>

#include <zstd.h>

namespace KswordEtwArchiveCompression
{
    namespace
    {
        constexpr int kEtwTextCompressionLevel = 3;
    }

    bool compressBlock(const std::span<const char> source, EncodedBlock* encodedOut)
    {
        if (source.empty() || encodedOut == nullptr)
        {
            return false;
        }

        try
        {
            const std::size_t compressionBound = ZSTD_compressBound(source.size());
            if (ZSTD_isError(compressionBound)
                || compressionBound > encodedOut->payload.max_size())
            {
                return false;
            }

            std::vector<char> compressed(compressionBound);
            const std::size_t compressedSize = ZSTD_compress(
                compressed.data(),
                compressed.size(),
                source.data(),
                source.size(),
                kEtwTextCompressionLevel);
            if (ZSTD_isError(compressedSize))
            {
                return false;
            }

            if (compressedSize < source.size())
            {
                compressed.resize(compressedSize);
                encodedOut->method = BlockMethod::Zstandard;
                encodedOut->payload = std::move(compressed);
            }
            else
            {
                encodedOut->method = BlockMethod::Stored;
                encodedOut->payload.assign(source.begin(), source.end());
            }
            return true;
        }
        catch (const std::bad_alloc&)
        {
            return false;
        }
        catch (const std::length_error&)
        {
            return false;
        }
    }

    bool decompressBlock(
        const BlockMethod method,
        const std::span<const char> encoded,
        const std::size_t expectedSize,
        std::vector<char>* decodedOut)
    {
        if (encoded.empty() || expectedSize == 0 || decodedOut == nullptr)
        {
            return false;
        }

        try
        {
            if (method == BlockMethod::Stored)
            {
                if (encoded.size() != expectedSize)
                {
                    return false;
                }
                decodedOut->assign(encoded.begin(), encoded.end());
                return true;
            }
            if (method != BlockMethod::Zstandard)
            {
                return false;
            }

            const unsigned long long frameSize = ZSTD_getFrameContentSize(
                encoded.data(),
                encoded.size());
            if (frameSize == ZSTD_CONTENTSIZE_ERROR
                || frameSize == ZSTD_CONTENTSIZE_UNKNOWN
                || frameSize != expectedSize
                || frameSize > decodedOut->max_size())
            {
                return false;
            }

            std::vector<char> decoded(expectedSize);
            const std::size_t decodedSize = ZSTD_decompress(
                decoded.data(),
                decoded.size(),
                encoded.data(),
                encoded.size());
            if (ZSTD_isError(decodedSize) || decodedSize != expectedSize)
            {
                return false;
            }

            *decodedOut = std::move(decoded);
            return true;
        }
        catch (const std::bad_alloc&)
        {
            return false;
        }
        catch (const std::length_error&)
        {
            return false;
        }
    }
}
