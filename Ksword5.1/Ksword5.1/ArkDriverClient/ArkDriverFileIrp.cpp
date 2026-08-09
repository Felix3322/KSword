#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

// ============================================================
// ArkDriverFileIrp.cpp
// 作用：
// 1) 封装"自建 IRP 直发文件系统栈"的两个 R0 接口；
// 2) 对响应做完整的协议版本与行边界校验，任何不一致都降级为通信失败，
//    绝不把半个响应当成有效数据交给 UI；
// 3) 不在本层做任何策略判断：写语义与危险 major 的确认由调用方给出，
//    本层只负责把它翻译成协议位和确认令牌。
// ============================================================

namespace ksword::ark
{
    namespace
    {
        // isUnsupportedIrpIoctlError 作用：
        // - 识别旧驱动未注册 IRP IOCTL 时的返回，供 UI 决定是否提示升级 R0。
        bool isUnsupportedIrpIoctlError(const unsigned long win32Error)
        {
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        // fixedWideToWString 作用：
        // - 把驱动固定宽字符字段转成 std::wstring，缺少结尾 NUL 时按容量截断。
        std::wstring fixedWideToWString(const wchar_t* textBuffer, const std::size_t maxChars)
        {
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return {};
            }
            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != L'\0')
            {
                ++length;
            }
            return std::wstring(textBuffer, textBuffer + length);
        }

        // appendDirectoryRows 作用：
        // - 逐行校验并追加目录行；任何越界名称都让整页作废，而不是静默丢弃单行。
        bool appendDirectoryRows(
            const KSWORD_ARK_DIRECTORY_ENTRY* rows,
            const std::size_t rowCount,
            std::vector<DirectoryEntryRecord>& entriesOut)
        {
            for (std::size_t index = 0U; index < rowCount; ++index)
            {
                const KSWORD_ARK_DIRECTORY_ENTRY& source = rows[index];
                if (source.nameLengthChars >= KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS ||
                    source.name[source.nameLengthChars] != L'\0')
                {
                    return false;
                }

                DirectoryEntryRecord record{};
                record.flags = source.flags;
                record.fileAttributes = source.fileAttributes;
                record.fileId = source.fileId;
                record.allocationSize = source.allocationSize;
                record.endOfFile = source.endOfFile;
                record.creationTime = source.creationTime;
                record.lastAccessTime = source.lastAccessTime;
                record.lastWriteTime = source.lastWriteTime;
                record.changeTime = source.changeTime;
                record.name.assign(source.name, source.name + source.nameLengthChars);
                entriesOut.push_back(std::move(record));
            }
            return true;
        }
    }

    FileIrpDirectoryResult DriverClient::enumerateDirectoryByIrp(
        const std::wstring& ntPath,
        const unsigned long targetLayer,
        const unsigned long maxEntries) const
    {
        FileIrpDirectoryResult result{};
        result.requestedLayer = targetLayer;
        result.resolvedLayer = targetLayer;

        if (ntPath.empty() ||
            ntPath.size() >= KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS ||
            targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
            maxEntries == 0UL ||
            maxEntries > KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message =
                "irp-directory request invalid, chars=" +
                std::to_string(ntPath.size()) +
                ", layer=" + std::to_string(targetLayer) +
                ", maxEntries=" + std::to_string(maxEntries);
            return result;
        }

        DriverHandle handle = open();
        unsigned long startIndex = 0UL;
        while (result.entries.size() < static_cast<std::size_t>(maxEntries))
        {
            const unsigned long remainingEntries =
                maxEntries - static_cast<unsigned long>(result.entries.size());
            const unsigned long pageEntries = (std::min)(
                remainingEntries,
                static_cast<unsigned long>(KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES));
            const std::size_t responseBytes =
                KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
                (static_cast<std::size_t>(pageEntries) *
                    sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
            std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);

            KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST request{};
            request.version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
            request.size = static_cast<unsigned long>(sizeof(request));
            request.flags = 0UL;
            request.targetLayer = targetLayer;
            request.startIndex = startIndex;
            request.maxEntries = pageEntries;
            request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
            std::copy(ntPath.begin(), ntPath.end(), request.path);
            request.path[request.pathLengthChars] = L'\0';

            result.io = deviceIoControl(
                IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()),
                &handle);
            if (!result.io.ok)
            {
                result.unsupported = isUnsupportedIrpIoctlError(result.io.win32Error);
                result.io.message =
                    "DeviceIoControl(IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY) failed, error=" +
                    std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned <
                KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "irp-directory response header truncated, bytesReturned=" +
                    std::to_string(result.io.bytesReturned);
                return result;
            }

            const auto* response =
                reinterpret_cast<const KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE*>(
                    responseBuffer.data());
            if (response->version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
                response->rowSize != static_cast<unsigned long>(sizeof(KSWORD_ARK_DIRECTORY_ENTRY)) ||
                response->startIndex != startIndex ||
                response->size < KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE ||
                response->size > result.io.bytesReturned ||
                response->reserved != 0UL ||
                response->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
                (response->responseFlags & ~(
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE |
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT)) != 0UL ||
                response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE ||
                response->queryStatus > KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_REVISION_MISMATCH;
                result.io.message = "irp-directory protocol header mismatch";
                return result;
            }

            const std::size_t availableRows =
                (static_cast<std::size_t>(result.io.bytesReturned) -
                    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
                sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
            const std::size_t declaredRows = response->rowCount;
            const std::size_t declaredBytes =
                KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
                (declaredRows * sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
            if (declaredRows > availableRows ||
                declaredRows > static_cast<std::size_t>(pageEntries) ||
                declaredBytes != static_cast<std::size_t>(response->size) ||
                response->nextIndex != startIndex + response->rowCount)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "irp-directory row boundary invalid, rows=" +
                    std::to_string(declaredRows);
                return result;
            }

            result.queryStatus = response->queryStatus;
            result.responseFlags = response->responseFlags;
            result.resolvedLayer = response->targetLayer;
            result.openStatus = response->openStatus;
            result.lastStatus = response->lastStatus;
            result.targetDeviceAddress = response->targetDeviceAddress;
            result.targetDriverAddress = response->targetDriverAddress;
            result.io.ntStatus = response->lastStatus;
            if (response->driverNameLengthChars != 0UL &&
                response->driverNameLengthChars < KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS)
            {
                result.driverName = fixedWideToWString(
                    response->driverName,
                    response->driverNameLengthChars);
            }
            if ((response->responseFlags &
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT) != 0UL)
            {
                if (response->fileSystemNameLengthChars == 0UL ||
                    response->fileSystemNameLengthChars >=
                        KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS ||
                    response->fileSystemName[
                        response->fileSystemNameLengthChars] != L'\0')
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message =
                        "irp-directory filesystem name boundary invalid";
                    return result;
                }
                result.fileSystemName = std::wstring(
                    response->fileSystemName,
                    response->fileSystemName + response->fileSystemNameLengthChars);
            }

            if (!appendDirectoryRows(response->rows, declaredRows, result.entries))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "irp-directory entry name boundary invalid";
                return result;
            }

            if ((response->responseFlags &
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE) == 0UL)
            {
                return result;
            }
            if (declaredRows == 0U)
            {
                // 驱动声称还有更多，但本页一行没给：继续循环只会死转，直接收尾。
                result.capped = true;
                return result;
            }
            startIndex = response->nextIndex;
        }

        result.capped = true;
        return result;
    }

    FileIrpSubmitResult DriverClient::submitFileIrp(
        const FileIrpSubmitRequestParams& params) const
    {
        FileIrpSubmitResult result{};
        result.majorFunction = params.majorFunction;
        result.minorFunction = params.minorFunction;
        result.requestedLayer = params.targetLayer;
        result.resolvedLayer = params.targetLayer;

        if (params.ntPath.empty() ||
            params.ntPath.size() >= KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS ||
            params.pattern.size() >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS ||
            params.majorFunction >= KSWORD_ARK_FILE_IRP_MAJOR_COUNT ||
            params.minorFunction > 0xFFUL ||
            params.targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
            params.inputData.size() > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES ||
            params.outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES ||
            params.timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message =
                "irp-submit request invalid, major=" +
                std::to_string(params.majorFunction) +
                ", layer=" + std::to_string(params.targetLayer) +
                ", inputBytes=" + std::to_string(params.inputData.size()) +
                ", outputBytes=" + std::to_string(params.outputBytes);
            return result;
        }

        const std::size_t inputBytes = params.inputData.size();
        const std::size_t requestBytes =
            static_cast<std::size_t>(KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE) +
            inputBytes;
        const std::size_t responseBytes =
            static_cast<std::size_t>(KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) +
            params.outputBytes;

        std::vector<std::uint8_t> requestBuffer(requestBytes, 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
        request->size = KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE;
        request->flags = params.flags & ~(
            KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED |
            KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS);
        if (params.uiConfirmed)
        {
            request->flags |= KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED;
            request->confirmationToken = KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN;
        }
        if (params.allowDangerous)
        {
            request->flags |= KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS;
        }
        request->majorFunction = params.majorFunction;
        request->minorFunction = params.minorFunction;
        request->targetLayer = params.targetLayer;
        request->timeoutMs = params.timeoutMs;
        request->desiredAccess = params.desiredAccess;
        request->shareAccess = params.shareAccess;
        request->createDisposition = params.createDisposition;
        request->createOptions = params.createOptions;
        request->fileAttributes = params.fileAttributes;
        request->informationClass = params.informationClass;
        request->controlCode = params.controlCode;
        request->securityInformation = params.securityInformation;
        request->inputBytes = static_cast<unsigned long>(inputBytes);
        request->outputBytes = params.outputBytes;
        request->lockKey = params.lockKey;
        request->byteOffset = params.byteOffset;
        request->lockLength = params.lockLength;
        request->pathLengthChars =
            static_cast<unsigned short>(params.ntPath.size());
        request->patternLengthChars =
            static_cast<unsigned short>(params.pattern.size());
        std::copy(params.ntPath.begin(), params.ntPath.end(), request->path);
        request->path[request->pathLengthChars] = L'\0';
        if (!params.pattern.empty())
        {
            std::copy(params.pattern.begin(), params.pattern.end(), request->pattern);
        }
        request->pattern[request->patternLengthChars] = L'\0';
        if (inputBytes != 0U)
        {
            std::memcpy(request->inputData, params.inputData.data(), inputBytes);
        }

        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.unsupported = isUnsupportedIrpIoctlError(result.io.win32Error);
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message =
                "irp-submit response header truncated, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*>(
                responseBuffer.data());
        const std::size_t availableOutputBytes =
            static_cast<std::size_t>(result.io.bytesReturned) -
            KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;
        if (response->version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
            response->status > KSWORD_ARK_FILE_IRP_STATUS_MAX ||
            response->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
            response->outputBytes > availableOutputBytes ||
            response->size !=
                KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE + response->outputBytes ||
            response->driverNameLengthChars >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS ||
            response->deviceNameLengthChars >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_REVISION_MISMATCH;
            result.io.message = "irp-submit protocol header mismatch";
            return result;
        }

        result.status = response->status;
        result.stageFlags = response->stageFlags;
        result.majorFunction = response->majorFunction;
        result.minorFunction = response->minorFunction;
        result.resolvedLayer = response->targetLayer;
        result.createStatus = response->createStatus;
        result.operationStatus = response->operationStatus;
        result.cleanupStatus = response->cleanupStatus;
        result.closeStatus = response->closeStatus;
        result.information = response->information;
        result.fileObjectAddress = response->fileObjectAddress;
        result.targetDeviceAddress = response->targetDeviceAddress;
        result.targetDriverAddress = response->targetDriverAddress;
        result.relatedDeviceAddress = response->relatedDeviceAddress;
        result.baseFsDeviceAddress = response->baseFsDeviceAddress;
        result.vpbDeviceAddress = response->vpbDeviceAddress;
        result.dispatchAddress = response->dispatchAddress;
        result.targetStackSize = response->targetStackSize;
        result.targetDeviceFlags = response->targetDeviceFlags;
        result.io.ntStatus = response->operationStatus;
        result.driverName = fixedWideToWString(
            response->driverName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS);
        result.deviceName = fixedWideToWString(
            response->deviceName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS);
        if (response->outputBytes != 0UL)
        {
            result.outputData.assign(
                response->outputData,
                response->outputData + response->outputBytes);
        }
        return result;
    }
}
