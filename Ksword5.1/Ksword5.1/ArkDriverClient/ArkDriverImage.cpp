#include "ArkDriverClient.h"

#include <cstddef>
#include <sstream>
#include <string>

static_assert(
    sizeof(KSWORD_ARK_DRIVER_IMAGE_REQUEST) == 664U,
    "Driver image request ABI drifted");
static_assert(
    sizeof(KSWORD_ARK_DRIVER_IMAGE_RESPONSE) == 816U,
    "Driver image response ABI drifted");

namespace
{
    // 复制 canonical 对象名到固定协议数组；输入过长时保留终止符并截断。
    void copyImageDriverName(
        wchar_t* destination,
        const std::size_t destinationChars,
        const std::wstring& source)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }
        const std::size_t copyChars =
            source.size() < (destinationChars - 1U)
            ? source.size()
            : (destinationChars - 1U);
        for (std::size_t index = 0U; index < copyChars; ++index)
        {
            destination[index] = source[index];
        }
        destination[copyChars] = L'\0';
    }

    // 固定数组转 std::wstring 时只读取边界内字符，拒绝越过未终止响应。
    std::wstring fixedImageDriverName(
        const wchar_t* source,
        const std::size_t sourceChars)
    {
        std::size_t length = 0U;
        if (source == nullptr)
        {
            return std::wstring();
        }
        while (length < sourceChars && source[length] != L'\0')
        {
            ++length;
        }
        return std::wstring(source, length);
    }

    // R3 友好值模型到共享协议结构；全部保留为 64 位，不做地址策略判断。
    KSWORD_ARK_DRIVER_IMAGE_VALUES toWireValues(
        const ksword::ark::DriverImageValues& source)
    {
        KSWORD_ARK_DRIVER_IMAGE_VALUES values{};
        values.driverStart = source.driverStart;
        values.driverSize = source.driverSize;
        values.driverSection = source.driverSection;
        values.kldrDllBase = source.kldrDllBase;
        values.kldrSizeOfImage = source.kldrSizeOfImage;
        return values;
    }

    // 共享协议结构转 R3 模型，供表格与详情统一使用。
    ksword::ark::DriverImageValues fromWireValues(
        const KSWORD_ARK_DRIVER_IMAGE_VALUES& source)
    {
        ksword::ark::DriverImageValues values{};
        values.driverStart = source.driverStart;
        values.driverSize = source.driverSize;
        values.driverSection = source.driverSection;
        values.kldrDllBase = source.kldrDllBase;
        values.kldrSizeOfImage = source.kldrSizeOfImage;
        return values;
    }

    // 旧驱动未实现该协议时向 UI 提供可区分的 unsupported 状态。
    bool isUnsupportedImageIoctl(const unsigned long error)
    {
        return error == ERROR_INVALID_FUNCTION ||
            error == ERROR_NOT_SUPPORTED ||
            error == ERROR_INVALID_PARAMETER;
    }
}

namespace ksword::ark
{
    // 统一 Driver image 事务传输。所有目标和值策略均由调用方决定，R3 只编码并校验协议。
    DriverImageControlResult DriverClient::controlDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long action,
        const unsigned long fieldMask,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration,
        const DriverImageValues& expectedValues,
        const DriverImageValues& desiredValues,
        const std::uint64_t expectedLinkFlink,
        const std::uint64_t expectedLinkBlink,
        const bool restoreLink,
        const bool uiConfirmed) const
    {
        DriverImageControlResult result{};
        KSWORD_ARK_DRIVER_IMAGE_REQUEST request{};
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE response{};

        request.version = KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION;
        request.action = action;
        request.flags = 0U;
        request.fieldMask = fieldMask;
        // 模块基址为零表示按精确 DriverObject/名称查询已有记录；
        // R0 会对新目标从实时 DriverStart 派生身份，并对旧目标返回冻结基址。
        if (moduleBase != 0U)
        {
            request.flags |= KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT;
            request.targetModuleBase = moduleBase;
        }
        request.expectedDriverObjectAddress =
            expectedDriverObjectAddress;
        request.expectedGeneration = expectedGeneration;
        request.expectedLinkFlink = expectedLinkFlink;
        request.expectedLinkBlink = expectedLinkBlink;
        request.expectedValues = toWireValues(expectedValues);
        request.desiredValues = toWireValues(desiredValues);

        if (expectedDriverObjectAddress != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;
        }
        if (expectedGeneration != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT;
        }
        if (action == KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT;
        }
        if (action == KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT;
        }
        if (restoreLink)
        {
            request.flags |= KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK;
        }
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_DRIVER_IMAGE_CONFIRMATION_TOKEN;
        }
        copyImageDriverName(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            canonicalDriverName);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.unsupported =
                isUnsupportedImageIoctl(result.io.win32Error);
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response))
        {
            result.io.ok = false;
            result.io.message =
                "driver-image response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (response.version != KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION ||
            response.action != action ||
            (moduleBase != 0U &&
             expectedDriverObjectAddress == 0U &&
             response.targetModuleBase != moduleBase) ||
            (response.lastStatus >= 0 &&
             expectedDriverObjectAddress != 0U &&
             response.driverObjectAddress != expectedDriverObjectAddress))
        {
            result.io.ok = false;
            result.io.message = "driver-image response protocol mismatch";
            return result;
        }

        result.version = response.version;
        result.action = response.action;
        result.state = response.state;
        result.responseFlags = response.responseFlags;
        result.lastStatus = response.lastStatus;
        result.loaderStatus = response.loaderStatus;
        result.generation = response.generation;
        result.managedFieldMask = response.managedFieldMask;
        result.ownedFieldMask = response.ownedFieldMask;
        result.conflictFieldMask = response.conflictFieldMask;
        result.changedFieldMask = response.changedFieldMask;
        result.layoutFlags = response.layoutFlags;
        result.targetModuleBase = response.targetModuleBase;
        result.driverObjectAddress = response.driverObjectAddress;
        result.selfDriverObjectAddress = response.selfDriverObjectAddress;
        result.loaderEntryAddress = response.loaderEntryAddress;
        result.listHeadAddress = response.listHeadAddress;
        result.listResourceAddress = response.listResourceAddress;
        result.loaderLinkAddress = response.loaderLinkAddress;
        result.currentLinkFlink = response.currentLinkFlink;
        result.currentLinkBlink = response.currentLinkBlink;
        result.originalLinkFlink = response.originalLinkFlink;
        result.originalLinkBlink = response.originalLinkBlink;
        result.currentValues = fromWireValues(response.currentValues);
        result.originalValues = fromWireValues(response.originalValues);
        result.appliedValues = fromWireValues(response.appliedValues);
        result.requestedValues = fromWireValues(response.requestedValues);
        result.driverName = fixedImageDriverName(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        result.io.ntStatus = result.lastStatus;

        std::ostringstream stream;
        stream << "action=" << result.action
            << ", status=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus)
            << ", loader=0x"
            << static_cast<unsigned long>(result.loaderStatus)
            << ", fields=0x" << result.managedFieldMask
            << ", flags=0x" << result.responseFlags
            << std::dec << ", generation=" << result.generation;
        result.io.message = stream.str();
        return result;
    }

    // 查询只携带稳定身份；R0 返回实时字段、链和可能存在的事务记录。
    DriverImageControlResult DriverClient::queryDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY,
            0U,
            expectedDriverObjectAddress,
            0U,
            DriverImageValues{},
            DriverImageValues{});
    }

    // 批量字段修改携带同一查询快照和代次，实现跨五字段的全有或全无语义。
    DriverImageControlResult DriverClient::applyDriverImageFields(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long fieldMask,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration,
        const DriverImageValues& expectedValues,
        const DriverImageValues& desiredValues) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS,
            fieldMask,
            expectedDriverObjectAddress,
            expectedGeneration,
            expectedValues,
            desiredValues,
            0U,
            0U,
            false,
            true);
    }

    // 摘链必须回传刚查询的精确邻接指针，避免覆盖并发加载/卸载变化。
    DriverImageControlResult DriverClient::hideDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration,
        const std::uint64_t expectedLinkFlink,
        const std::uint64_t expectedLinkBlink) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE,
            0U,
            expectedDriverObjectAddress,
            expectedGeneration,
            DriverImageValues{},
            DriverImageValues{},
            expectedLinkFlink,
            expectedLinkBlink,
            false,
            true);
    }

    // 恢复可同时选择字段和加载链；fieldMask 为零表示只处理加载链。
    DriverImageControlResult DriverClient::restoreDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long fieldMask,
        const bool restoreLink,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_RESTORE,
            fieldMask,
            expectedDriverObjectAddress,
            expectedGeneration,
            DriverImageValues{},
            DriverImageValues{},
            0U,
            0U,
            restoreLink,
            true);
    }

    // 放弃只删除 R0 恢复记录，不尝试触碰任何当前字段或加载链。
    DriverImageControlResult DriverClient::abandonDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON,
            0U,
            expectedDriverObjectAddress,
            expectedGeneration,
            DriverImageValues{},
            DriverImageValues{},
            0U,
            0U,
            false,
            true);
    }
}
