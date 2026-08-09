#include "DeviceTopologyEnumerator.h"

#include "../../Core/Common.h"

#include <cfgmgr32.h>
#include <setupapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <set>
#include <utility>
#include <vector>

#ifndef DN_PHANTOM
#define DN_PHANTOM 0x00004000
#endif

namespace Ksword::Features::HardwareStats {
namespace {

// The DEVPROPKEY values this module reads are spelled out instead of including
// devpkey.h. That header only declares its keys; the definitions appear only
// when INITGUID is defined first, which then also forces every DEFINE_GUID in
// the headers included afterwards to be emitted into this object file. Writing
// out the handful of keys used here keeps the translation unit free of that
// side effect while still going through the modern typed property API.
constexpr GUID kDevPropGuidDevice =
    { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } };

constexpr DEVPROPKEY kPropDeviceDesc = { kDevPropGuidDevice, 2 };
constexpr DEVPROPKEY kPropHardwareIds = { kDevPropGuidDevice, 3 };
constexpr DEVPROPKEY kPropService = { kDevPropGuidDevice, 6 };
constexpr DEVPROPKEY kPropClass = { kDevPropGuidDevice, 9 };
constexpr DEVPROPKEY kPropDriver = { kDevPropGuidDevice, 11 };
constexpr DEVPROPKEY kPropManufacturer = { kDevPropGuidDevice, 13 };
constexpr DEVPROPKEY kPropFriendlyName = { kDevPropGuidDevice, 14 };
constexpr DEVPROPKEY kPropLocationInfo = { kDevPropGuidDevice, 15 };
constexpr DEVPROPKEY kPropUiNumber = { kDevPropGuidDevice, 18 };
constexpr DEVPROPKEY kPropBusTypeGuid = { kDevPropGuidDevice, 21 };
constexpr DEVPROPKEY kPropLegacyBusType = { kDevPropGuidDevice, 22 };
constexpr DEVPROPKEY kPropBusNumber = { kDevPropGuidDevice, 23 };
constexpr DEVPROPKEY kPropEnumeratorName = { kDevPropGuidDevice, 24 };
constexpr DEVPROPKEY kPropAddress = { kDevPropGuidDevice, 30 };
constexpr DEVPROPKEY kPropLocationPaths = { kDevPropGuidDevice, 37 };

// The USB device interface classes are declared locally for the same reason: the
// GUIDs in usbiodef.h only become storage when INITGUID is in effect.
constexpr GUID kUsbDeviceInterface =
    { 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };
constexpr GUID kUsbHubInterface =
    { 0xF18A0E88, 0xC30C, 0x11D0, { 0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8 } };
constexpr GUID kUsbHostControllerInterface =
    { 0x3ABF6F2D, 0x71C4, 0x462A, { 0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27 } };

// DevInfoSet owns a SetupAPI HDEVINFO handle. Inputs are handles from
// SetupDiGetClassDevsW; processing releases the handle at scope exit; get()
// returns the raw handle without transferring ownership.
class DevInfoSet final {
public:
    explicit DevInfoSet(HDEVINFO handle) : handle_(handle) {}
    ~DevInfoSet() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            ::SetupDiDestroyDeviceInfoList(handle_);
        }
    }

    DevInfoSet(const DevInfoSet&) = delete;
    DevInfoSet& operator=(const DevInfoSet&) = delete;

    HDEVINFO get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HDEVINFO handle_;
};

std::wstring GuidToString(const GUID& guid) {
    wchar_t buffer[64] = {};
    const int written = swprintf_s(buffer,
        L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        static_cast<unsigned long>(guid.Data1),
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);
    return written > 0 ? std::wstring(buffer) : std::wstring();
}

// QueryRawProperty reads one device property into a byte buffer. Output is false
// when the devnode does not carry the property, which is normal rather than an
// error: bus placement properties only exist on devices that sit on a bus.
bool QueryRawProperty(HDEVINFO set,
    SP_DEVINFO_DATA& info,
    const DEVPROPKEY& key,
    DEVPROPTYPE& type,
    std::vector<BYTE>& data) {
    type = 0;
    data.clear();
    DWORD required = 0;
    ::SetupDiGetDevicePropertyW(set, &info, &key, &type, nullptr, 0, &required, 0);
    if (required == 0) {
        return false;
    }
    data.assign(static_cast<std::size_t>(required) + sizeof(wchar_t) * 2, 0);
    if (!::SetupDiGetDevicePropertyW(set, &info, &key, &type, data.data(), required, nullptr, 0)) {
        data.clear();
        return false;
    }
    return true;
}

std::wstring JoinStringList(const std::vector<BYTE>& data) {
    if (data.size() < sizeof(wchar_t)) {
        return {};
    }
    const auto* cursor = reinterpret_cast<const wchar_t*>(data.data());
    const auto* end = cursor + data.size() / sizeof(wchar_t);
    std::wstring joined;
    while (cursor < end && *cursor) {
        const std::wstring part(cursor);
        if (!joined.empty()) {
            joined += L"; ";
        }
        joined += part;
        cursor += part.size() + 1;
    }
    return joined;
}

std::wstring QueryStringProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data)) {
        return {};
    }
    if (type == DEVPROP_TYPE_STRING) {
        return std::wstring(reinterpret_cast<const wchar_t*>(data.data()));
    }
    if (type == DEVPROP_TYPE_STRING_LIST) {
        return JoinStringList(data);
    }
    return {};
}

std::wstring QueryStringListProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data)) {
        return {};
    }
    if (type == DEVPROP_TYPE_STRING_LIST) {
        return JoinStringList(data);
    }
    if (type == DEVPROP_TYPE_STRING) {
        return std::wstring(reinterpret_cast<const wchar_t*>(data.data()));
    }
    return {};
}

bool QueryUint32Property(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, DWORD& value) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data) || data.size() < sizeof(DWORD)) {
        return false;
    }
    if (type != DEVPROP_TYPE_UINT32 && type != DEVPROP_TYPE_INT32) {
        return false;
    }
    std::memcpy(&value, data.data(), sizeof(value));
    return true;
}

bool QueryGuidProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, GUID& value) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data) || data.size() < sizeof(GUID) ||
        type != DEVPROP_TYPE_GUID) {
        return false;
    }
    std::memcpy(&value, data.data(), sizeof(value));
    return true;
}

std::wstring DevInstToInstanceId(DEVINST devInst) {
    ULONG length = 0;
    if (::CM_Get_Device_ID_Size(&length, devInst, 0) != CR_SUCCESS) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 2, L'\0');
    if (::CM_Get_Device_IDW(devInst, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

std::wstring ParentInstanceId(DEVINST devInst) {
    DEVINST parent = 0;
    if (::CM_Get_Parent(&parent, devInst, 0) != CR_SUCCESS) {
        return {};
    }
    return DevInstToInstanceId(parent);
}

std::wstring ProblemCodeText(const ULONG problem) {
    switch (problem) {
    case CM_PROB_NOT_CONFIGURED: return L"未配置驱动（CM_PROB_NOT_CONFIGURED）";
    case CM_PROB_OUT_OF_MEMORY: return L"资源不足（CM_PROB_OUT_OF_MEMORY）";
    case CM_PROB_FAILED_START: return L"启动失败（CM_PROB_FAILED_START）";
    case CM_PROB_NORMAL_CONFLICT: return L"资源冲突（CM_PROB_NORMAL_CONFLICT）";
    case CM_PROB_NEED_RESTART: return L"需要重启（CM_PROB_NEED_RESTART）";
    case CM_PROB_DISABLED: return L"已被禁用（CM_PROB_DISABLED）";
    case CM_PROB_DEVICE_NOT_THERE: return L"设备不存在（CM_PROB_DEVICE_NOT_THERE）";
    case CM_PROB_DRIVER_FAILED_LOAD: return L"驱动加载失败（CM_PROB_DRIVER_FAILED_LOAD）";
    case CM_PROB_HELD_FOR_EJECT: return L"等待弹出（CM_PROB_HELD_FOR_EJECT）";
    case 0: return {};
    default: return L"问题代码 " + std::to_wstring(problem);
    }
}

// DescribeDeviceStatus turns the Configuration Manager status bits into text.
// The problem text is returned separately because a device can be started and
// still carry a warning, and folding both into one column would hide one of them.
std::wstring DescribeDeviceStatus(DEVINST devInst, std::wstring& problemText) {
    ULONG status = 0;
    ULONG problem = 0;
    problemText.clear();
    if (::CM_Get_DevNode_Status(&status, &problem, devInst, 0) != CR_SUCCESS) {
        return L"未知";
    }
    problemText = ProblemCodeText(problem);
    if ((status & DN_HAS_PROBLEM) != 0) {
        return problem == CM_PROB_DISABLED ? L"已禁用" : L"有问题";
    }
    if ((status & DN_STARTED) != 0) {
        return L"已启动";
    }
    if ((status & DN_PHANTOM) != 0) {
        return L"幻影节点";
    }
    return status != 0 ? L"已停止" : L"未知";
}

// CollectInterfaceOwners returns the instance IDs of every devnode exposing one
// device interface class. It is the reliable way to tell a hub from a plain
// device: the hub driver is what publishes the hub interface, so the answer does
// not depend on guessing from a service name or a class code.
std::set<std::wstring> CollectInterfaceOwners(const GUID& interfaceGuid) {
    std::set<std::wstring> owners;
    DevInfoSet set(::SetupDiGetClassDevsW(&interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set.valid()) {
        return owners;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        std::wstring instanceId = DevInstToInstanceId(info.DevInst);
        if (!instanceId.empty()) {
            owners.insert(std::move(instanceId));
        }
    }
    return owners;
}

// ExtractHexField pulls a fixed-width hex field such as VID_ or PID_ out of a
// hardware ID. Output is empty when the marker is absent, which is normal for
// hubs synthesized by the root enumerator.
std::wstring ExtractHexField(const std::wstring& text, const wchar_t* marker, const std::size_t width) {
    const std::size_t position = text.find(marker);
    if (position == std::wstring::npos) {
        return {};
    }
    const std::size_t start = position + std::wcslen(marker);
    if (start + width > text.size()) {
        return {};
    }
    const std::wstring field = text.substr(start, width);
    for (const wchar_t character : field) {
        const bool isHex = (character >= L'0' && character <= L'9') ||
            (character >= L'A' && character <= L'F') ||
            (character >= L'a' && character <= L'f');
        if (!isHex) {
            return {};
        }
    }
    return field;
}

// SerialNumberFromInstanceId recovers a USB serial number when the device has
// one. Windows synthesizes an instance segment containing '&' for devices that
// report no serial number, so a segment without '&' is the device's own string.
std::wstring SerialNumberFromInstanceId(const std::wstring& instanceId) {
    const std::size_t lastSeparator = instanceId.rfind(L'\\');
    if (lastSeparator == std::wstring::npos || lastSeparator + 1 >= instanceId.size()) {
        return {};
    }
    const std::wstring segment = instanceId.substr(lastSeparator + 1);
    if (segment.find(L'&') != std::wstring::npos) {
        return {};
    }
    return segment;
}

// FormatDeviceResources renders the resources the PnP arbiters actually handed
// to one devnode. The allocated configuration is preferred over the boot
// configuration because it is what the device is using right now; the boot list
// is only a fallback for devices the arbiters never revisited.
std::wstring FormatDeviceResources(DEVINST devInst) {
    LOG_CONF logConf = 0;
    CONFIGRET result = ::CM_Get_First_Log_Conf(&logConf, devInst, ALLOC_LOG_CONF);
    if (result != CR_SUCCESS) {
        result = ::CM_Get_First_Log_Conf(&logConf, devInst, BOOT_LOG_CONF);
    }
    if (result != CR_SUCCESS) {
        return {};
    }

    std::wstring text;
    const auto append = [&text](const std::wstring& part) {
        if (part.empty()) {
            return;
        }
        if (!text.empty()) {
            text += L"; ";
        }
        text += part;
    };

    RES_DES current = static_cast<RES_DES>(logConf);
    bool ownsCurrent = false;
    for (;;) {
        RES_DES next = 0;
        RESOURCEID resourceType = 0;
        const CONFIGRET step = ::CM_Get_Next_Res_Des(&next, current, ResType_All, &resourceType, 0);
        if (ownsCurrent) {
            ::CM_Free_Res_Des_Handle(current);
            ownsCurrent = false;
        }
        if (step != CR_SUCCESS) {
            break;
        }
        current = next;
        ownsCurrent = true;

        ULONG size = 0;
        if (::CM_Get_Res_Des_Data_Size(&size, current, 0) != CR_SUCCESS || size == 0) {
            continue;
        }
        std::vector<BYTE> data(size, 0);
        if (::CM_Get_Res_Des_Data(current, data.data(), size, 0) != CR_SUCCESS) {
            continue;
        }

        wchar_t buffer[128] = {};
        switch (resourceType) {
        case ResType_Mem:
            if (data.size() >= sizeof(MEM_DES)) {
                const auto* description = reinterpret_cast<const MEM_DES*>(data.data());
                swprintf_s(buffer, L"MEM 0x%016llX-0x%016llX",
                    static_cast<unsigned long long>(description->MD_Alloc_Base),
                    static_cast<unsigned long long>(description->MD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_MemLarge:
            if (data.size() >= sizeof(MEM_LARGE_DES)) {
                const auto* description = reinterpret_cast<const MEM_LARGE_DES*>(data.data());
                swprintf_s(buffer, L"MEM64 0x%016llX-0x%016llX",
                    static_cast<unsigned long long>(description->MLD_Alloc_Base),
                    static_cast<unsigned long long>(description->MLD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_IO:
            if (data.size() >= sizeof(IO_DES)) {
                const auto* description = reinterpret_cast<const IO_DES*>(data.data());
                swprintf_s(buffer, L"IO 0x%04llX-0x%04llX",
                    static_cast<unsigned long long>(description->IOD_Alloc_Base),
                    static_cast<unsigned long long>(description->IOD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_DMA:
            if (data.size() >= sizeof(DMA_DES)) {
                const auto* description = reinterpret_cast<const DMA_DES*>(data.data());
                swprintf_s(buffer, L"DMA %lu", static_cast<unsigned long>(description->DD_Alloc_Chan));
                append(buffer);
            }
            break;
        case ResType_IRQ:
            if (data.size() >= sizeof(IRQ_DES)) {
                const auto* description = reinterpret_cast<const IRQ_DES*>(data.data());
                swprintf_s(buffer, L"IRQ %lu", static_cast<unsigned long>(description->IRQD_Alloc_Num));
                append(buffer);
            }
            break;
        case ResType_BusNumber:
            append(L"BUS");
            break;
        default:
            break;
        }
    }

    if (ownsCurrent) {
        ::CM_Free_Res_Des_Handle(current);
    }
    ::CM_Free_Log_Conf_Handle(logConf);
    return text;
}

// BusTypeGuidName names the bus type GUIDs that ship with Windows. Unknown GUIDs
// deliberately fall through to their raw text instead of an invented label: a
// wrong bus name on this page would be worse than no name at all.
std::wstring BusTypeGuidName(const std::wstring& guidText) {
    static const std::map<std::wstring, const wchar_t*> names = {
        { L"{C8EBDFB0-B510-11D0-80E5-00A0C92542E3}", L"PCI" },
        { L"{9D7DEBBC-C85D-11D1-9EB4-006008C3A19A}", L"USB" },
        { L"{1530EA73-086B-11D1-A09F-00C04FC340B1}", L"Internal" },
        { L"{E676F854-D87D-11D0-92B2-00A0C9055FC5}", L"ISAPNP" },
        { L"{09343630-AF9F-11D0-92E9-0000F81E1B30}", L"PCMCIA" },
        { L"{DDC35509-F3FC-11D0-A537-0000F8753ED1}", L"EISA" },
        { L"{1C75997A-DC33-11D0-92B2-00A0C9055FC5}", L"MCA" },
        { L"{77114A87-8944-11D1-BD90-00A0C906BE2D}", L"Serenum" },
        { L"{F74E73EB-9AC5-45EB-BE4D-772CC71DDFB3}", L"IEEE 1394" },
        { L"{EEAF37D0-1963-47C4-AA48-72476DB7CF49}", L"HID" },
        { L"{C06FF265-AE09-48F0-812C-16753D7CBA83}", L"AVC" },
        { L"{7AE17DC1-C944-44D6-881F-4C2E61053BC1}", L"IrDA" },
        { L"{E700CC04-4036-4E89-9579-89EBF45F00CD}", L"SD" },
        { L"{C4CA1000-2DDC-11D5-A17A-00C04F60524D}", L"LPTENUM" },
        { L"{441EE000-4342-11D5-A184-00C04F60524D}", L"USBPRINT" },
        { L"{441EE001-4342-11D5-A184-00C04F60524D}", L"DOT4PRT" },
    };
    const auto found = names.find(guidText);
    return found != names.end() ? std::wstring(found->second) : std::wstring();
}

// LegacyBusTypeText renders the INTERFACE_TYPE enum the PnP manager reports.
// The numeric values are part of the driver ABI and are written out rather than
// pulled from wdm.h, which is a kernel-mode header this user-mode module must
// not include.
std::wstring LegacyBusTypeText(const DWORD value) {
    switch (value) {
    case 0: return L"Internal";
    case 1: return L"ISA";
    case 2: return L"EISA";
    case 3: return L"MicroChannel";
    case 4: return L"TurboChannel";
    case 5: return L"PCI";
    case 6: return L"VME";
    case 7: return L"NuBus";
    case 8: return L"PCMCIA";
    case 9: return L"CBus";
    case 10: return L"MPI";
    case 11: return L"MPSA";
    case 12: return L"ProcessorInternal";
    case 13: return L"InternalPower";
    case 14: return L"PNPISA";
    case 15: return L"PNP";
    case 16: return L"VMCS";
    case 17: return L"ACPI";
    default: return L"未知 (" + std::to_wstring(value) + L")";
    }
}

// UsbNodeFromDevInfo converts one devnode into a USB tree node without linking
// it to its parent yet. The hub and controller instance sets decide the node
// kind because only the driver that owns the port knows what it really is.
UsbNode UsbNodeFromDevInfo(HDEVINFO set,
    SP_DEVINFO_DATA& info,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers) {
    UsbNode node;
    node.instanceId = DevInstToInstanceId(info.DevInst);
    node.parentInstanceId = ParentInstanceId(info.DevInst);
    node.description = QueryStringProperty(set, info, kPropFriendlyName);
    if (node.description.empty()) {
        node.description = QueryStringProperty(set, info, kPropDeviceDesc);
    }
    if (node.description.empty()) {
        node.description = node.instanceId;
    }
    node.manufacturer = QueryStringProperty(set, info, kPropManufacturer);
    node.deviceClass = QueryStringProperty(set, info, kPropClass);
    node.service = QueryStringProperty(set, info, kPropService);
    node.driverKey = QueryStringProperty(set, info, kPropDriver);
    node.locationInfo = QueryStringProperty(set, info, kPropLocationInfo);
    node.hardwareIds = QueryStringListProperty(set, info, kPropHardwareIds);

    const std::wstring identitySource = node.hardwareIds.empty() ? node.instanceId : node.hardwareIds;
    node.vendorId = ExtractHexField(identitySource, L"VID_", 4);
    node.productId = ExtractHexField(identitySource, L"PID_", 4);
    node.revision = ExtractHexField(identitySource, L"REV_", 4);
    node.serialNumber = SerialNumberFromInstanceId(node.instanceId);

    DWORD port = 0;
    if (QueryUint32Property(set, info, kPropAddress, port)) {
        node.portText = std::to_wstring(port);
    } else if (!node.locationInfo.empty()) {
        // Some hubs report only the textual location, which still names the port.
        node.portText = node.locationInfo;
    }

    node.statusText = DescribeDeviceStatus(info.DevInst, node.problemText);
    if (controllers.count(node.instanceId) != 0) {
        node.kind = UsbNodeKind::HostController;
    } else if (hubs.count(node.instanceId) != 0) {
        node.kind = UsbNodeKind::Hub;
    } else {
        node.kind = UsbNodeKind::Device;
    }
    return node;
}

// AppendEnumeratorNodes adds every present devnode under one PnP enumerator.
void AppendEnumeratorNodes(const wchar_t* enumeratorName,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen) {
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, enumeratorName, nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES));
    if (!set.valid()) {
        return;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        UsbNode node = UsbNodeFromDevInfo(set.get(), info, hubs, controllers);
        if (node.instanceId.empty() || !seen.insert(node.instanceId).second) {
            continue;
        }
        nodes.push_back(std::move(node));
    }
}

// AppendInterfaceNodes adds the devnodes exposing one interface class. USB host
// controllers live under the PCI enumerator, so the USB enumerator pass alone
// would leave every hub parentless and flatten the tree.
void AppendInterfaceNodes(const GUID& interfaceGuid,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen) {
    DevInfoSet set(::SetupDiGetClassDevsW(&interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set.valid()) {
        return;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        UsbNode node = UsbNodeFromDevInfo(set.get(), info, hubs, controllers);
        if (node.instanceId.empty() || !seen.insert(node.instanceId).second) {
            continue;
        }
        nodes.push_back(std::move(node));
    }
}

// OrderUsbNodesDepthFirst rewrites the node vector so every parent precedes its
// children. A flat report ListView cannot express nesting on its own, so the
// snapshot order plus the depth field is what makes the tree readable.
std::vector<UsbNode> OrderUsbNodesDepthFirst(std::vector<UsbNode> nodes) {
    std::map<std::wstring, std::size_t> byInstance;
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        byInstance.emplace(nodes[index].instanceId, index);
    }

    std::vector<std::vector<std::size_t>> children(nodes.size());
    std::vector<std::size_t> roots;
    std::vector<int> parentOf(nodes.size(), -1);
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        const auto found = byInstance.find(nodes[index].parentInstanceId);
        if (found != byInstance.end() && found->second != index) {
            parentOf[index] = static_cast<int>(found->second);
            children[found->second].push_back(index);
        } else {
            roots.push_back(index);
        }
    }

    const auto orderKey = [&nodes](const std::size_t index) {
        // Sorting on the port keeps the children of one hub in physical order
        // rather than in whatever order SetupAPI happened to return them.
        const UsbNode& node = nodes[index];
        return node.portText + L"\x1F" + node.description;
    };
    const auto sortIndexes = [&orderKey](std::vector<std::size_t>& indexes) {
        std::sort(indexes.begin(), indexes.end(), [&orderKey](const std::size_t left, const std::size_t right) {
            return orderKey(left) < orderKey(right);
        });
    };
    sortIndexes(roots);
    for (auto& list : children) {
        sortIndexes(list);
    }

    std::vector<UsbNode> ordered;
    ordered.reserve(nodes.size());
    std::vector<char> visited(nodes.size(), 0);
    std::vector<std::pair<std::size_t, int>> stack;
    for (auto root = roots.rbegin(); root != roots.rend(); ++root) {
        stack.emplace_back(*root, 0);
    }
    while (!stack.empty()) {
        const auto [index, depth] = stack.back();
        stack.pop_back();
        if (visited[index]) {
            continue;
        }
        visited[index] = 1;
        UsbNode node = nodes[index];
        node.depth = depth;
        node.index = static_cast<int>(ordered.size());
        ordered.push_back(std::move(node));
        for (auto child = children[index].rbegin(); child != children[index].rend(); ++child) {
            stack.emplace_back(*child, depth + 1);
        }
    }

    // A cycle or a parent outside the snapshot would strand nodes; appending them
    // at depth zero keeps the table complete instead of silently dropping rows.
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        if (!visited[index]) {
            UsbNode node = nodes[index];
            node.depth = 0;
            node.index = static_cast<int>(ordered.size());
            ordered.push_back(std::move(node));
        }
    }

    std::map<std::wstring, int> orderedByInstance;
    for (const UsbNode& node : ordered) {
        orderedByInstance.emplace(node.instanceId, node.index);
    }
    for (UsbNode& node : ordered) {
        const auto found = orderedByInstance.find(node.parentInstanceId);
        node.parentIndex = found != orderedByInstance.end() && found->second != node.index
            ? found->second
            : -1;
    }
    return ordered;
}

BusDeviceRow BusRowFromDevInfo(HDEVINFO set, SP_DEVINFO_DATA& info) {
    BusDeviceRow row;
    row.instanceId = DevInstToInstanceId(info.DevInst);
    row.description = QueryStringProperty(set, info, kPropFriendlyName);
    if (row.description.empty()) {
        row.description = QueryStringProperty(set, info, kPropDeviceDesc);
    }
    if (row.description.empty()) {
        row.description = row.instanceId;
    }
    row.manufacturer = QueryStringProperty(set, info, kPropManufacturer);
    row.enumeratorName = QueryStringProperty(set, info, kPropEnumeratorName);
    row.deviceClass = QueryStringProperty(set, info, kPropClass);
    row.service = QueryStringProperty(set, info, kPropService);
    row.driverKey = QueryStringProperty(set, info, kPropDriver);
    row.locationInfo = QueryStringProperty(set, info, kPropLocationInfo);
    row.locationPaths = QueryStringListProperty(set, info, kPropLocationPaths);

    GUID busType{};
    if (QueryGuidProperty(set, info, kPropBusTypeGuid, busType)) {
        row.busTypeGuid = GuidToString(busType);
        row.busTypeText = BusTypeGuidName(row.busTypeGuid);
    }
    DWORD numeric = 0;
    if (QueryUint32Property(set, info, kPropLegacyBusType, numeric)) {
        row.legacyBusType = LegacyBusTypeText(numeric);
        if (row.busTypeText.empty()) {
            row.busTypeText = row.legacyBusType;
        }
    }
    if (row.busTypeText.empty()) {
        row.busTypeText = row.enumeratorName;
    }
    if (QueryUint32Property(set, info, kPropBusNumber, numeric)) {
        row.busNumber = std::to_wstring(numeric);
    }
    if (QueryUint32Property(set, info, kPropAddress, numeric)) {
        // A PCI address packs the device number in the high word and the
        // function number in the low word, so the decoded pair is shown next to
        // the raw value that other tools print.
        wchar_t buffer[64] = {};
        if (row.enumeratorName == L"PCI") {
            swprintf_s(buffer, L"0x%08lX (dev %lu, func %lu)",
                static_cast<unsigned long>(numeric),
                static_cast<unsigned long>(numeric >> 16),
                static_cast<unsigned long>(numeric & 0xFFFFu));
        } else {
            swprintf_s(buffer, L"0x%08lX", static_cast<unsigned long>(numeric));
        }
        row.address = buffer;
    }
    if (QueryUint32Property(set, info, kPropUiNumber, numeric)) {
        row.uiNumber = std::to_wstring(numeric);
    }

    row.resourceText = FormatDeviceResources(info.DevInst);
    row.statusText = DescribeDeviceStatus(info.DevInst, row.problemText);
    return row;
}

void AppendBusRows(const wchar_t* enumeratorName, std::vector<BusDeviceRow>& rows, std::set<std::wstring>& seen) {
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, enumeratorName, nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES));
    if (!set.valid()) {
        return;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        BusDeviceRow row = BusRowFromDevInfo(set.get(), info);
        if (row.instanceId.empty() || !seen.insert(row.instanceId).second) {
            continue;
        }
        rows.push_back(std::move(row));
    }
}

} // namespace

UsbTopologySnapshot EnumerateUsbTopology() {
    UsbTopologySnapshot snapshot;

    const std::set<std::wstring> hubs = CollectInterfaceOwners(kUsbHubInterface);
    const std::set<std::wstring> controllers = CollectInterfaceOwners(kUsbHostControllerInterface);

    std::vector<UsbNode> nodes;
    std::set<std::wstring> seen;
    AppendInterfaceNodes(kUsbHostControllerInterface, hubs, controllers, nodes, seen);
    AppendEnumeratorNodes(L"USB", hubs, controllers, nodes, seen);
    // USBSTOR children hang off a USB device and are what actually carries the
    // removable volume, so leaving them out would hide the interesting half of a
    // mass-storage device.
    AppendEnumeratorNodes(L"USBSTOR", hubs, controllers, nodes, seen);
    // The device interface pass is a safety net for devnodes whose enumerator is
    // not literally "USB" but which still publish the USB device interface.
    AppendInterfaceNodes(kUsbDeviceInterface, hubs, controllers, nodes, seen);

    if (nodes.empty()) {
        snapshot.success = false;
        snapshot.diagnosticText = L"未枚举到任何 USB 设备节点：" + Ksword::Core::LastErrorMessage();
        return snapshot;
    }

    snapshot.nodes = OrderUsbNodesDepthFirst(std::move(nodes));
    snapshot.success = true;
    snapshot.diagnosticText = L"共 " + std::to_wstring(snapshot.nodes.size()) + L" 个 USB 节点。";
    return snapshot;
}

BusDeviceSnapshot EnumerateBusDevices(const bool includeAllEnumerators) {
    BusDeviceSnapshot snapshot;
    std::set<std::wstring> seen;

    if (includeAllEnumerators) {
        DevInfoSet set(::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES));
        if (!set.valid()) {
            snapshot.success = false;
            snapshot.diagnosticText = L"SetupDiGetClassDevsW 失败：" + Ksword::Core::LastErrorMessage();
            return snapshot;
        }
        for (DWORD ordinal = 0;; ++ordinal) {
            SP_DEVINFO_DATA info{};
            info.cbSize = sizeof(info);
            if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
                break;
            }
            BusDeviceRow row = BusRowFromDevInfo(set.get(), info);
            if (row.instanceId.empty() || !seen.insert(row.instanceId).second) {
                continue;
            }
            snapshot.rows.push_back(std::move(row));
        }
    } else {
        for (const wchar_t* enumeratorName : { L"PCI", L"ACPI", L"ACPI_HAL", L"PCIIDE", L"ROOT" }) {
            AppendBusRows(enumeratorName, snapshot.rows, seen);
        }
    }

    if (snapshot.rows.empty()) {
        snapshot.success = false;
        snapshot.diagnosticText = L"未枚举到任何总线设备：" + Ksword::Core::LastErrorMessage();
        return snapshot;
    }

    std::sort(snapshot.rows.begin(), snapshot.rows.end(),
        [](const BusDeviceRow& left, const BusDeviceRow& right) {
            if (left.enumeratorName != right.enumeratorName) {
                return left.enumeratorName < right.enumeratorName;
            }
            return left.instanceId < right.instanceId;
        });

    snapshot.success = true;
    snapshot.diagnosticText = L"共 " + std::to_wstring(snapshot.rows.size()) + L" 个总线设备。";
    return snapshot;
}

} // namespace Ksword::Features::HardwareStats
