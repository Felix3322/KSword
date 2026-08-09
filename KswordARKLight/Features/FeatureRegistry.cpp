#include "FeatureRegistry.h"

#include "Driver/DriverFeature.h"
#include "File/FileFeature.h"
#include "Hardware/HardwareFeature.h"
#include "Handle/HandleFeature.h"
#include "Kernel/KernelFeature.h"
#include "Memory/MemoryFeature.h"
#include "Misc/MiscFeature.h"
#include "Monitor/MonitorFeature.h"
#include "Network/NetworkFeature.h"
#include "NetTools/NetToolsFeature.h"
#include "Privilege/PrivilegeFeature.h"
#include "Process/ProcessFeature.h"
#include "Registry/RegistryFeature.h"
#include "Service/ServiceFeature.h"
#include "Startup/StartupFeature.h"
#include "Window/WindowFeature.h"
#include "WindowTools/WindowToolsFeature.h"

namespace Ksword::Features {

std::vector<Ksword::Ui::ModuleDescriptor> GetModuleDescriptors() {
    return {
        { 40001, L"进程", L"NtQuerySystemInformation 进程列表、友好视图/详细视图、多选、图标、拖动选择和进程右键菜单。", Process::CreateProcessFeaturePage },
        { 40002, L"内存", L"仅保留通过 KswordARK R0 驱动执行的内存读取和写入。", Memory::CreateMemoryFeaturePage },
        { 40010, L"注册表", L"WinAPI/R0 双模式注册表浏览与读写、创建、删除、重命名。", Registry::CreateRegistryFeaturePage },
        { 40003, L"文件", L"Windows API 路径枚举和文件右键菜单；文件属性页已移除。", File::CreateFileFeaturePage },
        { 40004, L"驱动", L"驱动概览和对象信息。", Driver::CreateDriverFeaturePage },
        { 40005, L"内核", L"保留 SSDT、Shadow SSDT、Hook、对象命名空间、回调等内核功能入口。", [](HWND parent, const RECT& bounds) -> HWND {
            return Kernel::CreateKernelFeaturePage(parent, 40005, bounds);
        } },
        { 40006, L"监控", L"ETW 监控主页面，筛选器通过弹窗配置。", Monitor::CreateMonitorFeaturePage },
        { 40007, L"硬件", L"仅保留设备管理。", Hardware::CreateHardwareFeaturePage },
        { 40008, L"窗口", L"窗口管理和详细信息；桌面管理已移除。", Window::CreateWindowFeaturePage },
        { 40009, L"启动项", L"启动项管理。", Startup::CreateStartupFeaturePage },
        { 40014, L"服务", L"SCM 服务与驱动服务枚举、启停暂停继续、启动类型修改与配置风险标注。", Service::CreateServiceFeaturePage },
        { 40015, L"权限", L"当前进程令牌的身份、完整性级别、组与全部特权，可启用/禁用并标注越权类特权。", Privilege::CreatePrivilegeFeaturePage },
        { 40016, L"网络工具", L"TCP/UDP 连接管理与结束连接、ping/路由跟踪/DNS 诊断、防火墙规则只读枚举。", NetTools::CreateNetToolsFeaturePage },
        { 40017, L"窗口工具", L"剪贴板格式与占有者、窗口捕获保护、窗口层级与样式位诊断、全局热键占用探测。", WindowTools::CreateWindowToolsFeaturePage },
        { 40011, L"网络", L"Network Stack 审计入口，当前显示 AFD/TCPIP/NSI/WFP 只读审计状态和后续 R0 接入点。", Network::CreateNetworkFeaturePage },
        { 40012, L"句柄", L"HandleTable/ObjectHeader/ObjectType 只读审计，复用 ArkDriverClient 句柄查询协议。", Handle::CreateHandleFeaturePage },
        { 40013, L"杂项安全", L"Security / CI / VBS / Hyper-V 只读审计入口，显示 R3 证据与 R0 capability 状态。", Misc::CreateMiscFeaturePage }
    };
}

} // namespace Ksword::Features
