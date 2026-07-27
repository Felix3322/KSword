#include "KswordCeBridge.h"

#include <Windows.h>

namespace
{
    char g_pluginName[] = "KSword Driver Bridge 1.0";
}

// CEPlugin_GetVersion：
// - 输入：CE 分配的版本结构和结构长度。
// - 处理：声明 SDK v6 兼容性与稳定插件名称。
// - 返回：结构可写时 TRUE。
extern "C" BOOL __stdcall CEPlugin_GetVersion(
    ksword::ce::PluginVersion* const pluginVersion,
    const int pluginVersionSize)
{
    try
    {
        if (pluginVersion == nullptr ||
            pluginVersionSize < static_cast<int>(
                sizeof(ksword::ce::PluginVersion)))
        {
            return FALSE;
        }

        pluginVersion->version = ksword::ce::kCeSdkVersion;
        pluginVersion->pluginName = g_pluginName;
        return TRUE;
    }
    catch (...)
    {
        return FALSE;
    }
}

// CEPlugin_InitializePlugin：
// - 输入：CE 函数表和 CE 分配的插件 ID。
// - 处理：委托桥接层验证驱动并安装访问函数。
// - 返回：插件可用时 TRUE。
extern "C" BOOL __stdcall CEPlugin_InitializePlugin(
    ksword::ce::ExportedFunctions* const exportedFunctions,
    const int pluginId)
{
    try
    {
        return ksword::ce::initializeBridge(exportedFunctions, pluginId);
    }
    catch (...)
    {
        ::SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
}

// CEPlugin_DisablePlugin：
// - 输入：无。
// - 处理：恢复 CE 原函数并注销回调。
// - 返回：清理完成时 TRUE。
extern "C" BOOL __stdcall CEPlugin_DisablePlugin()
{
    try
    {
        return ksword::ce::disableBridge();
    }
    catch (...)
    {
        ::SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
}

// DllMain：
// - 输入：Windows DLL 生命周期参数。
// - 处理：关闭无用线程通知；业务初始化只允许由 CE 显式调用。
// - 返回：始终允许 DLL 加载。
BOOL APIENTRY DllMain(
    const HMODULE moduleHandle,
    const DWORD reason,
    LPVOID const reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH)
    {
        ::DisableThreadLibraryCalls(moduleHandle);
    }
    return TRUE;
}
