#pragma once

#include "CePluginSdk.h"

#include <Windows.h>

namespace ksword::ce
{
    // initializeBridge：
    // - 输入：CE 导出函数表和本插件 ID。
    // - 处理：验证驱动、保存原函数并安装四个 R0 桥接 hook。
    // - 返回：成功时 TRUE；失败时不留下半安装函数表。
    BOOL initializeBridge(ExportedFunctions* exportedFunctions, int pluginId);

    // disableBridge：
    // - 输入：无。
    // - 处理：仅当函数槽仍指向本插件时恢复原函数，并注销通知。
    // - 返回：清理完成时 TRUE。
    BOOL disableBridge();

    // notifyFunctionPointersChanged：
    // - 输入：CE 保留参数。
    // - 处理：CE 重建访问函数表后重新安装 KSword hook。
    // - 返回：无。
    void __stdcall notifyFunctionPointersChanged(int reserved);
}
