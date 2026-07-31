#pragma once

#include "ArkDriverTypes.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ksword::ark
{
    // RuntimeDynDataResolveResult 是本地 profile pack 未命中后的精确 PDB fallback 结果。
    // 输入：R0 返回的当前模块 PE 身份，以及调用方额外需要的符号名。
    // 处理：校验本机 PE 身份，通过串行 DbgHelp 会话加载该 PE 的精确 PDB，
    //       然后按与离线生成器相同的字段目录生成 v1/EX/v4 apply 输入。
    // 返回行为：valid=true 才允许调用方下发 apply 输入；失败只携带诊断，不猜跨版本偏移。
    struct RuntimeDynDataResolveResult
    {
        bool attempted = false;
        bool imageIdentityMatched = false;
        bool pdbIdentityAvailable = false;
        bool valid = false;
        std::wstring imagePath;
        std::wstring pdbPath;
        std::wstring diagnostics;
        std::uint32_t resolvedFieldCount = 0;
        std::uint32_t resolvedTypedItemCount = 0;
        std::uint32_t resolvedV4ItemCount = 0;
        DynDataProfileApplyInput profile;
        DynDataProfileApplyExInput profileEx;
        DynDataV4ApplyInput profileV4;
        std::unordered_map<std::string, std::uint32_t> symbolRvas;
    };

    // ResolveRuntimeDynDataProfile 尝试为当前已加载模块动态生成精确 profile。
    // 该函数可能访问配置的符号服务器，必须从后台线程调用；DbgHelp 全局状态在函数内串行化。
    RuntimeDynDataResolveResult ResolveRuntimeDynDataProfile(
        const ArkDynModuleIdentity& identity,
        const std::vector<std::string>& extraSymbolNames = {});
}
