#include "ArkDriverClient.h"

#include <cstddef>
#include <string>
#include <vector>

namespace ksword::ark
{
    IoResult DriverClient::setProcessProtectConfig(
        const unsigned long globalFlags,
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE>& rules,
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED>& trustedEntries) const
    {
        // 输入：UI 整理后的保护规则与信任白名单，两者都可以为空。
        // 处理：装配定长共享包并只经由 DriverClient 的统一 DeviceIoControl 下发；
        //       超限在 R3 侧就报错，不把半张表送进内核。
        // 返回：IoResult 描述 Win32 传输结果，R0 的语义校验失败会体现为
        //       ERROR_INVALID_PARAMETER。
        if (rules.size() > KSWORD_ARK_PROCESS_PROTECT_MAX_RULES)
        {
            IoResult errorResult{};
            errorResult.ok = false;
            errorResult.win32Error = ERROR_INVALID_PARAMETER;
            errorResult.message = "too many process protect rules, max=" +
                std::to_string(KSWORD_ARK_PROCESS_PROTECT_MAX_RULES);
            return errorResult;
        }
        if (trustedEntries.size() > KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED)
        {
            IoResult errorResult{};
            errorResult.ok = false;
            errorResult.win32Error = ERROR_INVALID_PARAMETER;
            errorResult.message = "too many process protect trusted entries, max=" +
                std::to_string(KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED);
            return errorResult;
        }

        KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION;
        request.globalFlags = globalFlags;
        request.ruleCount = static_cast<unsigned long>(rules.size());
        request.trustedCount = static_cast<unsigned long>(trustedEntries.size());

        for (std::size_t ruleIndex = 0U; ruleIndex < rules.size(); ++ruleIndex)
        {
            request.rules[ruleIndex] = rules[ruleIndex];
            // 内核只按 NUL 结尾比较字符串；这里先补上终止符，避免依赖调用方自觉。
            request.rules[ruleIndex].targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
            request.rules[ruleIndex].ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS - 1U] = L'\0';
        }
        for (std::size_t trustedIndex = 0U; trustedIndex < trustedEntries.size(); ++trustedIndex)
        {
            request.trusted[trustedIndex] = trustedEntries[trustedIndex];
            request.trusted[trustedIndex].image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
        }

        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);
    }

    ProcessProtectStateResult DriverClient::queryProcessProtectState() const
    {
        // 输入：无。
        // 处理：取回定长状态包，并校验内核确实写满了当前协议版本的结构体。
        // 返回：response 携带完整配置与计数器；短读或版本不符时 io.ok 置 false。
        ProcessProtectStateResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE,
            nullptr,
            0,
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (result.io.ok && result.io.bytesReturned < sizeof(result.response))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            result.io.message = "process protect state response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (result.io.ok &&
            (result.response.size < sizeof(result.response) ||
                result.response.version != KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "process protect state protocol mismatch, size=" +
                std::to_string(result.response.size) +
                ", version=" + std::to_string(result.response.version);
        }
        return result;
    }
}
