#pragma once

// ============================================================
// DumpAnalyzer.h
// 作用：
// - 把解析出来的原始事实（停止码/异常码、参数、崩溃地址、调用栈、
//   模块与已卸载模块）汇总成一份可直接读的诊断结论：
//   一句话结论 + 故障归类 + 证据链 + 肇事模块候选 + 排查建议；
// - 归因采用加权投票：同一个模块被多条证据命中就累加权重，
//   系统核心模块（ntoskrnl/hal/ntdll…）大幅降权，因为它们几乎总是
//   出现在栈上但通常只是“报告者”而非“肇事者”——这与 WinDbg
//   !analyze 先跳过系统模块再找第三方模块的思路一致。
// 局限：
// - 没有符号，归因粒度只到模块；调用栈来自栈扫描，含误报，
//   因此结论一律带可信度（High/Medium/Low），不做绝对断言。
// 调用方式：
// - 内核与用户态两条解析路径在收尾时各调一次 BuildAnalysis；
//   函数只读 result 里已填好的字段，就地写入 result.analysis。
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // BuildAnalysis 作用：生成综合诊断结论并写入 result.analysis。
    // 传入 modules 已建好的模块索引与 result 解析结果（就地修改）；
    // 要求调用前 result 的 kind/bugCheckCode/exceptionCode/faultingAddress/
    // stackFrames/modules/unloadedModules 已填好。
    void BuildAnalysis(const ModuleIndex& modules, DumpParseResult& result);

    // IsSystemModule 作用：判断模块名是否属于操作系统自带的核心模块。
    // 传入 moduleName 模块名（可带路径）；返回是否为系统核心模块。
    // 归因时这类模块权重打折，避免结论永远指向 ntoskrnl.exe。
    bool IsSystemModule(const QString& moduleName);

    // AnalysisConfidenceText 作用：把可信度枚举转成中文文本。
    // 传入 confidence；None 时返回“无结论”。
    QString AnalysisConfidenceText(AnalysisConfidence confidence);
}
