#pragma once

// ============================================================
// DumpAutoCheck.h
// 作用：
// - 启动后检查系统里最近是否产生过新的崩溃转储（默认 24 小时内），
//   有则由 MainWindow 询问用户是否立刻解析；
// - 判断一次解析结果是否与 KSword 自身组件相关：命中时应引导用户上报，
//   因为这类崩溃对本项目而言是必须修的缺陷，而不是"别人的驱动有问题"；
// - 提供上报指引文案（QQ 群 / GitHub Issues / 需要一并说明的触发流程）。
// 设计约束：
// - 扫描只做目录枚举与时间戳比较，不打开也不解析文件，可安全放在启动路径上；
// - 是否弹窗、是否记住"已问过"由调用方（MainWindow）依据持久设置决定，
//   本模块不读写配置，保持可测试与可复用。
// ============================================================

#include <QDateTime>
#include <QString>
#include <QStringList>

namespace ks::minidump
{
    struct DumpParseResult;

    // RecentDumpInfo：一次扫描找到的最新转储。
    struct RecentDumpInfo
    {
        bool found = false;        // found：是否找到符合时间条件的转储。
        QString filePath;          // filePath：转储文件完整路径。
        QDateTime modifiedTime;    // modifiedTime：文件最后修改时间（本地时区）。
        qint64 fileSizeBytes = 0;  // fileSizeBytes：文件字节数。
        bool isKernelDump = false; // isKernelDump：true=蓝屏转储，false=其它。
        int totalRecentCount = 0;  // totalRecentCount：时间窗口内的转储总数（含本条）。
    };

    // FindRecentDump 作用：查找时间窗口内最新的系统崩溃转储。
    // 扫描 C:\Windows\Minidump\*.dmp 与 C:\Windows\MEMORY.DMP；
    // 传入 maxAgeHours 时间窗口（小时，<=0 时按 24 小时处理）；
    // 返回最新的一条；窗口内没有转储时 found=false。
    // 函数只做目录枚举，不打开文件内容。
    RecentDumpInfo FindRecentDump(int maxAgeHours = 24);

    // KswordRelevance：解析结果与 KSword 自身组件的相关性判定。
    struct KswordRelevance
    {
        bool related = false;        // related：是否命中 KSword 自有模块。
        bool inBlameList = false;    // inBlameList：命中的是"肇事模块候选"（最强信号）。
        bool inStack = false;        // inStack：出现在疑似调用栈里。
        bool inUnloadedList = false; // inUnloadedList：出现在已卸载模块表里。
        bool onlyLoaded = false;     // onlyLoaded：仅出现在已加载模块表——这只说明程序当时在运行。
        QStringList matchedModules;  // matchedModules：命中的模块名（已去重）。
        QString summary;             // summary：一句话说明命中强度，可直接展示。
    };

    // EvaluateKswordRelevance 作用：判断解析结果是否指向 KSword 自身组件。
    // 传入 result 已完成的解析结果；返回相关性判定。
    // 判定分层：肇事候选 > 调用栈 > 已卸载表 > 仅在已加载模块表里出现。
    // 最后一层不构成"与 KSword 有关"的证据——KSword 正在运行时它必然在模块表里，
    // 据此提示用户上报只会制造噪音，因此 related 对该层返回 false。
    KswordRelevance EvaluateKswordRelevance(const DumpParseResult& result);

    // KswordQqGroupUrl / KswordIssuesUrl 作用：返回上报渠道地址。
    QString KswordQqGroupUrl();
    QString KswordIssuesUrl();

    // BuildKswordReportGuidance 作用：生成"命中 KSword 时"的上报指引正文。
    // 传入 relevance 判定结果与 dumpFilePath 转储文件路径；
    // 返回可直接放进对话框的多行中文文本，包含需要一并提供的触发流程要点。
    QString BuildKswordReportGuidance(
        const KswordRelevance& relevance,
        const QString& dumpFilePath);
}
