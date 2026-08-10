#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendHiddenEntries(std::vector<StartupEntry>* entryListOut)
{
    // 隐藏项检测完全在 ks::startup 后端完成：
    // - 后端对同一对象取两种系统视图（内核 vs Win32、注册表 vs SCM、TaskCache vs 任务计划 API 等），
    //   把对不上的部分整理成 std::vector<StartupEntry>；
    // - UI 层只负责展示、筛选和右键菜单，不参与判定；
    // - 返回值：无，直接追加结果。
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::EnumerateHiddenEntries());
}
