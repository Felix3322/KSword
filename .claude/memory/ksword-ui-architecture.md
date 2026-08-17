---
name: ksword-ui-architecture
description: KSword 主程序 UI/主题架构要点（theme.h token 体系、全局样式块链路、WindowChrome、透明背景与毛玻璃、Dock 懒加载）
metadata:
  type: project
---

KSword 主程序位于 `Ksword5.1/Ksword5.1`（Qt 6.9.3 Widgets + Qt Advanced Docking System，MSVC vcxproj 构建）。

## UI 主题架构

- `theme.h`（KswordTheme 命名空间）：design-token 中心。中性表面色（Window/Surface/SurfaceAlt/SurfaceMuted/Border）由 RGB 偏移从种子色派生；强调色 PrimaryBlueColor 可由用户自定义；提供 EnsureTextContrast 等 WCAG 对比度工具。
- 纯图标按钮的几何同样由 `theme.h` 收口：紧凑工具栏使用 `ApplyCompactIconButtonMetrics`（28px 按钮 / 16px 图标），独立或强调动作使用 `ApplyStandardIconButtonMetrics`（32px / 18px）；页面不得继续新增 30/34/36px 的临时组合。
- `MainWindow::applyAppearanceSettings`：主题应用唯一入口，设置 QApplication palette + 调用 `applyGlobalApplicationStyleBlocks`（带 marker 的 QSS 块替换机制，marker 常量在 MainWindow.cpp 顶部匿名命名空间）。
- 全局 QSS 块顺序：BaseControl（`UI/GlobalUiBaseStyle.cpp`）→ Tooltip → ContextMenu → ControlContrast → ComboBox，依次追加到 app stylesheet，基线块在最前，局部样式可覆盖。
- `UI/GlobalDialogTheme.cpp`：QApplication 事件过滤器给所有 QDialog 补主题（palette + 追加 QSS）；QMessageBox 由 `UI/ThemedMessageBox` 专管。
- `UI/WindowChrome.cpp`：事件过滤器对所有原生标题栏顶层窗口用 DwmSetWindowAttribute 染色（IMMERSIVE_DARK_MODE=20、BORDER=34、CAPTION=35、TEXT=36），主题切换时 `RefreshAllWindowChrome()`。
- 主窗口是 FramelessWindowHint + 自绘 `Framework/CustomTitleBar`；其余子窗口全是原生标题栏。

**全局基线样式只允许颜色/边框，禁止 min-height/padding 等几何属性**——app 级几何会穿透局部样式破坏紧凑布局（曾导致主窗口标题栏按钮被撑高、最大化后标题文字上偏）。

## 透明背景与毛玻璃（MainWindow.cpp）

配置项：`backgroundTransparencyEnabled`（总开关）+ `backgroundTranslucencyMaterial`（auto/mica/desktop）。

- 总开关需要 `WA_TranslucentBackground`，**必须在原生窗口创建前设置**，因此改动只能重启生效；材质选项可运行时切换。
- **DWM 云母（DWMWA_SYSTEMBACKDROP_TYPE）与 `WA_TranslucentBackground` 互斥**：云母要求窗口不透明、由 DWM 在其背后合成，遇到分层透明窗口会回退成系统浅色 fallback 底，表现为整窗发白。已改用 `SetWindowCompositionAttribute` + `ACCENT_ENABLE_ACRYLICBLURBEHIND`（Win10 1803+/Win11 通用），配置值仍叫 `mica` 仅为兼容旧配置。
- 毛玻璃生效时着色由系统随模糊合成，根容器必须画完全透明；未生效（旧系统/调用失败）才回退自绘半透明着色层保证文字可读——由 `applyMainWindowBackdropMaterial` 的返回值驱动。
- Acrylic 不会自动跟随窗口移动重采样，失焦后还会降级为静态回退色：`scheduleWindowBackdropRefresh()` 在 move/resize/WindowStateChange/ActivationChange 时重新下发组合特性，40ms 节流合并。
- 首次外观应用早于原生窗口创建，组合特性会被句柄守卫跳过，因此 `showEvent` 必须补调一次 `refreshWindowBackdropMaterial()`。
- **Dock 内容透明不能只看背景图**：`enableDockContentTransparency = 背景图就绪 || 窗口透明`，否则 DockManager 与各 Dock 的不透明表面会盖住底层，只剩菜单栏可见。KernelDock 会自绘实底，三处决策统一走 `shouldRenderTransparentDockContent()`。

## Dock 懒加载机制

- `ensureDockContentInitialized` 按 `ks_lazy_key` 创建真实 widget（成员指针 m_processWidget 等允许为 null，占位页 `createDockPlaceholderWidget`）。
- 主功能 Dock 一律 `DockWidgetClosable=false`（Tab 无关闭按钮）。曾实现过"Tab 关闭按钮=卸载内容"（CustomCloseHandling + unloadDockContent），最终整体撤销（23251d80）；若再有此需求注意：welcome 无懒加载工厂，kernel↔driver 有共享自驱动页 `attachKswordSelfDriverPage`，卸载会悬空。
- 跨 Dock 的进程详情入口仍可调用 `ensureDockContentInitialized(m_dockProcess)` 来复用 `ProcessDock` 的详情窗口管理与 identity 校验，但不得随后 `raise()` 或 `setVisible(true)` 激活进程 Dock；`ProcessDetailWindow` 是独立顶层窗口，打开它时应保留用户当前页签。

## 通用表格交互

- `UI/TableInteractionSupport.cpp` 通过应用级事件过滤器统一接入 `QTableView/QTableWidget`；表头点击排序由 `UI/TableHeaderSortingSupport.*` 负责。
- `VisibleTableWidget` 与 `TableActionTableView` 共用嵌入式 `TableActionBar`，但能力按表格用途分级：普通 `VisibleTableWidget` 默认只显示复制/导出的紧凑条，模型型 `TableActionTableView` 默认提供冻结、暂停和快照的完整条；窄小或纯展示表格用 `SetTableActionBarMode(..., None)` 禁用。操作条会同时出现在 Dock 和普通 `QDialog` 中，因此按钮、快照滚动区等几何/字体样式必须由操作条自身用 palette 角色封装；不能继承宿主弹窗的 `ThemedButtonStyle`，否则弹窗中的 padding/粗体会把同一套按钮放大并挤压固定高度操作条。
- 普通 `QTableView/QTableWidget` 的横纵表头由 `TableInteractionSupport` 强制应用同一套 palette 基线，页面不要再用蓝色粗体等局部表头 QSS 制造层级差异；十六进制编辑器等确实需要专业表头语义的控件须在设置局部样式前调用 `SetPreserveCustomTableHeaderStyle(table, true)` 显式声明例外。
- 未显式开启 Qt 持续排序的 `QTableWidget` 使用“一次点击、一次排序”，不改变 `sortingEnabled`。这样后续 `setRowCount/setItem` 批量或分批填充不会因实时搬行而写错列组。
- 手动排序后遇到增删行、模型重置或单元格更新会撤销排序箭头，不自动重排半成品数据。具有帧序、加载序、采集序等固定行序语义的表格调用 `SetTableHeaderClickSortingEnabled(table, false)`。
- 进程表使用 `QSortFilterProxyModel` 与友好分组专用排序；点击表头时首次为升序、同列再次为降序。父子树状视图点表头后保持“进程友好视图”未勾选，只把内部投影切成没有父子关系的普通扁平枚举并交给代理排序；用户再次切换友好视图复选框时退出该临时扁平模式。搜索结果与历史快照同样走代理原生排序。
- 句柄页等大型 `QTreeWidget` 结果必须先建立轻量摘要节点，展开分支时每批最多创建 300 个明细节点，并用末尾“继续加载”节点追加下一批。摘要始终保持业务配置顺序，表头排序只重排各摘要下已加载的明细；占位节点和“继续加载”节点固定在分支末尾。进程图标等异步资源只为已创建的明细解析，回填必须同时校验树重建代次，并允许同一源记录出现在多个规则分支。

## 踩坑记录

- 构建带 **i18n 审计钩子**：源码中任何"可提取"字符串字面量（中文日志、英文句子、无路径分隔的头文件名、甚至 `GetProcAddress` 的函数名）都必须在两个语言包的 `source_translations` 有条目，否则构建直接失败。QSS 选择器行要与 `{` 写在同一字符串片段内才会被审计排除。
- 语言包**只能定点编辑**：用脚本 json.load/dump 会重排键序与缩进，产生 5 万行无意义 diff。
- 约 1374 处散落 `setStyleSheet` 分布在 136 个文件（多带 `!important`），未来渐进收敛到全局基线。
- 构建产物被运行中的 exe 占用会导致 `LNK1104`；`vctip.exe` 残留会导致 obj `Permission denied`。

## 仓库规范（详见 AGENTS.md）

- 新增源码必须同步 `.vcxproj` 和 `.vcxproj.filters`。
- 用户可见文本必须同步 `languages/zh-CN.json` 与 `en-US.json`，并通过 `tools/i18n_language_pack.py audit`。
