---
name: ksword-file-metadata-editor
description: FileDock 文件元数据编辑的 Win32 写入边界、身份复核、异步回读与 i18n 约束
metadata:
  type: project
---

# FileDock 文件元数据编辑

主程序文件属性窗口位于 `Ksword5.1/Ksword5.1/FileDock/FileDock.cpp` 的
`FileDetailDialog`。元数据编辑作为左侧导航中的懒加载页接入，不应在文件属性窗口首屏
同步打开句柄或访问可能阻塞的网络路径。

## Win32 基本信息写入

- 使用 `CreateFileW` 打开 `FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES` 句柄，保留
  `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`，目录需要
  `FILE_FLAG_BACKUP_SEMANTICS`。
- 始终带 `FILE_FLAG_OPEN_REPARSE_POINT`，叶节点为符号链接/Junction 时修改链接自身，
  不静默跟随到目标。
- 通过 `GetFileInformationByHandleEx(FileBasicInfo)` 读取、
  `SetFileInformationByHandle(FileBasicInfo)` 写入，再用同一句柄回读实际结果。
- `FILE_BASIC_INFO` 中未选择的四个时间字段保持 `0`；`FileAttributes=0` 表示不修改属性。
  不要把完整旧结构原样回写，否则会无意重写未选择字段或结构性属性。
- UI 使用本地时区和毫秒精度；后台请求转换成自 1601-01-01 UTC 起的 100ns 计数。
  FAT/exFAT 等文件系统可能按自身时间粒度舍入，写入成功但回读不一致时展示实际值，
  不伪报为精确匹配。

## 属性与身份安全边界

- 只开放 `READONLY`、`HIDDEN`、`SYSTEM`、`ARCHIVE`、`TEMPORARY`、
  `NOT_CONTENT_INDEXED` 六个位。
- `DIRECTORY`、`REPARSE_POINT`、`COMPRESSED`、`ENCRYPTED`、`SPARSE_FILE`、
  `INTEGRITY_STREAM` 等必须保留；需要改变时走各自专用 API/FSCTL，不能当普通布尔位编辑。
- 初次读取时记录卷序列号和 64 位文件索引。用户确认后重新打开目标，在写入前用同一句柄
  复核身份；路径已替换时以 `ERROR_FILE_INVALID` 失败，不能把旧页面里的值写到新对象。
- 写入前在同一句柄重新读取最新 `FILE_BASIC_INFO`，只把六个开放位合并到最新属性值，
  避免属性窗停留期间的外部变化被覆盖。

## UI、异步与国际化

- 读取和写入都放入 `QThreadPool`，回填使用 `QPointer<FileDetailDialog>` 和操作代数；
  对话框关闭或新操作取代旧操作后丢弃迟到结果。
- 写入成功后刷新常规属性树并重新发起 R0 文件信息查询；R0 查询也要带代数，防止写入前
  的旧结果覆盖新状态。
- 组合文本必须先对模板调用 `ks::i18n::sourceText` 再 `.arg(...)`。新增可见文本定点同步
  `languages/zh-CN.json` 与 `languages/en-US.json`，并运行 `tools/i18n_language_pack.py audit`。
