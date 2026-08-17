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

## 统一暂存与 R3 编辑范围

- 文件属性窗口支持 `QStringList` 多目标。多选只打开一个批量窗口，常规页显示汇总，哈希页和
  元数据页支持批量处理；PE、签名、重解析点、占用、FileObject、Storage、Minifilter、依赖 DLL、
  字符串和十六进制等单文件分析导航在批量模式禁用并给出原因。
- 所有编辑页只生成 `ks::file::metadata::TargetPatch`，页面内的“暂存”按钮不触碰文件。窗口底部
  “保存全部修改”是唯一写入入口，带“创建备份再修改”选项，默认勾选。
- `ksword/file/file_metadata_transaction.*` 只使用 R3 Win32/NT API，统一执行卷序列号 + 文件索引
  身份复核、备份、后台写入、写后回读、逐操作结果和失败回滚。高风险操作（原始重解析点、EA、
  Object ID、PE 资源、嵌入式签名清除）未勾选备份时拒绝执行。
- 已覆盖基础属性/四个时间戳、重命名、8.3 短名、目录大小写敏感、Shell PropertyStore、ADS 与
  Zone.Identifier、EA 原始字节、安全 SDDL/Owner/Group/DACL/SACL/继承保护/有效权限、压缩/稀疏/
  EFS/Integrity Stream/Object ID/硬链接、原始重解析缓冲、PE VERSIONINFO/Manifest/其它资源原始
  更新，以及 R3 `WinVerifyTrust` 证书链、签名者、颁发者、SHA-256 指纹、有效期、时间戳和 Catalog
  状态展示。
- 默认数据流、文件长度、有效数据长度、分配大小、USN/MFT 日志和自动重新签名仍保持只读。已签名
  文件保存前提供“清除嵌入式签名并继续 / 保留签名数据并继续 / 取消”三选一，Catalog 签名只显示
  失效，不能从目标文件本身删除。
