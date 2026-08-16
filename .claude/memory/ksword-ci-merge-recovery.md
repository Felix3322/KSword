---
name: ksword-ci-merge-recovery
description: KSword 合并后 CI 回归的定位与修复边界
metadata:
  type: project
---

# CI 合并回归恢复

- 先看最新提交对应的 `Source integrity`、用户态构建和 `Driver CI` 日志；`git diff --check` 失败会跳过后续 JSON、i18n 与 IOCTL 审计，修完空白后必须单独补跑这些检查。
- `shared/driver/` 中的 R0/R3 IOCTL function ID 必须全局唯一。新增统一协议时不能复用仍需兼容的旧 IOCTL 编号；中央注册表也只能登记一次，否则线性查找会让后续 handler 永远不可达。
- 驱动源文件使用 `TOKEN_PRIVILEGES`、`ZwOpenProcessTokenEx`、`ZwQueryInformationToken` 等 NTIFS 声明时，需要显式包含 `<ntifs.h>`；仅包含项目的 `ark_driver.h`（其基础是 `<ntddk.h>`）不够。
- 驱动 Release 把警告视为错误。R0/R3 共享协议头避免匿名 struct/union；如需让同一 ABI 槽位兼容旧 `reserved` 与新动作语义，保留单个具名字段并让旧路径写入确定的零值。
- 多分支合并后不要只修第一个编译错误：对照最近一次两套 CI 都成功的 SHA，检查新增文件、被静默撤销的功能文件、工程引用、重复注册与协议编号，再运行语言包审计和 JSON 解析。
- 身份敏感的异步进程操作必须冻结 `PID + creationTime100ns`。R3 优先复用已校验并持续持有的进程句柄；R0 调整协议必须拒绝零创建时间，并由客户端复核响应中的创建时间与批量应用计数。仅在 UI 状态里保存 PID、稍后重新打开会把操作落到复用后的新进程。
- `TOKEN_PRIVILEGES` 是变长结构。R3 `GetTokenInformation` 和 R0 `ZwQueryInformationToken` 的第二次查询后，都要用实际返回字节数验证 `PrivilegeCount` 能被完整缓冲区覆盖，再遍历条目。
- 合并恢复崩溃处理时必须一起恢复共享 handler、Launcher reporter、两个工程引用、主程序启动挂钩和中英语言键；重复崩溃只能提供退出，不能继续暴露重启按钮形成崩溃循环。内部等待 PID 参数只有在新进程是该 PID 的直接子进程、双方映像路径相同，且确实观察到前一进程退出后，才能绕过单实例检查。
