# KSword 驱动候选地址安全读取

## 适用范围

运行期偏移探测、签名扫描、链表遍历、私有对象字段读取等路径中，只要地址来自候选偏移、链节点、运行期解析结果或可能失效的内核对象，就视为不可信地址。

## 强制规则

- 不得用 `__try/__except` 包裹 `RtlCopyMemory` 或直接解引用来读取不可信内核地址。未映射内核地址可能直接触发 `0x50 PAGE_FAULT_IN_NONPAGED_AREA`，异常处理不会接管。
- `APC_LEVEL` 及以下统一调用 `KswordARKRuntimeReadMemory`。该函数使用 `MmCopyMemory`，并且只在完整复制请求字节数时返回成功。
- 高于 `APC_LEVEL` 时拒绝候选地址读取，不把失败降级为直接访问。
- 多跳链表必须逐跳安全读取，每一跳都重新验证空指针、反向链接和遍历预算。

## 调试注意事项

Release 链接可能合并机器码相同的静态读取包装函数。转储符号可能显示其中一个同构函数名，定位时还要结合精确调用者、寄存器、源文件调用关系和匹配构建的 PDB。

2026-08-14 的匹配 Release 转储中，`KswordARKDriverResolveUniqueKldrListOffset` 沿候选 KLDR 链读取到驱动映像末尾前一字节，随后内联包装调用 `memcpy` 读取 16 字节并越界。修复后该路径和驱动映像编辑器的同构读取包装均转到 `KswordARKRuntimeReadMemory`。
