#pragma once

// ============================================================
// DumpSymbolIndex.h
// 作用：
// - 提供“地址 → 模块”的区间索引：把一个裸地址翻译成
//   “模块名+0x偏移”，并判定该地址落在已加载模块还是已卸载模块；
// - 提供地址性质判定：NULL 页 / 用户空间 / 内核空间 /
//   分配器哨兵值（未初始化、释放后使用），用于给 BugCheck 参数、
//   异常参数与寄存器值加中文注解；
// - 本模块不加载任何符号文件（PDB），只做映像级归属，
//   因此永远给不出函数名，只能给到 模块+偏移。
// 调用方式：
// - 解析器在填完 modules/unloadedModules 后构造 ModuleIndex，
//   随后对任意地址调用 resolve()/symbolText()。
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // ModuleIndex 作用：按基址排序的模块区间表，支持 O(log n) 地址归属查询。
    // 构造后内部数据只读，可在解析线程内自由拷贝使用。
    class ModuleIndex
    {
    public:
        // build 作用：从解析结果里的模块表与已卸载模块表建立索引。
        // 传入 modules 已加载模块、unloaded 已卸载模块、pointerSize 指针宽度（4/8）。
        void build(
            const std::vector<ModuleEntry>& modules,
            const std::vector<UnloadedModuleEntry>& unloaded,
            std::uint32_t pointerSize);

        // resolve 作用：把一个数值当作地址解读，给出模块归属与性质说明。
        // 传入 address 待解读数值；返回完整解读结果（永远有效，未命中时字段为空）。
        AddressNote resolve(std::uint64_t address) const;

        // symbolText 作用：只取“模块名+0x偏移”文本。
        // 传入 address 地址；命中模块时返回如 nvlddmkm.sys+0x1A2B3，否则返回空串。
        QString symbolText(std::uint64_t address) const;

        // annotate 作用：给一个数值生成用于表格“注解”列的一行中文说明。
        // 传入 address 数值；返回“模块名+偏移（已卸载驱动）”，或地址性质说明；
        // 数值太小（不像地址）时返回空串，避免在寄存器表里刷出无意义的注解。
        QString annotate(std::uint64_t address) const;

    private:
        // Range：一个模块占据的地址区间 [base, base+size)。
        struct Range
        {
            std::uint64_t base = 0;  // base：映像基址。
            std::uint64_t end = 0;   // end：映像结束地址（不含）。
            QString name;            // name：模块名（已去掉目录部分）。
            bool unloaded = false;   // unloaded：是否来自已卸载模块表。
        };

        std::vector<Range> m_ranges;      // m_ranges：按 base 升序排列的模块区间。
        std::uint32_t m_pointerSize = 8;  // m_pointerSize：目标机指针宽度，决定内核空间下界。
    };

    // PoisonValueText 作用：识别分配器/编译器填充的哨兵值。
    // 传入 value 数值与 pointerSize 指针宽度；命中时返回中文含义，否则返回空串。
    // 例如 0xCCCCCCCC 表示“未初始化的栈内存（MSVC /RTC 填充）”。
    QString PoisonValueText(std::uint64_t value, std::uint32_t pointerSize);

    // ClassifyAddress 作用：只按数值范围判定地址性质，不查模块表。
    // 传入 address 数值与 pointerSize 指针宽度；返回性质分类。
    AddressKind ClassifyAddress(std::uint64_t address, std::uint32_t pointerSize);

    // AddressKindText 作用：把地址性质分类转成中文说明。
    // 传入 kind 分类；返回中文文本，Unknown 时返回空串。
    QString AddressKindText(AddressKind kind);

    // BaseModuleName 作用：从完整路径里取出文件名部分。
    // 传入 path 模块路径（可能是 \SystemRoot\System32\drivers\x.sys）；返回 x.sys。
    QString BaseModuleName(const QString& path);
}
