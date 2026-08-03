#pragma once

// ============================================================
// DriverDock.ModuleDumpFile.h
// 作用：
// - 在目标目录创建并持有带 DELETE 权限的临时文件句柄；
// - 通过同一句柄完成刷新与无覆盖原子重命名；
// - 失败时按句柄删除临时文件，避免留下不完整的内核镜像。
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <QString>

#include <cstddef>
#include <cstdint>

namespace ksword::driver_dock_internal
{
    // DriverModuleDumpFileError：区分临时文件生命周期中的失败阶段，
    // 调用方据此映射为 DriverDock 的本地化错误提示。
    enum class DriverModuleDumpFileError : std::uint32_t
    {
        None = 0U,
        Create,
        Write,
        Flush,
        TargetExists,
        Commit
    };

    class DriverModuleDumpFile final
    {
    public:
        // 构造后先调用 create，再调用任意次数 write，最后调用 commit。
        DriverModuleDumpFile() noexcept = default;
        ~DriverModuleDumpFile() noexcept;

        DriverModuleDumpFile(const DriverModuleDumpFile&) = delete;
        DriverModuleDumpFile& operator=(const DriverModuleDumpFile&) = delete;
        DriverModuleDumpFile(DriverModuleDumpFile&&) = delete;
        DriverModuleDumpFile& operator=(DriverModuleDumpFile&&) = delete;

        // create：输入最终目标路径；输出是否已在同目录创建受保护临时文件。
        bool create(const QString& targetPath);

        // write：输入内存块地址和长度；输出是否完整写入当前临时文件。
        bool write(const std::uint8_t* dataPointer, std::size_t byteCount);

        // commit：输入应有文件大小；刷新数据并通过原句柄无覆盖重命名。
        bool commit(std::uint64_t expectedFileBytes);

        DriverModuleDumpFileError error() const noexcept;
        unsigned long win32Error() const noexcept;
        QString technicalDetail() const;

    private:
        // fail：集中记录失败阶段、Win32 错误码和内部诊断文本。
        bool fail(
            DriverModuleDumpFileError errorValue,
            unsigned long win32ErrorValue,
            const QString& technicalDetailValue);

        // discard：失败或提前返回时，优先通过仍持有的 DELETE 句柄删除临时文件。
        void discard() noexcept;

        HANDLE m_fileHandle = INVALID_HANDLE_VALUE; // m_fileHandle：临时文件读写、删除和重命名句柄。
        QString m_temporaryPath; // m_temporaryPath：异常清理时使用的临时文件绝对路径。
        QString m_targetPath; // m_targetPath：FileRenameInfo 使用的最终绝对路径。
        bool m_committed = false; // m_committed：成功重命名后禁止析构清理最终文件。
        DriverModuleDumpFileError m_error = DriverModuleDumpFileError::None; // m_error：最后失败阶段。
        unsigned long m_win32Error = ERROR_SUCCESS; // m_win32Error：最后一次 Win32 失败码。
        QString m_technicalDetail; // m_technicalDetail：供失败弹窗和日志使用的内部诊断。
    };
}
