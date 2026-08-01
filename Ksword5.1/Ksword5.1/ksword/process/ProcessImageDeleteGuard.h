#pragma once

// ============================================================
// ProcessImageDeleteGuard.h
// 作用说明：
// 1) 在结束进程前按 PID 创建时间和实时映像路径验证同一进程实例；
// 2) 持有目标映像文件的 DELETE 句柄，把后续删除绑定到同一文件对象；
// 3) 路径被替换、PID 被复用或文件身份不可验证时一律失败关闭。
// ============================================================

#include <cstdint>
#include <string>

namespace ks::process
{
    // CapturedProcessImageDeleteTarget：只能移动的精确文件对象删除凭据。
    class CapturedProcessImageDeleteTarget final
    {
    public:
        CapturedProcessImageDeleteTarget() = default;
        ~CapturedProcessImageDeleteTarget();

        CapturedProcessImageDeleteTarget(const CapturedProcessImageDeleteTarget&) = delete;
        CapturedProcessImageDeleteTarget& operator=(const CapturedProcessImageDeleteTarget&) = delete;
        CapturedProcessImageDeleteTarget(CapturedProcessImageDeleteTarget&& other) noexcept;
        CapturedProcessImageDeleteTarget& operator=(CapturedProcessImageDeleteTarget&& other) noexcept;

        bool valid() const noexcept;
        const std::wstring& finalPath() const noexcept;
        std::uint64_t fileIdentity() const noexcept;
        std::uint32_t volumeSerialNumber() const noexcept;

    private:
        friend bool CaptureProcessImageDeleteTarget(
            std::uint32_t,
            std::uint64_t,
            const std::wstring&,
            CapturedProcessImageDeleteTarget*,
            std::string*);
        friend bool DeleteCapturedProcessImage(
            CapturedProcessImageDeleteTarget*,
            std::string*);

        void close() noexcept;

        void* m_fileHandle = nullptr;
        std::wstring m_finalPath;
        std::uint64_t m_fileIdentity = 0;
        std::uint32_t m_volumeSerialNumber = 0;
    };

    // CaptureProcessImageDeleteTarget：结束动作前锁定实时进程映像的文件对象。
    bool CaptureProcessImageDeleteTarget(
        std::uint32_t processId,
        std::uint64_t expectedCreationTime100ns,
        const std::wstring& expectedImagePath,
        CapturedProcessImageDeleteTarget* targetOut,
        std::string* detailTextOut = nullptr);

    // DeleteCapturedProcessImage：仅对已锁定的同一个文件对象设置删除状态。
    bool DeleteCapturedProcessImage(
        CapturedProcessImageDeleteTarget* target,
        std::string* detailTextOut = nullptr);
}
