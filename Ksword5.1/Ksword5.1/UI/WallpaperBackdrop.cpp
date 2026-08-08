#include "WallpaperBackdrop.h"

#include <QtGlobal>

#ifdef Q_OS_WIN
#include <windows.h>
#include <objbase.h>
#include <shobjidl.h>
#pragma comment(lib, "ole32.lib")
#endif

namespace
{
    // kBackdropWorkingMaxWidth 作用：
    // - 模糊工作图的最大宽度；先缩小再模糊，成本与最终观感都更稳定；
    // - 绘制时平滑放大，本身就是低频画面，低分辨率不会产生可见劣化。
    constexpr int kBackdropWorkingMaxWidth = 480;
    // kBackdropBlurRadius 作用：工作分辨率下单趟盒式模糊的半径（像素）。
    constexpr int kBackdropBlurRadius = 6;
    // kBackdropBlurPassCount 作用：盒式模糊趟数；三趟盒式模糊即可良好近似高斯。
    constexpr int kBackdropBlurPassCount = 3;

    // blurRgb32Horizontally 作用：
    // - 对 RGB32 图做一趟水平方向的滑动窗口盒式模糊；
    // - 边缘按“钳制到最近像素”延拓，避免出现暗边。
    // 入参 sourceImage/targetImage：尺寸与格式必须一致；radius：模糊半径（>=1）。
    // 返回：无返回值，结果写入 targetImage。
    void blurRgb32Horizontally(const QImage& sourceImage, QImage& targetImage, const int radius)
    {
        const int imageWidth = sourceImage.width();
        const int imageHeight = sourceImage.height();
        const int windowSize = radius * 2 + 1;
        for (int y = 0; y < imageHeight; ++y)
        {
            const QRgb* sourceLine = reinterpret_cast<const QRgb*>(sourceImage.constScanLine(y));
            QRgb* targetLine = reinterpret_cast<QRgb*>(targetImage.scanLine(y));

            int sumRed = 0;
            int sumGreen = 0;
            int sumBlue = 0;
            for (int x = -radius; x <= radius; ++x)
            {
                const QRgb pixel = sourceLine[qBound(0, x, imageWidth - 1)];
                sumRed += qRed(pixel);
                sumGreen += qGreen(pixel);
                sumBlue += qBlue(pixel);
            }
            for (int x = 0; x < imageWidth; ++x)
            {
                targetLine[x] = qRgb(sumRed / windowSize, sumGreen / windowSize, sumBlue / windowSize);
                const QRgb leavingPixel = sourceLine[qBound(0, x - radius, imageWidth - 1)];
                const QRgb enteringPixel = sourceLine[qBound(0, x + radius + 1, imageWidth - 1)];
                sumRed += qRed(enteringPixel) - qRed(leavingPixel);
                sumGreen += qGreen(enteringPixel) - qGreen(leavingPixel);
                sumBlue += qBlue(enteringPixel) - qBlue(leavingPixel);
            }
        }
    }

    // blurRgb32Vertically 作用：
    // - 对 RGB32 图做一趟垂直方向的滑动窗口盒式模糊，其余同水平版本。
    void blurRgb32Vertically(const QImage& sourceImage, QImage& targetImage, const int radius)
    {
        const int imageWidth = sourceImage.width();
        const int imageHeight = sourceImage.height();
        const int windowSize = radius * 2 + 1;
        for (int x = 0; x < imageWidth; ++x)
        {
            int sumRed = 0;
            int sumGreen = 0;
            int sumBlue = 0;
            for (int y = -radius; y <= radius; ++y)
            {
                const QRgb pixel = reinterpret_cast<const QRgb*>(
                    sourceImage.constScanLine(qBound(0, y, imageHeight - 1)))[x];
                sumRed += qRed(pixel);
                sumGreen += qGreen(pixel);
                sumBlue += qBlue(pixel);
            }
            for (int y = 0; y < imageHeight; ++y)
            {
                reinterpret_cast<QRgb*>(targetImage.scanLine(y))[x] =
                    qRgb(sumRed / windowSize, sumGreen / windowSize, sumBlue / windowSize);
                const QRgb leavingPixel = reinterpret_cast<const QRgb*>(
                    sourceImage.constScanLine(qBound(0, y - radius, imageHeight - 1)))[x];
                const QRgb enteringPixel = reinterpret_cast<const QRgb*>(
                    sourceImage.constScanLine(qBound(0, y + radius + 1, imageHeight - 1)))[x];
                sumRed += qRed(enteringPixel) - qRed(leavingPixel);
                sumGreen += qGreen(enteringPixel) - qGreen(leavingPixel);
                sumBlue += qBlue(enteringPixel) - qBlue(leavingPixel);
            }
        }
    }

#ifdef Q_OS_WIN
    // ComInitializationScope 作用：
    // - 在当前线程按 STA 初始化 COM 并在析构时配对释放；
    // - RPC_E_CHANGED_MODE 表示线程已按其他模型初始化，此时直接复用，不做配对释放。
    class ComInitializationScope final
    {
    public:
        ComInitializationScope()
        {
            const HRESULT initializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            m_uninitializeRequired = (initializeResult == S_OK || initializeResult == S_FALSE);
        }
        ~ComInitializationScope()
        {
            if (m_uninitializeRequired)
            {
                ::CoUninitialize();
            }
        }
        ComInitializationScope(const ComInitializationScope&) = delete;
        ComInitializationScope& operator=(const ComInitializationScope&) = delete;

    private:
        bool m_uninitializeRequired = false; // m_uninitializeRequired：本对象是否负责 CoUninitialize。
    };

    // queryWallpaperViaDesktopWallpaperInterface 作用：
    // - 通过 IDesktopWallpaper 查询壁纸路径，优先返回窗口中心所在显示器的壁纸；
    // - 找不到匹配显示器时回退第一个有壁纸的显示器。
    // 入参 windowRectOnVirtualDesktop：主窗口在虚拟桌面坐标系中的矩形。
    // 返回：壁纸文件路径；接口不可用或无壁纸时返回空串。
    QString queryWallpaperViaDesktopWallpaperInterface(const QRect& windowRectOnVirtualDesktop)
    {
        IDesktopWallpaper* desktopWallpaper = nullptr;
        if (FAILED(::CoCreateInstance(
                __uuidof(DesktopWallpaper),
                nullptr,
                CLSCTX_ALL,
                IID_PPV_ARGS(&desktopWallpaper)))
            || desktopWallpaper == nullptr)
        {
            return QString();
        }

        QString matchedMonitorPath;
        QString firstMonitorFallbackPath;
        UINT monitorCount = 0;
        if (SUCCEEDED(desktopWallpaper->GetMonitorDevicePathCount(&monitorCount)))
        {
            for (UINT monitorIndex = 0; monitorIndex < monitorCount; ++monitorIndex)
            {
                LPWSTR monitorId = nullptr;
                if (FAILED(desktopWallpaper->GetMonitorDevicePathAt(monitorIndex, &monitorId))
                    || monitorId == nullptr)
                {
                    continue;
                }

                LPWSTR wallpaperFilePath = nullptr;
                if (SUCCEEDED(desktopWallpaper->GetWallpaper(monitorId, &wallpaperFilePath))
                    && wallpaperFilePath != nullptr)
                {
                    const QString candidatePath =
                        QString::fromWCharArray(wallpaperFilePath).trimmed();
                    ::CoTaskMemFree(wallpaperFilePath);
                    if (!candidatePath.isEmpty())
                    {
                        if (firstMonitorFallbackPath.isEmpty())
                        {
                            firstMonitorFallbackPath = candidatePath;
                        }
                        RECT monitorNativeRect{};
                        if (SUCCEEDED(desktopWallpaper->GetMonitorRECT(monitorId, &monitorNativeRect)))
                        {
                            const QRect monitorRect(
                                QPoint(monitorNativeRect.left, monitorNativeRect.top),
                                QPoint(monitorNativeRect.right - 1, monitorNativeRect.bottom - 1));
                            if (monitorRect.contains(windowRectOnVirtualDesktop.center()))
                            {
                                matchedMonitorPath = candidatePath;
                            }
                        }
                    }
                }
                ::CoTaskMemFree(monitorId);
                if (!matchedMonitorPath.isEmpty())
                {
                    break;
                }
            }
        }
        desktopWallpaper->Release();
        return matchedMonitorPath.isEmpty() ? firstMonitorFallbackPath : matchedMonitorPath;
    }

    // queryWallpaperViaSystemParameters 作用：
    // - SPI_GETDESKWALLPAPER 回退路径：仅返回“最后一次设置”的壁纸，不区分显示器。
    // 返回：壁纸文件路径；纯色桌面等场景返回空串。
    QString queryWallpaperViaSystemParameters()
    {
        wchar_t wallpaperPathBuffer[MAX_PATH]{};
        if (::SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, wallpaperPathBuffer, 0) == FALSE)
        {
            return QString();
        }
        return QString::fromWCharArray(wallpaperPathBuffer).trimmed();
    }
#endif
}

QString KswordWallpaperBackdrop::QueryDesktopWallpaperFilePath(
    const QRect& windowRectOnVirtualDesktop)
{
#ifdef Q_OS_WIN
    ComInitializationScope comInitializationScope;
    QString wallpaperFilePath =
        queryWallpaperViaDesktopWallpaperInterface(windowRectOnVirtualDesktop);
    if (wallpaperFilePath.isEmpty())
    {
        wallpaperFilePath = queryWallpaperViaSystemParameters();
    }
    return wallpaperFilePath;
#else
    Q_UNUSED(windowRectOnVirtualDesktop);
    return QString();
#endif
}

QImage KswordWallpaperBackdrop::BuildBlurredBackdropImage(const QImage& sourceImage)
{
    if (sourceImage.isNull())
    {
        return QImage();
    }

    // 先统一为不透明 RGB32 并缩到工作宽度：模糊底图不承载 alpha，
    // 透明度由绘制方的主题着色层控制。
    QImage workingImage = sourceImage.convertToFormat(QImage::Format_RGB32);
    if (workingImage.width() > kBackdropWorkingMaxWidth)
    {
        workingImage = workingImage
            .scaledToWidth(kBackdropWorkingMaxWidth, Qt::SmoothTransformation)
            .convertToFormat(QImage::Format_RGB32);
    }
    if (workingImage.width() < 1 || workingImage.height() < 1)
    {
        return QImage();
    }

    QImage scratchImage(workingImage.size(), QImage::Format_RGB32);
    for (int passIndex = 0; passIndex < kBackdropBlurPassCount; ++passIndex)
    {
        blurRgb32Horizontally(workingImage, scratchImage, kBackdropBlurRadius);
        blurRgb32Vertically(scratchImage, workingImage, kBackdropBlurRadius);
    }
    return workingImage;
}
