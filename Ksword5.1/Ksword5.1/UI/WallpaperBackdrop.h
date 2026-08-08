#pragma once

#include <QImage>
#include <QRect>
#include <QString>

// KswordWallpaperBackdrop 作用：
// - 为“毛玻璃磨砂”背景提供自绘数据源：读取当前桌面壁纸并生成模糊底图；
// - Windows 11 起 DWM 的传统 BLURBEHIND(3) 已退化为纯透明且忽略着色，
//   DWM 云母又与分层透明窗口互斥（整窗发白），因此毛玻璃改为应用侧
//   对壁纸做高斯级模糊（与系统云母同一思路：壁纸 + 着色层），
//   不依赖未公开接口，也没有亚克力拖慢鼠标消息的副作用。
namespace KswordWallpaperBackdrop
{
    // QueryDesktopWallpaperFilePath 作用：
    // - 查询指定窗口矩形所在显示器当前使用的壁纸文件路径；
    // - 优先 IDesktopWallpaper（支持逐显示器壁纸），失败回退 SPI_GETDESKWALLPAPER；
    // - 幻灯片放映、纯色桌面等取不到文件时返回空串，由调用方用着色层兜底。
    // 入参 windowRectOnVirtualDesktop：主窗口在虚拟桌面坐标系中的矩形，用于挑选显示器。
    // 返回：壁纸文件的本地路径；取不到时返回空串。
    // 线程要求：可在任意线程调用，内部自行完成 COM 初始化与配对释放。
    QString QueryDesktopWallpaperFilePath(const QRect& windowRectOnVirtualDesktop);

    // BuildBlurredBackdropImage 作用：
    // - 把壁纸原图缩到工作分辨率后做多趟盒式模糊（近似高斯），返回模糊结果；
    // - 结果保持不透明（RGB32）且分辨率较低，绘制方平滑放大并叠加主题着色即可。
    // 入参 sourceImage：壁纸原图；空图直接返回空图。
    // 返回：模糊后的工作图；失败返回空图。
    QImage BuildBlurredBackdropImage(const QImage& sourceImage);
}
