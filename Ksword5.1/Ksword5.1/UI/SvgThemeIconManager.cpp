#include "SvgThemeIconManager.h"

// ============================================================
// SvgThemeIconManager.cpp
// 实现说明：
// - 不修改 qrc 中的 SVG 源码，也不要求各个按钮改用新 API；
// - 只在主题加载/切换时遍历一次现有控件；
// - 后续懒加载控件通过同一事件过滤器进入共享缓存。
// ============================================================

#include <QAbstractButton>
#include <QAction>
#include <QActionEvent>
#include <QApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QHash>
#include <QImage>
#include <QList>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QSet>
#include <QSize>
#include <QTabWidget>
#include <QVariant>
#include <QWidget>

#include <algorithm>

namespace
{
    constexpr auto OriginalButtonIconProperty =
        "ksword_svg_theme_original_button_icon"; // 按钮原始图标属性名。
    constexpr auto LastButtonIconKeyProperty =
        "ksword_svg_theme_last_button_icon_key"; // 管理器最近写入按钮的 QIcon cacheKey。
    constexpr auto OriginalActionIconProperty =
        "ksword_svg_theme_original_action_icon"; // QAction 原始图标属性名。
    constexpr auto LastActionIconKeyProperty =
        "ksword_svg_theme_last_action_icon_key"; // 管理器最近写入 QAction 的 cacheKey。
    constexpr auto OriginalWindowIconProperty =
        "ksword_svg_theme_original_window_icon"; // 普通控件 windowIcon 原始值。
    constexpr auto LastWindowIconKeyProperty =
        "ksword_svg_theme_last_window_icon_key"; // 管理器最近写入 windowIcon 的 cacheKey。
    constexpr auto OriginalTabIconProperty =
        "ksword_svg_theme_original_tab_icon"; // Tab 页面保存所属标签原始图标。
    constexpr auto LastTabIconKeyProperty =
        "ksword_svg_theme_last_tab_icon_key"; // 管理器最近写入 Tab 图标的 cacheKey。

    // cachedTintedIcons：
    // - key 是原图像素签名 + 目标颜色；
    // - value 是已构造多尺寸 pixmap 的 QIcon，所有窗口共享。
    QHash<QByteArray, QIcon>& cachedTintedIcons()
    {
        static QHash<QByteArray, QIcon> iconCache;
        return iconCache;
    }

    // normalizedIconImage：
    // - 把任意 QIcon 统一渲染为 24x24 ARGB 图像；
    // - 同时用于候选识别和稳定缓存签名。
    QImage normalizedIconImage(const QIcon& sourceIcon)
    {
        QPixmap sourcePixmap =
            sourceIcon.pixmap(QSize(24, 24), QIcon::Normal, QIcon::Off);
        if (sourcePixmap.isNull())
        {
            return QImage();
        }
        return sourcePixmap.toImage().convertToFormat(QImage::Format_ARGB32);
    }

    // isThemeTintCandidate：
    // - SVG 图标通常可缩放且 availableSizes 为空；
    // - 旧 createBlueIcon 已转为位图，因此再用“低颜色数量”识别扁平图标；
    // - 多色进程/文件图标会超过阈值，不会被主题色覆盖。
    bool isThemeTintCandidate(const QIcon& sourceIcon, const QImage& normalizedImage)
    {
        if (sourceIcon.isNull() || normalizedImage.isNull())
        {
            return false;
        }
        if (sourceIcon.availableSizes(QIcon::Normal, QIcon::Off).isEmpty())
        {
            return true;
        }

        QSet<QRgb> opaqueColors; // opaqueColors：忽略透明度后见到的 RGB 集合。
        int visiblePixelCount = 0; // visiblePixelCount：用于排除全透明占位图标。
        constexpr int MaximumFlatColorCount = 48; // 扁平图标允许的最大颜色数量。
        for (int y = 0; y < normalizedImage.height(); ++y)
        {
            const QRgb* scanLine =
                reinterpret_cast<const QRgb*>(normalizedImage.constScanLine(y));
            for (int x = 0; x < normalizedImage.width(); ++x)
            {
                const QRgb pixelValue = scanLine[x];
                if (qAlpha(pixelValue) == 0)
                {
                    continue;
                }
                ++visiblePixelCount;
                opaqueColors.insert(qRgb(
                    qRed(pixelValue),
                    qGreen(pixelValue),
                    qBlue(pixelValue)));
                if (opaqueColors.size() > MaximumFlatColorCount)
                {
                    return false;
                }
            }
        }
        return visiblePixelCount > 0;
    }

    // iconCacheKey：
    // - 使用规范图像完整字节和目标 QColor 生成 SHA-256；
    // - 即使多个 QIcon 对象由同一 SVG 分别构造，也能命中同一缓存。
    QByteArray iconCacheKey(
        const QImage& normalizedImage,
        const QColor& themeColor)
    {
        QByteArray signatureBytes;
        signatureBytes.reserve(
            static_cast<int>(normalizedImage.sizeInBytes()) + 16);
        signatureBytes.append(
            reinterpret_cast<const char*>(normalizedImage.constBits()),
            static_cast<qsizetype>(normalizedImage.sizeInBytes()));
        signatureBytes.append(themeColor.name(QColor::HexArgb).toUtf8());
        return QCryptographicHash::hash(
            signatureBytes,
            QCryptographicHash::Sha256);
    }

    // tintPixmap：
    // - 保留源图 alpha/轮廓；
    // - 通过 SourceIn 一次性把所有可见像素替换为当前主题色。
    QPixmap tintPixmap(const QPixmap& sourcePixmap, const QColor& themeColor)
    {
        if (sourcePixmap.isNull())
        {
            return QPixmap();
        }
        QPixmap tintedPixmapValue = sourcePixmap;
        tintedPixmapValue.fill(Qt::transparent);

        QPainter painter(&tintedPixmapValue);
        painter.setCompositionMode(QPainter::CompositionMode_Source);
        painter.drawPixmap(0, 0, sourcePixmap);
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(tintedPixmapValue.rect(), themeColor);
        painter.end();
        return tintedPixmapValue;
    }

    // iconRenderSizes：
    // - UI 常用尺寸集中预渲染，后续绘制不再触发 SVG 解析；
    // - 保留源位图声明的合理尺寸，并限制最大 96px 防止缓存膨胀。
    QList<QSize> iconRenderSizes(const QIcon& sourceIcon)
    {
        QList<QSize> renderSizes{
            QSize(16, 16),
            QSize(20, 20),
            QSize(24, 24),
            QSize(32, 32),
            QSize(48, 48),
            QSize(64, 64)
        };
        const QList<QSize> sourceSizes =
            sourceIcon.availableSizes(QIcon::Normal, QIcon::Off);
        for (const QSize& sourceSize : sourceSizes)
        {
            if (sourceSize.isValid() &&
                sourceSize.width() <= 96 &&
                sourceSize.height() <= 96 &&
                !renderSizes.contains(sourceSize))
            {
                renderSizes.push_back(sourceSize);
            }
        }
        std::sort(
            renderSizes.begin(),
            renderSizes.end(),
            [](const QSize& leftSize, const QSize& rightSize)
            {
                return leftSize.width() * leftSize.height() <
                    rightSize.width() * rightSize.height();
            });
        return renderSizes;
    }

    // originalIconFromProperty：
    // - 首次处理时把当前图标保存到 QObject 动态属性；
    // - 后续改色始终从原始图标生成，避免重复着色和清晰度损失。
    QIcon originalIconFromProperty(
        QObject* ownerObject,
        const char* propertyName,
        const char* lastAppliedKeyPropertyName,
        const QIcon& currentIcon)
    {
        if (ownerObject == nullptr)
        {
            return currentIcon;
        }
        const QVariant lastAppliedKeyValue =
            ownerObject->property(lastAppliedKeyPropertyName);
        bool lastAppliedKeyValid = false;
        const qulonglong lastAppliedKey =
            lastAppliedKeyValue.toULongLong(&lastAppliedKeyValid);
        // 外部主题刷新若在两轮集中处理之间替换了图标，当前值就是新的正确基线。
        // 只有当前图标仍是管理器上轮写入值时，才继续复用原始属性。
        if (lastAppliedKeyValid &&
            static_cast<qulonglong>(currentIcon.cacheKey()) != lastAppliedKey)
        {
            ownerObject->setProperty(
                propertyName,
                QVariant::fromValue(currentIcon));
            return currentIcon;
        }
        const QVariant storedValue = ownerObject->property(propertyName);
        if (storedValue.isValid() && storedValue.canConvert<QIcon>())
        {
            return storedValue.value<QIcon>();
        }
        ownerObject->setProperty(propertyName, QVariant::fromValue(currentIcon));
        return currentIcon;
    }

    // rememberAppliedIconKey：
    // - 记录管理器最后一次写入的图标身份；
    // - 下一轮可据此区分“仍是管理器着色结果”和“控件自行刷新了新图标”。
    void rememberAppliedIconKey(
        QObject* ownerObject,
        const char* propertyName,
        const QIcon& appliedIcon)
    {
        if (ownerObject == nullptr)
        {
            return;
        }
        ownerObject->setProperty(
            propertyName,
            QVariant::fromValue<qulonglong>(appliedIcon.cacheKey()));
    }

    // directWidgetActions：
    // - 合并控件关联的 actions() 与其直接拥有的 QAction；
    // - 禁止对每个控件递归 findChildren，避免启动期遍历退化为 O(N²)。
    QList<QAction*> directWidgetActions(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return {};
        }
        QList<QAction*> actionList = widgetPointer->actions();
        const QList<QAction*> ownedActionList =
            widgetPointer->findChildren<QAction*>(
                QString(),
                Qt::FindDirectChildrenOnly);
        for (QAction* actionPointer : ownedActionList)
        {
            if (actionPointer != nullptr &&
                !actionList.contains(actionPointer))
            {
                actionList.push_back(actionPointer);
            }
        }
        return actionList;
    }
}

ks::ui::SvgThemeIconManager& ks::ui::SvgThemeIconManager::instance()
{
    static SvgThemeIconManager manager;
    return manager;
}

ks::ui::SvgThemeIconApplyResult
ks::ui::SvgThemeIconManager::applyToApplication(
    QApplication* application,
    const QColor& themeColor,
    const bool isDefaultThemeColor,
    const std::function<void(int, int)>& progressCallback)
{
    SvgThemeIconApplyResult result;
    QElapsedTimer elapsedTimer;
    elapsedTimer.start();
    if (application == nullptr || !themeColor.isValid())
    {
        result.elapsedMilliseconds = elapsedTimer.elapsed();
        return result;
    }

    if (!m_filterInstalled)
    {
        application->installEventFilter(this);
        m_filterInstalled = true;
    }

    // 默认色首次启动时不扫描控件；从自定义色恢复默认时才遍历并还原原图。
    const bool restoreOriginalIcons =
        isDefaultThemeColor && m_customTintActive;
    if (isDefaultThemeColor && !restoreOriginalIcons)
    {
        m_customTintActive = false;
        result.skippedDefaultTheme = true;
        result.elapsedMilliseconds = elapsedTimer.elapsed();
        if (progressCallback)
        {
            progressCallback(0, 0);
        }
        return result;
    }

    // 缓存只服务当前强调色；切换颜色时释放旧色的多尺寸 pixmap，
    // 避免用户反复试色让进程生命周期内的图标缓存无界增长。
    if (m_themeColor.isValid() && m_themeColor != themeColor)
    {
        cachedTintedIcons().clear();
    }
    m_themeColor = themeColor;
    m_customTintActive = !isDefaultThemeColor;
    // allWidgets() 返回裸指针快照，而进度回调会处理事件；先全部包进 QPointer，
    // 防止回调期间的延迟销毁让后续遍历解引用悬空 QWidget。
    const QWidgetList currentWidgetList = application->allWidgets();
    QList<QPointer<QWidget>> widgetList;
    widgetList.reserve(currentWidgetList.size());
    for (QWidget* widgetPointer : currentWidgetList)
    {
        widgetList.push_back(QPointer<QWidget>(widgetPointer));
    }
    result.visitedWidgetCount = widgetList.size();
    QSet<QAction*> processedActions; // processedActions：避免同一动作被多个父控件重复处理。
    for (int widgetIndex = 0; widgetIndex < widgetList.size(); ++widgetIndex)
    {
        QWidget* widgetPointer = widgetList.at(widgetIndex).data();
        if (widgetPointer != nullptr)
        {
            result.recoloredIconCount +=
                applyToWidget(widgetPointer, &result.cacheHitCount);

            const QList<QAction*> actionList =
                directWidgetActions(widgetPointer);
            for (QAction* actionPointer : actionList)
            {
                if (actionPointer == nullptr || processedActions.contains(actionPointer))
                {
                    continue;
                }
                processedActions.insert(actionPointer);
                if (applyToAction(actionPointer, &result.cacheHitCount))
                {
                    ++result.recoloredIconCount;
                }
            }
        }

        if (progressCallback &&
            (((widgetIndex + 1) % 64) == 0 ||
             widgetIndex + 1 == widgetList.size()))
        {
            progressCallback(widgetIndex + 1, widgetList.size());
            QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        }
    }
    result.elapsedMilliseconds = elapsedTimer.elapsed();
    return result;
}

bool ks::ui::SvgThemeIconManager::eventFilter(
    QObject* watchedObject,
    QEvent* eventObject)
{
    if (!m_customTintActive ||
        watchedObject == nullptr ||
        eventObject == nullptr)
    {
        return QObject::eventFilter(watchedObject, eventObject);
    }

    // Polish 覆盖按需创建的页面；ActionAdded 覆盖运行期新建右键菜单。
    if (eventObject->type() == QEvent::Polish)
    {
        if (QWidget* widgetPointer = qobject_cast<QWidget*>(watchedObject))
        {
            int ignoredCacheHits = 0; // ignoredCacheHits：懒加载单控件不单独记录统计。
            (void)applyToWidget(widgetPointer, &ignoredCacheHits);
            const QList<QAction*> actionList =
                directWidgetActions(widgetPointer);
            for (QAction* actionPointer : actionList)
            {
                (void)applyToAction(actionPointer, &ignoredCacheHits);
            }
        }
    }
    else if (eventObject->type() == QEvent::ActionAdded)
    {
        auto* actionEvent = static_cast<QActionEvent*>(eventObject);
        int ignoredCacheHits = 0; // ignoredCacheHits：事件增量处理不计入批量报告。
        (void)applyToAction(actionEvent->action(), &ignoredCacheHits);
    }
    return QObject::eventFilter(watchedObject, eventObject);
}

int ks::ui::SvgThemeIconManager::applyToWidget(
    QWidget* widgetPointer,
    int* cacheHitCount)
{
    if (widgetPointer == nullptr)
    {
        return 0;
    }
    int changedCount = 0; // changedCount：当前控件替换或还原的图标槽位数量。

    if (auto* buttonPointer = qobject_cast<QAbstractButton*>(widgetPointer))
    {
        const QIcon currentIcon = buttonPointer->icon();
        if (!currentIcon.isNull())
        {
            const QIcon originalIcon = originalIconFromProperty(
                buttonPointer,
                OriginalButtonIconProperty,
                LastButtonIconKeyProperty,
                currentIcon);
            if (!m_customTintActive)
            {
                buttonPointer->setIcon(originalIcon);
                rememberAppliedIconKey(
                    buttonPointer,
                    LastButtonIconKeyProperty,
                    originalIcon);
                ++changedCount;
            }
            else
            {
                bool cacheHit = false;
                const QIcon replacementIcon = themedIcon(originalIcon, &cacheHit);
                if (!replacementIcon.isNull())
                {
                    buttonPointer->setIcon(replacementIcon);
                    rememberAppliedIconKey(
                        buttonPointer,
                        LastButtonIconKeyProperty,
                        replacementIcon);
                    ++changedCount;
                    if (cacheHit && cacheHitCount != nullptr)
                    {
                        ++(*cacheHitCount);
                    }
                }
            }
        }
    }

    if (auto* tabWidgetPointer = qobject_cast<QTabWidget*>(widgetPointer))
    {
        changedCount += applyToTabWidget(tabWidgetPointer, cacheHitCount);
    }

    // Dock/面板图标也可能来自 SVG；顶层主窗口图标通常为多色资源，会被候选检测排除。
    const QIcon currentWindowIcon = widgetPointer->windowIcon();
    if (widgetPointer->isWindow() && !currentWindowIcon.isNull())
    {
        const QIcon originalWindowIcon = originalIconFromProperty(
            widgetPointer,
            OriginalWindowIconProperty,
            LastWindowIconKeyProperty,
            currentWindowIcon);
        if (!m_customTintActive)
        {
            widgetPointer->setWindowIcon(originalWindowIcon);
            rememberAppliedIconKey(
                widgetPointer,
                LastWindowIconKeyProperty,
                originalWindowIcon);
            ++changedCount;
        }
        else
        {
            bool cacheHit = false;
            const QIcon replacementIcon =
                themedIcon(originalWindowIcon, &cacheHit);
            if (!replacementIcon.isNull())
            {
                widgetPointer->setWindowIcon(replacementIcon);
                rememberAppliedIconKey(
                    widgetPointer,
                    LastWindowIconKeyProperty,
                    replacementIcon);
                ++changedCount;
                if (cacheHit && cacheHitCount != nullptr)
                {
                    ++(*cacheHitCount);
                }
            }
        }
    }
    return changedCount;
}

bool ks::ui::SvgThemeIconManager::applyToAction(
    QAction* actionPointer,
    int* cacheHitCount)
{
    if (actionPointer == nullptr || actionPointer->icon().isNull())
    {
        return false;
    }
    const QIcon originalIcon = originalIconFromProperty(
        actionPointer,
        OriginalActionIconProperty,
        LastActionIconKeyProperty,
        actionPointer->icon());
    if (!m_customTintActive)
    {
        actionPointer->setIcon(originalIcon);
        rememberAppliedIconKey(
            actionPointer,
            LastActionIconKeyProperty,
            originalIcon);
        return true;
    }

    bool cacheHit = false;
    const QIcon replacementIcon = themedIcon(originalIcon, &cacheHit);
    if (replacementIcon.isNull())
    {
        return false;
    }
    actionPointer->setIcon(replacementIcon);
    rememberAppliedIconKey(
        actionPointer,
        LastActionIconKeyProperty,
        replacementIcon);
    if (cacheHit && cacheHitCount != nullptr)
    {
        ++(*cacheHitCount);
    }
    return true;
}

int ks::ui::SvgThemeIconManager::applyToTabWidget(
    QTabWidget* tabWidgetPointer,
    int* cacheHitCount)
{
    if (tabWidgetPointer == nullptr)
    {
        return 0;
    }
    int changedCount = 0; // changedCount：当前 QTabWidget 实际处理的标签数量。
    for (int tabIndex = 0; tabIndex < tabWidgetPointer->count(); ++tabIndex)
    {
        QWidget* pagePointer = tabWidgetPointer->widget(tabIndex);
        const QIcon currentIcon = tabWidgetPointer->tabIcon(tabIndex);
        if (pagePointer == nullptr || currentIcon.isNull())
        {
            continue;
        }
        const QIcon originalIcon = originalIconFromProperty(
            pagePointer,
            OriginalTabIconProperty,
            LastTabIconKeyProperty,
            currentIcon);
        if (!m_customTintActive)
        {
            tabWidgetPointer->setTabIcon(tabIndex, originalIcon);
            rememberAppliedIconKey(
                pagePointer,
                LastTabIconKeyProperty,
                originalIcon);
            ++changedCount;
            continue;
        }

        bool cacheHit = false;
        const QIcon replacementIcon = themedIcon(originalIcon, &cacheHit);
        if (replacementIcon.isNull())
        {
            continue;
        }
        tabWidgetPointer->setTabIcon(tabIndex, replacementIcon);
        rememberAppliedIconKey(
            pagePointer,
            LastTabIconKeyProperty,
            replacementIcon);
        ++changedCount;
        if (cacheHit && cacheHitCount != nullptr)
        {
            ++(*cacheHitCount);
        }
    }
    return changedCount;
}

QIcon ks::ui::SvgThemeIconManager::themedIcon(
    const QIcon& sourceIcon,
    bool* cacheHitOut)
{
    if (cacheHitOut != nullptr)
    {
        *cacheHitOut = false;
    }
    const QImage normalizedImage = normalizedIconImage(sourceIcon);
    if (!isThemeTintCandidate(sourceIcon, normalizedImage))
    {
        return QIcon();
    }

    const QByteArray cacheKey = iconCacheKey(normalizedImage, m_themeColor);
    const auto cachedIterator = cachedTintedIcons().constFind(cacheKey);
    if (cachedIterator != cachedTintedIcons().constEnd())
    {
        if (cacheHitOut != nullptr)
        {
            *cacheHitOut = true;
        }
        return cachedIterator.value();
    }

    QIcon replacementIcon; // replacementIcon：包含常用尺寸的最终主题图标。
    const QList<QSize> renderSizes = iconRenderSizes(sourceIcon);
    for (const QSize& renderSize : renderSizes)
    {
        const QPixmap sourcePixmap =
            sourceIcon.pixmap(renderSize, QIcon::Normal, QIcon::Off);
        const QPixmap tintedPixmapValue =
            tintPixmap(sourcePixmap, m_themeColor);
        if (!tintedPixmapValue.isNull())
        {
            replacementIcon.addPixmap(
                tintedPixmapValue,
                QIcon::Normal,
                QIcon::Off);
        }
    }
    if (!replacementIcon.isNull())
    {
        cachedTintedIcons().insert(cacheKey, replacementIcon);
    }
    return replacementIcon;
}
