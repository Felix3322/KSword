#include "SmoothScrollSupport.h"

#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QApplication>
#include <QEasingCurve>
#include <QEvent>
#include <QHash>
#include <QPointer>
#include <QPropertyAnimation>
#include <QScrollBar>
#include <QVariant>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    constexpr char kInstalledProperty[] = "KSWORD_SMOOTH_SCROLL_SUPPORT_INSTALLED";
    constexpr char kEnabledProperty[] = "ksword_smooth_scrolling_enabled";
    constexpr char kOriginalVerticalModeProperty[] =
        "KSWORD_SMOOTH_SCROLL_ORIGINAL_VERTICAL_MODE";
    constexpr char kOriginalHorizontalModeProperty[] =
        "KSWORD_SMOOTH_SCROLL_ORIGINAL_HORIZONTAL_MODE";
    constexpr char kFrozenPaneAuxiliaryProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr int kWheelAnimationDurationMs = 180;
    constexpr int kPixelAnimationDurationMs = 100;

    class GlobalSmoothScrollFilter;
    QPointer<GlobalSmoothScrollFilter> g_installedFilter;

    class GlobalSmoothScrollFilter final : public QObject
    {
    public:
        explicit GlobalSmoothScrollFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        void applyEnabledStateToAllWidgets(const bool enabled)
        {
            const QWidgetList widgetList = QApplication::allWidgets();
            for (QWidget* widget : widgetList)
            {
                QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(widget);
                if (scrollArea != nullptr &&
                    !scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
                {
                    configureScrollArea(scrollArea, enabled);
                }
            }
            // 冻结覆盖视图必须在主表切换完滚动模式后再同步，防止关闭平滑滚动时单位不一致。
            for (QWidget* widget : widgetList)
            {
                QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(widget);
                if (scrollArea != nullptr &&
                    scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
                {
                    configureScrollArea(scrollArea, enabled);
                }
            }
            if (!enabled)
            {
                stopAllAnimations();
            }
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() == QEvent::Show ||
                eventObject->type() == QEvent::Polish)
            {
                if (QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(watchedObject))
                {
                    configureScrollArea(scrollArea, enabled());
                }
            }

            if (eventObject->type() != QEvent::Wheel || !enabled())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QAbstractScrollArea* scrollArea = scrollAreaForEventObject(watchedObject);
            if (scrollArea == nullptr ||
                scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            auto* wheelEvent = static_cast<QWheelEvent*>(eventObject);
            if (wheelEvent->modifiers().testFlag(Qt::ControlModifier) ||
                wheelEvent->modifiers().testFlag(Qt::AltModifier))
            {
                // 保留 Ctrl+滚轮缩放和业务自定义 Alt+滚轮行为。
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QPoint pixelDelta = wheelEvent->pixelDelta();
            const QPoint angleDelta = wheelEvent->angleDelta();
            const bool horizontal =
                wheelEvent->modifiers().testFlag(Qt::ShiftModifier) ||
                std::abs(pixelDelta.x()) > std::abs(pixelDelta.y()) ||
                std::abs(angleDelta.x()) > std::abs(angleDelta.y());
            QScrollBar* scrollBar = horizontal
                ? scrollArea->horizontalScrollBar()
                : scrollArea->verticalScrollBar();
            if (scrollBar == nullptr || scrollBar->minimum() == scrollBar->maximum())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const int rawPixelDelta = horizontal
                ? (pixelDelta.x() != 0 ? pixelDelta.x() : pixelDelta.y())
                : (pixelDelta.y() != 0 ? pixelDelta.y() : pixelDelta.x());
            const int rawAngleDelta = horizontal
                ? (angleDelta.x() != 0 ? angleDelta.x() : angleDelta.y())
                : (angleDelta.y() != 0 ? angleDelta.y() : angleDelta.x());
            if (rawPixelDelta == 0 && rawAngleDelta == 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const int directionMultiplier = wheelEvent->inverted() ? -1 : 1;
            int distance = 0;
            int durationMs = kWheelAnimationDurationMs;
            if (rawPixelDelta != 0)
            {
                distance = -rawPixelDelta * directionMultiplier;
                durationMs = kPixelAnimationDurationMs;
            }
            else
            {
                const double wheelSteps =
                    static_cast<double>(rawAngleDelta * directionMultiplier) / 120.0;
                const int pixelsPerStep = std::clamp(
                    scrollBar->singleStep() * 3,
                    48,
                    120);
                distance = static_cast<int>(std::lround(-wheelSteps * pixelsPerStep));
            }
            if (distance == 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QPropertyAnimation* animation = animationForScrollBar(scrollBar);
            const int accumulatedStart =
                animation->state() == QAbstractAnimation::Running
                ? animation->endValue().toInt()
                : scrollBar->value();
            const int targetValue = std::clamp(
                accumulatedStart + distance,
                scrollBar->minimum(),
                scrollBar->maximum());
            if (targetValue == scrollBar->value() &&
                animation->state() != QAbstractAnimation::Running)
            {
                // 到达边界时让未消费的滚轮事件继续向父滚动区域传播。
                return QObject::eventFilter(watchedObject, eventObject);
            }

            animation->stop();
            animation->setDuration(durationMs);
            animation->setStartValue(scrollBar->value());
            animation->setEndValue(targetValue);
            animation->setEasingCurve(QEasingCurve::OutCubic);
            animation->start();
            wheelEvent->accept();
            return true;
        }

    private:
        bool enabled() const
        {
            QApplication* appInstance =
                qobject_cast<QApplication*>(QCoreApplication::instance());
            return appInstance != nullptr &&
                appInstance->property(kEnabledProperty).toBool();
        }

        QAbstractScrollArea* scrollAreaForEventObject(QObject* watchedObject) const
        {
            if (QAbstractScrollArea* directArea =
                qobject_cast<QAbstractScrollArea*>(watchedObject))
            {
                return directArea;
            }
            QAbstractScrollArea* parentArea = qobject_cast<QAbstractScrollArea*>(
                watchedObject != nullptr ? watchedObject->parent() : nullptr);
            return parentArea != nullptr && parentArea->viewport() == watchedObject
                ? parentArea
                : nullptr;
        }

        void configureScrollArea(QAbstractScrollArea* scrollArea, const bool enabledState)
        {
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(scrollArea);
            if (itemView == nullptr)
            {
                return;
            }
            if (itemView->property(kFrozenPaneAuxiliaryProperty).toBool())
            {
                // 冻结窗格的偏移由 TableFrozenPaneController 按像素直接写入滚动条，
                // 跟随主表切到按整行滚动会让冻结区与主表错行，因此这里固定按像素。
                itemView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                itemView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                return;
            }

            if (enabledState)
            {
                if (!itemView->property(kOriginalVerticalModeProperty).isValid())
                {
                    itemView->setProperty(
                        kOriginalVerticalModeProperty,
                        static_cast<int>(itemView->verticalScrollMode()));
                    itemView->setProperty(
                        kOriginalHorizontalModeProperty,
                        static_cast<int>(itemView->horizontalScrollMode()));
                }
                itemView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                itemView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                return;
            }

            const QVariant originalVerticalMode =
                itemView->property(kOriginalVerticalModeProperty);
            const QVariant originalHorizontalMode =
                itemView->property(kOriginalHorizontalModeProperty);
            if (originalVerticalMode.isValid())
            {
                itemView->setVerticalScrollMode(
                    static_cast<QAbstractItemView::ScrollMode>(
                        originalVerticalMode.toInt()));
                itemView->setProperty(kOriginalVerticalModeProperty, QVariant());
            }
            if (originalHorizontalMode.isValid())
            {
                itemView->setHorizontalScrollMode(
                    static_cast<QAbstractItemView::ScrollMode>(
                        originalHorizontalMode.toInt()));
                itemView->setProperty(kOriginalHorizontalModeProperty, QVariant());
            }
        }

        QPropertyAnimation* animationForScrollBar(QScrollBar* scrollBar)
        {
            QPropertyAnimation* animation = m_animations.value(scrollBar, nullptr);
            if (animation != nullptr)
            {
                return animation;
            }

            animation = new QPropertyAnimation(scrollBar, "value", this);
            m_animations.insert(scrollBar, animation);
            connect(scrollBar, &QScrollBar::sliderPressed, animation, [animation]()
                {
                    animation->stop();
                });
            connect(scrollBar, &QObject::destroyed, this, [this, scrollBar]()
                {
                    if (QPropertyAnimation* removedAnimation =
                        m_animations.take(scrollBar))
                    {
                        removedAnimation->stop();
                        removedAnimation->deleteLater();
                    }
                });
            return animation;
        }

        void stopAllAnimations()
        {
            for (QPropertyAnimation* animation : std::as_const(m_animations))
            {
                if (animation != nullptr)
                {
                    animation->stop();
                }
            }
        }

        QHash<QScrollBar*, QPropertyAnimation*> m_animations;
    };

    GlobalSmoothScrollFilter* installedFilter()
    {
        return g_installedFilter.data();
    }
}

void ks::ui::InstallGlobalSmoothScrollSupport(QApplication* appInstance)
{
    if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
    {
        return;
    }

    auto* filter = new GlobalSmoothScrollFilter(appInstance);
    filter->setObjectName(QStringLiteral("KSWORD_GLOBAL_SMOOTH_SCROLL_FILTER"));
    g_installedFilter = filter;
    appInstance->installEventFilter(filter);
    appInstance->setProperty(kInstalledProperty, true);
    filter->applyEnabledStateToAllWidgets(
        appInstance->property(kEnabledProperty).toBool());
}

void ks::ui::SetGlobalSmoothScrollingEnabled(const bool enabled)
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        return;
    }
    appInstance->setProperty(kEnabledProperty, enabled);
    if (GlobalSmoothScrollFilter* filter = installedFilter())
    {
        filter->applyEnabledStateToAllWidgets(enabled);
    }
}

bool ks::ui::IsGlobalSmoothScrollingEnabled()
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    return appInstance != nullptr &&
        appInstance->property(kEnabledProperty).toBool();
}
