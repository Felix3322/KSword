#include "GlobalUiSearch.h"

#include "../include/ads/DockWidget.h"
#include "../theme.h"

#include <QAbstractButton>
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QComboBox>
#include <QEvent>
#include <QFrame>
#include <QGroupBox>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollArea>
#include <QPen>
#include <QSet>
#include <QStackedWidget>
#include <QStyleOption>
#include <QStyledItemDelegate>
#include <QTabWidget>
#include <QTableView>
#include <QTextDocument>
#include <QTextDocumentFragment>
#include <QTextOption>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>
#include <QVariantAnimation>

#include <algorithm>
#include <cmath>

namespace
{
    // 搜索与展示参数：
    // - kSearchDebounceIntervalMs：输入防抖间隔；
    // - kMaxHitsPerDock：单个 Dock 允许贡献的命中上限，避免单页刷屏；
    // - kMaxTotalHits：结果总量上限；
    // - kMaxVisibleResultRows：弹层一次最多完整展示的行数（超出滚动）；
    // - kResultItemHeight：结果行固定高度（两行：匹配文本 + 页面路径）；
    // - kSnippetMaxLength：匹配文本展示片段的最大字符数；
    // - kSnippetMatchLeadin：片段截取时命中位置前保留的字符数；
    // - kComboBoxItemScanLimit：下拉框条目参与索引的数量上限；
    // - kHeaderColumnScanLimit：表头列参与索引的数量上限；
    // - kFlashDelayMs：Dock 置前后到点亮高亮之间的布局稳定等待；
    // - kResultHtmlRole：列表项富文本内容的自定义数据角色。
    constexpr int kSearchDebounceIntervalMs = 220;
    constexpr int kMaxHitsPerDock = 24;
    constexpr int kMaxTotalHits = 96;
    constexpr int kMaxVisibleResultRows = 8;
    constexpr int kResultItemHeight = 46;
    constexpr int kSnippetMaxLength = 60;
    constexpr int kSnippetMatchLeadin = 18;
    constexpr int kComboBoxItemScanLimit = 60;
    constexpr int kHeaderColumnScanLimit = 80;
    constexpr int kFlashDelayMs = 140;
    constexpr int kResultHtmlRole = Qt::UserRole + 41;

    // normalizeUiText：
    // - 作用：把控件原始文本压成适合匹配与单行展示的纯文本；
    // - 处理：富文本转纯文本、换行/制表符归并为空格、去首尾空白；
    // - 传入 rawText：控件读取到的原始文本；
    // - 传出：规范化后的单行文本。
    QString normalizeUiText(QString rawText)
    {
        if (rawText.contains(QLatin1Char('<')) && Qt::mightBeRichText(rawText))
        {
            rawText = QTextDocumentFragment::fromHtml(rawText).toPlainText();
        }
        rawText.replace(QLatin1Char('\n'), QLatin1Char(' '));
        rawText.replace(QLatin1Char('\r'), QLatin1Char(' '));
        rawText.replace(QLatin1Char('\t'), QLatin1Char(' '));
        return rawText.simplified();
    }

    // stripMnemonicMarkers：
    // - 作用：去掉按钮/页签文本中的 '&' 助记符标记（'&&' 保留为单个 '&'）；
    // - 传入 sourceText：可能带助记符的文本；
    // - 传出：展示用文本。
    QString stripMnemonicMarkers(const QString& sourceText)
    {
        QString strippedText;
        strippedText.reserve(sourceText.size());
        for (int charIndex = 0; charIndex < sourceText.size(); ++charIndex)
        {
            const QChar currentChar = sourceText.at(charIndex);
            if (currentChar == QLatin1Char('&'))
            {
                if (charIndex + 1 < sourceText.size() && sourceText.at(charIndex + 1) == QLatin1Char('&'))
                {
                    strippedText.append(QLatin1Char('&'));
                    ++charIndex;
                }
                continue;
            }
            strippedText.append(currentChar);
        }
        return strippedText;
    }

    // isWidgetChainRevealable：
    // - 作用：判断目标控件是否能通过“切换页签”被真实展示出来；
    // - 规则：向上遍历到所属 Dock 为止，任何被显式隐藏、且其父不是
    //   QStackedWidget（页签导航性质隐藏）的祖先都视为不可揭示；
    // - 传入 targetWidget：候选命中控件；
    // - 传出：true=激活结果后可见，false=永远展示不出来（不收录）。
    bool isWidgetChainRevealable(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                return true;
            }
            if (cursorWidget->isHidden()
                && qobject_cast<QStackedWidget*>(cursorWidget->parentWidget()) == nullptr)
            {
                return false;
            }
        }
        return true;
    }

    // resolveMatchRank：
    // - 作用：计算命中排序权重；
    // - 规则：0=整串相等（忽略大小写），1=前缀命中，2=普通包含；
    // - 传入 normalizedText：命中文本；queryText：查询；matchIndex：首个命中位置。
    int resolveMatchRank(const QString& normalizedText, const QString& queryText, const int matchIndex)
    {
        if (normalizedText.compare(queryText, Qt::CaseInsensitive) == 0)
        {
            return 0;
        }
        return matchIndex == 0 ? 1 : 2;
    }

    // buildPagePathText：
    // - 作用：生成“Dock 标题 › 内部页签 › 分组框”形式的页面路径；
    // - 处理：从目标控件向上收集 QTabWidget/QStackedWidget 页名与
    //   QGroupBox 标题（目标自身标题不重复计入），由外到内拼接；
    // - 传入 dockWidget：所属 Dock；dockTitleText：Dock 标题；targetWidget：命中控件；
    // - 传出：页面路径文本。
    QString buildPagePathText(
        const ads::CDockWidget* dockWidget,
        const QString& dockTitleText,
        QWidget* targetWidget)
    {
        QStringList innerPathParts;
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (cursorWidget == dockWidget)
            {
                break;
            }

            QWidget* parentWidget = cursorWidget->parentWidget();
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int tabIndex = tabWidget->indexOf(cursorWidget);
                    if (tabIndex >= 0)
                    {
                        const QString tabText =
                            normalizeUiText(stripMnemonicMarkers(tabWidget->tabText(tabIndex)));
                        if (!tabText.isEmpty())
                        {
                            innerPathParts.prepend(tabText);
                        }
                    }
                }
            }

            if (cursorWidget != targetWidget)
            {
                if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(cursorWidget))
                {
                    const QString groupTitleText = normalizeUiText(groupBox->title());
                    if (!groupTitleText.isEmpty())
                    {
                        innerPathParts.prepend(groupTitleText);
                    }
                }
            }
        }

        QStringList fullPathParts;
        fullPathParts << dockTitleText;
        fullPathParts << innerPathParts;
        fullPathParts.removeAll(QString());
        return fullPathParts.join(QStringLiteral(" › "));
    }

    // collectDockSearchHits：
    // - 作用：在单个 Dock 的控件树内做关键词匹配并追加命中；
    // - 索引来源：QLabel 文本、按钮文本、分组框标题、QTabWidget 页签、
    //   下拉框条目、输入框占位符、表格/树视图水平表头；
    // - 传入 dockWidget：目标 Dock；queryText：查询；outHitList：命中输出；
    // - 传出：无返回值，命中追加到 outHitList（受单页上限约束）。
    void collectDockSearchHits(
        ads::CDockWidget* dockWidget,
        const QString& queryText,
        QVector<ks::ui::UiSearchHit>& outHitList)
    {
        QWidget* contentWidget = dockWidget->widget();
        if (contentWidget == nullptr)
        {
            return;
        }

        const QString dockTitleText = normalizeUiText(dockWidget->windowTitle());
        QSet<QString> dedupKeySet;
        int dockHitCount = 0;

        const auto tryAppendHit = [&](QWidget* targetWidget, const QString& rawText)
        {
            if (dockHitCount >= kMaxHitsPerDock || targetWidget == nullptr)
            {
                return;
            }
            const QString normalizedText = normalizeUiText(rawText);
            if (normalizedText.isEmpty())
            {
                return;
            }
            const int matchIndex = normalizedText.indexOf(queryText, 0, Qt::CaseInsensitive);
            if (matchIndex < 0)
            {
                return;
            }
            if (!isWidgetChainRevealable(targetWidget))
            {
                return;
            }
            const QString dedupKey =
                QString::number(reinterpret_cast<quintptr>(targetWidget), 16)
                + QLatin1Char('\x1f')
                + normalizedText;
            if (dedupKeySet.contains(dedupKey))
            {
                return;
            }
            dedupKeySet.insert(dedupKey);

            ks::ui::UiSearchHit hitEntry;
            hitEntry.pageDockWidget = dockWidget;
            hitEntry.targetWidget = targetWidget;
            hitEntry.matchedText = normalizedText;
            hitEntry.pagePathText = buildPagePathText(dockWidget, dockTitleText, targetWidget);
            hitEntry.matchRank = resolveMatchRank(normalizedText, queryText, matchIndex);
            outHitList.push_back(hitEntry);
            ++dockHitCount;
        };

        QList<QWidget*> candidateWidgetList = contentWidget->findChildren<QWidget*>();
        candidateWidgetList.prepend(contentWidget);
        for (QWidget* candidateWidget : candidateWidgetList)
        {
            if (candidateWidget == nullptr || candidateWidget->isWindow())
            {
                // 独立顶层窗口（下拉弹层、内嵌对话框等）不属于页面内容。
                continue;
            }

            if (QLabel* labelWidget = qobject_cast<QLabel*>(candidateWidget))
            {
                tryAppendHit(labelWidget, labelWidget->text());
            }
            else if (QAbstractButton* buttonWidget = qobject_cast<QAbstractButton*>(candidateWidget))
            {
                tryAppendHit(buttonWidget, stripMnemonicMarkers(buttonWidget->text()));
            }
            else if (QGroupBox* groupBoxWidget = qobject_cast<QGroupBox*>(candidateWidget))
            {
                tryAppendHit(groupBoxWidget, groupBoxWidget->title());
            }
            else if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(candidateWidget))
            {
                for (int tabIndex = 0; tabIndex < tabWidget->count(); ++tabIndex)
                {
                    tryAppendHit(
                        tabWidget->widget(tabIndex),
                        stripMnemonicMarkers(tabWidget->tabText(tabIndex)));
                }
            }
            else if (QComboBox* comboBoxWidget = qobject_cast<QComboBox*>(candidateWidget))
            {
                if (comboBoxWidget->count() <= kComboBoxItemScanLimit)
                {
                    for (int itemIndex = 0; itemIndex < comboBoxWidget->count(); ++itemIndex)
                    {
                        tryAppendHit(comboBoxWidget, comboBoxWidget->itemText(itemIndex));
                    }
                }
            }
            else if (QLineEdit* lineEditWidget = qobject_cast<QLineEdit*>(candidateWidget))
            {
                tryAppendHit(lineEditWidget, lineEditWidget->placeholderText());
            }
            else if (QAbstractItemView* itemViewWidget = qobject_cast<QAbstractItemView*>(candidateWidget))
            {
                // 只索引带水平表头的视图列头；单元格数据随刷新变化不参与搜索。
                const bool hasHorizontalHeader =
                    qobject_cast<QTableView*>(itemViewWidget) != nullptr
                    || qobject_cast<QTreeView*>(itemViewWidget) != nullptr;
                QAbstractItemModel* itemModel = itemViewWidget->model();
                if (hasHorizontalHeader && itemModel != nullptr)
                {
                    const int columnCount = std::min(itemModel->columnCount(), kHeaderColumnScanLimit);
                    for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
                    {
                        tryAppendHit(
                            itemViewWidget,
                            itemModel->headerData(columnIndex, Qt::Horizontal, Qt::DisplayRole).toString());
                    }
                }
            }

            if (dockHitCount >= kMaxHitsPerDock)
            {
                break;
            }
        }
    }

    // scrollAncestorsToWidget：
    // - 作用：让目标控件所有 QScrollArea 祖先滚动到目标可见位置；
    // - 传入 targetWidget：要露出的控件。
    void scrollAncestorsToWidget(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                break;
            }
            if (cursorWidget == targetWidget)
            {
                continue;
            }
            if (QScrollArea* scrollAreaWidget = qobject_cast<QScrollArea*>(cursorWidget))
            {
                scrollAreaWidget->ensureWidgetVisible(targetWidget, 48, 48);
            }
        }
    }

    // revealHitTargetWithinPage：
    // - 作用：在目标 Dock 内部逐层把目标控件揭示出来；
    // - 处理：向上遍历，命中 QTabWidget/QStackedWidget 页时切换到
    //   目标所在页，最后让滚动区域滚动到目标；
    // - 传入 targetWidget：命中控件。
    void revealHitTargetWithinPage(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                break;
            }
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (parentWidget == nullptr)
            {
                break;
            }
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int tabIndex = tabWidget->indexOf(cursorWidget);
                    if (tabIndex >= 0 && tabWidget->currentIndex() != tabIndex)
                    {
                        tabWidget->setCurrentIndex(tabIndex);
                    }
                }
                else
                {
                    const int stackIndex = stackedWidget->indexOf(cursorWidget);
                    if (stackIndex >= 0 && stackedWidget->currentIndex() != stackIndex)
                    {
                        stackedWidget->setCurrentIndex(stackIndex);
                    }
                }
            }
        }

        scrollAncestorsToWidget(targetWidget);
    }

    // buildSnippetHtml：
    // - 作用：把命中文本裁剪成展示片段并给命中的查询子串上强调色；
    // - 传入 matchedText：完整命中文本；queryText：查询；accentColorHex：强调色；
    // - 传出：转义后的 HTML 片段（含省略号标记）。
    QString buildSnippetHtml(
        const QString& matchedText,
        const QString& queryText,
        const QString& accentColorHex)
    {
        const int matchedLength = static_cast<int>(matchedText.size());
        const int firstMatchIndex = static_cast<int>(
            matchedText.indexOf(queryText, 0, Qt::CaseInsensitive));
        QString snippetText = matchedText;
        bool clippedHead = false;
        bool clippedTail = false;
        if (matchedLength > kSnippetMaxLength)
        {
            int snippetStart = 0;
            if (firstMatchIndex > kSnippetMatchLeadin)
            {
                snippetStart = std::min(
                    firstMatchIndex - kSnippetMatchLeadin,
                    matchedLength - kSnippetMaxLength);
            }
            snippetText = matchedText.mid(snippetStart, kSnippetMaxLength);
            clippedHead = snippetStart > 0;
            clippedTail = (snippetStart + kSnippetMaxLength) < matchedLength;
        }

        QString htmlText;
        int cursorIndex = 0;
        while (cursorIndex <= snippetText.size())
        {
            const int matchIndex = queryText.isEmpty()
                ? -1
                : snippetText.indexOf(queryText, cursorIndex, Qt::CaseInsensitive);
            if (matchIndex < 0)
            {
                htmlText += snippetText.mid(cursorIndex).toHtmlEscaped();
                break;
            }
            htmlText += snippetText.mid(cursorIndex, matchIndex - cursorIndex).toHtmlEscaped();
            htmlText += QStringLiteral("<span style=\"color:%1;font-weight:600;\">").arg(accentColorHex);
            htmlText += snippetText.mid(matchIndex, queryText.size()).toHtmlEscaped();
            htmlText += QStringLiteral("</span>");
            cursorIndex = matchIndex + queryText.size();
        }

        if (clippedHead)
        {
            htmlText.prepend(QStringLiteral("…"));
        }
        if (clippedTail)
        {
            htmlText.append(QStringLiteral("…"));
        }
        return htmlText;
    }

    // ============================================================
    // SearchResultItemDelegate
    // 说明：
    // - 结果行绘制委托：第一行匹配文本（命中子串强调色加粗），
    //   第二行页面路径（次级色小字号）；
    // - 选中/悬停行画主题强调色半透明圆角底。
    // ============================================================
    class SearchResultItemDelegate final : public QStyledItemDelegate
    {
    public:
        using QStyledItemDelegate::QStyledItemDelegate;

        void paint(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);

            const QRect itemRect = option.rect.adjusted(4, 2, -4, -2);
            const bool selectedState = option.state.testFlag(QStyle::State_Selected);
            const bool hoveredState = option.state.testFlag(QStyle::State_MouseOver);
            if (selectedState || hoveredState)
            {
                QColor rowBackgroundColor = KswordTheme::PrimaryAccentColor();
                rowBackgroundColor.setAlpha(selectedState ? 52 : 26);
                painter->setPen(Qt::NoPen);
                painter->setBrush(rowBackgroundColor);
                painter->drawRoundedRect(itemRect, 4, 4);
            }

            QTextDocument contentDocument;
            contentDocument.setDefaultFont(option.font);
            QTextOption noWrapOption = contentDocument.defaultTextOption();
            noWrapOption.setWrapMode(QTextOption::NoWrap);
            contentDocument.setDefaultTextOption(noWrapOption);
            contentDocument.setDocumentMargin(0.0);
            contentDocument.setHtml(index.data(kResultHtmlRole).toString());

            painter->translate(itemRect.left() + 8, itemRect.top() + 4);
            contentDocument.drawContents(
                painter,
                QRectF(0, 0, itemRect.width() - 16, itemRect.height() - 8));
            painter->restore();
        }

        QSize sizeHint(
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            Q_UNUSED(option);
            Q_UNUSED(index);
            return QSize(200, kResultItemHeight);
        }
    };

    // ============================================================
    // SearchHitFlashOverlay
    // 说明：
    // - 覆盖在命中控件上的临时高亮层：主题强调色圆角描边+浅填充，
    //   按正弦脉冲闪烁三次后自毁；
    // - 作为目标控件子控件随目标缩放，鼠标事件全透传。
    // ============================================================
    class SearchHitFlashOverlay final : public QWidget
    {
    public:
        // flashOnWidget：
        // - 作用：在目标控件上点亮一次搜索高亮（旧高亮先移除）；
        // - 传入 targetWidget：要高亮的控件。
        static void flashOnWidget(QWidget* targetWidget)
        {
            if (targetWidget == nullptr)
            {
                return;
            }
            if (QWidget* previousOverlay = targetWidget->findChild<QWidget*>(
                    QStringLiteral("ksSearchHitFlashOverlay"),
                    Qt::FindDirectChildrenOnly))
            {
                previousOverlay->deleteLater();
            }
            auto* overlayWidget = new SearchHitFlashOverlay(targetWidget);
            overlayWidget->show();
            overlayWidget->raise();
        }

        explicit SearchHitFlashOverlay(QWidget* targetWidget)
            : QWidget(targetWidget)
            , m_targetWidget(targetWidget)
        {
            setObjectName(QStringLiteral("ksSearchHitFlashOverlay"));
            setAttribute(Qt::WA_TransparentForMouseEvents, true);
            setAttribute(Qt::WA_NoSystemBackground, true);
            setGeometry(targetWidget->rect());
            targetWidget->installEventFilter(this);

            // kFlashPulseCount 用途：完整脉冲次数；动画值 0..N，小数部分驱动单次脉冲相位。
            constexpr double kFlashPulseCount = 3.0;
            auto* pulseAnimation = new QVariantAnimation(this);
            pulseAnimation->setStartValue(0.0);
            pulseAnimation->setEndValue(kFlashPulseCount);
            pulseAnimation->setDuration(1800);
            connect(pulseAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& animationValue) {
                const double phaseValue = animationValue.toDouble();
                const double pulseFraction = phaseValue - std::floor(phaseValue);
                // envelopeFactor 用途：整体强度随时间轻微衰减，结束前自然淡出。
                const double envelopeFactor = 1.0 - (phaseValue / 3.0) * 0.35;
                m_pulseIntensity = std::sin(pulseFraction * 3.14159265358979323846) * envelopeFactor;
                update();
            });
            connect(pulseAnimation, &QVariantAnimation::finished, this, [this]() {
                deleteLater();
            });
            pulseAnimation->start();
        }

    protected:
        void paintEvent(QPaintEvent* paintEventPointer) override
        {
            Q_UNUSED(paintEventPointer);
            if (m_pulseIntensity <= 0.0)
            {
                return;
            }

            QPainter overlayPainter(this);
            overlayPainter.setRenderHint(QPainter::Antialiasing, true);

            QColor accentColor = KswordTheme::PrimaryAccentColor();
            QColor borderColor = accentColor;
            borderColor.setAlpha(static_cast<int>(210.0 * m_pulseIntensity));
            QColor fillColor = accentColor;
            fillColor.setAlpha(static_cast<int>(42.0 * m_pulseIntensity));

            QPen borderPen(borderColor);
            borderPen.setWidthF(2.0);
            overlayPainter.setPen(borderPen);
            overlayPainter.setBrush(fillColor);
            overlayPainter.drawRoundedRect(
                QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5),
                4.0,
                4.0);
        }

        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == m_targetWidget)
            {
                if (eventObject->type() == QEvent::Resize)
                {
                    setGeometry(m_targetWidget->rect());
                }
                else if (eventObject->type() == QEvent::Hide
                    || eventObject->type() == QEvent::Destroy)
                {
                    deleteLater();
                }
            }
            return QWidget::eventFilter(watchedObject, eventObject);
        }

    private:
        QPointer<QWidget> m_targetWidget;  // m_targetWidget：被高亮的目标控件。
        double m_pulseIntensity = 0.0;     // m_pulseIntensity：当前脉冲强度（0..1）。
    };

    // widgetBelongsToBranch：
    // - 作用：判断控件是否位于指定祖先分支内（含祖先本身）；
    // - 传入 widgetObject：命中控件；expectedAncestor：期望祖先；
    // - 传出：true=属于该分支。
    bool widgetBelongsToBranch(const QWidget* widgetObject, const QWidget* expectedAncestor)
    {
        if (widgetObject == nullptr || expectedAncestor == nullptr)
        {
            return false;
        }
        for (const QWidget* cursorWidget = widgetObject;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (cursorWidget == expectedAncestor)
            {
                return true;
            }
        }
        return false;
    }
}

namespace ks::ui
{
    GlobalUiSearchController::GlobalUiSearchController(
        QWidget* popupHostWindow,
        QLineEdit* searchInputEdit,
        QWidget* popupAnchorWidget,
        QObject* parentObject)
        : QObject(parentObject)
        , m_popupHostWindow(popupHostWindow)
        , m_searchInputEdit(searchInputEdit)
        , m_popupAnchorWidget(popupAnchorWidget)
    {
        m_searchDebounceTimer = new QTimer(this);
        m_searchDebounceTimer->setSingleShot(true);
        m_searchDebounceTimer->setInterval(kSearchDebounceIntervalMs);
        connect(m_searchDebounceTimer, &QTimer::timeout, this, [this]() {
            runSearchNow();
        });

        if (m_searchInputEdit != nullptr)
        {
            m_searchInputEdit->installEventFilter(this);
        }
        if (m_popupHostWindow != nullptr)
        {
            m_popupHostWindow->installEventFilter(this);
        }
        if (qApp != nullptr)
        {
            // 应用级过滤只用于“点击弹层外区域收起”，弹层隐藏时直接透传。
            qApp->installEventFilter(this);
        }
    }

    void GlobalUiSearchController::setDockListProvider(DockListProvider dockListProvider)
    {
        m_dockListProvider = std::move(dockListProvider);
    }

    void GlobalUiSearchController::setDockPreparer(DockPreparer dockPreparer)
    {
        m_dockPreparer = std::move(dockPreparer);
    }

    void GlobalUiSearchController::setDockActivator(DockActivator dockActivator)
    {
        m_dockActivator = std::move(dockActivator);
    }

    void GlobalUiSearchController::handleQueryEdited(const QString& queryText)
    {
        m_pendingQueryText = queryText;
        if (!m_searchModeActive)
        {
            return;
        }
        if (!isQueryLongEnough(queryText.trimmed()))
        {
            dismissPopup();
            return;
        }
        m_searchDebounceTimer->start();
    }

    void GlobalUiSearchController::setSearchInputActive(const bool searchModeActive)
    {
        m_searchModeActive = searchModeActive;
        if (!searchModeActive)
        {
            dismissPopup();
        }
        else if (isQueryLongEnough(m_pendingQueryText.trimmed()))
        {
            m_searchDebounceTimer->start();
        }
    }

    void GlobalUiSearchController::dismissPopup()
    {
        if (m_searchDebounceTimer != nullptr)
        {
            m_searchDebounceTimer->stop();
        }
        if (m_popupPanel != nullptr && m_popupPanel->isVisible())
        {
            m_popupPanel->hide();
        }
    }

    bool GlobalUiSearchController::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        const QEvent::Type eventType = eventObject->type();

        if (watchedObject == m_searchInputEdit)
        {
            if (eventType == QEvent::KeyPress && m_searchModeActive)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                const bool popupVisible = m_popupPanel != nullptr && m_popupPanel->isVisible();
                switch (keyEvent->key())
                {
                case Qt::Key_Down:
                    if (popupVisible)
                    {
                        moveSelection(1);
                    }
                    else if (isQueryLongEnough(m_pendingQueryText.trimmed()))
                    {
                        runSearchNow();
                    }
                    return true;
                case Qt::Key_Up:
                    if (popupVisible)
                    {
                        moveSelection(-1);
                        return true;
                    }
                    break;
                case Qt::Key_Return:
                case Qt::Key_Enter:
                    if (popupVisible)
                    {
                        const int currentRow = m_resultListWidget != nullptr
                            ? std::max(0, m_resultListWidget->currentRow())
                            : 0;
                        activateHitAtRow(currentRow);
                    }
                    else if (isQueryLongEnough(m_pendingQueryText.trimmed()))
                    {
                        runSearchNow();
                    }
                    return true;
                case Qt::Key_Escape:
                    if (popupVisible)
                    {
                        dismissPopup();
                        return true;
                    }
                    break;
                default:
                    break;
                }
            }
            else if (eventType == QEvent::FocusIn
                && m_searchModeActive
                && isQueryLongEnough(m_pendingQueryText.trimmed()))
            {
                m_searchDebounceTimer->start();
            }
            return false;
        }

        if (watchedObject == m_popupHostWindow)
        {
            const bool popupVisible = m_popupPanel != nullptr && m_popupPanel->isVisible();
            if (popupVisible && (eventType == QEvent::Resize || eventType == QEvent::Move))
            {
                repositionPopupPanel();
            }
            else if (popupVisible && eventType == QEvent::WindowDeactivate)
            {
                dismissPopup();
            }
            return false;
        }

        if (eventType == QEvent::MouseButtonPress
            && m_popupPanel != nullptr
            && m_popupPanel->isVisible())
        {
            QWidget* clickedWidget = qobject_cast<QWidget*>(watchedObject);
            if (clickedWidget != nullptr
                && !widgetBelongsToBranch(clickedWidget, m_popupPanel)
                && !widgetBelongsToBranch(clickedWidget, m_popupAnchorWidget))
            {
                dismissPopup();
            }
        }

        return false;
    }

    void GlobalUiSearchController::ensurePopupCreated()
    {
        if (m_popupPanel != nullptr || m_popupHostWindow == nullptr)
        {
            return;
        }

        m_popupPanel = new QFrame(m_popupHostWindow);
        m_popupPanel->setObjectName(QStringLiteral("ksGlobalUiSearchPopup"));
        m_popupPanel->setAttribute(Qt::WA_StyledBackground, true);
        m_popupPanel->hide();

        auto* panelLayout = new QVBoxLayout(m_popupPanel);
        panelLayout->setContentsMargins(4, 4, 4, 4);
        panelLayout->setSpacing(0);

        m_resultListWidget = new QListWidget(m_popupPanel);
        m_resultListWidget->setObjectName(QStringLiteral("ksGlobalUiSearchResultList"));
        m_resultListWidget->setFrameShape(QFrame::NoFrame);
        m_resultListWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        m_resultListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        m_resultListWidget->setUniformItemSizes(true);
        m_resultListWidget->setMouseTracking(true);
        m_resultListWidget->viewport()->setAttribute(Qt::WA_Hover, true);
        m_resultListWidget->setItemDelegate(new SearchResultItemDelegate(m_resultListWidget));
        connect(m_resultListWidget, &QListWidget::itemClicked, this, [this](QListWidgetItem* listItem) {
            if (m_resultListWidget != nullptr && listItem != nullptr)
            {
                activateHitAtRow(m_resultListWidget->row(listItem));
            }
        });
        connect(m_resultListWidget, &QListWidget::itemActivated, this, [this](QListWidgetItem* listItem) {
            if (m_resultListWidget != nullptr && listItem != nullptr)
            {
                activateHitAtRow(m_resultListWidget->row(listItem));
            }
        });

        m_emptyHintLabel = new QLabel(QStringLiteral("未找到匹配内容"), m_popupPanel);
        m_emptyHintLabel->setObjectName(QStringLiteral("ksGlobalUiSearchEmptyHint"));
        m_emptyHintLabel->setAlignment(Qt::AlignCenter);

        panelLayout->addWidget(m_resultListWidget, 1);
        panelLayout->addWidget(m_emptyHintLabel, 0);
    }

    void GlobalUiSearchController::runSearchNow()
    {
        const QString queryText = m_pendingQueryText.trimmed();
        if (!m_searchModeActive || !isQueryLongEnough(queryText))
        {
            dismissPopup();
            return;
        }
        if (!m_dockListProvider)
        {
            return;
        }

        const QList<ads::CDockWidget*> dockList = m_dockListProvider();
        m_currentHitList.clear();
        for (ads::CDockWidget* dockWidget : dockList)
        {
            if (dockWidget == nullptr)
            {
                continue;
            }
            if (m_dockPreparer)
            {
                m_dockPreparer(dockWidget);
            }
            collectDockSearchHits(dockWidget, queryText, m_currentHitList);
            if (m_currentHitList.size() >= kMaxTotalHits)
            {
                break;
            }
        }
        if (m_currentHitList.size() > kMaxTotalHits)
        {
            m_currentHitList.resize(kMaxTotalHits);
        }

        std::stable_sort(
            m_currentHitList.begin(),
            m_currentHitList.end(),
            [](const UiSearchHit& leftHit, const UiSearchHit& rightHit) {
                return leftHit.matchRank < rightHit.matchRank;
            });

        rebuildResultList();
        showPopupPanel();
    }

    void GlobalUiSearchController::rebuildResultList()
    {
        ensurePopupCreated();
        if (m_resultListWidget == nullptr)
        {
            return;
        }

        const QString queryText = m_pendingQueryText.trimmed();
        const QString textPrimaryHex = KswordTheme::TextPrimaryColorHex();
        const QString textSecondaryHex = KswordTheme::TextSecondaryHex();
        const QString accentTextHex = KswordTheme::ThemeColorName(
            KswordTheme::EnsureTextContrast(
                KswordTheme::PrimaryAccentColor(),
                KswordTheme::SurfaceColor(),
                3.0));

        m_resultListWidget->clear();
        for (const UiSearchHit& hitEntry : m_currentHitList)
        {
            auto* listItem = new QListWidgetItem(m_resultListWidget);
            const QString itemHtml = QStringLiteral(
                "<div style=\"font-size:12px;color:%1;\">%2</div>"
                "<div style=\"font-size:11px;color:%3;margin-top:3px;\">%4</div>")
                .arg(
                    textPrimaryHex,
                    buildSnippetHtml(hitEntry.matchedText, queryText, accentTextHex),
                    textSecondaryHex,
                    hitEntry.pagePathText.toHtmlEscaped());
            listItem->setData(kResultHtmlRole, itemHtml);
            listItem->setToolTip(
                hitEntry.matchedText
                + QStringLiteral("\n")
                + hitEntry.pagePathText);
        }

        const bool hasResults = !m_currentHitList.isEmpty();
        m_resultListWidget->setVisible(hasResults);
        if (m_emptyHintLabel != nullptr)
        {
            m_emptyHintLabel->setVisible(!hasResults);
        }
        if (hasResults)
        {
            m_resultListWidget->setCurrentRow(0);
        }
    }

    void GlobalUiSearchController::showPopupPanel()
    {
        ensurePopupCreated();
        if (m_popupPanel == nullptr || m_popupHostWindow == nullptr)
        {
            return;
        }

        // 每次展示都重取主题 token，保证深浅色切换后样式即时正确。
        m_popupPanel->setStyleSheet(QStringLiteral(
            "#ksGlobalUiSearchPopup{"
            "  background:%1;"
            "  border:1px solid %2;"
            "  border-radius:6px;"
            "}"
            "#ksGlobalUiSearchPopup QListWidget{"
            "  background:transparent;"
            "  border:none;"
            "}"
            "#ksGlobalUiSearchPopup QLabel#ksGlobalUiSearchEmptyHint{"
            "  color:%3;"
            "  font-size:12px;"
            "  padding:14px 0;"
            "}")
            .arg(
                KswordTheme::SurfaceColorHex(),
                KswordTheme::BorderStrongColorHex(),
                KswordTheme::TextSecondaryHex()));

        const int anchorWidth = m_popupAnchorWidget != nullptr ? m_popupAnchorWidget->width() : 460;
        const int panelWidth = std::clamp(
            anchorWidth + 220,
            460,
            std::max(320, m_popupHostWindow->width() - 24));
        const int visibleRowCount = std::min(
            static_cast<int>(m_currentHitList.size()),
            kMaxVisibleResultRows);
        const int contentHeight = m_currentHitList.isEmpty()
            ? 48
            : visibleRowCount * kResultItemHeight + 2;
        m_popupPanel->setFixedSize(panelWidth, contentHeight + 8);

        repositionPopupPanel();
        m_popupPanel->raise();
        m_popupPanel->show();
    }

    void GlobalUiSearchController::repositionPopupPanel()
    {
        if (m_popupPanel == nullptr
            || m_popupHostWindow == nullptr
            || m_popupAnchorWidget == nullptr)
        {
            return;
        }

        const QPoint anchorBottomLeftGlobal =
            m_popupAnchorWidget->mapToGlobal(QPoint(0, m_popupAnchorWidget->height()));
        const QPoint anchorBottomLeftInHost =
            m_popupHostWindow->mapFromGlobal(anchorBottomLeftGlobal);

        int panelLeft = anchorBottomLeftInHost.x()
            + (m_popupAnchorWidget->width() - m_popupPanel->width()) / 2;
        const int maxPanelLeft = std::max(8, m_popupHostWindow->width() - m_popupPanel->width() - 8);
        panelLeft = std::clamp(panelLeft, 8, maxPanelLeft);

        const int panelTop = anchorBottomLeftInHost.y() + 6;
        m_popupPanel->move(panelLeft, panelTop);
    }

    void GlobalUiSearchController::activateHitAtRow(const int rowIndex)
    {
        if (rowIndex < 0 || rowIndex >= m_currentHitList.size())
        {
            return;
        }

        const UiSearchHit hitEntry = m_currentHitList.at(rowIndex);
        ads::CDockWidget* dockWidget = hitEntry.pageDockWidget.data();
        if (dockWidget == nullptr)
        {
            dismissPopup();
            return;
        }

        if (m_dockPreparer)
        {
            m_dockPreparer(dockWidget);
        }
        if (m_dockActivator)
        {
            m_dockActivator(dockWidget);
        }
        else
        {
            dockWidget->toggleView(true);
            dockWidget->raise();
        }

        QWidget* targetWidget = hitEntry.targetWidget.data();
        dismissPopup();
        if (targetWidget == nullptr)
        {
            return;
        }

        revealHitTargetWithinPage(targetWidget);

        // 页签切换与 Dock 置前后等一拍布局，再滚动一次并点亮高亮。
        QPointer<QWidget> guardedTarget(targetWidget);
        QTimer::singleShot(kFlashDelayMs, this, [guardedTarget]() {
            if (guardedTarget == nullptr)
            {
                return;
            }
            scrollAncestorsToWidget(guardedTarget);
            SearchHitFlashOverlay::flashOnWidget(guardedTarget);
        });
    }

    void GlobalUiSearchController::moveSelection(const int rowDelta)
    {
        if (m_resultListWidget == nullptr || m_resultListWidget->count() <= 0)
        {
            return;
        }
        const int targetRow = std::clamp(
            m_resultListWidget->currentRow() + rowDelta,
            0,
            m_resultListWidget->count() - 1);
        m_resultListWidget->setCurrentRow(targetRow);
    }

    bool GlobalUiSearchController::isQueryLongEnough(const QString& queryText)
    {
        if (queryText.isEmpty())
        {
            return false;
        }
        if (queryText.size() >= 2)
        {
            return true;
        }
        // 单字符查询只放行 CJK 等宽字符（U+2E80 起），单个 ASCII 字符噪声过大。
        return queryText.at(0).unicode() >= 0x2E80;
    }
}
