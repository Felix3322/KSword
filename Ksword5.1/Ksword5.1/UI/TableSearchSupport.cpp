#include "TableSearchSupport.h"

#include "GlobalUiSearch.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractItemModel>
#include <QApplication>
#include <QEvent>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLineEdit>
#include <QMargins>
#include <QPoint>
#include <QScrollBar>
#include <QSize>
#include <QSizePolicy>
#include <QStackedWidget>
#include <QStringList>
#include <QTabWidget>
#include <QTableView>
#include <QTimer>
#include <QToolButton>
#include <QVariant>

#include <algorithm>

namespace
{
    constexpr char kSearchSupportObjectName[] = "KSWORD_TABLE_SEARCH_SUPPORT";
    constexpr char kSearchSupportPropertyName[] = "KSWORD_TABLE_SEARCH_SUPPORT_OBJECT";
    constexpr char kTableActionBarObjectName[] = "KSWORD_TABLE_INTERACTION_ACTION_BAR";
    constexpr char kGenericSearchControlPropertyName[] = "ksword_generic_table_search_control";
    constexpr char kGlobalSearchInputPropertyName[] = "ksword_global_ui_search_input";
    constexpr char kExplicitTableNamePropertyName[] = "ksword_table_search_name";
    constexpr int kFullSearchWidth = 220;
    constexpr int kCollapsedSearchWidth = 28;
    constexpr int kSearchControlHeight = 24;
    constexpr int kSearchOuterMargin = 4;

    // textLooksLikeSearchControl：用控件元数据识别页面已有的搜索/筛选输入框。
    bool textLooksLikeSearchControl(const QString& sourceText)
    {
        const QString normalizedText = sourceText.trimmed().toLower();
        return normalizedText.contains(QStringLiteral("搜索"))
            || normalizedText.contains(QStringLiteral("筛选"))
            || normalizedText.contains(QStringLiteral("过滤"))
            || normalizedText.contains(QStringLiteral("search"))
            || normalizedText.contains(QStringLiteral("filter"))
            || normalizedText.contains(QStringLiteral("find"));
    }

    // nearestPageRoot：返回表格所在的最近页签页面；找不到时回退到顶层窗口内容根。
    QWidget* nearestPageRoot(QWidget* childWidget)
    {
        QWidget* fallbackRoot = childWidget;
        for (QWidget* cursorWidget = childWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            fallbackRoot = cursorWidget;
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (qobject_cast<QStackedWidget*>(parentWidget) != nullptr)
            {
                return cursorWidget;
            }
            if (cursorWidget->isWindow())
            {
                break;
            }
        }
        return fallbackRoot;
    }

    // hasDedicatedSearchControl：检查同页且位于表格上方/同组的专属搜索输入框。
    bool hasDedicatedSearchControl(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return false;
        }

        QWidget* pageRoot = nearestPageRoot(tableView);
        if (pageRoot == nullptr)
        {
            return false;
        }
        const QPoint tableTopLeft = tableView->mapTo(pageRoot, QPoint(0, 0));
        const QList<QLineEdit*> lineEditList = pageRoot->findChildren<QLineEdit*>();
        for (QLineEdit* lineEdit : lineEditList)
        {
            if (lineEdit == nullptr
                || lineEdit->property(kGenericSearchControlPropertyName).toBool()
                || lineEdit->property(kGlobalSearchInputPropertyName).toBool())
            {
                continue;
            }

            const QString searchMetadata = lineEdit->objectName()
                + QLatin1Char(' ')
                + lineEdit->placeholderText()
                + QLatin1Char(' ')
                + lineEdit->toolTip()
                + QLatin1Char(' ')
                + lineEdit->accessibleName();
            if (!textLooksLikeSearchControl(searchMetadata))
            {
                continue;
            }

            const QPoint editTopLeft = lineEdit->mapTo(pageRoot, QPoint(0, 0));
            const bool directlyAboveTable = editTopLeft.y() <= tableTopLeft.y()
                && tableTopLeft.y() - editTopLeft.y() <= 180;
            const bool sharesImmediateContainer = lineEdit->parentWidget() == tableView->parentWidget();
            if (directlyAboveTable || sharesImmediateContainer)
            {
                return true;
            }
        }
        return false;
    }

    // tableNeedsSearchAccess：只有模型内容实际超过当前垂直可视页时才需要入口。
    bool tableNeedsSearchAccess(QTableView* tableView)
    {
        return tableView != nullptr
            && tableView->model() != nullptr
            && tableView->model()->rowCount() > 0
            && tableView->verticalScrollBar() != nullptr
            && tableView->verticalScrollBar()->maximum()
                > tableView->verticalScrollBar()->minimum();
    }

    // resolveSearchHost：优先使用现有表格操作条，否则使用水平表头尾部空白区。
    QWidget* resolveSearchHost(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return nullptr;
        }
        QWidget* actionBar = tableView->findChild<QWidget*>(
            QString::fromLatin1(kTableActionBarObjectName),
            Qt::FindDirectChildrenOnly);
        return actionBar != nullptr ? actionBar : tableView->horizontalHeader();
    }

    // trailingHeaderSpace：计算水平表头最右侧没有被可见列占用的像素宽度。
    int trailingHeaderSpace(QTableView* tableView)
    {
        QHeaderView* headerView = tableView != nullptr ? tableView->horizontalHeader() : nullptr;
        if (headerView == nullptr)
        {
            return 0;
        }

        int occupiedRight = 0;
        for (int logicalIndex = 0; logicalIndex < headerView->count(); ++logicalIndex)
        {
            if (headerView->isSectionHidden(logicalIndex))
            {
                continue;
            }
            const int sectionLeft = headerView->sectionViewportPosition(logicalIndex);
            const int sectionRight = sectionLeft + headerView->sectionSize(logicalIndex);
            occupiedRight = std::max(occupiedRight, sectionRight);
        }
        return std::max(0, headerView->width() - occupiedRight);
    }

    // TableSearchAccessWidget：管理单个表格的自适应搜索框/按钮与宿主空间预留。
    class TableSearchAccessWidget final : public QFrame
    {
    public:
        explicit TableSearchAccessWidget(QTableView* tableView)
            : QFrame(resolveSearchHost(tableView))
            , m_tableView(tableView)
            , m_hostWidget(resolveSearchHost(tableView))
        {
            setObjectName(QString::fromLatin1(kSearchSupportObjectName));
            setFrameShape(QFrame::NoFrame);
            setAttribute(Qt::WA_StyledBackground, true);

            auto* rootLayout = new QHBoxLayout(this);
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->setSpacing(5);

            m_searchEdit = new QLineEdit(this);
            m_searchEdit->setProperty(kGenericSearchControlPropertyName, true);
            m_searchEdit->setClearButtonEnabled(true);
            m_searchEdit->setFixedHeight(kSearchControlHeight);
            rootLayout->addWidget(m_searchEdit, 1);

            m_searchButton = new QToolButton(this);
            m_searchButton->setProperty(kGenericSearchControlPropertyName, true);
            m_searchButton->setAutoRaise(true);
            m_searchButton->setIcon(QIcon(QStringLiteral(":/Icon/file_find.svg")));
            m_searchButton->setIconSize(QSize(16, 16));
            m_searchButton->setFixedSize(kCollapsedSearchWidth, kSearchControlHeight);
            rootLayout->addWidget(m_searchButton);

            connect(m_searchButton, &QToolButton::clicked, this, [this]() {
                if (!m_tableView.isNull())
                {
                    ks::ui::ActivateGlobalUiSearchForTable(
                        m_tableView.data(),
                        QString(),
                        true);
                }
            });
            connect(m_searchEdit, &QLineEdit::textEdited, this, [this](const QString& queryText) {
                if (!m_tableView.isNull())
                {
                    ks::ui::ActivateGlobalUiSearchForTable(
                        m_tableView.data(),
                        queryText,
                        false);
                }
            });

            if (m_hostWidget != nullptr && m_hostWidget->layout() != nullptr)
            {
                m_originalHostMargins = m_hostWidget->layout()->contentsMargins();
            }
            installObservers();
            refreshPresentation();
        }

        ~TableSearchAccessWidget() override
        {
            restoreHostMargins();
        }

        void refreshPresentation()
        {
            if (m_tableView.isNull() || m_hostWidget.isNull())
            {
                hide();
                return;
            }

            QTableView* tableView = m_tableView.data();
            const QString tableName = ks::ui::ResolveTableSearchDisplayName(tableView);
            m_searchEdit->setPlaceholderText(
                ks::i18n::sourceText(QStringLiteral("搜索%1")).arg(tableName));
            m_searchButton->setToolTip(
                ks::i18n::sourceText(QStringLiteral("搜索当前表格：%1")).arg(tableName));

            if (hasDedicatedSearchControl(tableView))
            {
                applyPresentation(0);
                return;
            }
            if (!tableNeedsSearchAccess(tableView))
            {
                applyPresentation(0);
                return;
            }

            QWidget* hostWidget = m_hostWidget.data();
            const bool hostedByActionBar = hostWidget != tableView->horizontalHeader();
            int availableWidth = trailingHeaderSpace(tableView);
            if (hostedByActionBar)
            {
                const int minimumContentWidth = hostWidget->layout() != nullptr
                    ? hostWidget->layout()->minimumSize().width()
                    : 0;
                // minimumSize 已包含当前搜索预留；加回该宽度后再决定是否升/降级，
                // 避免每次刷新先撤销再添加边距形成 LayoutRequest 循环。
                availableWidth = std::max(
                    0,
                    hostWidget->width() - minimumContentWidth + m_reservedHostWidth);
            }

            if (availableWidth >= kFullSearchWidth + kSearchOuterMargin)
            {
                applyPresentation(kFullSearchWidth);
            }
            else if (availableWidth >= kCollapsedSearchWidth + kSearchOuterMargin)
            {
                applyPresentation(kCollapsedSearchWidth);
            }
            else
            {
                applyPresentation(0);
            }
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject != nullptr
                && (eventObject->type() == QEvent::Resize
                    || eventObject->type() == QEvent::LayoutRequest
                    || eventObject->type() == QEvent::Show
                    || eventObject->type() == QEvent::StyleChange
                    || eventObject->type() == QEvent::LanguageChange))
            {
                scheduleRefresh();
            }
            return QFrame::eventFilter(watchedObject, eventObject);
        }

    private:
        void installObservers()
        {
            if (!m_tableView.isNull())
            {
                m_tableView->installEventFilter(this);
                if (m_tableView->verticalScrollBar() != nullptr)
                {
                    connect(
                        m_tableView->verticalScrollBar(),
                        &QScrollBar::rangeChanged,
                        this,
                        [this](int, int) { scheduleRefresh(); });
                }
                if (m_tableView->horizontalHeader() != nullptr)
                {
                    m_tableView->horizontalHeader()->installEventFilter(this);
                    connect(
                        m_tableView->horizontalHeader(),
                        &QHeaderView::geometriesChanged,
                        this,
                        [this]() { scheduleRefresh(); });
                }
            }
            if (!m_hostWidget.isNull())
            {
                m_hostWidget->installEventFilter(this);
            }
        }

        void scheduleRefresh()
        {
            if (m_refreshPending)
            {
                return;
            }
            m_refreshPending = true;
            QTimer::singleShot(0, this, [this]() {
                m_refreshPending = false;
                refreshPresentation();
            });
        }

        void restoreHostMargins()
        {
            if (!m_hostWidget.isNull()
                && m_hostWidget->layout() != nullptr
                && !m_tableView.isNull()
                && m_hostWidget.data() != m_tableView->horizontalHeader()
                && m_reservedHostWidth > 0)
            {
                m_hostWidget->layout()->setContentsMargins(m_originalHostMargins);
                m_reservedHostWidth = 0;
            }
        }

        void applyPresentation(const int requestedWidth)
        {
            if (requestedWidth <= 0 || m_hostWidget.isNull())
            {
                restoreHostMargins();
                hide();
                return;
            }

            QWidget* hostWidget = m_hostWidget.data();
            const bool fullSearchVisible = requestedWidth == kFullSearchWidth;
            m_searchEdit->setVisible(fullSearchVisible);
            m_searchButton->setVisible(!fullSearchVisible);

            if (hostWidget->layout() != nullptr
                && hostWidget != m_tableView->horizontalHeader())
            {
                const int requestedReservation = requestedWidth + kSearchOuterMargin;
                if (m_reservedHostWidth != requestedReservation)
                {
                    QMargins reservedMargins = m_originalHostMargins;
                    reservedMargins.setRight(
                        reservedMargins.right() + requestedReservation);
                    hostWidget->layout()->setContentsMargins(reservedMargins);
                    m_reservedHostWidth = requestedReservation;
                }
            }

            const int controlTop = std::max(0, (hostWidget->height() - kSearchControlHeight) / 2);
            const int controlLeft = std::max(
                0,
                hostWidget->width() - requestedWidth - kSearchOuterMargin);
            setGeometry(
                controlLeft,
                controlTop,
                requestedWidth,
                kSearchControlHeight);
            setStyleSheet(QStringLiteral(
                "QFrame#KSWORD_TABLE_SEARCH_SUPPORT{background:transparent;}"
                "QLineEdit{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:0 6px;}"
                "QLineEdit:focus{border-color:%4;}"
                "QToolButton{background:transparent;color:%2;border:1px solid transparent;border-radius:3px;}"
                "QToolButton:hover{background:%5;border-color:%4;}" )
                .arg(
                    KswordTheme::SurfaceColorHex(),
                    KswordTheme::TextPrimaryColorHex(),
                    KswordTheme::BorderStrongColorHex(),
                    KswordTheme::PrimaryBlueHex,
                    KswordTheme::SurfaceAltColorHex()));
            show();
            raise();
        }

        QPointer<QTableView> m_tableView;    // m_tableView：搜索入口对应的原始表格。
        QPointer<QWidget> m_hostWidget;      // m_hostWidget：操作条或水平表头宿主。
        QLineEdit* m_searchEdit = nullptr;   // m_searchEdit：空间充足时显示的输入框。
        QToolButton* m_searchButton = nullptr; // m_searchButton：空间不足时显示的图标按钮。
        QMargins m_originalHostMargins;      // m_originalHostMargins：操作条原始布局边距。
        int m_reservedHostWidth = 0;         // m_reservedHostWidth：当前为搜索入口预留的右侧宽度。
        bool m_refreshPending = false;       // m_refreshPending：合并同一事件循环内的刷新请求。
    };

    // searchSupportForTable：读取表格已安装的搜索入口对象。
    TableSearchAccessWidget* searchSupportForTable(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return nullptr;
        }
        QObject* supportObject = tableView->property(kSearchSupportPropertyName).value<QObject*>();
        return dynamic_cast<TableSearchAccessWidget*>(supportObject);
    }

    // normalizedMatchRank：计算单元格命中的排序优先级。
    int normalizedMatchRank(const QString& cellText, const QString& queryText)
    {
        if (cellText.compare(queryText, Qt::CaseInsensitive) == 0)
        {
            return 0;
        }
        return cellText.startsWith(queryText, Qt::CaseInsensitive) ? 1 : 2;
    }
}

namespace ks::ui
{
    void InstallTableSearchSupport(QTableView* tableView)
    {
        if (tableView == nullptr || searchSupportForTable(tableView) != nullptr)
        {
            return;
        }
        auto* searchSupport = new TableSearchAccessWidget(tableView);
        tableView->setProperty(
            kSearchSupportPropertyName,
            QVariant::fromValue<QObject*>(searchSupport));
    }

    void RefreshTableSearchSupport(QTableView* tableView)
    {
        if (TableSearchAccessWidget* searchSupport = searchSupportForTable(tableView))
        {
            searchSupport->refreshPresentation();
        }
    }

    QString ResolveTableSearchDisplayName(const QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return ks::i18n::sourceText(QStringLiteral("表格"));
        }

        const QString explicitName = tableView->property(kExplicitTableNamePropertyName)
            .toString()
            .trimmed();
        if (!explicitName.isEmpty())
        {
            return explicitName;
        }
        if (!tableView->accessibleName().trimmed().isEmpty())
        {
            return tableView->accessibleName().trimmed();
        }

        for (QWidget* cursorWidget = tableView->parentWidget();
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(cursorWidget))
            {
                if (!groupBox->title().trimmed().isEmpty())
                {
                    return groupBox->title().trimmed();
                }
            }
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int tabIndex = tabWidget->indexOf(cursorWidget);
                    if (tabIndex >= 0 && !tabWidget->tabText(tabIndex).trimmed().isEmpty())
                    {
                        return tabWidget->tabText(tabIndex).trimmed();
                    }
                }
            }
        }

        QString objectName = tableView->objectName().trimmed();
        if (objectName.startsWith(QStringLiteral("m_"), Qt::CaseInsensitive))
        {
            objectName.remove(0, 2);
        }
        const QStringList knownSuffixList = {
            QStringLiteral("tableWidget"),
            QStringLiteral("tableView"),
            QStringLiteral("table")
        };
        for (const QString& knownSuffix : knownSuffixList)
        {
            if (objectName.endsWith(knownSuffix, Qt::CaseInsensitive))
            {
                objectName.chop(knownSuffix.size());
                break;
            }
        }
        if (!objectName.isEmpty())
        {
            return objectName;
        }
        return ks::i18n::sourceText(QStringLiteral("表格"));
    }

    QVector<TableCellSearchMatch> CollectTableCellSearchMatches(
        QTableView* tableView,
        const QString& queryText,
        const int maxHitCount)
    {
        QVector<TableCellSearchMatch> resultList;
        if (tableView == nullptr
            || tableView->model() == nullptr
            || queryText.trimmed().isEmpty()
            || maxHitCount <= 0)
        {
            return resultList;
        }

        QAbstractItemModel* itemModel = tableView->model();
        const QString normalizedQuery = queryText.trimmed();
        const QString tableName = ResolveTableSearchDisplayName(tableView);
        const int columnCount = itemModel->columnCount();
        for (int columnIndex = 0;
             columnIndex < columnCount && resultList.size() < maxHitCount;
             ++columnIndex)
        {
            if (tableView->isColumnHidden(columnIndex) || itemModel->rowCount() <= 0)
            {
                continue;
            }

            const int remainingHitCount = maxHitCount - resultList.size();
            const QModelIndex startIndex = itemModel->index(0, columnIndex);
            const QModelIndexList matchedIndexList = itemModel->match(
                startIndex,
                Qt::DisplayRole,
                normalizedQuery,
                remainingHitCount,
                Qt::MatchContains | Qt::MatchRecursive);
            const QString columnName = itemModel
                ->headerData(columnIndex, Qt::Horizontal, Qt::DisplayRole)
                .toString()
                .trimmed();
            for (const QModelIndex& matchedIndex : matchedIndexList)
            {
                const QString matchedText = matchedIndex.data(Qt::DisplayRole).toString().trimmed();
                if (matchedText.isEmpty())
                {
                    continue;
                }

                TableCellSearchMatch searchMatch;
                searchMatch.tableView = tableView;
                searchMatch.modelIndex = QPersistentModelIndex(matchedIndex);
                searchMatch.matchedText = matchedText;
                searchMatch.locationText = columnName.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("%1，第 %2 行"))
                        .arg(tableName)
                        .arg(matchedIndex.row() + 1)
                    : ks::i18n::sourceText(QStringLiteral("%1，第 %2 行，%3 列"))
                        .arg(tableName)
                        .arg(matchedIndex.row() + 1)
                        .arg(columnName);
                searchMatch.matchRank = normalizedMatchRank(matchedText, normalizedQuery);
                resultList.push_back(searchMatch);
                if (resultList.size() >= maxHitCount)
                {
                    break;
                }
            }
        }
        return resultList;
    }

    void RevealTableCellSearchMatch(const TableCellSearchMatch& searchMatch)
    {
        QTableView* tableView = searchMatch.tableView.data();
        if (tableView == nullptr || !searchMatch.modelIndex.isValid())
        {
            return;
        }

        const QModelIndex modelIndex = searchMatch.modelIndex;
        tableView->scrollTo(modelIndex, QAbstractItemView::PositionAtCenter);
        tableView->setCurrentIndex(modelIndex);
        if (tableView->selectionModel() != nullptr)
        {
            tableView->selectionModel()->select(
                modelIndex,
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        tableView->setFocus(Qt::OtherFocusReason);
    }
}
