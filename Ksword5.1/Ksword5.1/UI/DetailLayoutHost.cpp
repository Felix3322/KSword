#include "DetailLayoutHost.h"

#include "CodeEditorWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QBoxLayout>
#include <QContextMenuEvent>
#include <QDialog>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QPlainTextEdit>
#include <QScreen>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <utility>

namespace
{
    // 专用角色避开页面普遍使用的 Qt::UserRole 缓存索引。
    constexpr int EmbeddedMarkerRole = Qt::UserRole + 410;
    constexpr int OriginalDecorationRole = Qt::UserRole + 411;

    QIcon embeddedIndicatorIcon(const bool expanded)
    {
        return QIcon(expanded
            ? QStringLiteral(":/Icon/detail_node_expanded.svg")
            : QStringLiteral(":/Icon/detail_node_collapsed.svg"));
    }

    // directChildUnder：返回 widget 在 ancestor 下的第一层子控件，用于识别分隔器面板。
    QWidget* directChildUnder(QWidget* widget, QWidget* ancestor)
    {
        QWidget* childWidget = widget;
        while (childWidget != nullptr && childWidget->parentWidget() != ancestor)
        {
            childWidget = childWidget->parentWidget();
        }
        return childWidget != nullptr && childWidget->parentWidget() == ancestor
            ? childWidget
            : nullptr;
    }

    // findSharedSplitter：从表格祖先向上查找同时包含详情编辑器的分隔器。
    QSplitter* findSharedSplitter(QAbstractItemView* tableView, CodeEditorWidget* detailEditor)
    {
        QWidget* ancestorWidget = tableView;
        while (ancestorWidget != nullptr)
        {
            QSplitter* splitter = qobject_cast<QSplitter*>(ancestorWidget);
            if (splitter != nullptr && splitter->isAncestorOf(detailEditor))
            {
                return splitter;
            }
            ancestorWidget = ancestorWidget->parentWidget();
        }
        return nullptr;
    }

    // findCommonParent：找到两个控件最近的共同 QWidget 祖先。
    QWidget* findCommonParent(QWidget* firstWidget, QWidget* secondWidget)
    {
        for (QWidget* firstParent = firstWidget; firstParent != nullptr;
            firstParent = firstParent->parentWidget())
        {
            for (QWidget* secondParent = secondWidget; secondParent != nullptr;
                secondParent = secondParent->parentWidget())
            {
                if (firstParent == secondParent)
                {
                    return firstParent;
                }
            }
        }
        return nullptr;
    }

    // createReadOnlyInlineEditor：创建方案三使用的普通只读文本框。
    QPlainTextEdit* createReadOnlyInlineEditor(QWidget* parentWidget, const QString& detailText)
    {
        QPlainTextEdit* textEditor = new QPlainTextEdit(parentWidget);
        textEditor->setReadOnly(true);
        textEditor->setPlainText(detailText);
        textEditor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        textEditor->setMinimumHeight(116);
        textEditor->setContextMenuPolicy(Qt::DefaultContextMenu);
        return textEditor;
    }

    // treeItemForIndex：通过公开的视图坐标接口取得可见 QModelIndex 对应的 QTreeWidgetItem。
    QTreeWidgetItem* treeItemForIndex(QTreeWidget* treeWidget, const QModelIndex& modelIndex)
    {
        if (treeWidget == nullptr || !modelIndex.isValid())
        {
            return nullptr;
        }
        const QRect itemRect = treeWidget->visualRect(modelIndex);
        return itemRect.isValid() ? treeWidget->itemAt(itemRect.center()) : nullptr;
    }
}

ks::ui::DetailLayoutHost::DetailLayoutHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget)
    : QObject(ownerWidget),
      m_tableView(tableView),
      m_detailEditor(detailEditor),
      m_ownerWidget(ownerWidget)
{
    initializeHostUi();
    initializeConnections();
}

ks::ui::DetailLayoutHost::~DetailLayoutHost()
{
    destroyFloatingWindow();
}

void ks::ui::DetailLayoutHost::setTableView(QAbstractItemView* tableView)
{
    if (tableView == nullptr || m_tableView == tableView)
    {
        return;
    }
    m_tableView = tableView;
    initializeConnections();
}

void ks::ui::DetailLayoutHost::setDetailEditor(CodeEditorWidget* detailEditor)
{
    if (detailEditor == nullptr || m_detailEditor == detailEditor)
    {
        return;
    }
    m_detailEditor = detailEditor;
    initializeConnections();
}

CodeEditorWidget* ks::ui::DetailLayoutHost::detailEditor() const
{
    return m_detailEditor.data();
}

void ks::ui::DetailLayoutHost::initializeHostUi()
{
    ensureManagedSplitter();
    if (m_splitter.isNull())
    {
        return;
    }

    // 固定宽度按钮不能直接成为纵向 QSplitter 子项，否则它的 maximumWidth 会把整个
    // 分隔器横向尺寸压窄。使用横向可扩展的承载条，只让中间箭头保持紧凑宽度。
    m_toggleBar = new QWidget(m_splitter.data());
    m_toggleBar->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_toggleBar->setMinimumWidth(0);
    m_toggleBar->setMaximumWidth(QWIDGETSIZE_MAX);
    m_toggleBar->setFixedHeight(18);

    QHBoxLayout* toggleLayout = new QHBoxLayout(m_toggleBar.data());
    toggleLayout->setContentsMargins(0, 0, 0, 0);
    toggleLayout->setSpacing(0);
    toggleLayout->addStretch(1);

    m_toggleButton = new QToolButton(m_toggleBar.data());
    m_toggleButton->setAutoRaise(true);
    m_toggleButton->setArrowType(Qt::UpArrow);
    m_toggleButton->setFocusPolicy(Qt::NoFocus);
    m_toggleButton->setFixedSize(44, 18);
    m_toggleButton->setToolTip(ks::i18n::text(
        QStringLiteral("detail.layout.toggle.tooltip"),
        QStringLiteral("展开或收起当前行详情")));
    toggleLayout->addWidget(m_toggleButton.data(), 0, Qt::AlignCenter);
    toggleLayout->addStretch(1);

    // 箭头作为分隔器中间项，折叠时正好停留在表格下沿，展开后位于表格与详情之间。
    m_splitter->insertWidget(1, m_toggleBar.data());
}

void ks::ui::DetailLayoutHost::ensureManagedSplitter()
{
    if (m_tableView.isNull() || m_detailEditor.isNull())
    {
        return;
    }

    QSplitter* sharedSplitter = findSharedSplitter(m_tableView.data(), m_detailEditor.data());
    if (sharedSplitter != nullptr)
    {
        m_splitter = sharedSplitter;
        m_detailPane = directChildUnder(m_detailEditor.data(), sharedSplitter);
        m_detailEditor->setMinimumHeight(0);
        m_detailEditor->setMaximumHeight(QWIDGETSIZE_MAX);
        return;
    }

    // 直接布局页面没有既有 QSplitter：保留原控件对象，仅把两者包装进统一分隔器。
    QWidget* commonParent = findCommonParent(m_tableView.data(), m_detailEditor.data());
    QBoxLayout* commonLayout = commonParent != nullptr
        ? qobject_cast<QBoxLayout*>(commonParent->layout())
        : nullptr;
    if (commonParent == nullptr || commonLayout == nullptr)
    {
        return;
    }

    QWidget* tablePane = directChildUnder(m_tableView.data(), commonParent);
    QWidget* detailPane = directChildUnder(m_detailEditor.data(), commonParent);
    if (tablePane == nullptr || detailPane == nullptr || tablePane == detailPane)
    {
        return;
    }

    const int tableIndex = commonLayout->indexOf(tablePane);
    const int detailIndex = commonLayout->indexOf(detailPane);
    const int insertionIndex = std::max(0, std::min(tableIndex, detailIndex));
    commonLayout->removeWidget(tablePane);
    commonLayout->removeWidget(detailPane);

    QSplitter* splitter = new QSplitter(Qt::Vertical, commonParent);
    tablePane->setParent(splitter);
    detailPane->setParent(splitter);
    splitter->addWidget(tablePane);
    splitter->addWidget(detailPane);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    commonLayout->insertWidget(insertionIndex, splitter, 1);

    m_splitter = splitter;
    m_detailPane = detailPane;
    m_detailEditor->setMinimumHeight(0);
    m_detailEditor->setMaximumHeight(QWIDGETSIZE_MAX);
}

void ks::ui::DetailLayoutHost::initializeConnections()
{
    if (!m_tableView.isNull())
    {
        // UniqueConnection 与成员 lambda 不兼容，因此用动态属性保证每个视图只绑定一次。
        if (!m_tableView->property("kswordDetailLayoutConnected").toBool())
        {
            m_tableView->setProperty("kswordDetailLayoutConnected", true);
            if (m_tableView->viewport() != nullptr)
            {
                m_tableView->viewport()->installEventFilter(this);
            }
            connect(m_tableView.data(), &QAbstractItemView::clicked, this,
                [this](const QModelIndex& modelIndex)
                {
                    handleViewClicked(QPersistentModelIndex(modelIndex));
                });

            if (m_tableView->model() != nullptr)
            {
                connect(m_tableView->model(), &QAbstractItemModel::rowsInserted, this,
                    [this](const QModelIndex&, int, int)
                    {
                        if (m_internalModelChange || m_scheme !=
                            ks::settings::DetailDisplayScheme::Embedded)
                        {
                            return;
                        }
                        QTimer::singleShot(0, this, [this]() { refreshEmbeddedIndicators(); });
                    });
                connect(m_tableView->model(), &QAbstractItemModel::modelAboutToBeReset, this,
                    [this]()
                    {
                        if (!m_internalModelChange)
                        {
                            m_embeddedEntries.clear();
                            m_tableSortingStateCaptured = false;
                        }
                    });
            }
        }
    }

    if (!m_detailEditor.isNull() &&
        !m_detailEditor->property("kswordDetailLayoutConnected").toBool())
    {
        m_detailEditor->setProperty("kswordDetailLayoutConnected", true);
        connect(m_detailEditor.data(), &CodeEditorWidget::contentChanged, this,
            [this](const QString& detailText) { handleDetailChanged(detailText); });
    }

    if (!m_toggleButton.isNull())
    {
        connect(m_toggleButton.data(), &QToolButton::clicked, this,
            [this]() { updateBottomExpanded(!m_bottomExpanded); });
    }
}

void ks::ui::DetailLayoutHost::applyScheme(
    const ks::settings::DetailDisplayScheme scheme)
{
    if (m_splitter.isNull() || m_detailPane.isNull())
    {
        m_scheme = scheme;
        return;
    }

    if (m_scheme == ks::settings::DetailDisplayScheme::Embedded &&
        scheme != ks::settings::DetailDisplayScheme::Embedded)
    {
        clearEmbeddedDetails();
    }
    if (m_scheme == ks::settings::DetailDisplayScheme::Floating &&
        scheme != ks::settings::DetailDisplayScheme::Floating)
    {
        destroyFloatingWindow();
    }

    const bool schemeChanged = m_scheme != scheme;
    m_scheme = scheme;
    if (!m_toggleBar.isNull())
    {
        m_toggleBar->setVisible(scheme == ks::settings::DetailDisplayScheme::BottomCollapsed);
    }
    switch (scheme)
    {
    case ks::settings::DetailDisplayScheme::Right:
        m_splitter->setOrientation(Qt::Horizontal);
        m_detailPane->setMinimumSize(0, 0);
        m_detailPane->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
        m_detailPane->setVisible(true);
        if (schemeChanged)
        {
            // 右侧详情默认约占 18%，保留拖动手柄供当前页面继续调整。
            m_splitter->setSizes({ 820, 0, 180 });
        }
        break;
    case ks::settings::DetailDisplayScheme::Embedded:
        m_splitter->setOrientation(Qt::Vertical);
        m_detailPane->setVisible(false);
        m_detailPane->setMinimumHeight(0);
        m_detailPane->setMaximumHeight(0);
        if (schemeChanged)
        {
            m_splitter->setSizes({ 1000, 0, 0 });
        }
        refreshEmbeddedIndicators();
        break;
    case ks::settings::DetailDisplayScheme::Floating:
        m_splitter->setOrientation(Qt::Vertical);
        m_detailPane->setVisible(false);
        m_detailPane->setMinimumHeight(0);
        m_detailPane->setMaximumHeight(0);
        if (schemeChanged)
        {
            m_splitter->setSizes({ 1000, 0, 0 });
        }
        break;
    case ks::settings::DetailDisplayScheme::BottomCollapsed:
    default:
        m_splitter->setOrientation(Qt::Vertical);
        if (schemeChanged || (!m_bottomExpanded && m_detailPane->isVisible()))
        {
            m_bottomExpanded = false;
            updateBottomExpanded(false);
        }
        break;
    }
}

void ks::ui::DetailLayoutHost::updateBottomExpanded(const bool expanded)
{
    if (m_scheme != ks::settings::DetailDisplayScheme::BottomCollapsed ||
        m_detailPane.isNull())
    {
        return;
    }
    m_bottomExpanded = expanded;
    m_detailPane->setMinimumHeight(0);
    if (expanded)
    {
        m_detailPane->setMaximumHeight(QWIDGETSIZE_MAX);
        m_detailPane->setVisible(true);
    }
    else
    {
        m_detailPane->setVisible(false);
        m_detailPane->setMaximumHeight(0);
    }
    if (!m_toggleButton.isNull())
    {
        m_toggleButton->setArrowType(expanded ? Qt::DownArrow : Qt::UpArrow);
        m_toggleButton->setToolTip(ks::i18n::text(
            expanded
                ? QStringLiteral("detail.layout.collapse.tooltip")
                : QStringLiteral("detail.layout.expand.tooltip"),
            expanded
                ? QStringLiteral("收起当前行详情")
                : QStringLiteral("展开当前行详情")));
    }
    if (expanded && !m_splitter.isNull())
    {
        m_splitter->setSizes({ 720, 18, 240 });
    }
    else if (!m_splitter.isNull())
    {
        m_splitter->setSizes({ 1000, 18, 0 });
    }
}

void ks::ui::DetailLayoutHost::handleViewClicked(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid() || isEmbeddedMarker(sourceIndex))
    {
        return;
    }

    switch (m_scheme)
    {
    case ks::settings::DetailDisplayScheme::Embedded:
        // 原页面的选择回调先更新 CodeEditorWidget，本处再把最新文本镜像为合成行。
        QTimer::singleShot(0, this, [this, sourceIndex]()
            {
                if (sourceIndex.isValid())
                {
                    toggleEmbeddedDetail(sourceIndex.sibling(sourceIndex.row(), 0));
                }
            });
        break;
    case ks::settings::DetailDisplayScheme::Floating:
        QTimer::singleShot(0, this, [this]() { showFloatingWindow(); });
        break;
    case ks::settings::DetailDisplayScheme::BottomCollapsed:
        updateBottomExpanded(true);
        break;
    case ks::settings::DetailDisplayScheme::Right:
    default:
        break;
    }
}

void ks::ui::DetailLayoutHost::handleDetailChanged(const QString& detailText)
{
    if (m_scheme == ks::settings::DetailDisplayScheme::Floating && !m_floatingEditor.isNull())
    {
        m_floatingEditor->setRawText(detailText);
    }

    if (m_scheme != ks::settings::DetailDisplayScheme::Embedded || m_tableView.isNull())
    {
        return;
    }

    const QModelIndex rawCurrentIndex = m_tableView->currentIndex();
    const QPersistentModelIndex currentIndex(
        rawCurrentIndex.isValid()
            ? rawCurrentIndex.sibling(rawCurrentIndex.row(), 0)
            : QModelIndex());
    for (EmbeddedEntry& entry : m_embeddedEntries)
    {
        if (!entry.textEditor.isNull() && entry.sourceIndex.isValid() &&
            currentIndex.isValid() && entry.sourceIndex == currentIndex)
        {
            entry.textEditor->setPlainText(detailText);
        }
    }
}

void ks::ui::DetailLayoutHost::toggleEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid() || m_detailEditor.isNull())
    {
        return;
    }
    if (removeEmbeddedEntry(sourceIndex))
    {
        setSourceExpandedIndicator(sourceIndex, false);
        return;
    }

    if (qobject_cast<QTableWidget*>(m_tableView.data()) != nullptr)
    {
        insertTableEmbeddedDetail(sourceIndex, m_detailEditor->text());
    }
    else if (qobject_cast<QTreeWidget*>(m_tableView.data()) != nullptr)
    {
        insertTreeEmbeddedDetail(sourceIndex, m_detailEditor->text());
    }
}

void ks::ui::DetailLayoutHost::insertTableEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data());
    if (tableWidget == nullptr || sourceIndex.row() < 0)
    {
        return;
    }

    m_internalModelChange = true;
    if (!m_tableSortingStateCaptured)
    {
        m_tableSortingWasEnabled = tableWidget->isSortingEnabled();
        m_tableSortingStateCaptured = true;
    }
    tableWidget->setSortingEnabled(false);
    const int detailRow = sourceIndex.row() + 1;
    tableWidget->insertRow(detailRow);
    QTableWidgetItem* markerItem = new QTableWidgetItem();
    markerItem->setData(EmbeddedMarkerRole, true);
    markerItem->setFlags(Qt::NoItemFlags);
    tableWidget->setItem(detailRow, 0, markerItem);
    tableWidget->setSpan(detailRow, 0, 1, std::max(1, tableWidget->columnCount()));

    QPlainTextEdit* textEditor = createReadOnlyInlineEditor(tableWidget, detailText);
    tableWidget->setCellWidget(detailRow, 0, textEditor);
    tableWidget->setRowHeight(detailRow, 128);
    m_internalModelChange = false;

    EmbeddedEntry entry;
    entry.sourceIndex = sourceIndex;
    entry.textEditor = textEditor;
    m_embeddedEntries.append(entry);
    setSourceExpandedIndicator(sourceIndex, true);
}

void ks::ui::DetailLayoutHost::insertTreeEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data());
    QTreeWidgetItem* sourceItem = treeWidget != nullptr
        ? treeItemForIndex(treeWidget, sourceIndex)
        : nullptr;
    if (treeWidget == nullptr || sourceItem == nullptr)
    {
        return;
    }

    m_internalModelChange = true;
    QTreeWidgetItem* detailItem = new QTreeWidgetItem(sourceItem);
    detailItem->setData(0, EmbeddedMarkerRole, true);
    detailItem->setFlags(Qt::NoItemFlags);
    detailItem->setFirstColumnSpanned(true);
    QPlainTextEdit* textEditor = createReadOnlyInlineEditor(treeWidget, detailText);
    treeWidget->setItemWidget(detailItem, 0, textEditor);
    sourceItem->setExpanded(true);
    m_internalModelChange = false;

    EmbeddedEntry entry;
    entry.sourceIndex = sourceIndex;
    entry.textEditor = textEditor;
    entry.treeSourceItem = sourceItem;
    entry.treeDetailItem = detailItem;
    m_embeddedEntries.append(entry);
    setSourceExpandedIndicator(sourceIndex, true);
}

bool ks::ui::DetailLayoutHost::removeEmbeddedEntry(
    const QPersistentModelIndex& sourceIndex)
{
    for (int entryIndex = 0; entryIndex < m_embeddedEntries.size(); ++entryIndex)
    {
        EmbeddedEntry& entry = m_embeddedEntries[entryIndex];
        if (!entry.sourceIndex.isValid() || entry.sourceIndex != sourceIndex)
        {
            continue;
        }

        m_internalModelChange = true;
        if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
        {
            for (int rowIndex = tableWidget->rowCount() - 1; rowIndex >= 0; --rowIndex)
            {
                QTableWidgetItem* markerItem = tableWidget->item(rowIndex, 0);
                if (markerItem != nullptr && markerItem->data(EmbeddedMarkerRole).toBool() &&
                    tableWidget->cellWidget(rowIndex, 0) == entry.textEditor.data())
                {
                    tableWidget->removeRow(rowIndex);
                    break;
                }
            }
        }
        else if (entry.treeDetailItem != nullptr)
        {
            delete entry.treeDetailItem;
        }
        m_internalModelChange = false;
        m_embeddedEntries.removeAt(entryIndex);
        if (m_embeddedEntries.isEmpty())
        {
            if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
            {
                if (m_tableSortingStateCaptured)
                {
                    tableWidget->setSortingEnabled(m_tableSortingWasEnabled);
                }
            }
            m_tableSortingStateCaptured = false;
        }
        return true;
    }
    return false;
}

void ks::ui::DetailLayoutHost::clearEmbeddedDetails()
{
    if (m_tableView.isNull())
    {
        m_embeddedEntries.clear();
        return;
    }

    m_internalModelChange = true;
    if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
    {
        tableWidget->setSortingEnabled(false);
        for (int rowIndex = tableWidget->rowCount() - 1; rowIndex >= 0; --rowIndex)
        {
            QTableWidgetItem* markerItem = tableWidget->item(rowIndex, 0);
            if (markerItem != nullptr && markerItem->data(EmbeddedMarkerRole).toBool())
            {
                tableWidget->removeRow(rowIndex);
            }
        }
        if (m_tableSortingStateCaptured)
        {
            tableWidget->setSortingEnabled(m_tableSortingWasEnabled);
        }
    }
    else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data()))
    {
        QList<QTreeWidgetItem*> pendingItems;
        for (int index = 0; index < treeWidget->topLevelItemCount(); ++index)
        {
            pendingItems.append(treeWidget->topLevelItem(index));
        }
        while (!pendingItems.isEmpty())
        {
            QTreeWidgetItem* item = pendingItems.takeLast();
            for (int childIndex = item->childCount() - 1; childIndex >= 0; --childIndex)
            {
                QTreeWidgetItem* childItem = item->child(childIndex);
                if (childItem->data(0, EmbeddedMarkerRole).toBool())
                {
                    delete item->takeChild(childIndex);
                }
                else
                {
                    pendingItems.append(childItem);
                }
            }
        }
    }
    m_internalModelChange = false;
    m_embeddedEntries.clear();
    m_tableSortingStateCaptured = false;
    restoreEmbeddedIndicators();
}

void ks::ui::DetailLayoutHost::prepareDataRebuild()
{
    clearEmbeddedDetails();
}

void ks::ui::DetailLayoutHost::refreshEmbeddedIndicators()
{
    if (m_tableView.isNull() || m_scheme != ks::settings::DetailDisplayScheme::Embedded)
    {
        return;
    }

    const QIcon collapsedIcon = embeddedIndicatorIcon(false);
    if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
    {
        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* firstItem = tableWidget->item(rowIndex, 0);
            if (firstItem == nullptr || firstItem->data(EmbeddedMarkerRole).toBool())
            {
                continue;
            }
            if (!firstItem->data(OriginalDecorationRole).isValid())
            {
                firstItem->setData(OriginalDecorationRole, firstItem->data(Qt::DecorationRole));
            }
            firstItem->setIcon(collapsedIcon);
        }
    }
    else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data()))
    {
        QList<QTreeWidgetItem*> pendingItems;
        for (int index = 0; index < treeWidget->topLevelItemCount(); ++index)
        {
            pendingItems.append(treeWidget->topLevelItem(index));
        }
        while (!pendingItems.isEmpty())
        {
            QTreeWidgetItem* item = pendingItems.takeLast();
            if (!item->data(0, EmbeddedMarkerRole).toBool())
            {
                if (!item->data(0, OriginalDecorationRole).isValid())
                {
                    item->setData(0, OriginalDecorationRole, item->data(0, Qt::DecorationRole));
                }
                item->setIcon(0, collapsedIcon);
            }
            for (int childIndex = 0; childIndex < item->childCount(); ++childIndex)
            {
                pendingItems.append(item->child(childIndex));
            }
        }
    }

    for (const EmbeddedEntry& entry : std::as_const(m_embeddedEntries))
    {
        if (entry.sourceIndex.isValid())
        {
            setSourceExpandedIndicator(entry.sourceIndex, true);
        }
    }
}

void ks::ui::DetailLayoutHost::restoreEmbeddedIndicators()
{
    if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
    {
        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* firstItem = tableWidget->item(rowIndex, 0);
            if (firstItem != nullptr && firstItem->data(OriginalDecorationRole).isValid())
            {
                firstItem->setData(Qt::DecorationRole, firstItem->data(OriginalDecorationRole));
                firstItem->setData(OriginalDecorationRole, QVariant());
            }
        }
    }
    else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data()))
    {
        QList<QTreeWidgetItem*> pendingItems;
        for (int index = 0; index < treeWidget->topLevelItemCount(); ++index)
        {
            pendingItems.append(treeWidget->topLevelItem(index));
        }
        while (!pendingItems.isEmpty())
        {
            QTreeWidgetItem* item = pendingItems.takeLast();
            if (item->data(0, OriginalDecorationRole).isValid())
            {
                item->setData(0, Qt::DecorationRole, item->data(0, OriginalDecorationRole));
                item->setData(0, OriginalDecorationRole, QVariant());
            }
            for (int childIndex = 0; childIndex < item->childCount(); ++childIndex)
            {
                pendingItems.append(item->child(childIndex));
            }
        }
    }
}

void ks::ui::DetailLayoutHost::setSourceExpandedIndicator(
    const QPersistentModelIndex& sourceIndex,
    const bool expanded)
{
    const QIcon stateIcon = embeddedIndicatorIcon(expanded);
    if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
    {
        QTableWidgetItem* firstItem = tableWidget->item(sourceIndex.row(), 0);
        if (firstItem != nullptr)
        {
            firstItem->setIcon(stateIcon);
        }
    }
    else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data()))
    {
        QTreeWidgetItem* sourceItem = treeItemForIndex(treeWidget, sourceIndex);
        if (sourceItem == nullptr)
        {
            for (const EmbeddedEntry& entry : std::as_const(m_embeddedEntries))
            {
                if (entry.sourceIndex == sourceIndex)
                {
                    sourceItem = entry.treeSourceItem;
                    break;
                }
            }
        }
        if (sourceItem != nullptr)
        {
            sourceItem->setIcon(0, stateIcon);
        }
    }
}

void ks::ui::DetailLayoutHost::showFloatingWindow()
{
    if (m_detailEditor.isNull() || m_ownerWidget.isNull())
    {
        return;
    }
    const bool windowWasVisible = !m_floatingWindow.isNull() && m_floatingWindow->isVisible();
    if (m_floatingWindow.isNull())
    {
        QDialog* detailWindow = new QDialog(m_ownerWidget.data(), Qt::Window);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, false);
        detailWindow->setModal(false);
        detailWindow->setWindowTitle(ks::i18n::text(
            QStringLiteral("detail.layout.window.title"),
            QStringLiteral("详情")));
        detailWindow->setStyleSheet(QStringLiteral(
            "QDialog{background:%1;color:%2;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex()));

        QVBoxLayout* windowLayout = new QVBoxLayout(detailWindow);
        windowLayout->setContentsMargins(8, 8, 8, 8);
        CodeEditorWidget* floatingEditor = new CodeEditorWidget(detailWindow);
        floatingEditor->setReadOnly(true);
        floatingEditor->setRawText(m_detailEditor->text());
        windowLayout->addWidget(floatingEditor, 1);

        QScreen* targetScreen = m_ownerWidget->screen();
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (targetScreen != nullptr)
        {
            const QRect availableRect = targetScreen->availableGeometry();
            const QSize initialSize(
                std::max(320, availableRect.width() / 3),
                std::max(240, availableRect.height() / 3));
            detailWindow->resize(initialSize);
            detailWindow->move(availableRect.center() - QPoint(
                initialSize.width() / 2,
                initialSize.height() / 2));
        }

        detailWindow->installEventFilter(this);
        m_floatingWindow = detailWindow;
        m_floatingEditor = floatingEditor;
    }
    else if (!m_floatingEditor.isNull())
    {
        m_floatingEditor->setRawText(m_detailEditor->text());
    }

    // 窗口已显示时只刷新文本，不能因表格选择变化再次抢走焦点。
    // 首次创建或用户关闭后重新唤出时，才执行显示和激活。
    if (!windowWasVisible)
    {
        m_floatingWindow->setWindowOpacity(1.0);
        m_floatingWindow->show();
        m_floatingWindow->raise();
        m_floatingWindow->activateWindow();
    }
}

void ks::ui::DetailLayoutHost::destroyFloatingWindow()
{
    if (!m_floatingWindow.isNull())
    {
        m_floatingWindow->removeEventFilter(this);
        m_floatingWindow->close();
        m_floatingWindow->deleteLater();
    }
    m_floatingEditor.clear();
    m_floatingWindow.clear();
}

bool ks::ui::DetailLayoutHost::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (!m_tableView.isNull() && watchedObject == m_tableView->viewport() &&
        eventObject != nullptr && eventObject->type() == QEvent::ContextMenu)
    {
        const QContextMenuEvent* contextMenuEvent =
            static_cast<const QContextMenuEvent*>(eventObject);
        const QModelIndex contextIndex = m_tableView->indexAt(contextMenuEvent->pos());
        if (isEmbeddedMarker(QPersistentModelIndex(contextIndex)))
        {
            // 合成详情行只允许其 QPlainTextEdit 自己提供复制菜单，不进入业务右键菜单。
            return true;
        }
    }
    if (watchedObject == m_floatingWindow.data() && eventObject != nullptr)
    {
        if (eventObject->type() == QEvent::WindowActivate)
        {
            m_floatingWindow->setWindowOpacity(1.0);
        }
        else if (eventObject->type() == QEvent::WindowDeactivate)
        {
            m_floatingWindow->setWindowOpacity(0.30);
        }
    }
    return QObject::eventFilter(watchedObject, eventObject);
}

bool ks::ui::DetailLayoutHost::isEmbeddedMarker(
    const QPersistentModelIndex& modelIndex) const
{
    return modelIndex.isValid() && modelIndex.sibling(modelIndex.row(), 0)
        .data(EmbeddedMarkerRole).toBool();
}
