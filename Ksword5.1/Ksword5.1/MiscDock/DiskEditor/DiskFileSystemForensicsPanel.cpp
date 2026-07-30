#include "DiskFileSystemForensicsPanel.h"

#include "../../ArkDriverClient/ArkDriverTypes.h"
#include "../../theme.h"
#include "../../UI/VisibleTableWidget.h"

#include <QAbstractItemView>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>
#include <utility>

namespace
{
    QString hexOffset(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QTableWidget* createTable(
        QWidget* parent,
        const QStringList& headers)
    {
        auto* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setAlternatingRowColors(true);
        table->horizontalHeader()->setStretchLastSection(true);
        table->setStyleSheet(QStringLiteral(
            "QTableWidget{border:1px solid %1;border-radius:6px;"
            "background:%2;alternate-background-color:%3;color:%4;}"
            "QHeaderView::section{border:none;border-bottom:1px solid %1;"
            "background:transparent;color:%5;padding:5px;font-weight:700;}")
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::SurfaceColorHex())
            .arg(KswordTheme::SurfaceAltColorHex())
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue)));
        return table;
    }

    bool parseUnsignedAddress(
        const QString& text,
        std::uint64_t& valueOut)
    {
        QString normalized = text.trimmed();
        int base = 10;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2);
            base = 16;
        }
        bool ok = false;
        const qulonglong parsed = normalized.toULongLong(&ok, base);
        if (!ok)
        {
            return false;
        }
        valueOut = parsed;
        return true;
    }
}

namespace ks::misc
{
    DiskFileSystemForensicsPanel::DiskFileSystemForensicsPanel(
        SelectionProvider selectionProvider,
        JumpCallback jumpCallback,
        QWidget* parent)
        : QWidget(parent)
        , m_selectionProvider(std::move(selectionProvider))
        , m_jumpCallback(std::move(jumpCallback))
    {
        initializeUi();
        initializeConnections();
    }

    void DiskFileSystemForensicsPanel::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(4, 4, 4, 4);
        rootLayout->setSpacing(6);

        auto* probeGroup = new QGroupBox(
            QStringLiteral("分区文件系统原始探测"),
            this);
        auto* probeLayout = new QVBoxLayout(probeGroup);
        auto* probeToolbar = new QGridLayout();
        m_probeButton = new QPushButton(
            QStringLiteral("探测当前分区"),
            probeGroup);
        m_probeButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_probeSummaryLabel = new QLabel(
            QStringLiteral(
                "支持 NTFS、FAT12/16/32、exFAT、ReFS、Ext2/3/4、"
                "BtrFS、APFS、HFS/HFS+ 的原始只读元数据探测。"),
            probeGroup);
        m_probeSummaryLabel->setWordWrap(true);
        probeToolbar->addWidget(m_probeButton, 0, 0);
        probeToolbar->addWidget(m_probeSummaryLabel, 0, 1);
        probeLayout->addLayout(probeToolbar);
        m_probeTable = createTable(probeGroup, {
            QStringLiteral("字段"),
            QStringLiteral("值"),
            QStringLiteral("绝对偏移"),
            QStringLiteral("长度"),
            QStringLiteral("说明")
            });
        probeLayout->addWidget(m_probeTable, 1);
        rootLayout->addWidget(probeGroup, 2);

        auto* deletedGroup = new QGroupBox(
            QStringLiteral("删除目录项取证与精确区间擦除"),
            this);
        auto* deletedLayout = new QVBoxLayout(deletedGroup);
        auto* deletedToolbar = new QGridLayout();
        m_deletedScanButton = new QPushButton(
            QStringLiteral("扫描 FAT/exFAT 删除项"),
            deletedGroup);
        m_deletedEraseButton = new QPushButton(
            QStringLiteral("安全擦除选中精确区间"),
            deletedGroup);
        m_deletedEraseButton->setEnabled(false);
        m_deletedScanButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_deletedEraseButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_deletedSummaryLabel = new QLabel(
            QStringLiteral(
                "NTFS 删除项由“文件管理 → 文件恢复”扫描；"
                "此处补充 FAT12/16/32 与 exFAT，并只允许擦除已证明精确且当前空闲的离线磁盘区间。"),
            deletedGroup);
        m_deletedSummaryLabel->setWordWrap(true);
        deletedToolbar->addWidget(m_deletedScanButton, 0, 0);
        deletedToolbar->addWidget(m_deletedEraseButton, 0, 1);
        deletedToolbar->addWidget(m_deletedSummaryLabel, 0, 2);
        deletedLayout->addLayout(deletedToolbar);
        m_deletedTable = createTable(deletedGroup, {
            QStringLiteral("名称"),
            QStringLiteral("原目录"),
            QStringLiteral("大小"),
            QStringLiteral("首簇"),
            QStringLiteral("目录项偏移"),
            QStringLiteral("精确区间"),
            QStringLiteral("擦除资格"),
            QStringLiteral("证据")
            });
        deletedLayout->addWidget(m_deletedTable, 1);
        rootLayout->addWidget(deletedGroup, 2);

        auto* extentGroup = new QGroupBox(
            QStringLiteral("文件物理区间与磁盘定位"),
            this);
        auto* extentLayout = new QVBoxLayout(extentGroup);
        auto* extentToolbar = new QGridLayout();
        m_filePathEdit = new QLineEdit(extentGroup);
        m_filePathEdit->setPlaceholderText(
            QStringLiteral("选择 Windows 已挂载卷中的文件或目录"));
        m_fileBrowseButton = new QPushButton(
            QStringLiteral("选择文件"),
            extentGroup);
        m_extentButton = new QPushButton(
            QStringLiteral("解析物理区间"),
            extentGroup);
        m_fileBrowseButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_extentButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        extentToolbar->addWidget(m_filePathEdit, 0, 0);
        extentToolbar->addWidget(m_fileBrowseButton, 0, 1);
        extentToolbar->addWidget(m_extentButton, 0, 2);
        extentLayout->addLayout(extentToolbar);
        m_extentTable = createTable(extentGroup, {
            QStringLiteral("磁盘"),
            QStringLiteral("文件偏移"),
            QStringLiteral("VCN"),
            QStringLiteral("LCN"),
            QStringLiteral("物理偏移"),
            QStringLiteral("长度"),
            QStringLiteral("状态")
            });
        extentLayout->addWidget(m_extentTable, 1);
        rootLayout->addWidget(extentGroup, 2);

        auto* reverseGroup = new QGroupBox(
            QStringLiteral("按卷簇号反查文件流"),
            this);
        auto* reverseLayout = new QVBoxLayout(reverseGroup);
        auto* reverseToolbar = new QGridLayout();
        m_volumePathEdit = new QLineEdit(
            QStringLiteral("C:"),
            reverseGroup);
        m_volumePathEdit->setPlaceholderText(
            QStringLiteral("卷路径，例如 C: 或 \\\\?\\Volume{GUID}\\"));
        m_clusterEdit = new QLineEdit(
            QStringLiteral("0"),
            reverseGroup);
        m_clusterEdit->setPlaceholderText(
            QStringLiteral("LCN，支持十进制或 0x"));
        m_reverseButton = new QPushButton(
            QStringLiteral("反查占用文件"),
            reverseGroup);
        m_reverseButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        reverseToolbar->addWidget(
            new QLabel(QStringLiteral("卷"), reverseGroup),
            0,
            0);
        reverseToolbar->addWidget(m_volumePathEdit, 0, 1);
        reverseToolbar->addWidget(
            new QLabel(QStringLiteral("簇号"), reverseGroup),
            0,
            2);
        reverseToolbar->addWidget(m_clusterEdit, 0, 3);
        reverseToolbar->addWidget(m_reverseButton, 0, 4);
        reverseLayout->addLayout(reverseToolbar);
        m_reverseTable = createTable(reverseGroup, {
            QStringLiteral("簇号"),
            QStringLiteral("簇数量"),
            QStringLiteral("文件流路径")
            });
        reverseLayout->addWidget(m_reverseTable, 1);
        rootLayout->addWidget(reverseGroup, 1);
    }

    void DiskFileSystemForensicsPanel::initializeConnections()
    {
        connect(m_probeButton, &QPushButton::clicked, this, [this]()
        {
            probeCurrentPartition();
        });
        connect(m_fileBrowseButton, &QPushButton::clicked, this, [this]()
        {
            const QString selected = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择要解析物理区间的文件"),
                m_filePathEdit->text());
            if (!selected.isEmpty())
            {
                m_filePathEdit->setText(selected);
            }
        });
        connect(m_extentButton, &QPushButton::clicked, this, [this]()
        {
            resolveCurrentFile();
        });
        connect(m_reverseButton, &QPushButton::clicked, this, [this]()
        {
            reverseLookupCurrentCluster();
        });
        connect(m_deletedScanButton, &QPushButton::clicked, this, [this]()
        {
            scanDeletedEntries();
        });
        connect(m_deletedEraseButton, &QPushButton::clicked, this, [this]()
        {
            eraseSelectedDeletedEntry();
        });
        connect(m_probeTable, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            const QTableWidgetItem* item = m_probeTable->item(row, 2);
            if (item != nullptr && m_jumpCallback)
            {
                m_jumpCallback(item->data(Qt::UserRole).toULongLong());
            }
        });
        connect(m_extentTable, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            const QTableWidgetItem* item = m_extentTable->item(row, 4);
            if (item != nullptr
                && item->data(Qt::UserRole + 1).toBool()
                && m_jumpCallback)
            {
                m_jumpCallback(item->data(Qt::UserRole).toULongLong());
            }
        });
        connect(
            m_deletedTable,
            &QTableWidget::itemSelectionChanged,
            this,
            [this]()
            {
                const int row = m_deletedTable->currentRow();
                const bool eligible =
                    row >= 0
                    && row < static_cast<int>(m_deletedEntries.size())
                    && m_deletedEntries[static_cast<std::size_t>(row)]
                        .exactExtents
                    && m_deletedEntries[static_cast<std::size_t>(row)]
                        .clustersCurrentlyFree;
                m_deletedEraseButton->setEnabled(!m_busy && eligible);
            });
        connect(
            m_deletedTable,
            &QTableWidget::cellDoubleClicked,
            this,
            [this](const int row, const int column)
            {
                Q_UNUSED(column);
                if (row < 0
                    || row >= static_cast<int>(m_deletedEntries.size())
                    || !m_jumpCallback)
                {
                    return;
                }
                const DeletedDirectoryEntry& entry =
                    m_deletedEntries[static_cast<std::size_t>(row)];
                const std::uint64_t offset = !entry.extents.empty()
                    ? entry.extents.front().physicalOffset
                    : entry.directoryEntryOffset;
                m_jumpCallback(offset);
            });
    }

    void DiskFileSystemForensicsPanel::probeCurrentPartition()
    {
        if (m_busy)
        {
            return;
        }
        const std::optional<DiskForensicsSelection> selection =
            m_selectionProvider ? m_selectionProvider() : std::nullopt;
        if (!selection.has_value())
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件系统取证"),
                QStringLiteral("请先在磁盘图或分区表中选择一个有效分区。"));
            return;
        }

        m_busy = true;
        m_probeButton->setEnabled(false);
        m_probeSummaryLabel->setText(
            QStringLiteral("正在探测 %1 ...").arg(selection->displayText));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selectionValue = *selection]()
        {
            FileSystemProbeResult result =
                DiskFileSystemForensics::probePartition(
                    selectionValue.diskIndex,
                    selectionValue.backend,
                    selectionValue.partitionOffset,
                    selectionValue.partitionLength,
                    selectionValue.logicalSectorSize);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyProbeResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::resolveCurrentFile()
    {
        if (m_busy)
        {
            return;
        }
        const QString filePath = m_filePathEdit->text().trimmed();
        if (filePath.isEmpty())
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件物理区间"),
                QStringLiteral("请先选择一个文件。"));
            return;
        }

        m_busy = true;
        m_extentButton->setEnabled(false);
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, filePath]()
        {
            FileExtentResult result =
                DiskFileSystemForensics::resolveFileExtents(filePath);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyExtentResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::reverseLookupCurrentCluster()
    {
        if (m_busy)
        {
            return;
        }
        std::uint64_t cluster = 0;
        if (!parseUnsignedAddress(m_clusterEdit->text(), cluster))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("簇号反查"),
                QStringLiteral("簇号格式无效。"));
            return;
        }

        const QString volumePath = m_volumePathEdit->text().trimmed();
        m_busy = true;
        m_reverseButton->setEnabled(false);
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, volumePath, cluster]()
        {
            ReverseClusterResult result =
                DiskFileSystemForensics::reverseLookupCluster(
                    volumePath,
                    cluster);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyReverseResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::scanDeletedEntries()
    {
        if (m_busy)
        {
            return;
        }
        const std::optional<DiskForensicsSelection> selection =
            m_selectionProvider ? m_selectionProvider() : std::nullopt;
        if (!selection.has_value())
        {
            QMessageBox::information(
                this,
                QStringLiteral("删除目录项取证"),
                QStringLiteral("请先在磁盘图或分区表中选择一个有效分区。"));
            return;
        }

        m_busy = true;
        m_deletedScanButton->setEnabled(false);
        m_deletedEraseButton->setEnabled(false);
        m_deletedSummaryLabel->setText(
            QStringLiteral("正在扫描 %1 的原始目录项 ...")
                .arg(selection->displayText));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selectionValue = *selection]()
        {
            DeletedEntryScanResult result =
                DiskDeletedEntryForensics::scan(
                    selectionValue.diskIndex,
                    selectionValue.backend,
                    selectionValue.partitionOffset,
                    selectionValue.partitionLength,
                    selectionValue.logicalSectorSize);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis,
                    selectionValue,
                    result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyDeletedResult(
                            selectionValue,
                            std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::eraseSelectedDeletedEntry()
    {
        if (m_busy || !m_deletedSelection.has_value())
        {
            return;
        }
        const int row = m_deletedTable->currentRow();
        if (row < 0 || row >= static_cast<int>(m_deletedEntries.size()))
        {
            return;
        }
        const DeletedDirectoryEntry entry =
            m_deletedEntries[static_cast<std::size_t>(row)];
        const DiskForensicsSelection selection = *m_deletedSelection;
        if (!entry.exactExtents || !entry.clustersCurrentlyFree)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral(
                    "该条目没有同时通过簇链/连续标志、分区边界和当前空闲状态校验，不能擦除。"));
            return;
        }
        if ((selection.capabilityFlags
                & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral("系统磁盘上的删除区间擦除被永久阻止。"));
            return;
        }
        if ((selection.capabilityFlags
                & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) == 0U)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral(
                    "目标磁盘必须先在 Windows 磁盘管理中切换为“脱机”。"
                    "这样可以避免文件系统缓存或重新分配与原始写入竞争。"));
            return;
        }

        std::uint64_t totalBytes = 0;
        for (const DeletedFileExtent& extent : entry.extents)
        {
            totalBytes += extent.lengthBytes;
        }
        const QMessageBox::StandardButton warningResult =
            QMessageBox::warning(
                this,
                QStringLiteral("不可逆精确区间擦除"),
                QStringLiteral(
                    "即将对离线磁盘中的 %1 个精确物理区间写零并逐块回读校验，"
                    "共 %2 字节。该操作不可撤销，且删除文件数据将无法恢复。\n\n"
                    "条目：%3/%4\n证据：%5")
                    .arg(entry.extents.size())
                    .arg(static_cast<qulonglong>(totalBytes))
                    .arg(entry.directoryPath)
                    .arg(entry.name)
                    .arg(entry.evidenceText),
                QMessageBox::Yes | QMessageBox::Cancel,
                QMessageBox::Cancel);
        if (warningResult != QMessageBox::Yes)
        {
            return;
        }

        bool accepted = false;
        const QString confirmation = QInputDialog::getText(
            this,
            QStringLiteral("输入最终确认短语"),
            QStringLiteral("请输入 ERASE EXACT EXTENTS 继续："),
            QLineEdit::Normal,
            QString(),
            &accepted);
        if (!accepted
            || confirmation.trimmed()
                != QStringLiteral("ERASE EXACT EXTENTS"))
        {
            QMessageBox::information(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral("确认短语不匹配，未执行任何写入。"));
            return;
        }

        m_busy = true;
        m_deletedScanButton->setEnabled(false);
        m_deletedEraseButton->setEnabled(false);
        m_deletedSummaryLabel->setText(
            QStringLiteral("正在写零并回读校验 %1/%2 ...")
                .arg(entry.directoryPath)
                .arg(entry.name));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selection, entry]()
        {
            ExtentEraseResult result =
                DiskDeletedEntryForensics::eraseExactFreeExtents(
                    selection.diskIndex,
                    selection.backend,
                    selection.logicalSectorSize,
                    KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE |
                        KSWORD_ARK_RAW_DISK_FLAG_FUA,
                    entry);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyEraseResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::applyProbeResult(
        FileSystemProbeResult result)
    {
        m_busy = false;
        m_probeButton->setEnabled(true);
        m_probeTable->setRowCount(0);
        if (!result.success)
        {
            m_probeSummaryLabel->setText(
                QStringLiteral("探测失败：%1").arg(result.errorText));
            return;
        }

        m_probeSummaryLabel->setText(
            QStringLiteral(
                "%1 | 扇区=%2 B | 块/簇=%3 B | 容量=%4 B | 能力：%5")
                .arg(result.name)
                .arg(result.logicalSectorSize)
                .arg(result.blockSize)
                .arg(static_cast<qulonglong>(result.totalBytes))
                .arg(result.capabilityText));
        m_probeTable->setRowCount(
            static_cast<int>(result.fields.size()));
        for (int row = 0; row < static_cast<int>(result.fields.size()); ++row)
        {
            const FileSystemProbeField& field =
                result.fields[static_cast<std::size_t>(row)];
            m_probeTable->setItem(row, 0, readOnlyItem(field.name));
            m_probeTable->setItem(row, 1, readOnlyItem(field.value));
            auto* offsetItem = readOnlyItem(hexOffset(field.absoluteOffset));
            offsetItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(field.absoluteOffset));
            m_probeTable->setItem(row, 2, offsetItem);
            m_probeTable->setItem(
                row,
                3,
                readOnlyItem(QString::number(field.sizeBytes)));
            m_probeTable->setItem(row, 4, readOnlyItem(field.detail));
        }
        m_probeTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyExtentResult(
        FileExtentResult result)
    {
        m_busy = false;
        m_extentButton->setEnabled(true);
        m_extentTable->setRowCount(0);
        if (!result.success)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("文件物理区间"),
                result.errorText);
            return;
        }

        m_extentTable->setRowCount(
            static_cast<int>(result.extents.size()));
        for (int row = 0; row < static_cast<int>(result.extents.size()); ++row)
        {
            const PhysicalFileExtent& extent =
                result.extents[static_cast<std::size_t>(row)];
            m_extentTable->setItem(
                row,
                0,
                readOnlyItem(extent.diskNumber >= 0
                    ? QStringLiteral("PhysicalDrive%1").arg(extent.diskNumber)
                    : QStringLiteral("-")));
            m_extentTable->setItem(row, 1, readOnlyItem(hexOffset(extent.fileOffset)));
            m_extentTable->setItem(row, 2, readOnlyItem(QString::number(extent.startingVcn)));
            m_extentTable->setItem(row, 3, readOnlyItem(extent.sparse ? QStringLiteral("Sparse") : QString::number(extent.startingLcn)));
            auto* physicalItem = readOnlyItem(extent.physicalMappingExact
                ? hexOffset(extent.physicalOffset)
                : QStringLiteral("-"));
            physicalItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(extent.physicalOffset));
            physicalItem->setData(
                Qt::UserRole + 1,
                extent.physicalMappingExact);
            m_extentTable->setItem(row, 4, physicalItem);
            m_extentTable->setItem(row, 5, readOnlyItem(QString::number(extent.lengthBytes)));
            m_extentTable->setItem(
                row,
                6,
                readOnlyItem(extent.sparse
                    ? QStringLiteral("稀疏区间")
                    : (extent.physicalMappingExact
                        ? QStringLiteral("可跳转")
                        : QStringLiteral("多区间卷，仅返回卷内 LCN"))));
        }
        m_extentTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyReverseResult(
        ReverseClusterResult result)
    {
        m_busy = false;
        m_reverseButton->setEnabled(true);
        m_reverseTable->setRowCount(0);
        if (!result.success)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("簇号反查"),
                result.errorText);
            return;
        }

        m_reverseTable->setRowCount(
            static_cast<int>(result.entries.size()));
        for (int row = 0; row < static_cast<int>(result.entries.size()); ++row)
        {
            const ReverseClusterEntry& entry =
                result.entries[static_cast<std::size_t>(row)];
            m_reverseTable->setItem(row, 0, readOnlyItem(QString::number(entry.cluster)));
            m_reverseTable->setItem(row, 1, readOnlyItem(QString::number(entry.clusterCount)));
            m_reverseTable->setItem(row, 2, readOnlyItem(entry.streamPath));
        }
        m_reverseTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyDeletedResult(
        DiskForensicsSelection selection,
        DeletedEntryScanResult result)
    {
        m_busy = false;
        m_deletedScanButton->setEnabled(true);
        m_deletedEraseButton->setEnabled(false);
        m_deletedTable->setRowCount(0);
        m_deletedEntries.clear();
        m_deletedSelection.reset();
        if (!result.success)
        {
            m_deletedSummaryLabel->setText(
                QStringLiteral("删除项扫描失败：%1").arg(result.errorText));
            return;
        }

        m_deletedSummaryLabel->setText(result.summaryText);
        m_deletedSelection = std::move(selection);
        m_deletedEntries = std::move(result.entries);
        m_deletedTable->setRowCount(
            static_cast<int>(m_deletedEntries.size()));
        for (int row = 0;
             row < static_cast<int>(m_deletedEntries.size());
             ++row)
        {
            const DeletedDirectoryEntry& entry =
                m_deletedEntries[static_cast<std::size_t>(row)];
            m_deletedTable->setItem(row, 0, readOnlyItem(entry.name));
            m_deletedTable->setItem(
                row,
                1,
                readOnlyItem(entry.directoryPath));
            m_deletedTable->setItem(
                row,
                2,
                readOnlyItem(QString::number(entry.fileSizeBytes)));
            m_deletedTable->setItem(
                row,
                3,
                readOnlyItem(QString::number(entry.firstCluster)));
            m_deletedTable->setItem(
                row,
                4,
                readOnlyItem(hexOffset(entry.directoryEntryOffset)));

            QStringList extentTexts;
            for (const DeletedFileExtent& extent : entry.extents)
            {
                extentTexts.push_back(
                    QStringLiteral("%1+%2")
                        .arg(hexOffset(extent.physicalOffset))
                        .arg(static_cast<qulonglong>(extent.lengthBytes)));
            }
            m_deletedTable->setItem(
                row,
                5,
                readOnlyItem(extentTexts.isEmpty()
                    ? QStringLiteral("-")
                    : extentTexts.join(QStringLiteral("; "))));
            m_deletedTable->setItem(
                row,
                6,
                readOnlyItem(entry.exactExtents
                        && entry.clustersCurrentlyFree
                        && !entry.directory
                    ? QStringLiteral("离线磁盘可擦除")
                    : QStringLiteral("只读取证")));
            m_deletedTable->setItem(
                row,
                7,
                readOnlyItem(entry.evidenceText));
        }
        m_deletedTable->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyEraseResult(
        ExtentEraseResult result)
    {
        m_busy = false;
        m_deletedScanButton->setEnabled(true);
        m_deletedEraseButton->setEnabled(false);
        if (!result.success)
        {
            m_deletedSummaryLabel->setText(
                QStringLiteral("精确区间擦除失败：%1")
                    .arg(result.errorText));
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                result.errorText);
            return;
        }

        m_deletedSummaryLabel->setText(
            QStringLiteral(
                "精确区间擦除完成：%1 个区间，%2 字节均已写零并回读验证。请重新扫描刷新分配状态。")
                .arg(result.extentsErased)
                .arg(static_cast<qulonglong>(result.bytesErased)));
        QMessageBox::information(
            this,
            QStringLiteral("精确区间擦除"),
            m_deletedSummaryLabel->text());
    }
}
