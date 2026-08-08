#include "StorageControllerResearchDialog.h"

#include "../../SettingsDock/AppearanceSettings.h"
#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>

namespace ks::misc
{
    StorageControllerResearchDialog::StorageControllerResearchDialog(QWidget* parent)
        : QDialog(parent)
    {
        initializeUi();
        if (!m_client.open())
        {
            appendLog(QStringLiteral(
                "控制器 companion 不可用。仅在设备管理器中将专用非启动控制器手动绑定后才会出现。"));
        }
        refreshState();
    }

    void StorageControllerResearchDialog::initializeUi()
    {
        setWindowTitle(QStringLiteral("控制器研究"));
        resize(940, 720);
        QVBoxLayout* root = new QVBoxLayout(this);

        m_riskLabel = new QLabel(
            QStringLiteral(
                "持续风险提示：此页直接驱动专用控制器的 BAR、DMA/队列或 IDE task-file。"
                "写入可立即破坏文件系统、分区表和启动数据；控制器重置可使设备离线。"
                "仅允许手动绑定的非启动、无挂载卷控制器。expected-hash 条件比较与写后"
                "复读不是硬件原子操作，不能消除设备并发写、固件缓存或掉电风险。"),
            this);
        m_riskLabel->setWordWrap(true);
        m_riskLabel->setStyleSheet(QStringLiteral(
            "QLabel{padding:10px;border:1px solid #D05050;background:#351D1D;color:#FFB0B0;font-weight:600;}"));
        root->addWidget(m_riskLabel);

        QGroupBox* stateGroup = new QGroupBox(QStringLiteral("资源与一致性"), this);
        QVBoxLayout* stateLayout = new QVBoxLayout(stateGroup);
        m_identityLabel = new QLabel(QStringLiteral("控制器：未查询"), stateGroup);
        m_identityLabel->setWordWrap(true);
        m_stateLabel = new QLabel(
            QStringLiteral("ownership=none；coherency=unknown；session=none"),
            stateGroup);
        m_stateLabel->setWordWrap(true);
        stateLayout->addWidget(m_identityLabel);
        stateLayout->addWidget(m_stateLabel);
        root->addWidget(stateGroup);

        QHBoxLayout* sessionLayout = new QHBoxLayout();
        QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新状态"), this);
        m_acquireButton = new QPushButton(QStringLiteral("取得独占会话"), this);
        m_releaseButton = new QPushButton(QStringLiteral("释放会话"), this);
        m_resetButton = new QPushButton(QStringLiteral("受控重置"), this);
        m_acquireButton->setToolTip(QStringLiteral("取得对该存储控制器的独占访问会话，用于底层 BAR/DMA 操作"));
        m_resetButton->setToolTip(QStringLiteral("对存储控制器执行受控复位（可能使设备暂时离线，操作危险）"));
        QPushButton* auditButton = new QPushButton(QStringLiteral("刷新审计"), this);
        sessionLayout->addWidget(refreshButton);
        sessionLayout->addWidget(m_acquireButton);
        sessionLayout->addWidget(m_releaseButton);
        sessionLayout->addWidget(m_resetButton);
        sessionLayout->addWidget(auditButton);
        sessionLayout->addStretch(1);
        root->addLayout(sessionLayout);

        QGroupBox* transferGroup = new QGroupBox(QStringLiteral("事务化原始访问"), this);
        QVBoxLayout* transferLayout = new QVBoxLayout(transferGroup);
        QFormLayout* rangeLayout = new QFormLayout();
        m_offsetEdit = new QLineEdit(QStringLiteral("0x0"), transferGroup);
        m_lengthEdit = new QLineEdit(QStringLiteral("0x1000"), transferGroup);
        rangeLayout->addRow(QStringLiteral("字节偏移"), m_offsetEdit);
        rangeLayout->addRow(QStringLiteral("字节长度"), m_lengthEdit);
        transferLayout->addLayout(rangeLayout);
        m_hexEdit = new QPlainTextEdit(transferGroup);
        m_hexEdit->setPlaceholderText(
            QStringLiteral("读取结果或待写入 HEX，例如：00 11 22 FF"));
        m_hexEdit->setMaximumBlockCount(8192);
        transferLayout->addWidget(m_hexEdit, 1);
        QHBoxLayout* transferButtons = new QHBoxLayout();
        m_readButton = new QPushButton(QStringLiteral("读取并建立条件写快照"), transferGroup);
        m_writeButton = new QPushButton(QStringLiteral("按快照写入并复读验证"), transferGroup);
        m_readButton->setToolTip(QStringLiteral("读取该区间并建立“条件写”比对快照，供后续按快照安全写入"));
        m_writeButton->setToolTip(QStringLiteral("仅当区间内容仍与快照一致时才写入，写完再读回校验，防止误写"));
        m_rollbackButton = new QPushButton(QStringLiteral("回滚最近一次写入"), transferGroup);
        transferButtons->addWidget(m_readButton);
        transferButtons->addWidget(m_writeButton);
        transferButtons->addWidget(m_rollbackButton);
        transferButtons->addStretch(1);
        transferLayout->addLayout(transferButtons);
        root->addWidget(transferGroup, 2);

        m_auditTable = new QTableWidget(this);
        m_auditTable->setColumnCount(7);
        m_auditTable->setHorizontalHeaderLabels({
            QStringLiteral("序号"),
            QStringLiteral("操作"),
            QStringLiteral("偏移"),
            QStringLiteral("长度"),
            QStringLiteral("结果"),
            QStringLiteral("风险"),
            QStringLiteral("进程")
            });
        m_auditTable->horizontalHeader()->setSectionResizeMode(
            QHeaderView::ResizeToContents);
        root->addWidget(m_auditTable, 1);

        m_logEdit = new QPlainTextEdit(this);
        m_logEdit->setReadOnly(true);
        m_logEdit->setMaximumBlockCount(500);
        m_logEdit->setMaximumHeight(120);
        root->addWidget(m_logEdit);

        connect(refreshButton, &QPushButton::clicked, this, [this]() { refreshState(); });
        connect(m_acquireButton, &QPushButton::clicked, this, [this]() { acquireSession(); });
        connect(m_releaseButton, &QPushButton::clicked, this, [this]() { releaseSession(); });
        connect(m_resetButton, &QPushButton::clicked, this, [this]() { resetController(); });
        connect(m_readButton, &QPushButton::clicked, this, [this]() { readRange(); });
        connect(m_writeButton, &QPushButton::clicked, this, [this]() { writeRange(); });
        connect(m_rollbackButton, &QPushButton::clicked, this, [this]() { rollbackRange(); });
        connect(auditButton, &QPushButton::clicked, this, [this]() { refreshAudit(); });
        updateActionState();
    }

    void StorageControllerResearchDialog::refreshState()
    {
        if (!m_client.isOpen() && !m_client.open())
        {
            m_identityLabel->setText(QStringLiteral("控制器：companion 未打开"));
            m_stateLabel->setText(
                QStringLiteral("ownership=none；coherency=unknown；无合法 PnP 资源所有权"));
            updateActionState();
            return;
        }
        applyQuery(m_client.query());
    }

    void StorageControllerResearchDialog::applyQuery(
        const ksword::ark::StorageControllerQueryResult& result)
    {
        if (!result.io.ok)
        {
            appendLog(QStringLiteral("状态查询失败：Win32=%1").arg(result.io.win32Error));
            updateActionState();
            return;
        }
        const auto& response = result.response;
        const QString bdf =
            response.pciBus == KSWORD_ARK_STORAGE_CONTROLLER_INDEX_UNAVAILABLE
            ? QStringLiteral("unavailable")
            : QStringLiteral("%1:%2.%3")
                .arg(response.pciBus)
                .arg(response.pciDevice)
                .arg(response.pciFunction);
        m_generation = response.generation;
        m_capabilities = response.capabilityFlags;
        m_sessionId = response.activeSessionId;
        m_resetRequired =
            response.controllerType ==
                KSWORD_ARK_STORAGE_CONTROLLER_TYPE_NVME &&
            response.status == KSWORD_ARK_STORAGE_CONTROLLER_STATUS_NOT_READY &&
            (response.riskFlags & (
                KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET |
                KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE)) != 0U;
        m_identityLabel->setText(
            QStringLiteral("%1；PCI=%2；型号=%3；序列=%4；容量=%5；扇区=%6；端口/NS=%7")
                .arg(controllerTypeText(response.controllerType))
                .arg(bdf)
                .arg(QString::fromWCharArray(response.model))
                .arg(QString::fromWCharArray(response.serial))
                .arg(static_cast<qulonglong>(response.capacityBytes))
                .arg(response.logicalSectorSize)
                .arg(response.portOrNamespace));
        m_stateLabel->setText(
            QStringLiteral(
                "ownership=%1；coherency=%2；generation=%3；session=0x%4；cap=0x%5；"
                "risk=%6；controller=0x%7；NT=0x%8；%9")
                .arg(ownershipText(response.ownership))
                .arg(coherencyText(response.coherency))
                .arg(response.generation)
                .arg(static_cast<qulonglong>(response.activeSessionId), 0, 16)
                .arg(response.capabilityFlags, 0, 16)
                .arg(riskText(response.riskFlags))
                .arg(response.lastControllerStatus, 0, 16)
                .arg(static_cast<qulonglong>(
                    static_cast<unsigned long>(response.lastStatus)), 0, 16)
                .arg(QString::fromWCharArray(response.detail)));
        updateActionState();
    }

    void StorageControllerResearchDialog::acquireSession()
    {
        if (!confirmDangerousOperation(
                QStringLiteral("取得控制器独占会话"),
                QStringLiteral(
                    "取得会话后命令直接进入当前 companion 独占拥有的控制器。"
                    "若该控制器承载启动盘或挂载卷，继续可能造成掉盘或数据损坏。")))
        {
            return;
        }
        const auto result = m_client.acquire(m_generation);
        if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
        {
            appendLog(QStringLiteral("取得会话失败：Win32=%1 status=%2 NT=0x%3")
                .arg(result.io.win32Error)
                .arg(result.response.status)
                .arg(static_cast<qulonglong>(
                    static_cast<unsigned long>(result.response.lastStatus)), 0, 16));
        }
        m_generation = result.response.newGeneration;
        m_sessionId = result.response.sessionId;
        refreshState();
    }

    void StorageControllerResearchDialog::releaseSession()
    {
        const auto result = m_client.release(m_generation, m_sessionId);
        if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
        {
            appendLog(QStringLiteral("释放会话失败：Win32=%1 status=%2")
                .arg(result.io.win32Error)
                .arg(result.response.status));
        }
        m_generation = result.response.newGeneration;
        m_sessionId = result.response.sessionId;
        refreshState();
    }

    void StorageControllerResearchDialog::resetController()
    {
        if (!confirmDangerousOperation(
                QStringLiteral("受控重置控制器"),
                QStringLiteral(
                    "重置会终止当前硬件队列并使设备短暂离线；未确认写入可能无法恢复。"
                    "重置完成后当前独占会话会失效。")))
        {
            return;
        }
        const auto result = m_client.reset(
            m_generation,
            m_sessionId);
        appendLog(QStringLiteral("重置结果：status=%1 NT=0x%2 risk=%3")
            .arg(result.response.status)
            .arg(static_cast<qulonglong>(
                static_cast<unsigned long>(result.response.lastStatus)), 0, 16)
            .arg(riskText(result.response.riskFlags)));
        m_generation = result.response.newGeneration;
        m_sessionId = result.response.sessionId;
        m_snapshotHash.clear();
        refreshState();
    }

    bool StorageControllerResearchDialog::parseRange(
        std::uint64_t& offset,
        std::uint32_t& length) const
    {
        bool offsetOk = false;
        bool lengthOk = false;
        const QString offsetText = m_offsetEdit->text().trimmed();
        const QString lengthText = m_lengthEdit->text().trimmed();
        offset = offsetText.toULongLong(
            &offsetOk,
            offsetText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        length = lengthText.toUInt(
            &lengthOk,
            lengthText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        return offsetOk && lengthOk && length != 0U &&
            length <= KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES;
    }

    void StorageControllerResearchDialog::readRange()
    {
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        if (!parseRange(offset, length))
        {
            QMessageBox::warning(this, QStringLiteral("控制器研究"), QStringLiteral("偏移或长度无效。"));
            return;
        }
        const auto result = m_client.read(m_generation, m_sessionId, offset, length);
        if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
        {
            appendLog(QStringLiteral("读取失败：Win32=%1 status=%2")
                .arg(result.io.win32Error)
                .arg(result.response.status));
            return;
        }
        const QByteArray bytes(
            reinterpret_cast<const char*>(result.bytes.data()),
            static_cast<qsizetype>(result.bytes.size()));
        m_hexEdit->setPlainText(QString::fromLatin1(bytes.toHex(' ')).toUpper());
        m_snapshotOffset = offset;
        m_snapshotLength = length;
        m_snapshotHash.assign(
            result.response.afterHash,
            result.response.afterHash + KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES);
        appendLog(QStringLiteral("读取 %1 字节；expected-hash=%2")
            .arg(result.bytes.size())
            .arg(hashText(result.response.afterHash)));
        updateActionState();
    }

    void StorageControllerResearchDialog::writeRange()
    {
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        if (!parseRange(offset, length))
        {
            QMessageBox::warning(this, QStringLiteral("控制器研究"), QStringLiteral("偏移或长度无效。"));
            return;
        }
        QByteArray hex = m_hexEdit->toPlainText().toLatin1();
        hex.replace(" ", "");
        hex.replace("\r", "");
        hex.replace("\n", "");
        hex.replace("\t", "");
        const QByteArray payload = QByteArray::fromHex(hex);
        if (payload.size() != static_cast<qsizetype>(length) ||
            m_snapshotOffset != offset ||
            m_snapshotLength != length ||
            m_snapshotHash.size() != KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("控制器研究"),
                QStringLiteral("写入字节必须与长度一致，并先对完全相同的范围建立条件写快照。"));
            return;
        }
        if (!confirmDangerousOperation(
                QStringLiteral("直接控制器写入"),
                QStringLiteral(
                    "即将绕过 Windows 存储栈写入专用控制器。操作会执行原数据哈希比较、"
                    "写入、flush 和复读验证，但仍可能永久损坏介质内容。")))
        {
            return;
        }
        const std::vector<std::uint8_t> bytes(
            reinterpret_cast<const std::uint8_t*>(payload.constData()),
            reinterpret_cast<const std::uint8_t*>(payload.constData()) + payload.size());
        std::uint32_t writeFlags =
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FLUSH;
        if ((m_capabilities &
             KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA) != 0U)
        {
            writeFlags |= KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA;
        }
        const auto result = m_client.write(
            m_generation,
            m_sessionId,
            offset,
            bytes,
            m_snapshotHash,
            writeFlags);
        appendLog(QStringLiteral("写入结果：status=%1 bytes=%2 before=%3 after=%4 risk=%5")
            .arg(result.response.status)
            .arg(result.response.bytesTransferred)
            .arg(hashText(result.response.beforeHash))
            .arg(hashText(result.response.afterHash))
            .arg(riskText(result.response.riskFlags)));
        m_generation = result.response.generation;
        m_snapshotHash.clear();
        refreshState();
    }

    void StorageControllerResearchDialog::rollbackRange()
    {
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        if (!parseRange(offset, length))
        {
            return;
        }
        if (!confirmDangerousOperation(
                QStringLiteral("回滚控制器写入"),
                QStringLiteral(
                    "回滚本身也是直接写盘。驱动会先确认当前字节仍等于最近写入结果，"
                    "再恢复原始快照并复读验证。")))
        {
            return;
        }
        const auto result = m_client.rollback(
            m_generation,
            m_sessionId,
            offset,
            length);
        appendLog(QStringLiteral("回滚结果：status=%1 bytes=%2 risk=%3")
            .arg(result.response.status)
            .arg(result.response.bytesTransferred)
            .arg(riskText(result.response.riskFlags)));
        m_generation = result.response.generation;
        refreshState();
    }

    void StorageControllerResearchDialog::refreshAudit()
    {
        const auto result = m_client.queryAudit();
        if (!result.io.ok)
        {
            appendLog(QStringLiteral("审计读取失败：Win32=%1").arg(result.io.win32Error));
            return;
        }
        m_auditTable->setRowCount(static_cast<int>(result.response.rowCount));
        for (unsigned long index = 0U; index < result.response.rowCount; ++index)
        {
            const auto& row = result.response.rows[index];
            const QString operation = row.operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ
                ? QStringLiteral("读取")
                : row.operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE
                    ? QStringLiteral("写入")
                    : QStringLiteral("回滚");
            const QStringList values = {
                QString::number(static_cast<qulonglong>(row.sequence)),
                operation,
                QStringLiteral("0x%1").arg(static_cast<qulonglong>(row.offset), 0, 16),
                QString::number(row.length),
                QString::number(row.status),
                riskText(row.riskFlags),
                QString::number(row.processId)
                };
            for (int column = 0; column < values.size(); ++column)
            {
                QTableWidgetItem* item = new QTableWidgetItem(values[column]);
                item->setFlags(item->flags() & ~Qt::ItemIsEditable);
                m_auditTable->setItem(static_cast<int>(index), column, item);
            }
        }
    }

    bool StorageControllerResearchDialog::confirmDangerousOperation(
        const QString& title,
        const QString& detail)
    {
        if (ks::settings::dangerousActionConfirmationsSuppressed())
        {
            appendLog(QStringLiteral("重复模态确认已关闭；持续风险提示、确认令牌、expected-hash 和审计仍然生效。"));
            return true;
        }
        return QMessageBox::warning(
            this,
            title,
            detail,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) == QMessageBox::Yes;
    }

    void StorageControllerResearchDialog::appendLog(const QString& message)
    {
        m_logEdit->appendPlainText(
            QStringLiteral("[%1] %2")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
                .arg(message));
    }

    void StorageControllerResearchDialog::updateActionState()
    {
        const bool open = m_client.isOpen();
        const bool session = open && m_sessionId != 0ULL;
        m_acquireButton->setEnabled(open && !session);
        m_releaseButton->setEnabled(session);
        m_resetButton->setEnabled(open && (session || m_resetRequired));
        m_readButton->setEnabled(session);
        m_writeButton->setEnabled(
            session &&
            m_snapshotHash.size() == KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES);
        m_rollbackButton->setEnabled(session);
    }

    QString StorageControllerResearchDialog::ownershipText(const unsigned long ownership)
    {
        if (ownership == KSWORD_ARK_STORAGE_OWNERSHIP_EXCLUSIVE)
        {
            return QStringLiteral("exclusive");
        }
        if (ownership == KSWORD_ARK_STORAGE_OWNERSHIP_SHARED_UNSUPPORTED)
        {
            return QStringLiteral("shared-unsupported");
        }
        return QStringLiteral("none");
    }

    QString StorageControllerResearchDialog::coherencyText(const unsigned long coherency)
    {
        if (coherency == KSWORD_ARK_STORAGE_COHERENCY_EXCLUSIVE)
        {
            return QStringLiteral("exclusive");
        }
        if (coherency == KSWORD_ARK_STORAGE_COHERENCY_UNPROVABLE)
        {
            return QStringLiteral("unprovable");
        }
        return QStringLiteral("unknown");
    }

    QString StorageControllerResearchDialog::riskText(const unsigned long flags)
    {
        if (flags == 0U)
        {
            return QStringLiteral("none");
        }
        QStringList rows;
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_SHARED_OWNER) != 0U) rows << QStringLiteral("shared-owner");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_COHERENCY_UNPROVABLE) != 0U) rows << QStringLiteral("coherency-unprovable");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_SYSTEM_DISK) != 0U) rows << QStringLiteral("system-disk");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_LIVE_VOLUMES) != 0U) rows << QStringLiteral("live-volume");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET) != 0U) rows << QStringLiteral("controller-reset");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE) != 0U) rows << QStringLiteral("recovery-unproven");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_WRITE) != 0U) rows << QStringLiteral("write");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_FORCE_USED) != 0U) rows << QStringLiteral("force-used");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_IDENTITY_CHANGED) != 0U) rows << QStringLiteral("identity-changed");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_BEFORE_MISMATCH) != 0U) rows << QStringLiteral("expected-hash-mismatch");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED) != 0U) rows << QStringLiteral("verify-failed");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_TIMEOUT) != 0U) rows << QStringLiteral("timeout");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_SYSTEM_DISK_UNKNOWN) != 0U) rows << QStringLiteral("system-disk-unverified");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_LIVE_VOLUMES_UNKNOWN) != 0U) rows << QStringLiteral("live-volumes-unverified");
        return rows.join(QLatin1Char('|'));
    }

    QString StorageControllerResearchDialog::controllerTypeText(const unsigned long type)
    {
        if (type == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_AHCI) return QStringLiteral("AHCI");
        if (type == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_NVME) return QStringLiteral("NVMe");
        if (type == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_IDE) return QStringLiteral("IDE");
        return QStringLiteral("Unknown");
    }

    QString StorageControllerResearchDialog::hashText(const unsigned char* hash)
    {
        const QByteArray bytes(
            reinterpret_cast<const char*>(hash),
            KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES);
        return QString::fromLatin1(bytes.toHex()).toUpper();
    }
}
