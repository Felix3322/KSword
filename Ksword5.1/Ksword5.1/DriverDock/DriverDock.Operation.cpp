#include "DriverDock.Internal.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../OnlineScan/SandboxUploadActions.h"

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::driver_dock_internal;

namespace
{
    QString driverOperationTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // driverOperationTableCellText：
        // - 输入：表格、行号、列号；
        // - 处理：安全读取单元格文本；
        // - 返回：单元格不存在时返回空字符串。
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    void copyDriverOperationCurrentRow(QTableWidget* table)
    {
        // copyDriverOperationCurrentRow：
        // - 输入：服务表或模块表；
        // - 处理：复制当前行 TSV；
        // - 返回：无，不触发任何驱动操作。
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            fields.push_back(driverOperationTableCellText(table, rowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    QString buildKernelSignatureNtPath(const QString& rawPathText)
    {
        QString pathText = ks::online_scan::normalizeKernelImagePathForUpload(rawPathText).trimmed();
        pathText.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (pathText.isEmpty())
        {
            return QString();
        }
        if (pathText.startsWith(QStringLiteral("\\??\\")) ||
            pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive) ||
            pathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
        {
            return pathText;
        }
        if (pathText.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + pathText.mid(4);
        }
        if (pathText.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + pathText.mid(2);
        }
        return QStringLiteral("\\??\\") + pathText;
    }

    // integrityClassText：
    // - 输入：Driver Integrity 证据类别常量；
    // - 处理：把类别映射为 DriverDock 侧可读文本；
    // - 返回：类别名称，未知值保留数值信息。
    QString integrityClassText(const std::uint32_t evidenceClass)
    {
        switch (evidenceClass)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return QStringLiteral("ModuleView");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return QStringLiteral("PsLoadedModules");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return QStringLiteral("DriverObject");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return QStringLiteral("DriverSection");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return QStringLiteral("MajorFunction");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return QStringLiteral("FastIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return QStringLiteral("DeviceChain");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return QStringLiteral("Service");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return QStringLiteral("CPU");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return QStringLiteral("Descriptor");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return QStringLiteral("MSR");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return QStringLiteral("IDT");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return QStringLiteral("OptionalGlobal");
        default: return QStringLiteral("Class(%1)").arg(evidenceClass);
        }
    }

    // integrityRiskText：
    // - 输入：Driver Integrity 风险位；
    // - 处理：转换为短文本，便于在证据页直接浏览；
    // - 返回：空风险显示“正常”。
    QString integrityRiskText(const std::uint32_t flags)
    {
        if (flags == 0U)
        {
            return driverText("driver.integrity.risk.normal", QStringLiteral("正常"));
        }
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.unavailable", QStringLiteral("不可用"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED)
            parts << driverText("driver.integrity.risk.query_failed", QStringLiteral("查询失败"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED)
            parts << driverText("driver.integrity.risk.module_unresolved", QStringLiteral("模块未解析"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH)
            parts << driverText("driver.integrity.risk.owner_mismatch", QStringLiteral("Owner不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE)
            parts << driverText("driver.integrity.risk.outside_image", QStringLiteral("外跳"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH)
            parts << driverText("driver.integrity.risk.section_mismatch", QStringLiteral("Section不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING)
            parts << driverText("driver.integrity.risk.service_missing", QStringLiteral("服务缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD)
            parts << driverText("driver.integrity.risk.empty_unload", QStringLiteral("Unload为空"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP)
            parts << driverText("driver.integrity.risk.device_loop", QStringLiteral("Device环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP)
            parts << driverText("driver.integrity.risk.attached_loop", QStringLiteral("Attached环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH)
            parts << driverText("driver.integrity.risk.cross_driver_attach", QStringLiteral("跨驱动挂接"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER)
            parts << driverText("driver.integrity.risk.null_pointer", QStringLiteral("空指针"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER)
            parts << driverText("driver.integrity.risk.idt_external_owner", QStringLiteral("IDT外部Owner"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED)
            parts << driverText("driver.integrity.risk.wp_disabled", QStringLiteral("WP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED)
            parts << driverText("driver.integrity.risk.nxe_disabled", QStringLiteral("NXE关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED)
            parts << driverText("driver.integrity.risk.smep_disabled", QStringLiteral("SMEP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)
            parts << driverText("driver.integrity.risk.smap_disabled", QStringLiteral("SMAP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID)
            parts << driverText("driver.integrity.risk.descriptor_invalid", QStringLiteral("描述符异常"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.dyndata_unavailable", QStringLiteral("DynData缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED)
            parts << driverText("driver.integrity.risk.truncated", QStringLiteral("截断"));
        return parts.join(QStringLiteral(" | "));
    }

    // appendEvidenceRow：
    // - 输入：通用证据表、行号和字段内容；
    // - 处理：在 6 列证据表中写入一条只读行；
    // - 返回：无。
    void appendEvidenceRow(
        QTableWidget* table,
        const int rowIndex,
        const QString& evidenceText,
        const QString& objectText,
        const QString& targetText,
        const QString& riskText,
        const QString& confidenceText,
        const QString& detailText)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setItem(rowIndex, 0, createReadOnlyItem(evidenceText));
        table->setItem(rowIndex, 1, createReadOnlyItem(objectText));
        table->setItem(rowIndex, 2, createReadOnlyItem(targetText));
        table->setItem(rowIndex, 3, createReadOnlyItem(riskText));
        table->setItem(rowIndex, 4, createReadOnlyItem(confidenceText));
        table->setItem(rowIndex, 5, createReadOnlyItem(detailText));
    }
}

void DriverDock::refreshDriverServiceRecords()
{
    kLogEvent refreshEvent;
    info << refreshEvent
        << driverText("driver.log.refresh_services_start", QStringLiteral("[DriverDock] 开始刷新驱动服务列表。"))
        << eol;

    std::vector<DriverServiceRecord> serviceRecordList;
    std::string errorText;
    if (!queryDriverServiceRecords(serviceRecordList, &errorText))
    {
        m_driverServiceCache.clear();
        rebuildDriverServiceTableByFilter();
        appendOperateLogLine(
            driverText("driver.operation.refresh.service_failed", QStringLiteral("刷新服务失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        if (m_overviewStatusLabel != nullptr)
        {
            m_overviewStatusLabel->setText(
                driverText(
                    "driver.operation.refresh.service_failed_status",
                    QStringLiteral("状态：服务刷新失败（%1）"))
                .arg(QString::fromUtf8(errorText.c_str())));
        }
        warn << refreshEvent
            << driverText("driver.log.refresh_services_failed", QStringLiteral("[DriverDock] 刷新服务失败, detail="))
            << errorText << eol;
        return;
    }

    m_driverServiceCache = std::move(serviceRecordList);
    rebuildDriverServiceTableByFilter();

    if (m_overviewStatusLabel != nullptr)
    {
        m_overviewStatusLabel->setText(
            driverText("driver.overview.count", QStringLiteral("状态：驱动服务 %1 条，模块 %2 条"))
            .arg(m_driverServiceCache.size())
            .arg(m_loadedModuleCache.size()));
    }

    info << refreshEvent
        << driverText("driver.log.refresh_services_completed", QStringLiteral("[DriverDock] 刷新服务完成, count="))
        << m_driverServiceCache.size() << eol;
}

void DriverDock::refreshLoadedKernelModuleRecords()
{
    kLogEvent refreshEvent;
    info << refreshEvent
        << driverText("driver.log.refresh_modules_start", QStringLiteral("[DriverDock] 开始刷新已加载模块列表。"))
        << eol;

    std::vector<LoadedKernelModuleRecord> moduleRecordList;
    std::string errorText;
    if (!queryLoadedKernelModuleRecords(moduleRecordList, &errorText))
    {
        ++m_moduleEvidenceQueryTicket;
        m_moduleEvidenceQuerying = false;
        if (m_refreshModuleEvidenceButton != nullptr)
        {
            m_refreshModuleEvidenceButton->setEnabled(true);
        }
        m_loadedModuleCache.clear();
        m_loadedModuleEvidenceCache.clear();
        rebuildLoadedModuleTable();
        appendOperateLogLine(
            driverText("driver.operation.refresh.module_failed", QStringLiteral("刷新模块失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        if (m_overviewStatusLabel != nullptr)
        {
            m_overviewStatusLabel->setText(
                driverText(
                    "driver.operation.refresh.module_failed_status",
                    QStringLiteral("状态：模块刷新失败（%1）"))
                .arg(QString::fromUtf8(errorText.c_str())));
        }
        warn << refreshEvent
            << driverText("driver.log.refresh_modules_failed", QStringLiteral("[DriverDock] 刷新模块失败, detail="))
            << errorText << eol;
        return;
    }

    ++m_moduleEvidenceQueryTicket;
    m_moduleEvidenceQuerying = false;
    if (m_refreshModuleEvidenceButton != nullptr)
    {
        m_refreshModuleEvidenceButton->setEnabled(true);
    }

    m_loadedModuleCache = std::move(moduleRecordList);
    m_loadedModuleEvidenceCache.clear();
    m_loadedModuleEvidenceCache.reserve(m_loadedModuleCache.size());
    for (const LoadedKernelModuleRecord& moduleRecord : m_loadedModuleCache)
    {
        m_loadedModuleEvidenceCache.push_back(buildPendingModuleEvidenceRecord(moduleRecord));
    }
    rebuildLoadedModuleTable();

    if (m_overviewStatusLabel != nullptr)
    {
        m_overviewStatusLabel->setText(
            driverText("driver.overview.count", QStringLiteral("状态：驱动服务 %1 条，模块 %2 条"))
            .arg(m_driverServiceCache.size())
            .arg(m_loadedModuleCache.size()));
    }
    if (m_moduleEvidenceStatusLabel != nullptr)
    {
        m_moduleEvidenceStatusLabel->setText(
            driverText("driver.evidence.status.modules_refreshed", QStringLiteral("证据：模块列表已刷新。")));
    }
    if (!m_loadedModuleCache.empty())
    {
        // 模块证据聚合只在已有模块快照时启动：
        // - 输入：当前 EnumDeviceDrivers 枚举出的模块缓存；
        // - 处理：交给后台线程调用现有 ArkDriverClient 只读接口；
        // - 返回：无；空列表直接停留在提示状态，避免刷新函数互相递归。
        refreshLoadedModuleEvidenceAsync();
    }
    else if (m_moduleEvidenceStatusLabel != nullptr)
    {
        m_moduleEvidenceStatusLabel->setText(
            driverText("driver.evidence.status.no_modules_short", QStringLiteral("证据：没有可聚合的模块。")));
    }

    info << refreshEvent
        << driverText("driver.log.refresh_modules_completed", QStringLiteral("[DriverDock] 刷新模块完成, count="))
        << m_loadedModuleCache.size() << eol;
}

void DriverDock::fillObjectDriverNameFromSelection()
{
    // 从当前服务行推导 DriverObject 名称：
    // - 大多数服务名与 \Driver\Name 一致；
    // - 如果用户已手工输入内容，本按钮仍明确覆盖，避免隐式猜测。
    if (m_serviceTable == nullptr ||
        m_serviceTable->selectionModel() == nullptr ||
        m_objectDriverNameEdit == nullptr)
    {
        return;
    }

    const QModelIndexList rowList = m_serviceTable->selectionModel()->selectedRows(0);
    if (rowList.isEmpty())
    {
        m_objectInfoStatusLabel->setText(
            driverText("driver.object.status.select_service", QStringLiteral("状态：请先在驱动服务表选中一行。")));
        return;
    }

    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowList.front().row(), 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString().trimmed();
    if (serviceNameText.isEmpty())
    {
        return;
    }
    m_objectDriverNameEdit->setText(QStringLiteral("\\Driver\\%1").arg(serviceNameText));
    if (m_tabWidget != nullptr && m_objectInfoPage != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_objectInfoPage);
    }
}

void DriverDock::showServiceTableContextMenu(const QPoint& localPosition)
{
    // 右键菜单入口：
    // - 普通 SCM 操作仍使用既有按钮/函数；
    // - 三种卸载互相独立：SCM 标准卸载、直接调用 DriverUnload、DriverObject 强拆。
    if (m_serviceTable == nullptr)
    {
        return;
    }

    const QModelIndex clickedIndex = m_serviceTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_serviceTable->selectRow(clickedIndex.row());
        syncOperateFormBySelectedService();
    }

    const QModelIndexList selectedRows =
        (m_serviceTable->selectionModel() == nullptr)
        ? QModelIndexList()
        : m_serviceTable->selectionModel()->selectedRows(0);
    if (selectedRows.isEmpty())
    {
        return;
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* fillObjectNameAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        driverText("driver.menu.fill_driver_object", QStringLiteral("填充 DriverObject 名称")));
    QAction* queryObjectAction = contextMenu.addAction(
        QIcon(":/Icon/process_refresh.svg"),
        driverText("driver.menu.query_driver_object", QStringLiteral("查询 DriverObject 信息")));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
    contextMenu.addSeparator();
    QAction* stopServiceAction = contextMenu.addAction(
        QIcon(":/Icon/process_uncritical.svg"),
        driverText("driver.menu.stop_service", QStringLiteral("标准卸载（SCM / sc stop）")));
    stopServiceAction->setToolTip(
        driverText(
            "driver.menu.stop_service.tooltip",
            QStringLiteral("通过服务控制管理器发送 SERVICE_CONTROL_STOP，走 Windows 标准驱动卸载路径。")));
    QAction* forceUnloadAction = contextMenu.addAction(
        QIcon(":/Icon/process_uncritical.svg"),
        driverText("driver.menu.force_unload_driver_object", QStringLiteral("直接调用 DriverUnload")));
    forceUnloadAction->setToolTip(
        driverText(
            "driver.menu.force_unload_driver_object.tooltip",
            QStringLiteral("跳过 SCM/ZwUnloadDriver，仅调用 DriverObject->DriverUnload；不修改 MajorFunction，不强停线程，不强删设备。")));
    QAction* forceDestructiveUnloadAction = contextMenu.addAction(
        QIcon(":/Icon/process_uncritical.svg"),
        driverText("driver.menu.destructive_unload_driver_object", QStringLiteral("DriverObject 强拆")));
    forceDestructiveUnloadAction->setToolTip(
        driverText(
            "driver.menu.destructive_unload_driver_object.tooltip",
            QStringLiteral("固定顺序：封 MajorFunction → 终止目标驱动线程 → 调 DriverUnload → 解除并删除设备链至 DeviceObject 为空。")));

    QAction* selectedAction = contextMenu.exec(m_serviceTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == fillObjectNameAction)
    {
        fillObjectDriverNameFromSelection();
        return;
    }
    if (selectedAction == queryObjectAction)
    {
        fillObjectDriverNameFromSelection();
        querySelectedDriverObjectInfo();
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyDriverOperationCurrentRow(m_serviceTable);
        return;
    }
    if (selectedAction == stopServiceAction)
    {
        stopDriverServiceFromServiceRow(selectedRows.front().row());
        return;
    }
    if (selectedAction == forceUnloadAction)
    {
        forceUnloadDriverFromServiceRow(selectedRows.front().row(), false);
        return;
    }
    if (selectedAction == forceDestructiveUnloadAction)
    {
        const QMessageBox::StandardButton confirmResult = QMessageBox::warning(
            this,
            driverText("driver.confirm.destructive_unload.title", QStringLiteral("DriverObject 强拆")),
            driverText(
                "driver.confirm.destructive_unload.body",
                QStringLiteral("该操作会绕过 SCM/PnP 生命周期，并严格按以下顺序执行：\n\n1. 将 MajorFunction/FastIo 改为拒绝入口\n2. 强制终止并等待该驱动镜像内的所有系统线程退出\n3. 调用 DriverObject->DriverUnload（若存在）\n4. 解除上下层设备关联并删除全部 DeviceObject，直至 DriverObject->DeviceObject 为空\n\n任一线程无法确认退出时不会继续调用 DriverUnload。该操作可能立即导致蓝屏，仅用于恶意驱动处置。\n\n是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmResult == QMessageBox::Yes)
        {
            forceUnloadDriverFromServiceRow(selectedRows.front().row(), true);
        }
        return;
    }
}

void DriverDock::stopDriverServiceFromServiceRow(const int rowIndex)
{
    // 服务列表停驱流程：
    // - 输入：服务表格行号。
    // - 处理：读取 SCM 服务短名，在后台线程调用 ControlService(SERVICE_CONTROL_STOP)；
    // - 返回：无返回值；结果通过操作日志和刷新后的服务/模块表体现。
    // 注意：这里刻意不调用 R0 DriverObject 强卸载。直接调用第三方 DriverUnload
    // 或清理 DriverObject/DeviceObject 会绕过 SCM/PnP 生命周期，目标仍在处理 IRP
    // 时容易导致 bugcheck。
    if (m_serviceTable == nullptr || rowIndex < 0 || rowIndex >= m_serviceTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowIndex, 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.stop.empty_name", QStringLiteral("停止服务失败：服务名为空。")));
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.stop.starting", QStringLiteral("开始停止驱动服务（SCM）：%1"))
        .arg(serviceNameText));

    QPointer<DriverDock> guardThis(this);
    const std::wstring serviceNameWide = toWideString(serviceNameText);
    auto* stopTask = QRunnable::create([guardThis, serviceNameText, serviceNameWide]()
        {
            ks::service::ServiceStatus finalStatus{};
            std::string errorText;
            std::uint32_t errorCode = 0U;
            const bool stopOk = ks::service::StopServiceByName(
                serviceNameWide,
                10000U,
                SERVICE_STOPPED,
                &finalStatus,
                &errorText,
                &errorCode);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, serviceNameText, stopOk, finalStatus, errorText, errorCode]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    if (stopOk)
                    {
                        guardThis->appendOperateLogLine(
                            finalStatus.currentState == SERVICE_STOPPED
                            ? driverText("driver.operation.stop.success", QStringLiteral("停止服务成功：service=%1"))
                                .arg(serviceNameText)
                            : driverText(
                                "driver.operation.stop.completed",
                                QStringLiteral("停止服务结束：service=%1，当前状态=%2"))
                            .arg(serviceNameText)
                            .arg(guardThis->serviceStateToText(finalStatus.currentState)));
                    }
                    else
                    {
                        (void)ks::ui::promptForPrivilegeFailure(
                            guardThis,
                            QStringLiteral("停止驱动服务"),
                            errorCode);
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.stop.failed",
                                QStringLiteral("停止服务失败：service=%1，error=%2，detail=%3"))
                            .arg(serviceNameText)
                            .arg(errorCode)
                            .arg(QString::fromUtf8(errorText.c_str())));
                    }
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    stopTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(stopTask);
}

void DriverDock::forceUnloadDriverFromServiceRow(const int rowIndex, const bool destructiveCleanup)
{
    // 强制卸载流程：
    // - 使用服务名推导 \Driver\ServiceName；
    // - R0 内部再通过 ObReferenceObjectByName 引用对象；
    // - destructiveCleanup=false：跳过系统路径，只调用 DriverUnload；
    // - destructiveCleanup=true：执行固定顺序的 DriverObject 强拆。
    if (m_serviceTable == nullptr || rowIndex < 0 || rowIndex >= m_serviceTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowIndex, 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.force_unload.empty_name", QStringLiteral("强制卸载失败：服务名为空。")));
        return;
    }

    const QString driverObjectNameText = QStringLiteral("\\Driver\\%1").arg(serviceNameText);
    appendOperateLogLine(
        driverText("driver.operation.force_unload.starting", QStringLiteral("开始 R0 强制卸载：%1"))
        .arg(driverObjectNameText));

    QPointer<DriverDock> guardThis(this);
    const std::wstring driverObjectNameWide = driverObjectNameText.toStdWString();
    auto* unloadTask = QRunnable::create([guardThis, driverObjectNameText, driverObjectNameWide, destructiveCleanup]()
        {
            unsigned long cleanupFlags = KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL;
            if (destructiveCleanup)
            {
                cleanupFlags = KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP |
                    KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;
            }
            const ksword::ark::DriverForceUnloadResult result =
                ksword::ark::DriverClient().forceUnloadDriver(
                    driverObjectNameWide,
                    cleanupFlags,
                    3000UL);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, driverObjectNameText, destructiveCleanup, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const QString resultLine = driverText(
                        "driver.operation.force_unload.result",
                        QStringLiteral(
                            "驱动卸载完成：%1 | IO说明=%2 | Status=%3 | Flags=%4 | Applied=%5 | Deleted=%6 | Detached=%7 | Threads=%8/%9 fail=%10 last=%11 | Last=%12 | Wait=%13 | Object=%14 | Unload=%15 | Name=%16"))
                        .arg(driverObjectNameText)
                        .arg(friendlyDriverIoMessage(result.io.message))
                        .arg(driverForceUnloadStatusText(result.status))
                        .arg(formatHex32(result.flags))
                        .arg(formatHex32(result.cleanupFlagsApplied))
                        .arg(result.deletedDeviceCount)
                        .arg(result.detachedDeviceCount)
                        .arg(result.threadsTerminated)
                        .arg(result.threadCandidates)
                        .arg(result.threadFailures)
                        .arg(formatNtStatusText(result.threadLastStatus))
                        .arg(formatNtStatusText(result.lastStatus))
                        .arg(formatNtStatusText(result.waitStatus))
                        .arg(formatCompactAddress(result.driverObjectAddress))
                        .arg(formatCompactAddress(result.driverUnloadAddress))
                        .arg(QString::fromStdWString(result.driverName));
                    guardThis->appendOperateLogLine(resultLine);
                    if (destructiveCleanup)
                    {
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.high_risk_notice",
                                QStringLiteral("已执行 DriverObject 强拆请求：封 MajorFunction → 停目标线程 → 调 DriverUnload → 拆空 DeviceObject 链。")));
                    }
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    unloadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(unloadTask);
}

void DriverDock::showModuleTableContextMenu(const QPoint& localPosition)
{
    // 模块表右键入口：
    // - 服务已停止但模块仍残留时，服务名路径可能已经失效；
    // - 这里改用模块基址，让 R0 扫描对象目录反查 DriverObject。
    if (m_moduleTable == nullptr)
    {
        return;
    }

    const QModelIndex clickedIndex = m_moduleTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_moduleTable->selectRow(clickedIndex.row());
    }

    const QModelIndexList selectedRows =
        (m_moduleTable->selectionModel() == nullptr)
        ? QModelIndexList()
        : m_moduleTable->selectionModel()->selectedRows(0);
    if (selectedRows.isEmpty())
    {
        return;
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* refreshEvidenceAction = contextMenu.addAction(
        QIcon(":/Icon/process_refresh.svg"),
        driverText("driver.menu.refresh_module_evidence", QStringLiteral("刷新模块证据聚合")));
    QAction* copyEvidenceAction = contextMenu.addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        driverText("driver.menu.copy_module_evidence", QStringLiteral("复制当前模块证据详情")));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* queryKernelSignatureAction = contextMenu.addAction(
        driverText("driver.menu.query_kernel_signature", QStringLiteral("R0 读取内核签名证据")));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [this]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：DriverDock 已加载模块表当前行。
            // 处理：读取路径列并规范化 \SystemRoot/\Device 等内核路径。
            // 返回：待上传驱动文件路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            const int rowIndex = m_moduleTable != nullptr ? m_moduleTable->currentRow() : -1;
            const QTableWidgetItem* pathItem =
                (m_moduleTable != nullptr && rowIndex >= 0) ? m_moduleTable->item(rowIndex, 8) : nullptr;
            const QTableWidgetItem* nameItem =
                (m_moduleTable != nullptr && rowIndex >= 0) ? m_moduleTable->item(rowIndex, 0) : nullptr;
            if (pathItem == nullptr)
            {
                uploadTarget.errorText = driverText(
                    "driver.upload.module_path_missing",
                    QStringLiteral("当前模块行没有可用路径。"));
                return uploadTarget;
            }
            uploadTarget.filePath = ks::online_scan::normalizeKernelImagePathForUpload(pathItem->text());
            uploadTarget.sourceText = driverText("driver.upload.module_source", QStringLiteral("驱动模块 %1"))
                .arg(nameItem != nullptr ? nameItem->text() : QStringLiteral("<未知模块>"));
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(!selectedRows.isEmpty());
    }
    contextMenu.addSeparator();
    QAction* forceCleanupByBaseAction = contextMenu.addAction(
        QIcon(":/Icon/process_uncritical.svg"),
        driverText("driver.menu.force_unload_by_base", QStringLiteral("按模块基址直接调用 DriverUnload")));
    forceCleanupByBaseAction->setToolTip(
        driverText(
            "driver.menu.force_unload_by_base.tooltip",
            QStringLiteral("按模块基址反查 DriverObject，跳过系统卸载路径，仅调用 DriverUnload。")));
    QAction* forceDeepCleanupByBaseAction = contextMenu.addAction(
        QIcon(":/Icon/process_uncritical.svg"),
        driverText("driver.menu.deep_cleanup_by_base", QStringLiteral("按模块基址 DriverObject 强拆")));
    forceDeepCleanupByBaseAction->setToolTip(
        driverText(
            "driver.menu.deep_cleanup_by_base.tooltip",
            QStringLiteral("先封 MajorFunction、终止并确认目标线程退出，再清理可验证回调、调用 DriverUnload，并解除/删除设备链。")));

    QAction* selectedAction = contextMenu.exec(m_moduleTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == refreshEvidenceAction)
    {
        refreshLoadedModuleEvidenceAsync();
        return;
    }
    if (selectedAction == copyEvidenceAction)
    {
        showSelectedModuleEvidenceDetail();
        if (m_moduleEvidenceDetailEditor != nullptr && QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(m_moduleEvidenceDetailEditor->text());
        }
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyDriverOperationCurrentRow(m_moduleTable);
        return;
    }
    if (selectedAction == queryKernelSignatureAction)
    {
        querySelectedModuleKernelSignature();
        return;
    }
    if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    if (selectedAction == forceCleanupByBaseAction)
    {
        // 普通模块基址清理不需要二次确认，直接复用当前选中行。
        forceUnloadDriverFromModuleRow(selectedRows.front().row(), false, false);
        return;
    }
    if (selectedAction == forceDeepCleanupByBaseAction)
    {
        // 强力清理是高风险动作，因此保留二次确认：
        // - 全局 QMessageBox 主题器已不再拦截 Close 事件；
        // - 这里可以恢复使用标准按钮返回值，避免业务层绕过全局弹窗语义。
        const QMessageBox::StandardButton confirmResult = QMessageBox::warning(
            this,
            driverText("driver.confirm.deep_cleanup.title", QStringLiteral("R0 强力清理")),
            driverText(
                "driver.confirm.deep_cleanup.body",
                QStringLiteral("该操作会按模块基址反查 DriverObject，并执行完整强拆：封 MajorFunction、终止并等待目标驱动线程、清理可验证回调、调用 DriverUnload、解除并删除全部设备对象。\n\n不会摘 PsLoadedModuleList，但可能立即导致系统崩溃。\n\n是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmResult == QMessageBox::Yes)
        {
            forceUnloadDriverFromModuleRow(selectedRows.front().row(), true, true);
        }
        return;
    }
}

void DriverDock::querySelectedModuleKernelSignature()
{
    if (m_moduleTable == nullptr)
    {
        return;
    }
    const int rowIndex = m_moduleTable->currentRow();
    const QTableWidgetItem* nameItem = rowIndex >= 0 ? m_moduleTable->item(rowIndex, 0) : nullptr;
    const QTableWidgetItem* baseItem = rowIndex >= 0 ? m_moduleTable->item(rowIndex, 1) : nullptr;
    const QTableWidgetItem* pathItem = rowIndex >= 0 ? m_moduleTable->item(rowIndex, 8) : nullptr;
    const QString moduleName = nameItem != nullptr ? nameItem->text().trimmed() : QString();
    const QString rawPath = pathItem != nullptr ? pathItem->text().trimmed() : QString();
    const QString ntPath = buildKernelSignatureNtPath(rawPath);
    const std::uint64_t moduleBase = baseItem != nullptr
        ? baseItem->data(Qt::UserRole).toULongLong()
        : 0U;
    if (rowIndex < 0 || ntPath.isEmpty() || moduleBase == 0U)
    {
        if (m_moduleEvidenceStatusLabel != nullptr)
        {
            m_moduleEvidenceStatusLabel->setText(driverText(
                "driver.signature.status.invalid_selection",
                QStringLiteral("内核签名查询失败：当前模块缺少有效路径或基址。")));
        }
        return;
    }

    if (m_moduleEvidenceStatusLabel != nullptr)
    {
        m_moduleEvidenceStatusLabel->setText(driverText(
            "driver.signature.status.querying",
            QStringLiteral("正在通过 R0 读取模块签名证据：%1"))
            .arg(moduleName));
    }
    if (m_moduleEvidenceDetailEditor != nullptr)
    {
        m_moduleEvidenceDetailEditor->setLocalizedText(
            QStringLiteral("R0 签名证据查询中..."));
    }

    QPointer<DriverDock> guardThis(this);
    auto* queryTask = QRunnable::create([guardThis, moduleName, rawPath, ntPath, moduleBase]()
        {
            const ksword::ark::ImageSignatureQueryResult signatureResult =
                ksword::ark::DriverClient().queryImageSignature(ntPath.toStdWString(), moduleBase);
            DriverDock* targetDock = guardThis.data();
            if (targetDock == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                targetDock,
                [guardThis, moduleName, rawPath, ntPath, moduleBase, signatureResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    QString report;
                    report += QStringLiteral("[R0 内核签名证据]\n");
                    report += QStringLiteral("模块: %1\n").arg(moduleName);
                    report += QStringLiteral("原始路径: %1\n").arg(rawPath);
                    report += QStringLiteral("NT 路径: %1\n").arg(ntPath);
                    report += QStringLiteral("模块基址: %1\n\n").arg(formatCompactAddress(moduleBase));
                    report += QString::fromStdString(ksword::ark::formatImageSignatureEvidence(signatureResult));
                    report += QStringLiteral("\n");
                    report += QStringLiteral("结论边界：PE 证书表结构不等于证书链可信；CI cached signing level 是独立的内核缓存结果。此查询未调用 WinTrust。已加载模块绑定仅核对枚举基址和文件名；证书表仍来自当前磁盘文件。");
                    if (guardThis->m_moduleEvidenceDetailEditor != nullptr)
                    {
                        guardThis->m_moduleEvidenceDetailEditor->setLocalizedText(report);
                    }
                    if (guardThis->m_moduleEvidenceStatusLabel != nullptr)
                    {
                        guardThis->m_moduleEvidenceStatusLabel->setText(signatureResult.io.ok
                            ? driverText(
                                "driver.signature.status.complete",
                                QStringLiteral("R0 内核签名证据读取完成：%1"))
                                .arg(moduleName)
                            : driverText(
                                "driver.signature.status.failed",
                                QStringLiteral("R0 内核签名证据读取失败：%1（Win32=%2）"))
                                .arg(moduleName)
                                .arg(signatureResult.io.win32Error));
                    }
                },
                Qt::QueuedConnection);
        });
    queryTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(queryTask);
}

void DriverDock::forceUnloadDriverFromModuleRow(
    const int rowIndex,
    const bool removeCallbacksFirst,
    const bool destructiveCleanup)
{
    // 按模块基址清理：
    // - R3 只传模块基址和模块名兜底文本；
    // - R0 先按 DriverStart 反查真实 DriverObject，再执行分级强制卸载；
    // - removeCallbacksFirst 为 true 时请求 R0 在 DriverObject 处理成功后移除可验证回调；
    // - destructiveCleanup=false：按模块基址反查后只调用 DriverUnload；
    // - destructiveCleanup=true：执行封 dispatch、停线程、调 unload、拆设备的固定强拆顺序。
    if (m_moduleTable == nullptr || rowIndex < 0 || rowIndex >= m_moduleTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* moduleNameItem = m_moduleTable->item(rowIndex, 0);
    QTableWidgetItem* moduleBaseItem = m_moduleTable->item(rowIndex, 1);
    if (moduleNameItem == nullptr || moduleBaseItem == nullptr)
    {
        return;
    }

    const QString moduleNameText = moduleNameItem->text().trimmed();
    const std::uint64_t moduleBaseValue = moduleBaseItem->data(Qt::UserRole).toULongLong();
    if (moduleBaseValue == 0U)
    {
        appendOperateLogLine(
            driverText("driver.operation.module_cleanup.empty_base", QStringLiteral("模块基址清理失败：模块基址为空。")));
        return;
    }

    QString fallbackNameText = moduleNameText;
    if (fallbackNameText.endsWith(QStringLiteral(".sys"), Qt::CaseInsensitive))
    {
        fallbackNameText.chop(4);
    }

    appendOperateLogLine(
        driverText("driver.operation.module_cleanup.starting", QStringLiteral("开始 R0 按模块基址%1：%2 | base=%3"))
        .arg(removeCallbacksFirst
            ? driverText(
                "driver.operation.module_cleanup.mode.callbacks",
                QStringLiteral("强力清理回调+DriverObject"))
            : driverText(
                "driver.operation.module_cleanup.mode.force_unload",
                QStringLiteral("强制卸载 DriverObject")))
        .arg(moduleNameText, formatCompactAddress(moduleBaseValue)));

    QPointer<DriverDock> guardThis(this);
    const std::wstring fallbackNameWide = fallbackNameText.toStdWString();
    auto* unloadTask = QRunnable::create([guardThis, moduleNameText, moduleBaseValue, fallbackNameWide, removeCallbacksFirst, destructiveCleanup]()
        {
            unsigned long cleanupFlags =
                KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT |
                KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL;
            if (destructiveCleanup)
            {
                cleanupFlags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP |
                    KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;
            }
            if (removeCallbacksFirst)
            {
                cleanupFlags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE;
            }
            const ksword::ark::DriverForceUnloadResult result =
                ksword::ark::DriverClient().forceUnloadDriverByModuleBase(
                    moduleBaseValue,
                    fallbackNameWide,
                    cleanupFlags,
                    3000UL);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, moduleNameText, moduleBaseValue, removeCallbacksFirst, destructiveCleanup, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const QString resultLine = driverText(
                        "driver.operation.module_cleanup.result",
                        QStringLiteral(
                            "R0 模块基址%1完成：%2 | Base=%3 | IO说明=%4 | Status=%5 | Flags=%6 | Applied=%7 | Deleted=%8 | Detached=%9 | Threads=%10/%11 fail=%12 last=%13 | Last=%14 | Wait=%15 | Object=%16 | Unload=%17 | Callbacks=%18/%19 fail=%20 last=%21 | Name=%22"))
                        .arg(removeCallbacksFirst
                            ? driverText("driver.operation.module_cleanup.mode.deep", QStringLiteral("强力清理"))
                            : driverText("driver.operation.module_cleanup.mode.clean", QStringLiteral("清理")))
                        .arg(moduleNameText)
                        .arg(formatCompactAddress(moduleBaseValue))
                        .arg(friendlyDriverIoMessage(result.io.message))
                        .arg(driverForceUnloadStatusText(result.status))
                        .arg(formatHex32(result.flags))
                        .arg(formatHex32(result.cleanupFlagsApplied))
                        .arg(result.deletedDeviceCount)
                        .arg(result.detachedDeviceCount)
                        .arg(result.threadsTerminated)
                        .arg(result.threadCandidates)
                        .arg(result.threadFailures)
                        .arg(formatNtStatusText(result.threadLastStatus))
                        .arg(formatNtStatusText(result.lastStatus))
                        .arg(formatNtStatusText(result.waitStatus))
                        .arg(formatCompactAddress(result.driverObjectAddress))
                        .arg(formatCompactAddress(result.driverUnloadAddress))
                        .arg(result.callbacksRemoved)
                        .arg(result.callbackCandidates)
                        .arg(result.callbackFailures)
                        .arg(formatNtStatusText(result.callbackLastStatus))
                        .arg(QString::fromStdWString(result.driverName));
                    guardThis->appendOperateLogLine(resultLine);
                    if (destructiveCleanup)
                    {
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.high_risk_notice",
                                QStringLiteral("已执行 DriverObject 强拆请求：封 MajorFunction → 停目标线程 → 调 DriverUnload → 拆空 DeviceObject 链。")));
                    }
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    unloadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(unloadTask);
}

void DriverDock::querySelectedDriverObjectInfo()
{
    // DriverObject 查询：
    // - 只接受对象名，不接受地址；
    // - 后台线程中通过 ArkDriverClient 访问 KswordARK，避免阻塞 UI。
    if (m_objectInfoQuerying || m_objectDriverNameEdit == nullptr)
    {
        return;
    }

    const QString driverNameText = m_objectDriverNameEdit->text().trimmed();
    if (driverNameText.isEmpty())
    {
        if (m_objectInfoStatusLabel != nullptr)
        {
            m_objectInfoStatusLabel->setText(
                driverText("driver.object.status.name_empty", QStringLiteral("状态：DriverObject 名称不能为空。")));
        }
        return;
    }

    m_objectInfoQuerying = true;
    const std::uint64_t ticketValue = ++m_objectInfoQueryTicket;
    if (m_queryObjectInfoButton != nullptr)
    {
        m_queryObjectInfoButton->setEnabled(false);
    }
    if (m_objectInfoStatusLabel != nullptr)
    {
        m_objectInfoStatusLabel->setText(
            driverText("driver.object.status.querying", QStringLiteral("状态：正在查询 DriverObject...")));
    }

    QPointer<DriverDock> guardThis(this);
    const std::wstring driverNameWide = driverNameText.toStdWString();
    auto* queryTask = QRunnable::create([guardThis, ticketValue, driverNameWide]()
        {
            const ksword::ark::DriverObjectQueryResult result =
                ksword::ark::DriverClient().queryDriverObject(
                    driverNameWide,
                    KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
                    KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
                    KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticketValue, result]()
                {
                    if (guardThis == nullptr ||
                        guardThis->m_objectInfoQueryTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyDriverObjectQueryResult(result);
                },
                Qt::QueuedConnection);
        });
    queryTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(queryTask);
}

void DriverDock::applyDriverObjectQueryResult(const ksword::ark::DriverObjectQueryResult& result)
{
    // 查询结果回填：
    // - 所有地址都作为诊断文本展示；
    // - 不在 UI 中将地址作为任何二次操作输入。
    m_objectInfoQuerying = false;
    m_lastDriverObjectQueryResult = result;
    m_hasDriverObjectQueryResult = true;
    if (m_queryObjectInfoButton != nullptr)
    {
        m_queryObjectInfoButton->setEnabled(true);
    }

    if (m_objectInfoStatusLabel != nullptr)
    {
        const QString readableIoText = friendlyDriverIoMessage(result.io.message);
        m_objectInfoStatusLabel->setText(
            driverText("driver.object.status.io", QStringLiteral("状态：%1 | %2"))
            .arg(result.io.ok ? driverObjectQueryStatusText(result.queryStatus) : QStringLiteral("IO failed"))
            .arg(readableIoText));
    }

    if (m_objectInfoSummaryEdit != nullptr)
    {
        const QString readableIoText = friendlyDriverIoMessage(result.io.message);
        QStringList summaryLines;
        summaryLines << QStringLiteral("[DriverObject]");
        summaryLines << driverText("driver.object.summary.io_note", QStringLiteral("IO说明: %1"))
            .arg(readableIoText);
        summaryLines << QStringLiteral("QueryStatus: %1").arg(driverObjectQueryStatusText(result.queryStatus));
        summaryLines << QStringLiteral("LastStatus: %1").arg(formatNtStatusText(result.lastStatus));
        summaryLines << QStringLiteral("DriverName: %1").arg(QString::fromStdWString(result.driverName));
        summaryLines << QStringLiteral("ServiceKey: %1").arg(QString::fromStdWString(result.serviceKeyName));
        summaryLines << QStringLiteral("ImagePath: %1").arg(QString::fromStdWString(result.imagePath));
        summaryLines << QStringLiteral("DriverObject: %1").arg(formatCompactAddress(result.driverObjectAddress));
        summaryLines << QStringLiteral("DriverStart: %1 Size=%2")
            .arg(formatCompactAddress(result.driverStart))
            .arg(formatHex32(result.driverSize));
        summaryLines << QStringLiteral("DriverSection: %1").arg(formatCompactAddress(result.driverSection));
        summaryLines << QStringLiteral("DriverUnload: %1").arg(formatCompactAddress(result.driverUnload));
        summaryLines << QStringLiteral("Flags: %1 FieldFlags=%2")
            .arg(formatHex32(result.driverFlags))
            .arg(formatHex32(result.fieldFlags));
        summaryLines << QStringLiteral("MajorFunctions: %1 DeviceObjects: %2/%3")
            .arg(result.majorFunctions.size())
            .arg(result.devices.size())
            .arg(result.totalDeviceCount);
        m_objectInfoSummaryEdit->setText(summaryLines.join('\n'));
    }
    rebuildDriverObjectEvidenceViews();
}

void DriverDock::rebuildDriverObjectEvidenceViews()
{
    // 输入：当前 DriverObject 缓存与完整性缓存。
    // 处理：仅在 UI 线程投影为只读表格，不重新访问驱动。
    // 返回：无。
    if (!m_hasDriverObjectQueryResult)
    {
        if (m_driverObjectPageSummaryEdit != nullptr)
        {
            m_driverObjectPageSummaryEdit->setText(
                driverText("driver.object.page_summary.query_first", QStringLiteral("请先执行 DriverObject 查询。")));
        }
        if (m_driverExtensionStatusLabel != nullptr)
        {
            m_driverExtensionStatusLabel->setText(
                driverText(
                    "driver.object.driver_extension.status.waiting",
                    QStringLiteral("状态：等待 DriverObject 查询。")));
        }
        if (m_fastIoStatusLabel != nullptr)
        {
            m_fastIoStatusLabel->setText(
                driverText(
                    "driver.object.fast_io.status.waiting",
                    QStringLiteral("状态：等待 Driver Integrity 证据。")));
        }
        return;
    }

    const ksword::ark::DriverObjectQueryResult& result = m_lastDriverObjectQueryResult;
    if (m_driverObjectPageSummaryEdit != nullptr)
    {
        QStringList lines;
        lines << QStringLiteral("DriverObject: %1").arg(formatCompactAddress(result.driverObjectAddress));
        lines << QStringLiteral("DriverStart: %1").arg(formatCompactAddress(result.driverStart));
        lines << QStringLiteral("DriverSection: %1").arg(formatCompactAddress(result.driverSection));
        lines << QStringLiteral("DriverUnload: %1").arg(formatCompactAddress(result.driverUnload));
        lines << QStringLiteral("DriverSize: %1").arg(formatHex32(result.driverSize));
        lines << QStringLiteral("DriverFlags: %1").arg(formatHex32(result.driverFlags));
        lines << QStringLiteral("MajorFunctions: %1").arg(result.majorFunctions.size());
        lines << QStringLiteral("DeviceObjects: %1/%2").arg(result.devices.size()).arg(result.totalDeviceCount);
        m_driverObjectPageSummaryEdit->setText(lines.join('\n'));
    }

    if (m_driverObjectEvidenceTable != nullptr)
    {
        const QSignalBlocker blocker(m_driverObjectEvidenceTable);
        m_driverObjectEvidenceTable->setSortingEnabled(false);
        m_driverObjectEvidenceTable->setRowCount(0);
        const QStringList rows = {
            QStringLiteral("DriverObject"),
            QStringLiteral("DriverStart"),
            QStringLiteral("DriverSection"),
            QStringLiteral("DriverUnload"),
            QStringLiteral("DriverSize"),
            QStringLiteral("DriverFlags"),
            QStringLiteral("FieldFlags"),
            QStringLiteral("MajorFunctionCount"),
            QStringLiteral("DeviceCount")
        };
        const QStringList values = {
            formatCompactAddress(result.driverObjectAddress),
            formatCompactAddress(result.driverStart),
            formatCompactAddress(result.driverSection),
            formatCompactAddress(result.driverUnload),
            formatHex32(result.driverSize),
            formatHex32(result.driverFlags),
            formatHex32(result.fieldFlags),
            QString::number(result.majorFunctions.size()),
            QStringLiteral("%1/%2").arg(result.devices.size()).arg(result.totalDeviceCount)
        };
        m_driverObjectEvidenceTable->setRowCount(rows.size());
        for (int index = 0; index < rows.size(); ++index)
        {
            appendEvidenceRow(
                m_driverObjectEvidenceTable,
                index,
                rows[index],
                values[index],
                QStringLiteral("-"),
                driverText("driver.integrity.risk.normal", QStringLiteral("正常")),
                QStringLiteral("100"),
                driverText("driver.object.evidence.read_only_summary", QStringLiteral("DriverObject 只读摘要")));
        }
        m_driverObjectEvidenceTable->setSortingEnabled(true);
    }

    if (m_majorFunctionTable != nullptr)
    {
        const QSignalBlocker blocker(m_majorFunctionTable);
        m_majorFunctionTable->setSortingEnabled(false);
        m_majorFunctionTable->setRowCount(0);
        for (const ksword::ark::DriverMajorFunctionEntry& majorEntry : result.majorFunctions)
        {
            const int rowIndex = m_majorFunctionTable->rowCount();
            m_majorFunctionTable->insertRow(rowIndex);
            m_majorFunctionTable->setItem(rowIndex, 0, createReadOnlyItem(driverMajorFunctionName(majorEntry.majorFunction)));
            m_majorFunctionTable->setItem(rowIndex, 1, createReadOnlyItem(formatCompactAddress(majorEntry.dispatchAddress)));
            m_majorFunctionTable->setItem(rowIndex, 2, createReadOnlyItem(QString::fromStdWString(majorEntry.moduleName).isEmpty()
                ? QStringLiteral("-")
                : QString::fromStdWString(majorEntry.moduleName)));
            m_majorFunctionTable->setItem(rowIndex, 3, createReadOnlyItem(formatCompactAddress(majorEntry.moduleBase)));
            m_majorFunctionTable->setItem(rowIndex, 4, createReadOnlyItem(driverDispatchLocationText(majorEntry.flags)));
            if ((majorEntry.flags & 0x00000002U) == 0U)
            {
                for (int columnIndex = 0; columnIndex < m_majorFunctionTable->columnCount(); ++columnIndex)
                {
                    QTableWidgetItem* cellItem = m_majorFunctionTable->item(rowIndex, columnIndex);
                    if (cellItem != nullptr)
                    {
                        cellItem->setToolTip(
                            driverText(
                                "driver.object.major_function.external_tooltip",
                                QStringLiteral("Dispatch 不在 DriverObject 自身镜像范围内。")));
                    }
                }
            }
        }
        m_majorFunctionTable->setSortingEnabled(true);
    }

    if (m_deviceObjectTable != nullptr)
    {
        const QSignalBlocker blocker(m_deviceObjectTable);
        m_deviceObjectTable->setSortingEnabled(false);
        m_deviceObjectTable->setRowCount(0);
        for (const ksword::ark::DriverDeviceEntry& deviceEntry : result.devices)
        {
            const int rowIndex = m_deviceObjectTable->rowCount();
            m_deviceObjectTable->insertRow(rowIndex);
            m_deviceObjectTable->setItem(rowIndex, 0, createReadOnlyItem(deviceEntry.relationDepth == 0U
                ? QStringLiteral("Root")
                : QStringLiteral("Attached +%1").arg(deviceEntry.relationDepth)));
            m_deviceObjectTable->setItem(rowIndex, 1, createReadOnlyItem(formatCompactAddress(deviceEntry.deviceObjectAddress)));
            QTableWidgetItem* nameItem = createReadOnlyItem(QString::fromStdWString(deviceEntry.deviceName).isEmpty()
                ? QStringLiteral("(unnamed)")
                : QString::fromStdWString(deviceEntry.deviceName));
            nameItem->setToolTip(QStringLiteral("NameStatus=%1").arg(formatNtStatusText(deviceEntry.nameStatus)));
            m_deviceObjectTable->setItem(rowIndex, 2, nameItem);
            m_deviceObjectTable->setItem(rowIndex, 3, createReadOnlyItem(driverDeviceTypeText(deviceEntry.deviceType)));
            m_deviceObjectTable->setItem(rowIndex, 4, createReadOnlyItem(formatHex32(deviceEntry.flags)));
            m_deviceObjectTable->setItem(rowIndex, 5, createReadOnlyItem(formatHex32(deviceEntry.characteristics)));
            m_deviceObjectTable->setItem(rowIndex, 6, createReadOnlyItem(QString::number(deviceEntry.stackSize)));
            m_deviceObjectTable->setItem(rowIndex, 7, createReadOnlyItem(formatCompactAddress(deviceEntry.nextDeviceObjectAddress)));
            m_deviceObjectTable->setItem(rowIndex, 8, createReadOnlyItem(formatCompactAddress(deviceEntry.attachedDeviceObjectAddress)));
            m_deviceObjectTable->setItem(rowIndex, 9, createReadOnlyItem(formatCompactAddress(deviceEntry.driverObjectAddress)));
        }
        m_deviceObjectTable->setSortingEnabled(true);
    }

    if (m_driverExtensionStatusLabel != nullptr)
    {
        m_driverExtensionStatusLabel->setText(
            driverText(
                "driver.object.driver_extension.status.projected",
                QStringLiteral("状态：DriverExtension 未直接暴露；当前仅展示 DriverObject / DeviceChain / FastIo 关联证据。")));
    }
    if (m_driverExtensionEvidenceTable != nullptr)
    {
        const QSignalBlocker blocker(m_driverExtensionEvidenceTable);
        m_driverExtensionEvidenceTable->setSortingEnabled(false);
        m_driverExtensionEvidenceTable->setRowCount(0);
        const QStringList evidenceNames = {
            QStringLiteral("DriverExtension"),
            QStringLiteral("DeviceChain"),
            QStringLiteral("MajorFunction"),
            QStringLiteral("FastIo")
        };
        const QStringList detailTexts = {
            driverText(
                "driver.object.driver_extension.detail.unavailable",
                QStringLiteral("当前 R3 协议未直接返回 DriverExtension 指针。")),
            driverText(
                "driver.object.driver_extension.detail.device_chain",
                QStringLiteral("DeviceObject 链已由对象页展示。")),
            driverText(
                "driver.object.driver_extension.detail.major_function",
                QStringLiteral("MajorFunction 表已由对象页展示。")),
            driverText(
                "driver.object.driver_extension.detail.fast_io",
                QStringLiteral("FastIo 仅在完整性页中作为证据归档。"))
        };
        m_driverExtensionEvidenceTable->setRowCount(evidenceNames.size());
        for (int index = 0; index < evidenceNames.size(); ++index)
        {
            appendEvidenceRow(
                m_driverExtensionEvidenceTable,
                index,
                evidenceNames[index],
                QStringLiteral("Unavailable"),
                QStringLiteral("-"),
                driverText("driver.evidence.status.unknown", QStringLiteral("未知")),
                QStringLiteral("0"),
                detailTexts[index]);
        }
        m_driverExtensionEvidenceTable->setSortingEnabled(true);
    }

    if (m_fastIoStatusLabel != nullptr)
    {
        m_fastIoStatusLabel->setText(
            driverText(
                "driver.object.fast_io.status.projected",
                QStringLiteral("状态：FastIo 关联证据由 Driver Integrity 页回填，当前记录数 %1。"))
            .arg(m_driverIntegrityCache.size()));
    }
    if (m_fastIoEvidenceTable != nullptr)
    {
        const QSignalBlocker blocker(m_fastIoEvidenceTable);
        m_fastIoEvidenceTable->setSortingEnabled(false);
        m_fastIoEvidenceTable->setRowCount(0);
        int visibleRows = 0;
        for (const auto& row : m_driverIntegrityCache)
        {
            if (row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO &&
                row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT &&
                row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION &&
                row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION)
            {
                continue;
            }
            const int rowIndex = m_fastIoEvidenceTable->rowCount();
            m_fastIoEvidenceTable->insertRow(rowIndex);
            appendEvidenceRow(
                m_fastIoEvidenceTable,
                rowIndex,
                integrityClassText(row.evidenceClass),
                formatCompactAddress(row.objectAddress),
                formatCompactAddress(row.targetAddress),
                integrityRiskText(row.riskFlags),
                QString::number(row.confidence),
                QString::fromStdWString(row.detail));
            ++visibleRows;
        }
        if (visibleRows == 0)
        {
            m_fastIoEvidenceTable->setRowCount(1);
            appendEvidenceRow(
                m_fastIoEvidenceTable,
                0,
                QStringLiteral("FastIo"),
                QStringLiteral("Unavailable"),
                QStringLiteral("-"),
                driverText("driver.integrity.risk.normal", QStringLiteral("正常")),
                QStringLiteral("0"),
                driverText(
                    "driver.object.fast_io.empty",
                    QStringLiteral("当前 Driver Integrity 缓存未返回 FastIo 证据。")));
        }
        m_fastIoEvidenceTable->setSortingEnabled(true);
    }
}

void DriverDock::rebuildDriverServiceTableByFilter()
{
    if (m_serviceTable == nullptr)
    {
        return;
    }

    const QString filterText = (m_serviceFilterEdit == nullptr)
        ? QString()
        : m_serviceFilterEdit->text().trimmed();

    m_serviceTable->setRowCount(0);
    int visibleCount = 0;
    for (const DriverServiceRecord& serviceRecord : m_driverServiceCache)
    {
        const bool matchFilter =
            filterText.isEmpty() ||
            serviceRecord.serviceName.contains(filterText, Qt::CaseInsensitive) ||
            serviceRecord.displayName.contains(filterText, Qt::CaseInsensitive) ||
            serviceRecord.binaryPath.contains(filterText, Qt::CaseInsensitive) ||
            serviceRecord.description.contains(filterText, Qt::CaseInsensitive);
        if (!matchFilter)
        {
            continue;
        }

        const int rowIndex = m_serviceTable->rowCount();
        m_serviceTable->insertRow(rowIndex);

        QTableWidgetItem* serviceNameItem = createReadOnlyItem(serviceRecord.serviceName);
        serviceNameItem->setData(Qt::UserRole, serviceRecord.serviceName);
        m_serviceTable->setItem(rowIndex, 0, serviceNameItem);
        m_serviceTable->setItem(rowIndex, 1, createReadOnlyItem(serviceRecord.displayName));
        m_serviceTable->setItem(rowIndex, 2, createReadOnlyItem(serviceStateToText(serviceRecord.currentState)));
        m_serviceTable->setItem(rowIndex, 3, createReadOnlyItem(startTypeToText(serviceRecord.startType)));
        m_serviceTable->setItem(rowIndex, 4, createReadOnlyItem(errorControlToText(serviceRecord.errorControl)));

        QTableWidgetItem* pathItem = createReadOnlyItem(serviceRecord.binaryPath);
        pathItem->setToolTip(serviceRecord.binaryPath);
        m_serviceTable->setItem(rowIndex, 5, pathItem);

        QTableWidgetItem* descriptionItem = createReadOnlyItem(serviceRecord.description);
        descriptionItem->setToolTip(serviceRecord.description);
        m_serviceTable->setItem(rowIndex, 6, descriptionItem);

        if (serviceRecord.currentState == SERVICE_RUNNING)
        {
            for (int columnIndex = 0; columnIndex < m_serviceTable->columnCount(); ++columnIndex)
            {
                QTableWidgetItem* cellItem = m_serviceTable->item(rowIndex, columnIndex);
                if (cellItem != nullptr)
                {
                    cellItem->setBackground(KswordTheme::NewRowBackgroundColor());
                }
            }
        }
        ++visibleCount;
    }

    if (m_overviewStatusLabel != nullptr)
    {
        m_overviewStatusLabel->setText(
            driverText("driver.overview.count.filtered", QStringLiteral("状态：驱动服务 %1 条（显示 %2 条），模块 %3 条"))
            .arg(m_driverServiceCache.size())
            .arg(visibleCount)
            .arg(m_loadedModuleCache.size()));
    }
}

void DriverDock::rebuildLoadedModuleTable()
{
    if (m_moduleTable == nullptr)
    {
        return;
    }

    m_moduleTable->setRowCount(0);
    for (std::size_t sourceIndex = 0U; sourceIndex < m_loadedModuleCache.size(); ++sourceIndex)
    {
        const LoadedKernelModuleRecord& moduleRecord = m_loadedModuleCache[sourceIndex];
        const int rowIndex = m_moduleTable->rowCount();
        m_moduleTable->insertRow(rowIndex);
        QTableWidgetItem* moduleNameItem = createReadOnlyItem(moduleRecord.moduleName);
        moduleNameItem->setData(
            ModuleRecordIndexRole,
            QVariant::fromValue<qulonglong>(static_cast<qulonglong>(sourceIndex)));
        m_moduleTable->setItem(rowIndex, 0, moduleNameItem);
        QTableWidgetItem* baseItem = createReadOnlyItem(formatAddress(moduleRecord.baseAddress));
        baseItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(
            static_cast<qulonglong>(moduleRecord.baseAddress)));
        m_moduleTable->setItem(rowIndex, 1, baseItem);
        for (int evidenceColumn = 2; evidenceColumn <= 7; ++evidenceColumn)
        {
            m_moduleTable->setItem(
                rowIndex,
                evidenceColumn,
                createReadOnlyItem(driverText("driver.evidence.pending", QStringLiteral("待扫描"))));
        }
        QTableWidgetItem* pathItem = createReadOnlyItem(moduleRecord.imagePath);
        pathItem->setToolTip(moduleRecord.imagePath);
        m_moduleTable->setItem(rowIndex, 8, pathItem);
    }
    if (m_moduleTable->rowCount() > 0)
    {
        m_moduleTable->setCurrentCell(0, 0);
    }
    rebuildLoadedModuleEvidenceViews();
}

void DriverDock::syncOperateFormBySelectedService()
{
    if (m_serviceTable == nullptr || m_serviceTable->selectionModel() == nullptr)
    {
        return;
    }

    const QModelIndexList rowList = m_serviceTable->selectionModel()->selectedRows(0);
    if (rowList.isEmpty())
    {
        return;
    }

    const int rowIndex = rowList.front().row();
    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowIndex, 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString();
    auto iterator = std::find_if(
        m_driverServiceCache.begin(),
        m_driverServiceCache.end(),
        [&serviceNameText](const DriverServiceRecord& record)
        {
            return record.serviceName.compare(serviceNameText, Qt::CaseInsensitive) == 0;
        });
    if (iterator == m_driverServiceCache.end())
    {
        return;
    }

    if (m_serviceNameEdit != nullptr)
    {
        m_serviceNameEdit->setText(iterator->serviceName);
    }
    if (m_displayNameEdit != nullptr)
    {
        m_displayNameEdit->setText(iterator->displayName);
    }
    if (m_binaryPathEdit != nullptr)
    {
        m_binaryPathEdit->setText(trimQuotedText(iterator->binaryPath));
    }
    if (m_descriptionEdit != nullptr)
    {
        m_descriptionEdit->setText(iterator->description);
    }

    if (m_startTypeCombo != nullptr)
    {
        const int startTypeIndex = m_startTypeCombo->findData(static_cast<int>(iterator->startType));
        if (startTypeIndex >= 0)
        {
            m_startTypeCombo->setCurrentIndex(startTypeIndex);
        }
    }
    if (m_errorControlCombo != nullptr)
    {
        const int errorControlIndex = m_errorControlCombo->findData(static_cast<int>(iterator->errorControl));
        if (errorControlIndex >= 0)
        {
            m_errorControlCombo->setCurrentIndex(errorControlIndex);
        }
    }
}

void DriverDock::refreshSelectedServiceStateToForm()
{
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent queryEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.query.empty_name", QStringLiteral("查询失败：服务名不能为空。")));
        warn << queryEvent
            << driverText("driver.log.query.empty_name", QStringLiteral("[DriverDock] 查询状态失败：服务名为空。"))
            << eol;
        return;
    }

    // UI adapter only: the reusable service layer owns SCM open/query/close details.
    ks::service::ServiceStatus statusInfo;
    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::QueryServiceStatus(
        toWideString(serviceNameText),
        &statusInfo,
        &errorText,
        &errorCode))
    {
        appendOperateLogLine(
            driverText("driver.operation.query.failed", QStringLiteral("查询失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        warn << queryEvent
            << driverText("driver.log.query.failed", QStringLiteral("[DriverDock] 查询状态失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.query.status", QStringLiteral("服务 %1 当前状态：%2"))
        .arg(serviceNameText)
        .arg(serviceStateToText(statusInfo.currentState)));

    info << queryEvent
        << driverText("driver.log.query.succeeded", QStringLiteral("[DriverDock] 查询状态成功, service="))
        << serviceNameText.toStdString()
        << ", state=" << statusInfo.currentState
        << eol;
}


void DriverDock::registerOrUpdateDriverService()
{
    if (m_serviceNameEdit == nullptr ||
        m_binaryPathEdit == nullptr ||
        m_startTypeCombo == nullptr ||
        m_errorControlCombo == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    const QString displayNameText = (m_displayNameEdit == nullptr)
        ? QString()
        : m_displayNameEdit->text().trimmed();
    const QString descriptionText = (m_descriptionEdit == nullptr)
        ? QString()
        : m_descriptionEdit->text().trimmed();
    const QString binaryPathText = normalizeDriverBinaryPath(m_binaryPathEdit->text().trimmed());

    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.register.empty_service", QStringLiteral("注册/更新失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.register.empty_service", QStringLiteral("[DriverDock] 注册/更新失败：服务名为空。"))
            << eol;
        return;
    }
    if (binaryPathText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.register.empty_path", QStringLiteral("注册/更新失败：驱动路径不能为空。")));
        warn << operationEvent
            << driverText("driver.log.register.empty_path", QStringLiteral("[DriverDock] 注册/更新失败：路径为空。"))
            << eol;
        return;
    }

    const QString unquotedPathText = trimQuotedText(binaryPathText);
    if (!QFileInfo::exists(unquotedPathText) &&
        !unquotedPathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive) &&
        !unquotedPathText.startsWith(QStringLiteral("%SystemRoot%"), Qt::CaseInsensitive))
    {
        appendOperateLogLine(
            driverText(
                "driver.operation.register.path_unavailable",
                QStringLiteral("警告：驱动路径当前不可访问，仍将尝试注册。")));
    }

    ks::service::KernelDriverServiceConfig serviceConfig;
    serviceConfig.serviceName = toWideString(serviceNameText);
    serviceConfig.displayName = toWideString(displayNameText);
    serviceConfig.description = toWideString(descriptionText);
    serviceConfig.binaryPath = toWideString(binaryPathText);
    serviceConfig.startType = static_cast<std::uint32_t>(m_startTypeCombo->currentData().toInt());
    serviceConfig.errorControl = static_cast<std::uint32_t>(m_errorControlCombo->currentData().toInt());

    bool created = false;
    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::CreateOrUpdateKernelDriverService(
        serviceConfig,
        &created,
        &errorText,
        &errorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("注册或更新驱动服务"),
            errorCode);
        appendOperateLogLine(
            driverText("driver.operation.register.failed", QStringLiteral("注册/更新失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        err << operationEvent
            << driverText("driver.log.register.failed", QStringLiteral("[DriverDock] 注册/更新失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.register.succeeded", QStringLiteral("%1成功：service=%2"))
        .arg(created
            ? driverText("driver.operation.register.created", QStringLiteral("注册"))
            : driverText("driver.operation.register.updated", QStringLiteral("更新")))
        .arg(serviceNameText));

    info << operationEvent
        << driverText("driver.log.register.succeeded", QStringLiteral("[DriverDock] 注册/更新成功, created="))
        << (created ? "true" : "false")
        << ", service=" << serviceNameText.toStdString()
        << eol;

    refreshDriverServiceRecords();
}


void DriverDock::loadSelectedDriverService()
{
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.load.empty_name", QStringLiteral("挂载失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.load.empty_name", QStringLiteral("[DriverDock] 挂载失败：服务名为空。"))
            << eol;
        return;
    }

    ks::service::ServiceStatus finalStatus;
    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::StartServiceByName(
        toWideString(serviceNameText),
        6000,
        SERVICE_RUNNING,
        &finalStatus,
        &errorText,
        &errorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("挂载驱动服务"),
            errorCode);
        if (isDriverSignatureLoadError(static_cast<DWORD>(errorCode)))
        {
            const QString binaryPathText =
                (m_binaryPathEdit == nullptr) ? QString() : m_binaryPathEdit->text().trimmed();
            const QString adviceText =
                buildDriverSignatureLoadAdvice(static_cast<DWORD>(errorCode), serviceNameText, binaryPathText);
            appendOperateLogLine(adviceText);
            err << operationEvent
                << driverText(
                    "driver.log.load.signature_failed",
                    QStringLiteral("[DriverDock] 挂载失败：驱动签名/镜像校验失败, service="))
                << serviceNameText.toStdString()
                << ", error=" << errorCode
                << ", path=" << binaryPathText.toStdString()
                << eol;
            return;
        }

        appendOperateLogLine(
            driverText("driver.operation.load.failed", QStringLiteral("挂载失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        err << operationEvent
            << driverText("driver.log.load.failed", QStringLiteral("[DriverDock] 挂载失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(finalStatus.currentState == SERVICE_RUNNING
        ? driverText("driver.operation.load.success", QStringLiteral("挂载成功：service=%1"))
            .arg(serviceNameText)
        : driverText("driver.operation.load.completed", QStringLiteral("挂载结束：当前状态=%1"))
            .arg(serviceStateToText(finalStatus.currentState)));

    info << operationEvent
        << driverText("driver.log.load.completed", QStringLiteral("[DriverDock] 挂载执行完成, service="))
        << serviceNameText.toStdString()
        << ", finalState=" << finalStatus.currentState
        << eol;

    refreshDriverServiceRecords();
    refreshLoadedKernelModuleRecords();
}


void DriverDock::unloadSelectedDriverService()
{
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.unload.empty_name", QStringLiteral("卸载失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.unload.empty_name", QStringLiteral("[DriverDock] 卸载失败：服务名为空。"))
            << eol;
        return;
    }

    ks::service::ServiceStatus finalStatus;
    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::StopServiceByName(
        toWideString(serviceNameText),
        6000,
        SERVICE_STOPPED,
        &finalStatus,
        &errorText,
        &errorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("卸载驱动服务"),
            errorCode);
        appendOperateLogLine(
            driverText("driver.operation.unload.failed", QStringLiteral("卸载失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        err << operationEvent
            << driverText("driver.log.unload.failed", QStringLiteral("[DriverDock] 卸载失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(finalStatus.currentState == SERVICE_STOPPED
        ? driverText("driver.operation.unload.success", QStringLiteral("卸载成功：service=%1"))
            .arg(serviceNameText)
        : driverText("driver.operation.unload.completed", QStringLiteral("卸载结束：当前状态=%1"))
            .arg(serviceStateToText(finalStatus.currentState)));

    info << operationEvent
        << driverText("driver.log.unload.completed", QStringLiteral("[DriverDock] 卸载执行完成, service="))
        << serviceNameText.toStdString()
        << ", finalState=" << finalStatus.currentState
        << eol;

    refreshDriverServiceRecords();
    refreshLoadedKernelModuleRecords();
}


void DriverDock::deleteSelectedDriverService()
{
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.delete.empty_name", QStringLiteral("删除失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.delete.empty_name", QStringLiteral("[DriverDock] 删除失败：服务名为空。"))
            << eol;
        return;
    }

    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::DeleteServiceByName(
        toWideString(serviceNameText),
        true,
        4000,
        &errorText,
        &errorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("删除驱动服务"),
            errorCode);
        appendOperateLogLine(
            driverText("driver.operation.delete.failed", QStringLiteral("删除失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        err << operationEvent
            << driverText("driver.log.delete.failed", QStringLiteral("[DriverDock] 删除失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.delete.succeeded", QStringLiteral("删除成功（或已标记删除）：service=%1"))
        .arg(serviceNameText));
    info << operationEvent
        << driverText("driver.log.delete.completed", QStringLiteral("[DriverDock] 删除执行完成, service="))
        << serviceNameText.toStdString() << eol;
    refreshDriverServiceRecords();
    refreshLoadedKernelModuleRecords();
}
