#include "KernelHvmTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum HvmCpuColumn : int
    {
        CpuColumnProcessor = 0,
        CpuColumnResource,
        CpuColumnSelfTest,
        CpuColumnVmxResult,
        CpuColumnNtStatus,
        CpuColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelHvmTab::KernelHvmTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelHvmTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(
            this,
            [this]() { refreshAsync(); },
            Qt::QueuedConnection);
    }
}

void KernelHvmTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    m_warningLabel = new QLabel(
        kernelText(
            "kernel.hvm.warning",
            QStringLiteral("⚠ 内核虚拟化实验后端：准备会分配每 CPU VMXON/VMCS 区域并构造 EPT；自检会在每个 CPU 上短暂执行 VMXON/VMXOFF。Hyper-V、VBS、嵌套虚拟化或其它 VMM 可能拒绝操作。准备完成或自检通过都不等于虚拟机已经启动。")),
        this);
    m_warningLabel->setWordWrap(true);
    m_warningLabel->setStyleSheet(QStringLiteral(
        "QLabel{padding:8px;border:1px solid %1;border-radius:4px;"
        "background:%2;color:%3;font-weight:600;}")
        .arg(KswordTheme::WarningHex())
        .arg(KswordTheme::ThemeColorName(
            KswordTheme::WarningBackgroundColor()))
        .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_warningLabel);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.hvm.refresh", QStringLiteral("刷新能力")),
        this);
    m_prepareButton = new QPushButton(
        kernelText("kernel.hvm.prepare", QStringLiteral("准备 VMX/EPT")),
        this);
    m_selfTestButton = new QPushButton(
        kernelText("kernel.hvm.self_test", QStringLiteral("逐 CPU 自检")),
        this);
    m_teardownButton = new QPushButton(
        kernelText("kernel.hvm.teardown", QStringLiteral("释放后端")),
        this);
    m_allowNestedCheck = new QCheckBox(
        kernelText(
            "kernel.hvm.allow_nested",
            QStringLiteral("允许在已检测到的 Hypervisor 中尝试嵌套 VMX")),
        this);
    for (QPushButton* button :
         { m_refreshButton, m_prepareButton, m_selfTestButton, m_teardownButton })
    {
        button->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }
    m_statusLabel = new QLabel(
        kernelText("kernel.hvm.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_prepareButton);
    toolbar->addWidget(m_selfTestButton);
    toolbar->addWidget(m_teardownButton);
    toolbar->addWidget(m_allowNestedCheck);
    toolbar->addStretch(1);
    toolbar->addWidget(m_statusLabel);
    rootLayout->addLayout(toolbar);

    m_summaryLabel = new QLabel(this);
    m_summaryLabel->setWordWrap(true);
    m_summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_summaryLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}")
            .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_summaryLabel);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_cpuTable = new ks::ui::VisibleTableWidget(splitter);
    m_cpuTable->setColumnCount(CpuColumnCount);
    m_cpuTable->setHorizontalHeaderLabels({
        kernelText("kernel.hvm.cpu.processor", QStringLiteral("处理器")),
        kernelText("kernel.hvm.cpu.resource", QStringLiteral("VMX 区域")),
        kernelText("kernel.hvm.cpu.self_test", QStringLiteral("自检")),
        kernelText("kernel.hvm.cpu.vmx_result", QStringLiteral("VMX 指令结果")),
        kernelText("kernel.hvm.cpu.ntstatus", QStringLiteral("NTSTATUS"))
    });
    m_cpuTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_cpuTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_cpuTable->setAlternatingRowColors(true);
    m_cpuTable->verticalHeader()->setVisible(false);
    m_cpuTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_cpuTable->horizontalHeader()->setStretchLastSection(true);

    m_detailEdit = new QTextEdit(splitter);
    m_detailEdit->setReadOnly(true);
    m_detailEdit->setPlaceholderText(
        kernelText(
            "kernel.hvm.detail.placeholder",
            QStringLiteral("刷新后显示 VMX MSR、EPT 映射与生命周期证据")));
    splitter->addWidget(m_cpuTable);
    splitter->addWidget(m_detailEdit);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    rootLayout->addWidget(splitter, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
    connect(m_prepareButton, &QPushButton::clicked, this, [this]() {
        prepareBackend();
    });
    connect(m_selfTestButton, &QPushButton::clicked, this, [this]() {
        selfTestBackend();
    });
    connect(m_teardownButton, &QPushButton::clicked, this, [this]() {
        teardownBackend();
    });
    updateButtons();
}

void KernelHvmTab::refreshAsync()
{
    if (m_operationRunning)
    {
        return;
    }
    m_operationRunning = true;
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.refreshing",
            QStringLiteral("正在读取 CPUID、VMX MSR 与后端状态...")));
    updateButtons();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis]() {
        ksword::ark::DriverClient client;
        auto result = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result = std::move(result)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyStatus(std::move(result));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyStatus(ksword::ark::HvmStatusResult result)
{
    m_operationRunning = false;
    m_supported = result.io.ok && !result.unsupported;
    if (!m_supported)
    {
        m_snapshot = {};
        m_cpuTable->setRowCount(0);
        m_summaryLabel->setText(
            result.unsupported
                ? kernelText(
                      "kernel.hvm.status.unsupported",
                      QStringLiteral("当前驱动不支持 HVM 协议，请更新并重新加载驱动。"))
                : kernelText(
                      "kernel.hvm.status.failed",
                      QStringLiteral("HVM 状态读取失败：%1"))
                      .arg(QString::fromStdString(result.io.message)));
        m_detailEdit->clear();
        m_statusLabel->setText(
            kernelText("kernel.hvm.status.failed_short", QStringLiteral("状态：读取失败")));
        updateButtons();
        return;
    }

    m_snapshot = result.response;
    const QString cpuVendor = fixedAscii(
        m_snapshot.cpuVendor,
        KSWORD_ARK_HVM_VENDOR_CHARS);
    const QString hypervisorVendor = fixedAscii(
        m_snapshot.hypervisorVendor,
        KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS);
    m_summaryLabel->setText(
        kernelText(
            "kernel.hvm.summary",
            QStringLiteral("CPU：%1　Hypervisor：%2　状态：%3　准备 CPU：%4/%5　自检通过：%6/%5　EPT 页表页：%7　RAM 映射：%8 GiB"))
            .arg(cpuVendor.isEmpty() ? QStringLiteral("-") : cpuVendor)
            .arg(hypervisorVendor.isEmpty()
                     ? kernelText("kernel.hvm.none", QStringLiteral("未检测到"))
                     : hypervisorVendor)
            .arg(stateText(m_snapshot.stateFlags))
            .arg(m_snapshot.preparedProcessorCount)
            .arg(m_snapshot.processorCount)
            .arg(m_snapshot.selfTestPassedProcessorCount)
            .arg(m_snapshot.eptPageCount)
            .arg(
                static_cast<double>(m_snapshot.mappedRamBytes) /
                    (1024.0 * 1024.0 * 1024.0),
                0,
                'f',
                2));

    const int rowCount = static_cast<int>(std::min<unsigned long>(
        m_snapshot.processorCount,
        KSWORD_ARK_HVM_MAX_PROCESSORS));
    m_cpuTable->setRowCount(rowCount);
    for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex)
    {
        const auto& cpu = m_snapshot.processors[rowIndex];
        const bool resourceReady =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY) != 0U;
        const bool tested =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED) != 0U;
        const bool passed =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED) != 0U;
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnProcessor,
            readOnlyItem(
                QStringLiteral("%1:%2")
                    .arg(cpu.processorGroup)
                    .arg(cpu.processorNumber)));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnResource,
            readOnlyItem(
                resourceReady
                    ? kernelText("kernel.hvm.yes", QStringLiteral("已准备"))
                    : kernelText("kernel.hvm.no", QStringLiteral("未准备"))));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnSelfTest,
            readOnlyItem(
                !tested
                    ? kernelText("kernel.hvm.not_tested", QStringLiteral("未执行"))
                    : (passed
                           ? kernelText("kernel.hvm.passed", QStringLiteral("通过"))
                           : kernelText("kernel.hvm.failed", QStringLiteral("失败")))));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnVmxResult,
            readOnlyItem(
                cpu.vmxInstructionResult == 0xFFU
                    ? QStringLiteral("-")
                    : QString::number(cpu.vmxInstructionResult)));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnNtStatus,
            readOnlyItem(ntStatusText(cpu.lastStatus)));
    }
    m_detailEdit->setPlainText(buildDetail(m_snapshot));
    m_allowNestedCheck->setVisible(
        (m_snapshot.featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL);
    m_statusLabel->setText(
        kernelText("kernel.hvm.status.ready", QStringLiteral("状态：已刷新")));
    updateButtons();
}

void KernelHvmTab::runControlAsync(
    const unsigned long command,
    const bool force)
{
    if (m_operationRunning)
    {
        return;
    }
    m_operationRunning = true;
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.operating",
            QStringLiteral("正在执行 HVM 生命周期操作...")));
    updateButtons();
    const unsigned long generation = m_snapshot.generation;
    const bool allowNested = m_allowNestedCheck->isChecked();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis, command, generation, force, allowNested]() {
        ksword::ark::DriverClient client;
        auto control = client.controlHvm(
            command,
            generation,
            force,
            allowNested,
            true);
        auto status = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis,
             command,
             control = std::move(control),
             status = std::move(status)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyControl(
                        command,
                        std::move(control),
                        std::move(status));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyControl(
    const unsigned long command,
    ksword::ark::HvmControlResult control,
    ksword::ark::HvmStatusResult status)
{
    m_operationRunning = false;
    if (!control.io.ok ||
        control.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.hvm.operation.title", QStringLiteral("HVM 操作")),
            kernelText(
                "kernel.hvm.operation.failed",
                QStringLiteral("操作未完成。\n协议状态：%1\nNTSTATUS：%2\n%3"))
                .arg(control.response.status)
                .arg(ntStatusText(control.response.lastStatus))
                .arg(QString::fromStdString(control.io.message)));
    }
    else
    {
        const QString action =
            command == KSWORD_ARK_HVM_CONTROL_PREPARE
            ? kernelText("kernel.hvm.action.prepared", QStringLiteral("VMX/EPT 后端已准备"))
            : (command == KSWORD_ARK_HVM_CONTROL_SELF_TEST
                   ? kernelText("kernel.hvm.action.tested", QStringLiteral("逐 CPU VMX 自检已完成"))
                   : kernelText("kernel.hvm.action.torn_down", QStringLiteral("HVM 后端资源已释放")));
        QMessageBox::information(
            this,
            kernelText("kernel.hvm.operation.title", QStringLiteral("HVM 操作")),
            action);
    }
    applyStatus(std::move(status));
}

void KernelHvmTab::prepareBackend()
{
    const QString warning = kernelText(
        "kernel.hvm.prepare.warning",
        QStringLiteral(
            "准备操作会为每个活动 CPU 分配物理连续的 VMXON/VMCS 页面，并根据已安装 RAM 构造 EPT 恒等映射。"
            "它不会执行 VMLAUNCH，但会增加不可分页内存占用；驱动卸载或“释放后端”会回收这些资源。"));
    if (confirmTyped(warning, QStringLiteral("PREPARE HVM")))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_PREPARE, false);
    }
}

void KernelHvmTab::selfTestBackend()
{
    const QString warning = kernelText(
        "kernel.hvm.self_test.warning",
        QStringLiteral(
            "这是高风险硬件自检：驱动会将系统线程依次绑定到每个 CPU，短暂调整 CR4.VMXE，执行 VMXON 后立即 VMXOFF，再恢复原始 CR4。"
            "已运行的 Hyper-V/VBS/其它 VMM、固件限制或异常 VMX 实现可能导致操作被拒绝、系统不稳定，极端情况下可能蓝屏。"
            "请先保存工作并确保你接受重启风险。"));
    if (confirmTyped(warning, QStringLiteral("RUN VMX SELF TEST")))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_SELF_TEST, true);
    }
}

void KernelHvmTab::teardownBackend()
{
    if (QMessageBox::question(
            this,
            kernelText("kernel.hvm.teardown.title", QStringLiteral("释放 HVM 后端")),
            kernelText(
                "kernel.hvm.teardown.warning",
                QStringLiteral("释放所有 VMXON、VMCS 和 EPT 页表资源，并清除本次自检结果。继续吗？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) == QMessageBox::Yes)
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_TEARDOWN, false);
    }
}

bool KernelHvmTab::confirmTyped(
    const QString& warning,
    const QString& phrase)
{
    const auto answer = QMessageBox::warning(
        this,
        kernelText("kernel.hvm.confirm.title", QStringLiteral("内核虚拟化风险确认")),
        warning,
        QMessageBox::Ok | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (answer != QMessageBox::Ok)
    {
        return false;
    }
    bool accepted = false;
    const QString input = QInputDialog::getText(
        this,
        kernelText("kernel.hvm.confirm.typed.title", QStringLiteral("输入确认短语")),
        kernelText(
            "kernel.hvm.confirm.typed.prompt",
            QStringLiteral("请输入 %1 以继续："))
            .arg(phrase),
        QLineEdit::Normal,
        QString(),
        &accepted);
    return accepted && input == phrase;
}

void KernelHvmTab::updateButtons()
{
    const bool resourcesReady =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0U;
    m_refreshButton->setEnabled(!m_operationRunning);
    m_prepareButton->setEnabled(
        !m_operationRunning && m_supported && !resourcesReady);
    m_selfTestButton->setEnabled(
        !m_operationRunning && m_supported && resourcesReady);
    m_teardownButton->setEnabled(
        !m_operationRunning && m_supported && resourcesReady);
    m_allowNestedCheck->setEnabled(
        !m_operationRunning && !resourcesReady);
}

QString KernelHvmTab::buildDetail(
    const KSWORD_ARK_QUERY_HVM_RESPONSE& response) const
{
    return kernelText(
        "kernel.hvm.detail",
        QStringLiteral(
            "协议版本：%1\n"
            "查询状态：%2\n"
            "生命周期：%3\n"
            "代次：%4\n"
            "CPU 能力：%5\n"
            "IA32_FEATURE_CONTROL：0x%6\n"
            "IA32_VMX_BASIC：0x%7\n"
            "IA32_VMX_EPT_VPID_CAP：0x%8\n"
            "CR0 fixed0/fixed1：0x%9 / 0x%10\n"
            "CR4 fixed0/fixed1：0x%11 / 0x%12\n"
            "EPTP：0x%13\n"
            "EPT PML4/PDPT/2MiB leaf：%14 / %15 / %16\n"
            "映射 RAM：%17 bytes\n"
            "最高映射物理地址：0x%18\n"
            "最近 NTSTATUS：%19\n\n"
            "边界：当前后端只完成能力证明、资源准备、RAM EPT 恒等映射与 VMXON/VMXOFF 自检；"
            "它没有执行 VMLAUNCH，不应被解释为活动虚拟机或活动监控器。"))
        .arg(response.version)
        .arg(response.queryStatus)
        .arg(stateText(response.stateFlags))
        .arg(response.generation)
        .arg(featureText(response.featureFlags))
        .arg(QString::number(response.featureControl, 16).toUpper())
        .arg(QString::number(response.vmxBasic, 16).toUpper())
        .arg(QString::number(response.vmxEptVpidCapabilities, 16).toUpper())
        .arg(QString::number(response.cr0Fixed0, 16).toUpper())
        .arg(QString::number(response.cr0Fixed1, 16).toUpper())
        .arg(QString::number(response.cr4Fixed0, 16).toUpper())
        .arg(QString::number(response.cr4Fixed1, 16).toUpper())
        .arg(QString::number(response.eptPointer, 16).toUpper())
        .arg(response.eptPml4Entries)
        .arg(response.eptPdptEntries)
        .arg(response.eptLargePageEntries)
        .arg(response.mappedRamBytes)
        .arg(QString::number(
            response.highestMappedPhysicalAddress,
            16).toUpper())
        .arg(ntStatusText(response.lastStatus));
}

QString KernelHvmTab::featureText(const std::uint64_t flags)
{
    struct FeatureName
    {
        std::uint64_t flag;
        const char* name;
    };
    static constexpr std::array<FeatureName, 16> names{{
        { KSWORD_ARK_HVM_FEATURE_INTEL, "Intel" },
        { KSWORD_ARK_HVM_FEATURE_VMX, "VMX" },
        { KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED, "FeatureControlLocked" },
        { KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX, "VmxOutsideSmx" },
        { KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS, "TrueControls" },
        { KSWORD_ARK_HVM_FEATURE_EPT, "EPT" },
        { KSWORD_ARK_HVM_FEATURE_EPT_WB, "EPT-WB" },
        { KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL, "EPT-4Level" },
        { KSWORD_ARK_HVM_FEATURE_EPT_2MB, "EPT-2MiB" },
        { KSWORD_ARK_HVM_FEATURE_EPT_AD, "EPT-A/D" },
        { KSWORD_ARK_HVM_FEATURE_INVEPT, "INVEPT" },
        { KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE, "INVEPT-Single" },
        { KSWORD_ARK_HVM_FEATURE_INVEPT_ALL, "INVEPT-All" },
        { KSWORD_ARK_HVM_FEATURE_VPID, "VPID" },
        { KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT, "HypervisorPresent" },
        { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED, "NestedVmxExposed" }
    }};
    QStringList values;
    for (const auto& value : names)
    {
        if ((flags & value.flag) != 0ULL)
        {
            values.push_back(QString::fromLatin1(value.name));
        }
    }
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(", "));
}

QString KernelHvmTab::stateText(const std::uint32_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_HVM_STATE_INITIALIZED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.initialized", QStringLiteral("已初始化")));
    if ((flags & KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.resources", QStringLiteral("资源已准备")));
    if ((flags & KSWORD_ARK_HVM_STATE_EPT_READY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.ept", QStringLiteral("EPT 已准备")));
    if ((flags & KSWORD_ARK_HVM_STATE_SELF_TESTED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.tested", QStringLiteral("已自检")));
    if ((flags & KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.passed", QStringLiteral("自检通过")));
    if ((flags & KSWORD_ARK_HVM_STATE_BUSY) != 0U)
        values.push_back(kernelText("kernel.hvm.state.busy", QStringLiteral("操作中")));
    if ((flags & KSWORD_ARK_HVM_STATE_FAULTED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.faulted", QStringLiteral("存在失败")));
    if ((flags & KSWORD_ARK_HVM_STATE_EPT_TRUNCATED) != 0U)
        values.push_back(kernelText("kernel.hvm.state.truncated", QStringLiteral("EPT 映射已截断")));
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(" / "));
}

QString KernelHvmTab::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(
            static_cast<quint32>(status),
            8,
            16,
            QLatin1Char('0'))
        .toUpper();
}

QString KernelHvmTab::fixedAscii(const char* text, const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return {};
    }
    int length = 0;
    while (length < capacity && text[length] != '\0')
    {
        ++length;
    }
    return QString::fromLatin1(text, length);
}
