#include "BugcheckGuardPage.h"

#include "../../ArkDriverClient/ArkDriverClient.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

#include <QCheckBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QShowEvent>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

#include <Windows.h>

namespace
{
    bool sendWinPrintScreen()
    {
        INPUT inputs[4]{};
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].ki.wVk = VK_LWIN;
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].ki.wVk = VK_SNAPSHOT;
        inputs[2].type = INPUT_KEYBOARD;
        inputs[2].ki.wVk = VK_SNAPSHOT;
        inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;
        inputs[3].type = INPUT_KEYBOARD;
        inputs[3].ki.wVk = VK_LWIN;
        inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

        const UINT sent = SendInput(4U, inputs, sizeof(INPUT));
        if (sent != 4U) {
            INPUT releases[2]{};
            releases[0].type = INPUT_KEYBOARD;
            releases[0].ki.wVk = VK_SNAPSHOT;
            releases[0].ki.dwFlags = KEYEVENTF_KEYUP;
            releases[1].type = INPUT_KEYBOARD;
            releases[1].ki.wVk = VK_LWIN;
            releases[1].ki.dwFlags = KEYEVENTF_KEYUP;
            (void)SendInput(2U, releases, sizeof(INPUT));
        }
        return sent == 4U;
    }

    QString bugcheckGuardStatusText(
        const unsigned long status,
        const long lastStatus)
    {
        QString reason;
        switch (status) {
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.active"),
                QStringLiteral("缓冲 Hook 已启用，等待一次 KeBugCheckEx"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.inactive"),
                QStringLiteral("缓冲 Hook 未启用"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.confirm"),
                QStringLiteral("R0 拒绝：缺少用户风险确认"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.unsupported"),
                QStringLiteral("当前驱动或 Windows 环境不支持此 Hook"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.conflict"),
                QStringLiteral("KeBugCheckEx 已被其它 Hook 修改，已拒绝覆盖"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.patch_failed"),
                QStringLiteral("Hook 写入失败，未启用"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.busy"),
                QStringLiteral("上一次触发仍在执行或等待清理，请先禁用并重试"));
            break;
        default:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.invalid"),
                QStringLiteral("蓝屏缓冲状态不可用"));
            break;
        }
        return QStringLiteral("%1；NTSTATUS=0x%2")
            .arg(reason)
            .arg(
                static_cast<unsigned long>(lastStatus),
                8,
                16,
                QLatin1Char('0'))
            .toUpper();
    }

    void showOpaqueMessage(
        QWidget* parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksBugcheckGuardMessageBox"));
        dialog.setStyleSheet(
            KswordTheme::OpaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
    }
}

namespace ks::misc
{
    BugcheckGuardPage::BugcheckGuardPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
    }

    void BugcheckGuardPage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
    }

    void BugcheckGuardPage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        auto& language = ks::i18n::LanguageManager::instance();
        m_warningLabel = new QLabel(this);
        m_warningLabel->setWordWrap(true);
        m_warningLabel->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;font-weight:650;}")
                .arg(KswordTheme::ErrorHex())
                .arg(KswordTheme::ThemeColorName(
                    KswordTheme::WarningBackgroundColor()))
                .arg(KswordTheme::TextPrimaryHex()));
        language.bindText(
            m_warningLabel,
            QStringLiteral("misc.experimental.bugcheck.warning"),
            QStringLiteral(
                "⚠ 蓝屏缓冲会修改 ntoskrnl!KeBugCheckEx 的入口。它不能修复导致蓝屏的错误，"
                "不能保证给出任何可用时间，也不能避免系统最终崩溃。触发时系统可能已经损坏、"
                "冻结或无法调度你的程序；PatchGuard 或安全产品也可能更早导致崩溃。"
                "“尝试忽略错误”会从一个按不返回方式设计的内核路径强行返回，可能立即执行无效代码。"
                "仅用于隔离的内核调试环境。"));
        rootLayout->addWidget(m_warningLabel);

        m_persistenceLabel = new QLabel(this);
        m_persistenceLabel->setWordWrap(true);
        m_persistenceLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));
        language.bindText(
            m_persistenceLabel,
            QStringLiteral("misc.experimental.bugcheck.persistence"),
            QStringLiteral(
                "该 Hook 默认关闭且一次性：命中时会先还原 KeBugCheckEx 入口，再给出缓冲。"
                "普通模式随后进入常规 BugCheck；忽略模式只尝试返回调用方，绝不代表系统已恢复。"
                "关闭或卸载驱动会还原尚未触发的 Hook；不要把它当作保护措施。"));
        rootLayout->addWidget(m_persistenceLabel);

        auto* controlGroup = new QGroupBox(this);
        language.bindText(
            controlGroup,
            QStringLiteral("misc.experimental.bugcheck.control.title"),
            QStringLiteral("实验性控制"));
        auto* controlLayout = new QVBoxLayout(controlGroup);
        auto* delayLayout = new QHBoxLayout();
        m_delayLabel = new QLabel(controlGroup);
        language.bindText(
            m_delayLabel,
            QStringLiteral("misc.experimental.bugcheck.delay"),
            QStringLiteral("触发后的缓冲时间："));
        m_delaySpin = new QSpinBox(controlGroup);
        m_delaySpin->setRange(
            static_cast<int>(KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS),
            static_cast<int>(KSWORD_ARK_BUGCHECK_GUARD_MAX_DELAY_SECONDS));
        m_delaySpin->setValue(10);
        language.bindSuffix(
            m_delaySpin,
            QStringLiteral("misc.experimental.bugcheck.delay.suffix"),
            QStringLiteral(" 秒"));
        m_delaySpin->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.delay.tooltip"),
                QStringLiteral("只允许 1 到 30 秒；实际缓冲可能不会生效。")));
        delayLayout->addWidget(m_delayLabel);
        delayLayout->addWidget(m_delaySpin);
        delayLayout->addStretch(1);
        controlLayout->addLayout(delayLayout);

        m_acknowledgeCheck = new QCheckBox(controlGroup);
        language.bindText(
            m_acknowledgeCheck,
            QStringLiteral("misc.experimental.bugcheck.ack"),
            QStringLiteral(
                "我已保存工作，理解这不是崩溃恢复，也理解强行返回可能立即蓝屏、死锁或损坏数据"));
        controlLayout->addWidget(m_acknowledgeCheck);

        m_tryIgnoreErrorCheck = new QCheckBox(controlGroup);
        language.bindText(
            m_tryIgnoreErrorCheck,
            QStringLiteral("misc.experimental.bugcheck.try_ignore"),
            QStringLiteral(
                "缓冲结束后尝试忽略当前错误并返回调用方（极危险）"));
        m_tryIgnoreErrorCheck->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.try_ignore.tooltip"),
                QStringLiteral(
                    "KeBugCheckEx 及其调用路径按不返回方式设计。强行返回后可能立即执行无效代码、"
                    "再次蓝屏、死锁或静默损坏数据；即使暂时可操作也必须尽快保存并强制重启。")));
        controlLayout->addWidget(m_tryIgnoreErrorCheck);

        m_screenshotOnTriggerCheck = new QCheckBox(controlGroup);
        language.bindText(
            m_screenshotOnTriggerCheck,
            QStringLiteral("misc.experimental.bugcheck.screenshot"),
            QStringLiteral("Hook 命中后立即模拟 Win+PrintScreen 截屏"));
        m_screenshotOnTriggerCheck->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.screenshot.tooltip"),
                QStringLiteral(
                    "由 R3 每 10 毫秒查询一次 Hook 状态；命中后只发送一次 Win+PrintScreen。"
                    "如果用户态、输入栈、DWM 或当前桌面已失去调度，截屏不会成功，也无法确认文件已保存。")));
        controlLayout->addWidget(m_screenshotOnTriggerCheck);

        m_screenshotPollTimer = new QTimer(this);
        m_screenshotPollTimer->setInterval(10);
        m_screenshotPollTimer->setTimerType(Qt::PreciseTimer);

        auto* actionLayout = new QHBoxLayout();
        m_refreshButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QString(),
            controlGroup);
        m_enableButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QString(),
            controlGroup);
        m_disableButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
            QString(),
            controlGroup);
        language.bindText(
            m_refreshButton,
            QStringLiteral("misc.experimental.bugcheck.refresh"),
            QStringLiteral("刷新状态"));
        language.bindText(
            m_enableButton,
            QStringLiteral("misc.experimental.bugcheck.enable"),
            QStringLiteral("启用一次性蓝屏缓冲"));
        language.bindText(
            m_disableButton,
            QStringLiteral("misc.experimental.bugcheck.disable"),
            QStringLiteral("禁用并还原 Hook"));
        for (QPushButton* button :
             { m_refreshButton, m_enableButton, m_disableButton }) {
            button->setStyleSheet(KswordTheme::ThemedButtonStyle());
        }
        actionLayout->addWidget(m_refreshButton);
        actionLayout->addWidget(m_enableButton);
        actionLayout->addWidget(m_disableButton);
        actionLayout->addStretch(1);
        controlLayout->addLayout(actionLayout);
        rootLayout->addWidget(controlGroup);

        auto* statusGroup = new QGroupBox(this);
        language.bindText(
            statusGroup,
            QStringLiteral("misc.experimental.bugcheck.status.title"),
            QStringLiteral("当前状态"));
        auto* statusLayout = new QVBoxLayout(statusGroup);
        m_statusLabel = new QLabel(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.waiting"),
                QStringLiteral("等待查询 R0 状态")),
            statusGroup);
        m_statusLabel->setWordWrap(true);
        m_statusLabel->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
        m_detailLabel = new QLabel(statusGroup);
        m_detailLabel->setWordWrap(true);
        m_detailLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        statusLayout->addWidget(m_statusLabel);
        statusLayout->addWidget(m_detailLabel);
        rootLayout->addWidget(statusGroup);
        rootLayout->addStretch(1);

        connect(
            m_refreshButton,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            m_enableButton,
            &QPushButton::clicked,
            this,
            [this]() { enableGuard(); });
        connect(
            m_disableButton,
            &QPushButton::clicked,
            this,
            [this]() { disableGuard(); });
        connect(
            m_acknowledgeCheck,
            &QCheckBox::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            m_screenshotPollTimer,
            &QTimer::timeout,
            this,
            [this]() { pollForScreenshot(); });
        updateButtons();
    }

    void BugcheckGuardPage::refreshStatus()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY);
        setBusy(false);
        if (!result.io.ok) {
            m_supported = false;
            m_active = false;
            m_statusLabel->setText(
                result.unsupported
                    ? ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.driver_old"),
                        QStringLiteral("当前 R0 驱动不支持蓝屏缓冲，请更新驱动"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.query_failed"),
                        QStringLiteral("无法读取 R0 蓝屏缓冲状态")));
            m_detailLabel->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.detail.io"),
                    QStringLiteral("Win32=%1；%2"))
                    .arg(result.io.win32Error)
                    .arg(QString::fromStdString(result.io.message)));
            updateButtons();
            return;
        }
        m_supported = true;
        updateFromResponse(result.response);
    }

    void BugcheckGuardPage::enableGuard()
    {
        if (m_busy || !m_acknowledgeCheck->isChecked()) {
            showOpaqueMessage(
                this,
                QMessageBox::Warning,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.ack_required"),
                    QStringLiteral("请先保存工作并勾选风险确认。")));
            return;
        }
        m_screenshotPollTimer->stop();
        m_screenshotDriverHandle.reset();
        m_screenshotWatcherArmed = false;
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE,
            static_cast<unsigned long>(m_delaySpin->value()),
            true,
            m_tryIgnoreErrorCheck->isChecked());
        setBusy(false);
        if (result.io.ok &&
            result.response.status ==
                KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE) {
            m_screenshotWatcherArmed =
                m_screenshotOnTriggerCheck->isChecked();
            m_screenshotAttempted = false;
            m_screenshotInputAccepted = false;
            if (m_screenshotWatcherArmed) {
                m_screenshotDriverHandle = client.open();
                m_screenshotPollTimer->start();
            }
        }
        if (!result.io.ok ||
            result.response.status != KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE) {
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                result.io.ok
                    ? bugcheckGuardStatusText(
                        result.response.status,
                        result.response.lastStatus)
                    : QString::fromStdString(result.io.message));
        }
        refreshStatus();
    }

    void BugcheckGuardPage::disableGuard()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE);
        setBusy(false);
        if (!result.io.ok) {
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                QString::fromStdString(result.io.message));
        }
        refreshStatus();
    }

    void BugcheckGuardPage::pollForScreenshot()
    {
        if (!m_screenshotWatcherArmed || m_screenshotAttempted) {
            m_screenshotPollTimer->stop();
            m_screenshotDriverHandle.reset();
            return;
        }

        ksword::ark::DriverClient client;
        if (!m_screenshotDriverHandle.isValid()) {
            m_screenshotDriverHandle = client.open();
        }
        if (!m_screenshotDriverHandle.isValid()) {
            return;
        }
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY,
            0UL,
            false,
            false,
            &m_screenshotDriverHandle);
        if (!result.io.ok) {
            m_screenshotDriverHandle.reset();
            return;
        }

        const bool fired =
            (result.response.stateFlags &
             KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED) != 0UL;
        if (fired) {
            attemptScreenshot();
            updateFromResponse(result.response);
            return;
        }

        const bool active =
            (result.response.stateFlags &
             KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE) != 0UL;
        if (!active) {
            m_screenshotPollTimer->stop();
            m_screenshotDriverHandle.reset();
            m_screenshotWatcherArmed = false;
        }
    }

    void BugcheckGuardPage::attemptScreenshot()
    {
        if (!m_screenshotWatcherArmed || m_screenshotAttempted) {
            return;
        }
        m_screenshotAttempted = true;
        m_screenshotInputAccepted = sendWinPrintScreen();
        m_screenshotPollTimer->stop();
        m_screenshotDriverHandle.reset();
    }

    void BugcheckGuardPage::updateFromResponse(
        const KSWORD_ARK_BUGCHECK_GUARD_RESPONSE& response)
    {
        const bool fired =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED) != 0UL;
        const bool ignored =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED) != 0UL;
        const bool executing =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING) != 0UL;
        const bool tryIgnore =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR) != 0UL;
        m_active =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE) != 0UL;
        if (m_active || fired) {
            m_delaySpin->setValue(static_cast<int>(response.delaySeconds));
            m_tryIgnoreErrorCheck->setChecked(tryIgnore || ignored);
        }
        m_triggered = fired || ignored || executing;
        if (fired) {
            attemptScreenshot();
        }
        if (m_screenshotWatcherArmed &&
            !m_screenshotAttempted &&
            m_active) {
            m_screenshotPollTimer->start();
        }
        else if (m_screenshotAttempted ||
                 (!m_active && !fired && !executing)) {
            m_screenshotPollTimer->stop();
        }
        if (!m_active && !fired && !executing) {
            m_screenshotDriverHandle.reset();
            m_screenshotWatcherArmed = false;
        }

        if (ignored) {
            m_statusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.ignored"),
                    QStringLiteral(
                        "已尝试从 KeBugCheckEx 返回。系统仍处于不可信状态；"
                        "立即保存能够保存的工作，然后强制重启。")));
        }
        else if (executing) {
            m_statusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.executing"),
                    QStringLiteral("Hook 正在执行或等待清理；系统可能随时崩溃。")));
        }
        else if (fired) {
            m_statusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.fired"),
                    QStringLiteral("已触发一次蓝屏缓冲；Hook 入口已还原。")));
        }
        else {
            m_statusLabel->setText(
                bugcheckGuardStatusText(response.status, response.lastStatus));
        }
        if (m_screenshotWatcherArmed) {
            const QString screenshotStatus = m_screenshotAttempted
                ? m_screenshotInputAccepted
                    ? ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.screenshot.status.sent"),
                        QStringLiteral(
                            "已发送 Win+PrintScreen；Windows 是否真正保存截图无法确认。"))
                    : ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.screenshot.status.failed"),
                        QStringLiteral(
                            "发送 Win+PrintScreen 失败；系统可能已无法处理用户态输入。"))
                : ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.screenshot.status.waiting"),
                    QStringLiteral("截屏监视已就绪，等待 Hook 命中。"));
            m_statusLabel->setText(
                QStringLiteral("%1\n%2")
                    .arg(m_statusLabel->text(), screenshotStatus));
        }
        m_statusLabel->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(ignored || executing
                    ? KswordTheme::ErrorHex()
                    : m_active
                        ? KswordTheme::WarningHex()
                        : KswordTheme::SuccessHex()));
        m_detailLabel->setText(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.detail.state"),
                QStringLiteral(
                    "KeBugCheckEx=0x%1；状态位=0x%2；缓冲=%3 秒；模式=%4；NTSTATUS=0x%5"))
                .arg(response.targetAddress, 16, 16, QLatin1Char('0'))
                .arg(response.stateFlags, 8, 16, QLatin1Char('0'))
                .arg(response.delaySeconds)
                .arg(
                    tryIgnore || ignored
                        ? ks::i18n::text(
                            QStringLiteral("misc.experimental.bugcheck.mode.ignore"),
                            QStringLiteral("尝试忽略错误并返回"))
                        : ks::i18n::text(
                            QStringLiteral("misc.experimental.bugcheck.mode.normal"),
                            QStringLiteral("转入常规 BugCheck")))
                .arg(
                    static_cast<unsigned long>(response.lastStatus),
                    8,
                    16,
                    QLatin1Char('0'))
            .toUpper());
        updateButtons();
    }

    void BugcheckGuardPage::updateButtons()
    {
        m_refreshButton->setEnabled(!m_busy);
        m_enableButton->setEnabled(
            !m_busy && m_supported && !m_active && !m_triggered &&
            m_acknowledgeCheck->isChecked());
        m_disableButton->setEnabled(
            !m_busy && m_supported && (m_active || m_triggered));
        m_delaySpin->setEnabled(!m_busy && !m_active && !m_triggered);
        m_acknowledgeCheck->setEnabled(!m_busy && !m_active && !m_triggered);
        m_tryIgnoreErrorCheck->setEnabled(!m_busy && !m_active && !m_triggered);
        m_screenshotOnTriggerCheck->setEnabled(
            !m_busy && !m_active && !m_triggered);
    }

    void BugcheckGuardPage::setBusy(const bool busy)
    {
        m_busy = busy;
        updateButtons();
    }
}
