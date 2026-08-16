#include "ProcessDetailWindow.InternalCommon.h"

#include <QSignalBlocker>

using namespace process_detail_window_internal;

namespace
{
    // ScopedPrivilegeIdentityHandle：在令牌查询/调整期间持有目标进程对象，阻止 PID 被复用。
    class ScopedPrivilegeIdentityHandle final
    {
    public:
        explicit ScopedPrivilegeIdentityHandle(const HANDLE handleValue)
            : m_handle(handleValue)
        {
        }

        ~ScopedPrivilegeIdentityHandle()
        {
            if (m_handle != nullptr)
            {
                ::CloseHandle(m_handle);
            }
        }

        ScopedPrivilegeIdentityHandle(const ScopedPrivilegeIdentityHandle&) = delete;
        ScopedPrivilegeIdentityHandle& operator=(const ScopedPrivilegeIdentityHandle&) = delete;

    private:
        HANDLE m_handle = nullptr;
    };

    // invokePrivilegeActionForIdentity：校验 PID 创建时间，并在动作结束前持续持有进程句柄。
    bool invokePrivilegeActionForIdentity(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime100ns,
        const std::function<bool(std::string*)>& actionInvoker,
        std::string* const detailTextOut)
    {
        if (!actionInvoker)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::action invoker is unavailable";
            }
            return false;
        }
        if (processId == 0U || expectedCreationTime100ns == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::process identity is unavailable";
            }
            return false;
        }

        HANDLE rawProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            processId);
        if (rawProcessHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::OpenProcess failed, error="
                    + std::to_string(::GetLastError());
            }
            return false;
        }
        ScopedPrivilegeIdentityHandle processHandle(rawProcessHandle);

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(
            rawProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::GetProcessTimes failed, error="
                    + std::to_string(::GetLastError());
            }
            return false;
        }

        const std::uint64_t actualCreationTime100ns =
            (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U)
            | static_cast<std::uint64_t>(creationTime.dwLowDateTime);
        if (actualCreationTime100ns == 0U
            || actualCreationTime100ns != expectedCreationTime100ns)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::process identity changed";
            }
            return false;
        }

        return actionInvoker(detailTextOut);
    }
}

void ProcessDetailWindow::requestAsyncActionPrivilegeRefresh()
{
    if (m_actionPrivilegeStatusLabel == nullptr || m_actionPrivilegeRefreshing)
    {
        return;
    }

    m_actionPrivilegeInitialRefreshStarted = true;
    m_actionPrivilegeRefreshing = true;
    m_actionPrivilegeReadable = false;
    const std::uint64_t refreshTicket = ++m_actionPrivilegeRefreshTicket;
    m_actionPrivilegeStatusLabel->setText(
        ks::i18n::text(QStringLiteral("process.detail.privileges.status.querying"), QString()));
    m_actionPrivilegeStatusLabel->setStyleSheet(
        buildStateLabelStyle(statusSecondaryColor(), 600));
    if (m_actionPrivilegeRefreshButton != nullptr)
    {
        m_actionPrivilegeRefreshButton->setEnabled(false);
    }
    if (m_applyActionPrivilegeR3Button != nullptr)
    {
        m_applyActionPrivilegeR3Button->setEnabled(false);
    }
    if (m_applyActionPrivilegeR0Button != nullptr)
    {
        m_applyActionPrivilegeR0Button->setEnabled(false);
    }
    for (QCheckBox* privilegeCheckBox : m_actionPrivilegeCheckBoxes)
    {
        if (privilegeCheckBox != nullptr)
        {
            privilegeCheckBox->setEnabled(false);
        }
    }

    const std::uint32_t processId = m_baseRecord.pid;
    const std::uint64_t creationTime100ns = m_baseRecord.creationTime100ns;
    const std::string expectedIdentityKey = identityKey();
    const QPointer<ProcessDetailWindow> guard(this);
    QRunnable* backgroundTask = QRunnable::create([
        guard,
        processId,
        creationTime100ns,
        expectedIdentityKey,
        refreshTicket]()
    {
        ActionPrivilegeRefreshResult refreshResult;
        refreshResult.identityKey = expectedIdentityKey;
        refreshResult.ticket = refreshTicket;
        std::string detailText;
        refreshResult.queryOk = invokePrivilegeActionForIdentity(
            processId,
            creationTime100ns,
            [processId, &refreshResult](std::string* const actionDetailText)
            {
                return ks::process::QueryTokenPrivilegesByPid(
                    processId,
                    &refreshResult.privileges,
                    actionDetailText);
            },
            &detailText);
        refreshResult.diagnosticText = QString::fromStdString(detailText);

        if (guard == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(guard, [guard, refreshResult = std::move(refreshResult)]() mutable
        {
            if (guard == nullptr)
            {
                return;
            }
            guard->applyActionPrivilegeRefreshResult(refreshResult);
        }, Qt::QueuedConnection);
    });
    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

void ProcessDetailWindow::applyActionPrivilegeRefreshResult(
    const ActionPrivilegeRefreshResult& refreshResult)
{
    if (refreshResult.ticket != m_actionPrivilegeRefreshTicket
        || refreshResult.identityKey != identityKey())
    {
        return;
    }

    m_actionPrivilegeRefreshing = false;
    m_actionPrivilegeReadable = refreshResult.queryOk;
    m_actionPrivilegeSnapshot = refreshResult.privileges;
    if (m_actionPrivilegeRefreshButton != nullptr)
    {
        m_actionPrivilegeRefreshButton->setEnabled(true);
    }

    std::size_t adjustableCount = 0U;
    std::size_t enabledCount = 0U;
    for (std::size_t privilegeIndex = 0U;
         privilegeIndex < m_actionPrivilegeCheckBoxes.size();
         ++privilegeIndex)
    {
        QCheckBox* const privilegeCheckBox = m_actionPrivilegeCheckBoxes[privilegeIndex];
        if (privilegeCheckBox == nullptr)
        {
            continue;
        }

        const QSignalBlocker signalBlocker(privilegeCheckBox);
        privilegeCheckBox->setChecked(false);
        privilegeCheckBox->setEnabled(false);
        if (!refreshResult.queryOk || privilegeIndex >= refreshResult.privileges.size())
        {
            privilegeCheckBox->setToolTip(
                ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.unknown"),
                    QString()));
            continue;
        }

        const ks::process::TokenPrivilegeInfo& privilegeInfo =
            refreshResult.privileges[privilegeIndex];
        if (privilegeInfo.state == ks::process::TokenPrivilegeState::Enabled
            || privilegeInfo.state == ks::process::TokenPrivilegeState::Disabled)
        {
            const bool enabled =
                privilegeInfo.state == ks::process::TokenPrivilegeState::Enabled;
            privilegeCheckBox->setChecked(enabled);
            privilegeCheckBox->setEnabled(true);
            privilegeCheckBox->setToolTip(
                ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.adjustable"),
                    QString()));
            ++adjustableCount;
            if (enabled)
            {
                ++enabledCount;
            }
            continue;
        }

        privilegeCheckBox->setToolTip(
            privilegeInfo.state == ks::process::TokenPrivilegeState::NotPresent
                ? ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.not_present"),
                    QString())
                : ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.unknown"),
                    QString()));
    }

    if (m_applyActionPrivilegeR3Button != nullptr)
    {
        m_applyActionPrivilegeR3Button->setEnabled(refreshResult.queryOk && adjustableCount > 0U);
    }
    // 驱动协议接入前保持禁用；后续提交会按 R0 capability 动态启用。
    if (m_applyActionPrivilegeR0Button != nullptr)
    {
        m_applyActionPrivilegeR0Button->setEnabled(false);
    }

    if (m_actionPrivilegeStatusLabel == nullptr)
    {
        return;
    }
    if (!refreshResult.queryOk)
    {
        m_actionPrivilegeStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("process.detail.privileges.status.unavailable"),
                QString()).arg(refreshResult.diagnosticText));
        m_actionPrivilegeStatusLabel->setStyleSheet(
            buildStateLabelStyle(statusWarningColor(), 700));
        return;
    }

    m_actionPrivilegeStatusLabel->setText(
        ks::i18n::text(
            QStringLiteral("process.detail.privileges.status.current"),
            QString())
            .arg(enabledCount)
            .arg(adjustableCount)
            .arg(refreshResult.usedR0
                ? ks::i18n::text(
                    QStringLiteral("process.detail.privileges.source.r0"),
                    QString())
                : ks::i18n::text(
                    QStringLiteral("process.detail.privileges.source.r3"),
                    QString())));
    m_actionPrivilegeStatusLabel->setStyleSheet(
        buildStateLabelStyle(statusIdleColor(), 600));
}

void ProcessDetailWindow::executeApplyActionPrivileges(const bool useR0)
{
    if (m_actionPrivilegeRefreshing || !m_actionPrivilegeReadable)
    {
        return;
    }
    if (useR0)
    {
        // R0 Token IOCTL 在驱动协议提交后接入；禁用按钮保证这里不会由当前 UI 触发。
        return;
    }

    std::vector<ks::process::TokenPrivilegeEdit> privilegeEdits;
    const std::size_t comparableCount = std::min(
        m_actionPrivilegeSnapshot.size(),
        m_actionPrivilegeCheckBoxes.size());
    for (std::size_t privilegeIndex = 0U;
         privilegeIndex < comparableCount;
         ++privilegeIndex)
    {
        const ks::process::TokenPrivilegeInfo& privilegeInfo =
            m_actionPrivilegeSnapshot[privilegeIndex];
        QCheckBox* const privilegeCheckBox = m_actionPrivilegeCheckBoxes[privilegeIndex];
        if (privilegeCheckBox == nullptr
            || !privilegeCheckBox->isEnabled()
            || (privilegeInfo.state != ks::process::TokenPrivilegeState::Enabled
                && privilegeInfo.state != ks::process::TokenPrivilegeState::Disabled))
        {
            continue;
        }

        const bool currentlyEnabled =
            privilegeInfo.state == ks::process::TokenPrivilegeState::Enabled;
        const bool requestedEnabled = privilegeCheckBox->isChecked();
        if (currentlyEnabled == requestedEnabled)
        {
            continue;
        }

        ks::process::TokenPrivilegeEdit privilegeEdit;
        privilegeEdit.privilegeName = privilegeInfo.privilegeName;
        privilegeEdit.action = requestedEnabled
            ? ks::process::TokenPrivilegeAction::Enable
            : ks::process::TokenPrivilegeAction::Disable;
        privilegeEdits.push_back(std::move(privilegeEdit));
    }

    if (privilegeEdits.empty())
    {
        if (m_actionPrivilegeStatusLabel != nullptr)
        {
            m_actionPrivilegeStatusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("process.detail.privileges.status.no_changes"),
                    QString()));
            m_actionPrivilegeStatusLabel->setStyleSheet(
                buildStateLabelStyle(statusSecondaryColor(), 600));
        }
        return;
    }

    m_actionPrivilegeRefreshing = true;
    const std::uint64_t applyTicket = ++m_actionPrivilegeRefreshTicket;
    if (m_actionPrivilegeStatusLabel != nullptr)
    {
        m_actionPrivilegeStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("process.detail.privileges.status.applying_r3"),
                QString()).arg(privilegeEdits.size()));
        m_actionPrivilegeStatusLabel->setStyleSheet(
            buildStateLabelStyle(statusSecondaryColor(), 600));
    }
    if (m_actionPrivilegeRefreshButton != nullptr)
    {
        m_actionPrivilegeRefreshButton->setEnabled(false);
    }
    if (m_applyActionPrivilegeR3Button != nullptr)
    {
        m_applyActionPrivilegeR3Button->setEnabled(false);
    }
    if (m_applyActionPrivilegeR0Button != nullptr)
    {
        m_applyActionPrivilegeR0Button->setEnabled(false);
    }
    for (QCheckBox* privilegeCheckBox : m_actionPrivilegeCheckBoxes)
    {
        if (privilegeCheckBox != nullptr)
        {
            privilegeCheckBox->setEnabled(false);
        }
    }

    struct ApplyTaskResult
    {
        ActionPrivilegeRefreshResult refreshResult;
        QString failureDetails;
        std::size_t editCount = 0U;
        bool allSucceeded = false;
    };

    const std::uint32_t processId = m_baseRecord.pid;
    const std::uint64_t creationTime100ns = m_baseRecord.creationTime100ns;
    const std::string expectedIdentityKey = identityKey();
    const QPointer<ProcessDetailWindow> guard(this);
    QRunnable* backgroundTask = QRunnable::create([
        guard,
        processId,
        creationTime100ns,
        expectedIdentityKey,
        applyTicket,
        privilegeEdits = std::move(privilegeEdits)]() mutable
    {
        ApplyTaskResult taskResult;
        taskResult.editCount = privilegeEdits.size();
        taskResult.refreshResult.identityKey = expectedIdentityKey;
        taskResult.refreshResult.ticket = applyTicket;
        QStringList failureLines;
        std::string identityDetailText;
        const bool identityActionOk = invokePrivilegeActionForIdentity(
            processId,
            creationTime100ns,
            [processId, &privilegeEdits, &taskResult, &failureLines](std::string* const actionDetailText)
            {
                taskResult.allSucceeded = true;
                for (const ks::process::TokenPrivilegeEdit& privilegeEdit : privilegeEdits)
                {
                    std::string privilegeDetailText;
                    if (ks::process::ApplyTokenPrivilegeEditsByPid(
                        processId,
                        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                        false,
                        std::vector<ks::process::TokenPrivilegeEdit>{ privilegeEdit },
                        &privilegeDetailText))
                    {
                        continue;
                    }

                    taskResult.allSucceeded = false;
                    failureLines.push_back(QStringLiteral("%1: %2")
                        .arg(QString::fromStdString(privilegeEdit.privilegeName))
                        .arg(QString::fromStdString(privilegeDetailText)));
                }

                taskResult.refreshResult.queryOk = ks::process::QueryTokenPrivilegesByPid(
                    processId,
                    &taskResult.refreshResult.privileges,
                    actionDetailText);
                return taskResult.refreshResult.queryOk;
            },
            &identityDetailText);
        if (!identityActionOk)
        {
            taskResult.allSucceeded = false;
            taskResult.refreshResult.queryOk = false;
            taskResult.refreshResult.diagnosticText = QString::fromStdString(identityDetailText);
        }
        taskResult.failureDetails = failureLines.join(QStringLiteral("\n"));

        if (guard == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(guard, [guard, taskResult = std::move(taskResult)]() mutable
        {
            if (guard == nullptr)
            {
                return;
            }

            guard->applyActionPrivilegeRefreshResult(taskResult.refreshResult);
            if (taskResult.refreshResult.ticket != guard->m_actionPrivilegeRefreshTicket
                || taskResult.refreshResult.identityKey != guard->identityKey()
                || guard->m_actionPrivilegeStatusLabel == nullptr)
            {
                return;
            }

            guard->m_actionPrivilegeStatusLabel->setText(
                ks::i18n::text(
                    taskResult.allSucceeded
                        ? QStringLiteral("process.detail.privileges.status.applied_r3")
                        : QStringLiteral("process.detail.privileges.status.apply_failed"),
                    QString())
                    .arg(taskResult.editCount)
                    .arg(taskResult.failureDetails));
            guard->m_actionPrivilegeStatusLabel->setStyleSheet(
                buildStateLabelStyle(
                    taskResult.allSucceeded ? statusIdleColor() : statusWarningColor(),
                    taskResult.allSucceeded ? 600 : 700));

            kLogEvent actionEvent;
            (taskResult.allSucceeded ? info : warn) << actionEvent
                << "[ProcessDetailWindow]::R3 token privilege apply, pid="
                << guard->m_baseRecord.pid
                << "::editCount=" << taskResult.editCount
                << "::allSucceeded=" << (taskResult.allSucceeded ? "true" : "false")
                << "::detail=" << taskResult.failureDetails.toStdString()
                << eol;
        }, Qt::QueuedConnection);
    });
    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}
