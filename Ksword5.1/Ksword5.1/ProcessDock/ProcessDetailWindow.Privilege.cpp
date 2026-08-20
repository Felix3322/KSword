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
        const std::function<bool(HANDLE, std::string*)>& actionInvoker,
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

        return actionInvoker(rawProcessHandle, detailTextOut);
    }

    bool queryTokenPrivilegesWithR0Fallback(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime100ns,
        const HANDLE processHandle,
        std::vector<ks::process::TokenPrivilegeInfo>* const privilegesOut,
        bool* const usedR0Out,
        std::string* const detailTextOut)
    {
        if (usedR0Out != nullptr)
        {
            *usedR0Out = false;
        }

        std::string r3DetailText;
        if (ks::process::QueryTokenPrivilegesByProcessHandle(
            processHandle,
            privilegesOut,
            &r3DetailText))
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }

        ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessTokenPrivilegeResult r0Result =
            driverClient.queryProcessTokenPrivileges(
                processId,
                expectedCreationTime100ns);
        if (r0Result.io.ok
            && (r0Result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                || r0Result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL))
        {
            std::vector<ks::process::TokenPrivilegeLuidEntry> r0Entries;
            r0Entries.reserve(r0Result.entries.size());
            for (const ksword::ark::ProcessTokenPrivilegeEntry& r0Entry : r0Result.entries)
            {
                ks::process::TokenPrivilegeLuidEntry entry{};
                entry.luidLowPart = r0Entry.luidLowPart;
                entry.luidHighPart = r0Entry.luidHighPart;
                entry.attributes = r0Entry.attributes;
                r0Entries.push_back(entry);
            }
            if (ks::process::BuildKnownTokenPrivilegeSnapshot(
                r0Entries,
                privilegesOut,
                detailTextOut))
            {
                if (usedR0Out != nullptr)
                {
                    *usedR0Out = true;
                }
                return true;
            }
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = r3DetailText;
            if (!r0Result.io.message.empty())
            {
                *detailTextOut += " | ";
                *detailTextOut += r0Result.io.message;
            }
        }
        return false;
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
            [processId, creationTime100ns, &refreshResult](
                const HANDLE processHandle,
                std::string* const actionDetailText)
            {
                return queryTokenPrivilegesWithR0Fallback(
                    processId,
                    creationTime100ns,
                    processHandle,
                    &refreshResult.privileges,
                    &refreshResult.usedR0,
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
    if (m_applyActionPrivilegeR0Button != nullptr)
    {
        m_applyActionPrivilegeR0Button->setEnabled(refreshResult.queryOk && adjustableCount > 0U);
    }

    if (m_actionPrivilegeStatusLabel == nullptr)
    {
        return;
    }
    if (!refreshResult.queryOk)
    {
        kLogEvent queryEvent;
        warn << queryEvent
            << "[ProcessDetailWindow] token privilege query failed, pid="
            << m_baseRecord.pid
            << ", detail="
            << (refreshResult.diagnosticText.isEmpty()
                ? "none"
                : refreshResult.diagnosticText.toStdString())
            << eol;
        m_actionPrivilegeStatusLabel->setText(
            ks::i18n::text(
                QStringLiteral("process.detail.privileges.status.unavailable"),
                QString()));
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

    struct PendingPrivilegeEdit
    {
        ks::process::TokenPrivilegeEdit edit;
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        bool luidKnown = false;
    };

    std::vector<PendingPrivilegeEdit> privilegeEdits;
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

        PendingPrivilegeEdit privilegeEdit;
        privilegeEdit.edit.privilegeName = privilegeInfo.privilegeName;
        privilegeEdit.edit.action = requestedEnabled
            ? ks::process::TokenPrivilegeAction::Enable
            : ks::process::TokenPrivilegeAction::Disable;
        privilegeEdit.luidLowPart = privilegeInfo.luidLowPart;
        privilegeEdit.luidHighPart = privilegeInfo.luidHighPart;
        privilegeEdit.luidKnown = privilegeInfo.luidKnown;
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
                useR0
                    ? QStringLiteral("process.detail.privileges.status.applying_r0")
                    : QStringLiteral("process.detail.privileges.status.applying_r3"),
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
        useR0,
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
            [
                processId,
                creationTime100ns,
                useR0,
                &privilegeEdits,
                &taskResult,
                &failureLines](
                    const HANDLE processHandle,
                    std::string* const actionDetailText)
            {
                std::string privilegeDetailText;
                if (useR0)
                {
                    std::vector<ksword::ark::ProcessTokenPrivilegeEntry> r0Edits;
                    r0Edits.reserve(privilegeEdits.size());
                    for (const PendingPrivilegeEdit& privilegeEdit : privilegeEdits)
                    {
                        if (!privilegeEdit.luidKnown)
                        {
                            failureLines.push_back(
                                QStringLiteral("%1: privilege LUID is unavailable")
                                    .arg(QString::fromStdString(
                                        privilegeEdit.edit.privilegeName)));
                            continue;
                        }

                        ksword::ark::ProcessTokenPrivilegeEntry r0Edit{};
                        r0Edit.luidLowPart = privilegeEdit.luidLowPart;
                        r0Edit.luidHighPart = privilegeEdit.luidHighPart;
                        r0Edit.action = privilegeEdit.edit.action ==
                                ks::process::TokenPrivilegeAction::Enable
                            ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE
                            : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE;
                        r0Edits.push_back(r0Edit);
                    }

                    if (r0Edits.size() == privilegeEdits.size())
                    {
                        ksword::ark::DriverClient driverClient;
                        const ksword::ark::ProcessTokenPrivilegeResult r0Result =
                            driverClient.adjustProcessTokenPrivileges(
                                processId,
                                creationTime100ns,
                                r0Edits,
                                false);
                        taskResult.allSucceeded = r0Result.io.ok
                            && r0Result.status ==
                                KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                            && r0Result.appliedCount == r0Edits.size();
                        privilegeDetailText = r0Result.io.message;
                    }
                    else
                    {
                        taskResult.allSucceeded = false;
                    }
                }
                else
                {
                    std::vector<ks::process::TokenPrivilegeEdit> r3Edits;
                    r3Edits.reserve(privilegeEdits.size());
                    for (const PendingPrivilegeEdit& privilegeEdit : privilegeEdits)
                    {
                        r3Edits.push_back(privilegeEdit.edit);
                    }
                    taskResult.allSucceeded =
                        ks::process::ApplyTokenPrivilegeEditsByProcessHandle(
                            processHandle,
                            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                            false,
                            r3Edits,
                            &privilegeDetailText);
                }

                if (!taskResult.allSucceeded && !privilegeDetailText.empty())
                {
                    failureLines.push_back(QString::fromStdString(privilegeDetailText));
                }

                taskResult.refreshResult.queryOk = queryTokenPrivilegesWithR0Fallback(
                    processId,
                    creationTime100ns,
                    processHandle,
                    &taskResult.refreshResult.privileges,
                    &taskResult.refreshResult.usedR0,
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
        QMetaObject::invokeMethod(guard, [guard, useR0, taskResult = std::move(taskResult)]() mutable
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
                        ? (useR0
                            ? QStringLiteral("process.detail.privileges.status.applied_r0")
                            : QStringLiteral("process.detail.privileges.status.applied_r3"))
                        : QStringLiteral("process.detail.privileges.status.apply_failed"),
                    QString())
                    .arg(taskResult.editCount));
            guard->m_actionPrivilegeStatusLabel->setStyleSheet(
                buildStateLabelStyle(
                    taskResult.allSucceeded ? statusIdleColor() : statusWarningColor(),
                    taskResult.allSucceeded ? 600 : 700));

            kLogEvent actionEvent;
            (taskResult.allSucceeded ? info : warn) << actionEvent
                << "[ProcessDetailWindow]::token privilege apply, path="
                << (useR0 ? "R0" : "R3")
                << ", pid="
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
