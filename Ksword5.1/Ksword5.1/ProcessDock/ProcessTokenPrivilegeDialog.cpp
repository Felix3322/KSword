#include "ProcessTokenPrivilegeDialog.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../ksword/process/process.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    enum class TokenPrivilegeExecutionMode : int
    {
        Automatic = 0,
        UserMode = 1,
        KernelMode = 2
    };

    struct TokenPrivilegeRow
    {
        LUID luid{};
        DWORD attributes = 0;
        QString privilegeName;
        QString displayName;
    };

    QString sourceText(const QString& text)
    {
        return ks::i18n::sourceText(text);
    }

    QString stableWin32ErrorText(const QString& stepText, const DWORD errorCode)
    {
        return QStringLiteral("%1 failed, error=%2").arg(stepText).arg(errorCode);
    }

    std::uint64_t fileTimeValue(const FILETIME& fileTime)
    {
        return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32U) |
            static_cast<std::uint64_t>(fileTime.dwLowDateTime);
    }

    bool enableCurrentDebugPrivilege()
    {
        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &tokenHandle) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL adjusted = ::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            static_cast<DWORD>(sizeof(tokenPrivileges)),
            nullptr,
            nullptr);
        const DWORD adjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        return adjusted != FALSE && adjustError == ERROR_SUCCESS;
    }

    QString privilegeNameForLuid(const LUID& privilegeLuid)
    {
        wchar_t nameBuffer[128]{};
        DWORD nameLength = 128U;
        if (::LookupPrivilegeNameW(
            nullptr,
            const_cast<LUID*>(&privilegeLuid),
            nameBuffer,
            &nameLength) != FALSE)
        {
            return QString::fromWCharArray(nameBuffer, static_cast<qsizetype>(nameLength));
        }

        return QStringLiteral("LUID %1:%2")
            .arg(privilegeLuid.HighPart)
            .arg(privilegeLuid.LowPart);
    }

    QString privilegeDisplayName(const QString& privilegeName)
    {
        wchar_t displayBuffer[256]{};
        DWORD displayLength = 256U;
        DWORD languageId = 0;
        if (::LookupPrivilegeDisplayNameW(
            nullptr,
            reinterpret_cast<LPCWSTR>(privilegeName.utf16()),
            displayBuffer,
            &displayLength,
            &languageId) != FALSE)
        {
            return QString::fromWCharArray(displayBuffer, static_cast<qsizetype>(displayLength));
        }
        return QStringLiteral("-");
    }

    QString privilegeAttributesText(const DWORD attributes)
    {
        QStringList parts;
        if ((attributes & SE_PRIVILEGE_ENABLED) != 0U)
        {
            parts << sourceText(QStringLiteral("已启用"));
        }
        else
        {
            parts << sourceText(QStringLiteral("已禁用"));
        }
        if ((attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0U)
        {
            parts << sourceText(QStringLiteral("默认启用"));
        }
        if ((attributes & SE_PRIVILEGE_USED_FOR_ACCESS) != 0U)
        {
            parts << sourceText(QStringLiteral("已用于访问"));
        }
        return parts.join(QStringLiteral(" · "));
    }

    bool shouldFallbackToR3(const ksword::ark::ProcessTokenPrivilegeResult& r0Result)
    {
        if (r0Result.io.ok)
        {
            return false;
        }
        if (r0Result.unsupported)
        {
            return true;
        }
        return r0Result.io.win32Error == ERROR_FILE_NOT_FOUND ||
            r0Result.io.win32Error == ERROR_PATH_NOT_FOUND ||
            r0Result.io.win32Error == ERROR_SERVICE_DOES_NOT_EXIST ||
            r0Result.io.win32Error == ERROR_INVALID_FUNCTION ||
            r0Result.io.win32Error == ERROR_NOT_SUPPORTED ||
            r0Result.io.win32Error == ERROR_INVALID_PARAMETER;
    }

    class ProcessTokenPrivilegeDialog final : public QDialog
    {
    public:
        ProcessTokenPrivilegeDialog(
            QWidget* parent,
            const std::uint32_t processId,
            const std::uint64_t expectedCreateTime100ns,
            QString processDisplayName)
            : QDialog(parent),
              m_processId(processId),
              m_expectedCreateTime100ns(expectedCreateTime100ns),
              m_processDisplayName(std::move(processDisplayName))
        {
            setWindowTitle(sourceText(QStringLiteral("调整进程令牌特权（R3/R0）")));
            resize(920, 620);
            setModal(true);

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            QLabel* targetLabel = new QLabel(
                sourceText(QStringLiteral("目标：PID %1 · %2"))
                    .arg(m_processId)
                    .arg(m_processDisplayName.trimmed().isEmpty()
                        ? sourceText(QStringLiteral("未知进程"))
                        : m_processDisplayName),
                this);
            targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            rootLayout->addWidget(targetLabel);

            QLabel* riskLabel = new QLabel(
                sourceText(QStringLiteral(
                    "启用或禁用会立即改变目标主令牌；移除特权在该进程生命周期内不可恢复。自动模式优先使用 R0，仅在驱动不可用或版本过旧时回退 R3。")),
                this);
            riskLabel->setWordWrap(true);
            rootLayout->addWidget(riskLabel);

            m_executionModeCombo = new QComboBox(this);
            m_executionModeCombo->addItem(
                sourceText(QStringLiteral("自动（R0 优先，R3 回退）")),
                static_cast<int>(TokenPrivilegeExecutionMode::Automatic));
            m_executionModeCombo->addItem(
                sourceText(QStringLiteral("R3（AdjustTokenPrivileges）")),
                static_cast<int>(TokenPrivilegeExecutionMode::UserMode));
            m_executionModeCombo->addItem(
                sourceText(QStringLiteral("R0（ZwAdjustPrivilegesToken）")),
                static_cast<int>(TokenPrivilegeExecutionMode::KernelMode));
            rootLayout->addWidget(m_executionModeCombo);

            m_table = new QTableWidget(0, 4, this);
            m_table->setHorizontalHeaderLabels(QStringList{
                sourceText(QStringLiteral("特权名")),
                sourceText(QStringLiteral("显示名称")),
                sourceText(QStringLiteral("当前状态")),
                sourceText(QStringLiteral("操作")) });
            m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
            m_table->setSelectionMode(QAbstractItemView::SingleSelection);
            m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            m_table->setAlternatingRowColors(true);
            m_table->verticalHeader()->setVisible(false);
            m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
            m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
            m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
            rootLayout->addWidget(m_table, 1);

            m_statusLabel = new QLabel(this);
            m_statusLabel->setWordWrap(true);
            m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            rootLayout->addWidget(m_statusLabel);

            QDialogButtonBox* buttonBox = new QDialogButtonBox(
                QDialogButtonBox::Apply | QDialogButtonBox::Close,
                this);
            m_applyButton = buttonBox->button(QDialogButtonBox::Apply);
            m_applyButton->setText(sourceText(QStringLiteral("应用调整")));
            buttonBox->button(QDialogButtonBox::Close)->setText(sourceText(QStringLiteral("关闭")));
            m_refreshButton = buttonBox->addButton(
                sourceText(QStringLiteral("刷新")),
                QDialogButtonBox::ResetRole);
            rootLayout->addWidget(buttonBox);

            connect(m_applyButton, &QPushButton::clicked, this, [this]() {
                applySelectedEdits();
            });
            connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
                loadPrivileges();
            });
            connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

            loadPrivileges();
        }

        ~ProcessTokenPrivilegeDialog() override
        {
            if (m_identityProcessHandle != nullptr)
            {
                ::CloseHandle(m_identityProcessHandle);
                m_identityProcessHandle = nullptr;
            }
        }

        bool changed() const
        {
            return m_changed;
        }

    private:
        bool acquireStableProcessHandle(QString* errorText)
        {
            if (m_identityProcessHandle != nullptr)
            {
                return true;
            }

            (void)enableCurrentDebugPrivilege();
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                m_processId);
            if (processHandle == nullptr)
            {
                if (errorText != nullptr)
                {
                    *errorText = stableWin32ErrorText(
                        QStringLiteral("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)"),
                        ::GetLastError());
                }
                return false;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) == FALSE)
            {
                const DWORD queryError = ::GetLastError();
                ::CloseHandle(processHandle);
                if (errorText != nullptr)
                {
                    *errorText = stableWin32ErrorText(QStringLiteral("GetProcessTimes"), queryError);
                }
                return false;
            }

            const std::uint64_t actualCreateTime100ns = fileTimeValue(creationTime);
            if (actualCreateTime100ns == 0U ||
                (m_expectedCreateTime100ns != 0U &&
                 actualCreateTime100ns != m_expectedCreateTime100ns))
            {
                ::CloseHandle(processHandle);
                if (errorText != nullptr)
                {
                    *errorText = sourceText(QStringLiteral("进程身份已变化（PID 可能已被复用），已拒绝操作。"));
                }
                return false;
            }

            m_expectedCreateTime100ns = actualCreateTime100ns;
            m_identityProcessHandle = processHandle;
            return true;
        }

        bool queryPrivilegesByR3(std::vector<TokenPrivilegeRow>* rowsOut, QString* errorText)
        {
            if (rowsOut == nullptr)
            {
                return false;
            }
            rowsOut->clear();

            if (!acquireStableProcessHandle(errorText))
            {
                return false;
            }

            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(m_identityProcessHandle, TOKEN_QUERY, &tokenHandle) == FALSE)
            {
                if (errorText != nullptr)
                {
                    *errorText = stableWin32ErrorText(QStringLiteral("OpenProcessToken(TOKEN_QUERY)"), ::GetLastError());
                }
                return false;
            }

            DWORD requiredBytes = 0;
            (void)::GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0, &requiredBytes);
            if (requiredBytes < sizeof(DWORD))
            {
                const DWORD queryError = ::GetLastError();
                ::CloseHandle(tokenHandle);
                if (errorText != nullptr)
                {
                    *errorText = stableWin32ErrorText(QStringLiteral("GetTokenInformation(TokenPrivileges length)"), queryError);
                }
                return false;
            }

            std::vector<BYTE> tokenBuffer(requiredBytes);
            if (::GetTokenInformation(
                tokenHandle,
                TokenPrivileges,
                tokenBuffer.data(),
                requiredBytes,
                &requiredBytes) == FALSE)
            {
                const DWORD queryError = ::GetLastError();
                ::CloseHandle(tokenHandle);
                if (errorText != nullptr)
                {
                    *errorText = stableWin32ErrorText(QStringLiteral("GetTokenInformation(TokenPrivileges)"), queryError);
                }
                return false;
            }
            ::CloseHandle(tokenHandle);

            const TOKEN_PRIVILEGES* tokenPrivileges =
                reinterpret_cast<const TOKEN_PRIVILEGES*>(tokenBuffer.data());
            rowsOut->reserve(tokenPrivileges->PrivilegeCount);
            for (DWORD privilegeIndex = 0; privilegeIndex < tokenPrivileges->PrivilegeCount; ++privilegeIndex)
            {
                const LUID_AND_ATTRIBUTES& sourcePrivilege = tokenPrivileges->Privileges[privilegeIndex];
                TokenPrivilegeRow row;
                row.luid = sourcePrivilege.Luid;
                row.attributes = sourcePrivilege.Attributes;
                row.privilegeName = privilegeNameForLuid(row.luid);
                row.displayName = privilegeDisplayName(row.privilegeName);
                rowsOut->push_back(std::move(row));
            }
            return true;
        }

        bool queryPrivilegesByR0(std::vector<TokenPrivilegeRow>* rowsOut, QString* errorText)
        {
            if (rowsOut == nullptr)
            {
                return false;
            }
            rowsOut->clear();

            const ksword::ark::DriverClient driverClient;
            const ksword::ark::ProcessTokenPrivilegeResult queryResult =
                driverClient.queryProcessTokenPrivileges(
                    m_processId,
                    m_expectedCreateTime100ns);
            const bool usableResult = queryResult.io.ok &&
                (queryResult.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
                 queryResult.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL);
            if (!usableResult)
            {
                if (errorText != nullptr)
                {
                    *errorText = QString::fromStdString(queryResult.io.message);
                }
                return false;
            }

            if (queryResult.processCreateTime100ns != 0U)
            {
                m_expectedCreateTime100ns = queryResult.processCreateTime100ns;
            }
            rowsOut->reserve(queryResult.entries.size());
            for (const ksword::ark::ProcessTokenPrivilegeEntry& sourcePrivilege : queryResult.entries)
            {
                TokenPrivilegeRow row;
                row.luid.LowPart = sourcePrivilege.luidLowPart;
                row.luid.HighPart = sourcePrivilege.luidHighPart;
                row.attributes = sourcePrivilege.attributes;
                row.privilegeName = privilegeNameForLuid(row.luid);
                row.displayName = privilegeDisplayName(row.privilegeName);
                rowsOut->push_back(std::move(row));
            }
            return true;
        }

        void populateTable()
        {
            std::sort(
                m_privileges.begin(),
                m_privileges.end(),
                [](const TokenPrivilegeRow& left, const TokenPrivilegeRow& right) {
                    return QString::compare(
                        left.privilegeName,
                        right.privilegeName,
                        Qt::CaseInsensitive) < 0;
                });

            m_table->setRowCount(static_cast<int>(m_privileges.size()));
            for (int rowIndex = 0; rowIndex < m_table->rowCount(); ++rowIndex)
            {
                const TokenPrivilegeRow& privilege = m_privileges[static_cast<std::size_t>(rowIndex)];
                m_table->setItem(rowIndex, 0, new QTableWidgetItem(privilege.privilegeName));
                m_table->setItem(rowIndex, 1, new QTableWidgetItem(privilege.displayName));
                m_table->setItem(rowIndex, 2, new QTableWidgetItem(privilegeAttributesText(privilege.attributes)));

                QComboBox* actionCombo = new QComboBox(m_table);
                actionCombo->addItem(
                    sourceText(QStringLiteral("保持")),
                    static_cast<unsigned int>(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP));
                actionCombo->addItem(
                    sourceText(QStringLiteral("启用")),
                    static_cast<unsigned int>(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE));
                actionCombo->addItem(
                    sourceText(QStringLiteral("禁用")),
                    static_cast<unsigned int>(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE));
                actionCombo->addItem(
                    sourceText(QStringLiteral("移除（不可恢复）")),
                    static_cast<unsigned int>(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE));
                m_table->setCellWidget(rowIndex, 3, actionCombo);
            }
        }

        void loadPrivileges()
        {
            m_applyButton->setEnabled(false);
            m_refreshButton->setEnabled(false);
            m_statusLabel->setText(sourceText(QStringLiteral("正在读取目标令牌特权…")));

            std::vector<TokenPrivilegeRow> rows;
            QString r3ErrorText;
            QString r0ErrorText;
            if (queryPrivilegesByR3(&rows, &r3ErrorText))
            {
                m_privileges = std::move(rows);
                populateTable();
                m_statusLabel->setText(
                    sourceText(QStringLiteral("已通过 R3 读取 %1 项特权。"))
                        .arg(m_privileges.size()));
                m_applyButton->setEnabled(!m_privileges.empty());
            }
            else if (queryPrivilegesByR0(&rows, &r0ErrorText))
            {
                m_privileges = std::move(rows);
                populateTable();
                m_statusLabel->setText(
                    sourceText(QStringLiteral("R3 读取失败，已通过 R0 读取 %1 项特权。R3：%2"))
                        .arg(m_privileges.size())
                        .arg(r3ErrorText));
                m_applyButton->setEnabled(!m_privileges.empty());
            }
            else
            {
                m_privileges.clear();
                m_table->setRowCount(0);
                m_statusLabel->setText(
                    sourceText(QStringLiteral("读取目标令牌失败。R3：%1；R0：%2"))
                        .arg(r3ErrorText, r0ErrorText));
                QMessageBox::warning(
                    this,
                    sourceText(QStringLiteral("无法读取进程令牌")),
                    m_statusLabel->text());
            }
            m_refreshButton->setEnabled(true);
        }

        bool applyByR3(
            const std::vector<ks::process::TokenPrivilegeEdit>& edits,
            QString* detailText,
            bool* partiallyApplied)
        {
            if (partiallyApplied != nullptr)
            {
                *partiallyApplied = false;
            }
            QString identityErrorText;
            if (!acquireStableProcessHandle(&identityErrorText))
            {
                if (detailText != nullptr)
                {
                    *detailText = identityErrorText;
                }
                return false;
            }

            for (std::size_t editIndex = 0; editIndex < edits.size(); ++editIndex)
            {
                const std::vector<ks::process::TokenPrivilegeEdit> singleEdit{ edits[editIndex] };
                std::string editDetailText;
                if (!ks::process::ApplyTokenPrivilegeEditsByPid(
                    m_processId,
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    false,
                    singleEdit,
                    &editDetailText))
                {
                    if (partiallyApplied != nullptr)
                    {
                        *partiallyApplied = editIndex != 0U;
                    }
                    if (detailText != nullptr)
                    {
                        std::ostringstream detailStream;
                        detailStream << "PrivilegeEdit[" << editIndex << "] failed after "
                            << editIndex << " successful edit(s): " << editDetailText;
                        *detailText = QString::fromStdString(detailStream.str());
                    }
                    return false;
                }
            }

            if (detailText != nullptr)
            {
                std::ostringstream detailStream;
                detailStream << "AdjustTokenPrivileges succeeded, edited privileges=" << edits.size();
                *detailText = QString::fromStdString(detailStream.str());
            }
            return true;
        }

        bool applyByR0(
            const std::vector<ksword::ark::ProcessTokenPrivilegeEntry>& edits,
            const bool allowRemove,
            QString* detailText,
            bool* fallbackAllowed,
            bool* partiallyApplied)
        {
            const ksword::ark::DriverClient driverClient;
            const ksword::ark::ProcessTokenPrivilegeResult result =
                driverClient.adjustProcessTokenPrivileges(
                    m_processId,
                    m_expectedCreateTime100ns,
                    edits,
                    allowRemove);
            if (detailText != nullptr)
            {
                *detailText = QString::fromStdString(result.io.message);
            }
            if (fallbackAllowed != nullptr)
            {
                *fallbackAllowed = shouldFallbackToR3(result);
            }
            if (partiallyApplied != nullptr)
            {
                *partiallyApplied = result.io.ok && result.appliedCount != 0U;
            }
            return result.io.ok &&
                result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK &&
                result.appliedCount == static_cast<std::uint32_t>(edits.size());
        }

        void applySelectedEdits()
        {
            std::vector<ks::process::TokenPrivilegeEdit> r3Edits;
            std::vector<ksword::ark::ProcessTokenPrivilegeEntry> r0Edits;
            bool containsRemove = false;
            for (int rowIndex = 0; rowIndex < m_table->rowCount(); ++rowIndex)
            {
                const QComboBox* actionCombo =
                    qobject_cast<QComboBox*>(m_table->cellWidget(rowIndex, 3));
                if (actionCombo == nullptr)
                {
                    continue;
                }
                const std::uint32_t action = actionCombo->currentData().toUInt();
                if (action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP)
                {
                    continue;
                }

                const TokenPrivilegeRow& privilege = m_privileges[static_cast<std::size_t>(rowIndex)];
                ks::process::TokenPrivilegeEdit r3Edit;
                r3Edit.privilegeName = privilege.privilegeName.toStdString();
                switch (action)
                {
                case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE:
                    r3Edit.action = ks::process::TokenPrivilegeAction::Enable;
                    break;
                case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE:
                    r3Edit.action = ks::process::TokenPrivilegeAction::Disable;
                    break;
                case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE:
                    r3Edit.action = ks::process::TokenPrivilegeAction::Remove;
                    containsRemove = true;
                    break;
                default:
                    continue;
                }
                r3Edits.push_back(std::move(r3Edit));

                ksword::ark::ProcessTokenPrivilegeEntry r0Edit;
                r0Edit.luidLowPart = privilege.luid.LowPart;
                r0Edit.luidHighPart = privilege.luid.HighPart;
                r0Edit.attributes = privilege.attributes;
                r0Edit.action = action;
                r0Edits.push_back(r0Edit);
            }

            if (r3Edits.empty())
            {
                QMessageBox::information(
                    this,
                    sourceText(QStringLiteral("没有待应用的调整")),
                    sourceText(QStringLiteral("请先把至少一项特权的操作从“保持”改为启用、禁用或移除。")));
                return;
            }

            const QString confirmationText = containsRemove
                ? sourceText(QStringLiteral(
                    "将调整 %1 项特权，其中包含永久移除。被移除的特权在目标进程退出前无法重新添加，并可能立即破坏目标功能。是否继续？")).arg(r3Edits.size())
                : sourceText(QStringLiteral(
                    "将立即调整目标进程的 %1 项令牌特权。目标功能或安全边界可能随即变化，是否继续？"))
                    .arg(r3Edits.size());
            const QMessageBox::StandardButton confirmation = QMessageBox::warning(
                this,
                sourceText(QStringLiteral("确认调整进程令牌")),
                confirmationText,
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (confirmation != QMessageBox::Yes)
            {
                return;
            }

            const TokenPrivilegeExecutionMode executionMode =
                static_cast<TokenPrivilegeExecutionMode>(m_executionModeCombo->currentData().toInt());
            QString detailText;
            bool applied = false;
            bool partiallyApplied = false;
            if (executionMode == TokenPrivilegeExecutionMode::UserMode)
            {
                applied = applyByR3(r3Edits, &detailText, &partiallyApplied);
                detailText.prepend(QStringLiteral("R3: "));
            }
            else
            {
                bool fallbackAllowed = false;
                applied = applyByR0(
                    r0Edits,
                    containsRemove,
                    &detailText,
                    &fallbackAllowed,
                    &partiallyApplied);
                detailText.prepend(QStringLiteral("R0: "));
                if (!applied &&
                    executionMode == TokenPrivilegeExecutionMode::Automatic &&
                    fallbackAllowed)
                {
                    QString r3DetailText;
                    bool r3PartiallyApplied = false;
                    applied = applyByR3(r3Edits, &r3DetailText, &r3PartiallyApplied);
                    partiallyApplied = partiallyApplied || r3PartiallyApplied;
                    detailText += sourceText(QStringLiteral("\nR3 回退：")) + r3DetailText;
                }
            }

            if (applied)
            {
                m_changed = true;
                m_statusLabel->setText(
                    sourceText(QStringLiteral("令牌特权调整成功。%1")).arg(detailText));
                QMessageBox::information(
                    this,
                    sourceText(QStringLiteral("进程令牌已更新")),
                    m_statusLabel->text());
                loadPrivileges();
                return;
            }

            if (partiallyApplied)
            {
                m_changed = true;
                m_statusLabel->setText(
                    sourceText(QStringLiteral("令牌特权仅部分应用；请刷新并核对当前状态。%1")).arg(detailText));
            }
            else
            {
                m_statusLabel->setText(
                    sourceText(QStringLiteral("令牌特权调整失败。%1")).arg(detailText));
            }
            QMessageBox::warning(
                this,
                sourceText(QStringLiteral("进程令牌调整未完成")),
                m_statusLabel->text());
            loadPrivileges();
        }

        std::uint32_t m_processId = 0;
        std::uint64_t m_expectedCreateTime100ns = 0;
        QString m_processDisplayName;
        HANDLE m_identityProcessHandle = nullptr;
        QComboBox* m_executionModeCombo = nullptr;
        QTableWidget* m_table = nullptr;
        QLabel* m_statusLabel = nullptr;
        QPushButton* m_applyButton = nullptr;
        QPushButton* m_refreshButton = nullptr;
        std::vector<TokenPrivilegeRow> m_privileges;
        bool m_changed = false;
    };
}

namespace ks::process_ui
{
    bool showProcessTokenPrivilegeDialog(
        QWidget* parent,
        const std::uint32_t processId,
        const std::uint64_t expectedCreateTime100ns,
        const QString& processDisplayName)
    {
        ProcessTokenPrivilegeDialog dialog(
            parent,
            processId,
            expectedCreateTime100ns,
            processDisplayName);
        (void)dialog.exec();
        return dialog.changed();
    }
}
