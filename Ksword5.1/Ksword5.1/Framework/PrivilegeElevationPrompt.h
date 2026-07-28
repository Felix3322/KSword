#pragma once

#include <QCoreApplication>
#include <QMessageBox>
#include <QPushButton>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <shellapi.h>
#include <windows.h>

#include "../Internationalization/LanguageManager.h"

namespace ks::ui
{
    inline bool isCurrentProcessElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        TOKEN_ELEVATION elevation{};
        DWORD returnedBytes = 0;
        const BOOL queryOk = ::GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &returnedBytes);
        ::CloseHandle(tokenHandle);
        return queryOk != FALSE && elevation.TokenIsElevated != 0;
    }

    inline QString quoteWindowsArgument(const QString& argument)
    {
        QString quoted = argument;
        quoted.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(quoted);
    }

    // requestAdministratorRestartForFeature：
    // - 在功能已明确需要管理员权限、而当前实例尚未提升时调用；
    // - 对用户说明当前功能与重启影响，确认后以 runas 重新启动整个 KSword；
    // - 返回 false，调用方应立即停止当前功能，用户可在管理员实例中重试。
    inline bool requestAdministratorRestartForFeature(
        QWidget* const parent,
        const QString& featureName)
    {
        if (isCurrentProcessElevated())
        {
            return true;
        }

        QMessageBox prompt(parent);
        prompt.setIcon(QMessageBox::Information);
        prompt.setWindowTitle(ks::i18n::text(
            QStringLiteral("privilege.admin_required.title"),
            QStringLiteral("需要管理员权限")));
        prompt.setText(ks::i18n::text(
            QStringLiteral("privilege.admin_required.message"),
            QStringLiteral("“%1”需要管理员权限。\n\n是否以管理员身份重新启动 Ksword？")).arg(featureName));
        prompt.setInformativeText(ks::i18n::text(
            QStringLiteral("privilege.admin_required.hint"),
            QStringLiteral("确认 Windows UAC 后，当前实例会退出；请在新实例中重试该功能。")));
        QPushButton* const elevateButton = prompt.addButton(
            ks::i18n::text(
                QStringLiteral("privilege.admin_required.elevate"),
                QStringLiteral("以管理员身份重启")),
            QMessageBox::AcceptRole);
        prompt.addButton(
            ks::i18n::text(QStringLiteral("privilege.admin_required.cancel"), QStringLiteral("取消")),
            QMessageBox::RejectRole);
        prompt.exec();
        if (prompt.clickedButton() != elevateButton)
        {
            return false;
        }

        const QStringList argumentList = QCoreApplication::arguments();
        QStringList parameterList;
        for (int index = 1; index < argumentList.size(); ++index)
        {
            parameterList.push_back(quoteWindowsArgument(argumentList.at(index)));
        }
        if (!parameterList.contains(QStringLiteral("\"--ksword-privilege-restart\""), Qt::CaseInsensitive))
        {
            parameterList.push_back(QStringLiteral("--ksword-privilege-restart"));
        }

        const std::wstring executablePath = QCoreApplication::applicationFilePath().toStdWString();
        const std::wstring parameterText = parameterList.join(QLatin1Char(' ')).toStdWString();
        const HINSTANCE result = ::ShellExecuteW(
            parent != nullptr ? reinterpret_cast<HWND>(parent->winId()) : nullptr,
            L"runas",
            executablePath.c_str(),
            parameterText.empty() ? nullptr : parameterText.c_str(),
            nullptr,
            SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(result) <= 32)
        {
            QMessageBox::warning(
                parent,
                ks::i18n::text(
                    QStringLiteral("privilege.admin_required.restart_failed.title"),
                    QStringLiteral("管理员重启失败")),
                ks::i18n::text(
                    QStringLiteral("privilege.admin_required.restart_failed.message"),
                    QStringLiteral("管理员重启未启动，可能被取消或被系统策略阻止。")));
            return false;
        }

        QCoreApplication::quit();
        return false;
    }
}
