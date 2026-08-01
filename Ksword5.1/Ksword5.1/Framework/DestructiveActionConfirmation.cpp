#include "DestructiveActionConfirmation.h"

#include "../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QMessageBox>
#include <QSettings>

namespace
{
    QString confirmationSettingKey(const QString& suppressionKey)
    {
        return QStringLiteral("Safety/DestructiveActionConfirmations/%1/Disabled")
            .arg(suppressionKey);
    }
}

bool ks::ui::confirmDestructiveAction(
    QWidget* const parent,
    const QString& suppressionKey,
    const QString& actionTitle,
    const QString& targetDescription,
    const QString& riskDescription)
{
    QSettings settings;
    const QString settingKey = confirmationSettingKey(suppressionKey);
    if (!suppressionKey.isEmpty() && settings.value(settingKey, false).toBool())
    {
        return true;
    }

    QMessageBox dialog(parent);
    dialog.setIcon(QMessageBox::Warning);
    dialog.setWindowTitle(ks::i18n::sourceText(QStringLiteral("确认高风险操作")));
    dialog.setText(
        ks::i18n::sourceText(QStringLiteral("即将执行“%1”。"))
            .arg(actionTitle));

    const QString effectiveRiskDescription = riskDescription.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral(
            "此操作可能导致未保存的数据丢失、目标程序异常或系统不稳定。请确认目标无误后再继续。"))
        : riskDescription;
    dialog.setInformativeText(
        ks::i18n::sourceText(QStringLiteral("目标：%1\n\n%2"))
            .arg(targetDescription, effectiveRiskDescription));
    dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    dialog.setDefaultButton(QMessageBox::No);
    dialog.setEscapeButton(QMessageBox::No);

    auto* const suppressCheckBox = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("不再弹出此类操作的确认提示")),
        &dialog);
    dialog.setCheckBox(suppressCheckBox);

    const bool confirmed = dialog.exec() == QMessageBox::Yes;
    if (confirmed && !suppressionKey.isEmpty() && suppressCheckBox->isChecked())
    {
        settings.setValue(settingKey, true);
    }
    return confirmed;
}
