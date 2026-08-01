#pragma once

#include <QString>

class QWidget;

namespace ks::ui
{
    // 为不可逆操作显示统一确认框。仅当用户确认并勾选“不再弹出”时持久保存跳过设置。
    bool confirmDestructiveAction(
        QWidget* parent,
        const QString& suppressionKey,
        const QString& actionTitle,
        const QString& targetDescription,
        const QString& riskDescription = QString());
}
