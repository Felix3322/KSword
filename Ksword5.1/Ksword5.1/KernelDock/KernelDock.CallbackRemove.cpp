#include "KernelDock.h"

#include "../../../shared/KswordArkLogProtocol.h"
#include "../../../shared/driver/KswordArkCallbackIoctl.h"
#include "../UI/CodeEditorWidget.h"
#include "../theme.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

namespace
{
    // callbackRemoveParseAddress：
    // - 作用：把输入文本解析为 64 位地址（支持 0x 前缀）。
    bool callbackRemoveParseAddress(const QString& textValue, quint64& addressOut)
    {
        QString normalizedText = textValue.trimmed();
        bool parseOk = false;

        if (normalizedText.isEmpty())
        {
            return false;
        }

        if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalizedText = normalizedText.mid(2);
        }

        addressOut = normalizedText.toULongLong(&parseOk, 16);
        return parseOk;
    }
}

void KernelDock::initializeCallbackRemoveTab()
{
    if (m_callbackRemovePage == nullptr || m_callbackRemoveLayout != nullptr)
    {
        return;
    }

    m_callbackRemoveLayout = new QVBoxLayout(m_callbackRemovePage);
    m_callbackRemoveLayout->setContentsMargins(8, 8, 8, 8);
    m_callbackRemoveLayout->setSpacing(6);

    m_callbackRemoveToolLayout = new QHBoxLayout();
    m_callbackRemoveToolLayout->setContentsMargins(0, 0, 0, 0);
    m_callbackRemoveToolLayout->setSpacing(6);

    m_callbackRemoveTypeCombo = new QComboBox(m_callbackRemovePage);
    m_callbackRemoveTypeCombo->addItem(
        QStringLiteral("进程创建回调"),
        static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS));
    m_callbackRemoveTypeCombo->addItem(
        QStringLiteral("线程创建回调"),
        static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD));
    m_callbackRemoveTypeCombo->addItem(
        QStringLiteral("镜像加载回调"),
        static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE));

    m_callbackRemoveAddressEdit = new QLineEdit(m_callbackRemovePage);
    m_callbackRemoveAddressEdit->setPlaceholderText(QStringLiteral("输入回调地址（例如 0xFFFFF80012345678）"));
    m_callbackRemoveAddressEdit->setClearButtonEnabled(true);

    m_callbackRemoveButton = new QPushButton(QStringLiteral("移除回调"), m_callbackRemovePage);
    m_callbackRemoveButton->setStyleSheet(QStringLiteral(
        "QPushButton{color:%1;background:%2;border:1px solid %3;border-radius:3px;padding:3px 10px;}"
        "QPushButton:hover{background:#2E8BFF;color:#FFFFFF;border:1px solid #2E8BFF;}"
        "QPushButton:pressed{background:%4;color:#FFFFFF;}"
    ).arg(
        KswordTheme::PrimaryBlueHex,
        KswordTheme::SurfaceHex(),
        KswordTheme::PrimaryBlueBorderHex,
        KswordTheme::PrimaryBluePressedHex));

    m_callbackRemoveStatusLabel = new QLabel(QStringLiteral("状态：等待操作"), m_callbackRemovePage);
    m_callbackRemoveStatusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_callbackRemoveToolLayout->addWidget(new QLabel(QStringLiteral("类型："), m_callbackRemovePage));
    m_callbackRemoveToolLayout->addWidget(m_callbackRemoveTypeCombo, 0);
    m_callbackRemoveToolLayout->addWidget(m_callbackRemoveAddressEdit, 1);
    m_callbackRemoveToolLayout->addWidget(m_callbackRemoveButton, 0);
    m_callbackRemoveLayout->addLayout(m_callbackRemoveToolLayout);
    m_callbackRemoveLayout->addWidget(m_callbackRemoveStatusLabel, 0);

    m_callbackRemoveDetailEditor = new CodeEditorWidget(m_callbackRemovePage);
    m_callbackRemoveDetailEditor->setReadOnly(true);
    m_callbackRemoveDetailEditor->setText(QStringLiteral("提示：该页面通过 KswordARK 驱动调用内核接口移除指定地址的回调。"));
    m_callbackRemoveLayout->addWidget(m_callbackRemoveDetailEditor, 1);

    connect(m_callbackRemoveButton, &QPushButton::clicked, this, [this]() {
        HANDLE deviceHandle = ::CreateFileW(
            KSWORD_ARK_DEVICE_SYMBOLIC,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (deviceHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD errorCode = ::GetLastError();
            m_callbackRemoveStatusLabel->setText(QStringLiteral("状态：连接驱动失败，error=%1").arg(errorCode));
            QMessageBox::warning(this, QStringLiteral("回调移除"), m_callbackRemoveStatusLabel->text());
            return;
        }

        quint64 callbackAddress = 0;
        if (!callbackRemoveParseAddress(m_callbackRemoveAddressEdit->text(), callbackAddress) || callbackAddress == 0)
        {
            ::CloseHandle(deviceHandle);
            QMessageBox::warning(this, QStringLiteral("回调移除"), QStringLiteral("请输入合法的十六进制回调地址。"));
            return;
        }

        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
        requestPacket.callbackClass = static_cast<quint32>(m_callbackRemoveTypeCombo->currentData().toUInt());
        requestPacket.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
        requestPacket.callbackAddress = callbackAddress;

        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE responsePacket{};
        DWORD bytesReturned = 0;
        const BOOL ioctlOk = ::DeviceIoControl(
            deviceHandle,
            IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK,
            &requestPacket,
            static_cast<DWORD>(sizeof(requestPacket)),
            &responsePacket,
            static_cast<DWORD>(sizeof(responsePacket)),
            &bytesReturned,
            nullptr);
        const DWORD lastError = ::GetLastError();
        ::CloseHandle(deviceHandle);

        if (!ioctlOk)
        {
            m_callbackRemoveStatusLabel->setText(QStringLiteral("状态：移除失败，error=%1").arg(lastError));
            m_callbackRemoveDetailEditor->setText(QStringLiteral("DeviceIoControl 失败，Win32 错误码=%1。\n地址=0x%2")
                .arg(lastError)
                .arg(QString::number(callbackAddress, 16).toUpper()));
            QMessageBox::warning(this, QStringLiteral("回调移除"), m_callbackRemoveStatusLabel->text());
            return;
        }

        const QString detailText = QStringLiteral(
            "移除请求已执行。\n"
            "- 类型：%1\n"
            "- 地址：0x%2\n"
            "- 返回字节：%3\n"
            "- NTSTATUS：0x%4")
            .arg(m_callbackRemoveTypeCombo->currentText())
            .arg(QString::number(callbackAddress, 16).toUpper())
            .arg(bytesReturned)
            .arg(QString::number(static_cast<quint32>(responsePacket.ntstatus), 16).rightJustified(8, QLatin1Char('0')).toUpper());
        m_callbackRemoveDetailEditor->setText(detailText);

        if (responsePacket.ntstatus >= 0)
        {
            m_callbackRemoveStatusLabel->setText(QStringLiteral("状态：移除完成。"));
        }
        else
        {
            m_callbackRemoveStatusLabel->setText(QStringLiteral("状态：驱动返回失败，NTSTATUS=0x%1")
                .arg(QString::number(static_cast<quint32>(responsePacket.ntstatus), 16).toUpper()));
            QMessageBox::warning(this, QStringLiteral("回调移除"), m_callbackRemoveStatusLabel->text());
        }
    });
}
