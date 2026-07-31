#pragma once

// ============================================================
// SystemTimePage.h
// 作用：
// 1) 在“杂项”中提供系统全局加速、减速与恢复入口；
// 2) 通过 ArkDriverClient 查询和控制 R0 计时重映射；
// 3) 持续展示高风险警告、接管状态和冲突诊断。
// ============================================================

#include "../../Framework.h"

#include <QWidget>

class QCheckBox;
class QHideEvent;
class QLabel;
class QPushButton;
class QRadioButton;
class QShowEvent;
class QSpinBox;
class QTimer;

namespace ks::misc
{
    class SystemTimePage final : public QWidget
    {
    public:
        // 构造函数：创建页面但不主动访问 R0，避免打开“杂项”时弹出驱动提示。
        explicit SystemTimePage(QWidget* parent = nullptr);
        ~SystemTimePage() override = default;

    protected:
        // 页面真正可见时才查询并轮询状态，隐藏后停止周期 IOCTL。
        void showEvent(QShowEvent* event) override;
        void hideEvent(QHideEvent* event) override;

    private:
        // initializeUi：创建永久警告、倍率控件、确认开关和状态证据区。
        void initializeUi();
        // initializeConnections：连接刷新、应用、恢复和定时状态查询。
        void initializeConnections();
        // refreshStatus：通过 ArkDriverClient 获取最新倍率、代次与接管状态。
        void refreshStatus();
        // applyRequestedMode：执行双重确认后应用当前加速或减速倍率。
        void applyRequestedMode();
        // resetSystemTime：无额外门槛地恢复 1x 原始计时路径。
        void resetSystemTime();
        // confirmHighRisk：显示风险清单并要求输入固定确认短语。
        bool confirmHighRisk(const QString& modeText, unsigned long factor);
        // updateStatusDisplay：把协议字段转换为用户可读状态和诊断证据。
        void updateStatusDisplay(
            unsigned long status,
            unsigned long stateFlags,
            unsigned long generation,
            unsigned long command,
            unsigned long factor,
            unsigned long osBuildNumber,
            long lastStatus,
            unsigned long long counterSourceAddress,
            unsigned long long primarySlotAddress,
            unsigned long long secondarySlotAddress);
        // updateButtons：根据忙碌、协议支持和风险确认状态更新按钮。
        void updateButtons();
        // setBusy：防止一次同步 IOCTL 尚未完成时重复点击。
        void setBusy(bool busy);

    private:
        QLabel* m_warningLabel = nullptr; // m_warningLabel：永久显示的系统失稳警告。
        QLabel* m_persistenceLabel = nullptr; // m_persistenceLabel：离开页面不自动恢复的说明。
        QLabel* m_currentModeLabel = nullptr; // m_currentModeLabel：当前 1x/加速/减速状态。
        QLabel* m_backendLabel = nullptr; // m_backendLabel：构建与解析策略摘要。
        QLabel* m_diagnosticLabel = nullptr; // m_diagnosticLabel：槽地址和 NTSTATUS 证据。
        QLabel* m_operationLabel = nullptr; // m_operationLabel：最近刷新或控制结果。
        QRadioButton* m_speedUpRadio = nullptr; // m_speedUpRadio：选择 N 倍加速。
        QRadioButton* m_slowDownRadio = nullptr; // m_slowDownRadio：选择 1/N 减速。
        QSpinBox* m_factorSpin = nullptr; // m_factorSpin：2 到协议上限的倍率输入。
        QCheckBox* m_acknowledgeCheck = nullptr; // m_acknowledgeCheck：持久风险确认开关。
        QPushButton* m_refreshButton = nullptr; // m_refreshButton：图标化状态刷新按钮。
        QPushButton* m_applyButton = nullptr; // m_applyButton：应用选定模式和倍率。
        QPushButton* m_resetButton = nullptr; // m_resetButton：紧急恢复 1x。
        QTimer* m_refreshTimer = nullptr; // m_refreshTimer：页面可见时的状态轮询器。
        unsigned long m_generation = 0UL; // m_generation：最近查询到的并发控制代次。
        bool m_supported = false; // m_supported：当前 R0 是否解析并支持本功能。
        bool m_busy = false; // m_busy：同步控制期间阻止重复操作。
    };
}
