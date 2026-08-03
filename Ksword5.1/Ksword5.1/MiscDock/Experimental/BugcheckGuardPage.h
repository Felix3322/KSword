#pragma once
#include "../../ArkDriverClient/ArkDriverTypes.h"

#include "../../Framework.h"

#include <QWidget>

class QCheckBox;
class QLabel;
class QPushButton;
class QShowEvent;
class QSpinBox;
class QTimer;

namespace ks::misc
{
    // An opt-in, one-shot BugCheck delay control. HVCI systems use a callback
    // backend; other systems may use the KeBugCheckEx entry hook. The page
    // never claims that either backend is a crash recovery mechanism.
    class BugcheckGuardPage final : public QWidget
    {
    public:
        explicit BugcheckGuardPage(QWidget* parent = nullptr);
        ~BugcheckGuardPage() override = default;

    protected:
        void showEvent(QShowEvent* event) override;

    private:
        void initializeUi();
        void refreshStatus();
        void enableGuard();
        void disableGuard();
        void pollForScreenshot();
        void attemptScreenshot();
        void updateFromResponse(
            const KSWORD_ARK_BUGCHECK_GUARD_RESPONSE& response);
        void updateButtons();
        void setBusy(bool busy);

        QLabel* m_warningLabel = nullptr;
        QLabel* m_persistenceLabel = nullptr;
        QLabel* m_delayLabel = nullptr;
        QLabel* m_statusLabel = nullptr;
        QLabel* m_detailLabel = nullptr;
        QSpinBox* m_delaySpin = nullptr;
        QCheckBox* m_tryIgnoreErrorCheck = nullptr;
        QCheckBox* m_screenshotOnTriggerCheck = nullptr;
        QCheckBox* m_acknowledgeCheck = nullptr;
        QPushButton* m_refreshButton = nullptr;
        QPushButton* m_enableButton = nullptr;
        QPushButton* m_disableButton = nullptr;
        QTimer* m_screenshotPollTimer = nullptr;
        ksword::ark::DriverHandle m_screenshotDriverHandle;
        bool m_supported = false;
        bool m_active = false;
        bool m_busy = false;
        bool m_triggered = false;
        bool m_hvciEnabled = false;
        bool m_callbackBackend = false;
        bool m_screenshotWatcherArmed = false;
        bool m_screenshotAttempted = false;
        bool m_screenshotInputAccepted = false;
    };
}
