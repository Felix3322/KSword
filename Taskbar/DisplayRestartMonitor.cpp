#include "DisplayRestartMonitor.h"
#include "TaskbarRestartCoordinator.h"

#include <windows.h>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QStringList>

DisplayRestartMonitor::DisplayRestartMonitor(QObject* parent)
    : QObject(parent),
      m_initialDisplaySignature(buildDisplaySignature()),
      m_restartScheduled(false)
{
    // 注册原生事件过滤器，确保 Windows 分辨率变化消息也能触发重启。
    if (QCoreApplication::instance()) {
        QCoreApplication::instance()->installNativeEventFilter(this);
    }

    // Qt 层面监控屏幕数量变化和每个屏幕的几何变化。
    connect(
        qApp,
        &QGuiApplication::screenAdded,
        this,
        &DisplayRestartMonitor::onScreenAdded
    );
    connect(
        qApp,
        &QGuiApplication::screenRemoved,
        this,
        &DisplayRestartMonitor::onScreenRemoved
    );

    for (QScreen* screen : QGuiApplication::screens()) {
        attachScreen(screen);
    }

    // 延迟重启用于合并显卡驱动发出的多次屏幕变化事件。
    m_restartTimer.setSingleShot(true);
    m_restartTimer.setInterval(1000);
    connect(&m_restartTimer, &QTimer::timeout, this, &DisplayRestartMonitor::restartProcess);
}

DisplayRestartMonitor::~DisplayRestartMonitor()
{
    // 注销过滤器，避免 QApplication 析构阶段仍回调已释放对象。
    if (QCoreApplication::instance()) {
        QCoreApplication::instance()->removeNativeEventFilter(this);
    }
}

bool DisplayRestartMonitor::nativeEventFilter(const QByteArray& eventType,
                                              void* message,
                                              qintptr* result)
{
    Q_UNUSED(eventType);
    Q_UNUSED(result);

    MSG* nativeMessage = static_cast<MSG*>(message);
    if (nativeMessage && nativeMessage->message == WM_DISPLAYCHANGE) {
        scheduleRestart();
    }

    return false;
}

void DisplayRestartMonitor::onScreenAdded(QScreen* screen)
{
    // 新显示器加入后先挂接几何信号，再判断是否需要重启。
    attachScreen(screen);
    scheduleRestartIfChanged();
}

void DisplayRestartMonitor::onScreenRemoved(QScreen* screen)
{
    // 屏幕移除时 Qt 可能已经更新 screens()，这里不访问被移除屏幕。
    Q_UNUSED(screen);
    scheduleRestartIfChanged();
}

void DisplayRestartMonitor::onScreenGeometryChanged(const QRect& geometry)
{
    // 分辨率或屏幕坐标变化都会改变 geometry，统一走签名比较。
    Q_UNUSED(geometry);
    scheduleRestartIfChanged();
}

QString DisplayRestartMonitor::buildDisplaySignature() const
{
    // 签名只包含屏幕数量和几何，不使用 availableGeometry，避免 AppBar 自身改变工作区导致自重启。
    QStringList screenParts;
    for (QScreen* screen : QGuiApplication::screens()) {
        if (!screen) {
            continue;
        }

        const QRect geometry = screen->geometry();
        screenParts.append(QString("%1,%2,%3,%4")
            .arg(geometry.x())
            .arg(geometry.y())
            .arg(geometry.width())
            .arg(geometry.height()));
    }

    screenParts.sort();
    return screenParts.join("|");
}

void DisplayRestartMonitor::attachScreen(QScreen* screen)
{
    // 每个屏幕只需要关注物理几何变化，Qt::UniqueConnection 防止重复挂接。
    if (!screen) {
        return;
    }

    connect(
        screen,
        &QScreen::geometryChanged,
        this,
        &DisplayRestartMonitor::onScreenGeometryChanged,
        Qt::UniqueConnection
    );
}

void DisplayRestartMonitor::scheduleRestartIfChanged()
{
    // 只有数量或分辨率/坐标签名真的变化时才重启，减少无意义重启。
    if (buildDisplaySignature() != m_initialDisplaySignature) {
        scheduleRestart();
    }
}

void DisplayRestartMonitor::scheduleRestart()
{
    // 多个屏幕事件可能连续到达，保证只安排一次重启。
    if (m_restartScheduled) {
        return;
    }

    m_restartScheduled = true;
    m_restartTimer.start();
}

void DisplayRestartMonitor::restartProcess()
{
    // 接替实例等待本进程退出后才初始化，避免两个实例重叠注册每屏 AppBar。
    if (TaskbarRestartCoordinator::scheduleAfterCurrentProcessExit()) {
        QCoreApplication::quit();
        return;
    }

    // 调度失败时保留当前实例，并允许后续显示器变化再次尝试。
    m_restartScheduled = false;
}
