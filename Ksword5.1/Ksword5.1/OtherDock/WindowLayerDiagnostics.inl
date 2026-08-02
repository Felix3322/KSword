#pragma once

// WindowDetailDialog is intentionally kept untouched. This module is compiled once
// through OtherDock.WindowProtection.cpp and injects a read-only diagnostics tab.

#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QCoreApplication>
#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHash>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QTabWidget>
#include <QTextCursor>
#include <QTextDocument>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <optional>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x00005000L
#endif

namespace ks::window::layerdiag
{
    constexpr char kAttachedProperty[] = "ksword.windowLayerDiagnostics.attached";
    constexpr DWORD kDwmwaExtendedFrameBounds = 9;
    constexpr DWORD kDwmwaCloaked = 14;
    constexpr int kWalkLimit = 100000;
    constexpr int kEventBlockLimit = 1000;

    QString hwndText(HWND hwnd)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(hwnd)), 0, 16)
            .toUpper();
    }

    QString hexText(quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
    }

    QString yesNo(bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    QString errorText(DWORD error)
    {
        return QStringLiteral("%1 (%2)").arg(error).arg(hexText(error));
    }

    QString className(HWND hwnd)
    {
        std::array<wchar_t, 512> buffer{};
        const int length = ::GetClassNameW(hwnd, buffer.data(), static_cast<int>(buffer.size()));
        return length > 0 ? QString::fromWCharArray(buffer.data(), length) : QString();
    }

    QString windowTitle(HWND hwnd)
    {
        const int length = ::GetWindowTextLengthW(hwnd);
        if (length <= 0)
        {
            return QString();
        }
        std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1U, L'\0');
        const int copied = ::GetWindowTextW(hwnd, buffer.data(), static_cast<int>(buffer.size()));
        return copied > 0 ? QString::fromWCharArray(buffer.data(), copied) : QString();
    }

    QString objectName(HANDLE handle)
    {
        if (handle == nullptr)
        {
            return QString();
        }
        DWORD bytes = 0;
        ::GetUserObjectInformationW(handle, UOI_NAME, nullptr, 0, &bytes);
        if (bytes == 0)
        {
            return QString();
        }
        std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1U, L'\0');
        if (::GetUserObjectInformationW(handle, UOI_NAME, buffer.data(), bytes, &bytes) == FALSE)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    struct LongPtrResult
    {
        bool ok = false;
        LONG_PTR value = 0;
        DWORD error = ERROR_SUCCESS;
    };

    LongPtrResult readLongPtr(HWND hwnd, int index)
    {
        LongPtrResult result;
        ::SetLastError(ERROR_SUCCESS);
        result.value = ::GetWindowLongPtrW(hwnd, index);
        result.error = ::GetLastError();
        result.ok = result.value != 0 || result.error == ERROR_SUCCESS;
        return result;
    }

    QString longPtrText(const LongPtrResult& result)
    {
        return result.ok
            ? hexText(static_cast<quint64>(result.value))
            : QStringLiteral("<失败: %1>").arg(errorText(result.error));
    }

    struct BandResult
    {
        bool available = false;
        bool ok = false;
        DWORD value = 0;
        DWORD error = ERROR_SUCCESS;
    };

    BandResult readBand(HWND hwnd)
    {
        using Fn = BOOL(WINAPI*)(HWND, PDWORD);
        static const Fn fn = []() -> Fn {
            const HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
            return user32 != nullptr
                ? reinterpret_cast<Fn>(::GetProcAddress(user32, "GetWindowBand"))
                : nullptr;
        }();

        BandResult result;
        result.available = fn != nullptr;
        if (fn == nullptr)
        {
            result.error = ERROR_PROC_NOT_FOUND;
            return result;
        }

        DWORD value = 0xFFFFFFFFUL;
        ::SetLastError(ERROR_SUCCESS);
        result.ok = fn(hwnd, &value) != FALSE;
        result.error = result.ok ? ERROR_SUCCESS : ::GetLastError();
        if (result.ok)
        {
            result.value = value;
        }
        return result;
    }

    QString bandName(DWORD value)
    {
        switch (value)
        {
        case 0: return QStringLiteral("ZBID_DEFAULT");
        case 1: return QStringLiteral("ZBID_DESKTOP");
        case 2: return QStringLiteral("ZBID_UIACCESS");
        case 3: return QStringLiteral("ZBID_IMMERSIVE_IHM");
        case 4: return QStringLiteral("ZBID_IMMERSIVE_NOTIFICATION");
        case 5: return QStringLiteral("ZBID_IMMERSIVE_APPCHROME");
        case 6: return QStringLiteral("ZBID_IMMERSIVE_MOGO");
        case 7: return QStringLiteral("ZBID_IMMERSIVE_EDGY");
        case 8: return QStringLiteral("ZBID_IMMERSIVE_INACTIVEMOBODY");
        case 9: return QStringLiteral("ZBID_IMMERSIVE_INACTIVEDOCK");
        case 10: return QStringLiteral("ZBID_IMMERSIVE_ACTIVEMOBODY");
        case 11: return QStringLiteral("ZBID_IMMERSIVE_ACTIVEDOCK");
        case 12: return QStringLiteral("ZBID_IMMERSIVE_BACKGROUND");
        case 13: return QStringLiteral("ZBID_IMMERSIVE_SEARCH");
        case 14: return QStringLiteral("ZBID_GENUINE_WINDOWS");
        case 15: return QStringLiteral("ZBID_IMMERSIVE_RESTRICTED");
        case 16: return QStringLiteral("ZBID_SYSTEM_TOOLS");
        case 17: return QStringLiteral("ZBID_LOCK");
        case 18: return QStringLiteral("ZBID_ABOVELOCK_UX");
        default: return QStringLiteral("ZBID_UNKNOWN");
        }
    }

    int zIndex(HWND target)
    {
        QSet<quintptr> visited;
        HWND current = ::GetTopWindow(nullptr);
        for (int index = 0; current != nullptr && index < kWalkLimit; ++index)
        {
            const quintptr raw = reinterpret_cast<quintptr>(current);
            if (visited.contains(raw))
            {
                break;
            }
            visited.insert(raw);
            if (current == target)
            {
                return index;
            }
            current = ::GetWindow(current, GW_HWNDNEXT);
        }
        return -1;
    }

    struct TokenInfo
    {
        bool opened = false;
        DWORD error = ERROR_SUCCESS;
        QString integrity;
        bool uiAccessKnown = false;
        bool uiAccess = false;
        bool appContainerKnown = false;
        bool appContainer = false;
        bool sessionKnown = false;
        DWORD sessionId = 0;
    };

    QString integrityName(DWORD rid)
    {
        if (rid < SECURITY_MANDATORY_LOW_RID) return QStringLiteral("Untrusted");
        if (rid < SECURITY_MANDATORY_MEDIUM_RID) return QStringLiteral("Low");
        if (rid < SECURITY_MANDATORY_HIGH_RID) return QStringLiteral("Medium");
        if (rid < SECURITY_MANDATORY_SYSTEM_RID) return QStringLiteral("High");
        if (rid < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return QStringLiteral("System");
        return QStringLiteral("Protected");
    }

    TokenInfo tokenInfo(DWORD pid)
    {
        TokenInfo result;
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process == nullptr)
        {
            result.error = ::GetLastError();
            return result;
        }

        HANDLE token = nullptr;
        if (::OpenProcessToken(process, TOKEN_QUERY, &token) == FALSE)
        {
            result.error = ::GetLastError();
            ::CloseHandle(process);
            return result;
        }
        result.opened = true;

        DWORD bytes = 0;
        ::GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &bytes);
        if (bytes > 0)
        {
            QByteArray buffer(static_cast<int>(bytes), '\0');
            if (::GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), bytes, &bytes) != FALSE)
            {
                const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.constData());
                if (label->Label.Sid != nullptr && ::IsValidSid(label->Label.Sid) != FALSE)
                {
                    const UCHAR count = *::GetSidSubAuthorityCount(label->Label.Sid);
                    if (count > 0)
                    {
                        const DWORD rid = *::GetSidSubAuthority(label->Label.Sid, count - 1U);
                        result.integrity = QStringLiteral("%1 RID=%2")
                            .arg(integrityName(rid))
                            .arg(hexText(rid));
                    }
                }
            }
        }

        DWORD value = 0;
        DWORD returned = 0;
        if (::GetTokenInformation(token, TokenUIAccess, &value, sizeof(value), &returned) != FALSE)
        {
            result.uiAccessKnown = true;
            result.uiAccess = value != 0;
        }
        value = 0;
        if (::GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &returned) != FALSE)
        {
            result.appContainerKnown = true;
            result.appContainer = value != 0;
        }
        value = 0;
        if (::GetTokenInformation(token, TokenSessionId, &value, sizeof(value), &returned) != FALSE)
        {
            result.sessionKnown = true;
            result.sessionId = value;
        }

        ::CloseHandle(token);
        ::CloseHandle(process);
        return result;
    }

    struct Snapshot
    {
        QDateTime time;
        HWND hwnd = nullptr;
        bool valid = false;
        bool visible = false;
        bool enabled = false;
        DWORD pid = 0;
        DWORD tid = 0;
        QString title;
        QString cls;
        RECT rect{};
        bool rectKnown = false;
        LongPtrResult style;
        LongPtrResult exStyle;
        LongPtrResult wndProc;
        LongPtrResult userData;
        LongPtrResult hInstance;
        BandResult band;
        HWND parent = nullptr;
        HWND owner = nullptr;
        HWND root = nullptr;
        HWND rootOwner = nullptr;
        HWND previous = nullptr;
        HWND next = nullptr;
        HWND top = nullptr;
        int z = -1;
        bool dwmAvailable = false;
        bool cloakedKnown = false;
        DWORD cloaked = 0;
        HRESULT cloakedHr = E_NOTIMPL;
        bool frameKnown = false;
        RECT frame{};
        HRESULT frameHr = E_NOTIMPL;
        bool guiKnown = false;
        DWORD guiError = ERROR_SUCCESS;
        GUITHREADINFO gui{};
        HWND foreground = nullptr;
        bool affinityKnown = false;
        DWORD affinity = 0;
        DWORD affinityError = ERROR_SUCCESS;
        bool layeredKnown = false;
        COLORREF colorKey = 0;
        BYTE alpha = 255;
        DWORD layeredFlags = 0;
        DWORD layeredError = ERROR_SUCCESS;
        POINT probe{};
        HWND hit = nullptr;
        HWND hitRoot = nullptr;
        HWND childHit = nullptr;
        HWND realChildHit = nullptr;
        TokenInfo token;
        QString desktop;
        QString inspectorWindowStation;
    };

    Snapshot capture(HWND hwnd)
    {
        Snapshot s;
        s.time = QDateTime::currentDateTime();
        s.hwnd = hwnd;
        s.valid = ::IsWindow(hwnd) != FALSE;
        if (!s.valid)
        {
            return s;
        }

        s.visible = ::IsWindowVisible(hwnd) != FALSE;
        s.enabled = ::IsWindowEnabled(hwnd) != FALSE;
        s.tid = ::GetWindowThreadProcessId(hwnd, &s.pid);
        s.title = windowTitle(hwnd);
        s.cls = className(hwnd);
        s.rectKnown = ::GetWindowRect(hwnd, &s.rect) != FALSE;
        s.style = readLongPtr(hwnd, GWL_STYLE);
        s.exStyle = readLongPtr(hwnd, GWL_EXSTYLE);
        s.wndProc = readLongPtr(hwnd, GWLP_WNDPROC);
        s.userData = readLongPtr(hwnd, GWLP_USERDATA);
        s.hInstance = readLongPtr(hwnd, GWLP_HINSTANCE);
        s.band = readBand(hwnd);
        s.parent = ::GetParent(hwnd);
        s.owner = ::GetWindow(hwnd, GW_OWNER);
        s.root = ::GetAncestor(hwnd, GA_ROOT);
        s.rootOwner = ::GetAncestor(hwnd, GA_ROOTOWNER);
        s.previous = ::GetWindow(hwnd, GW_HWNDPREV);
        s.next = ::GetWindow(hwnd, GW_HWNDNEXT);
        s.top = ::GetTopWindow(nullptr);
        s.z = zIndex(hwnd);

        using DwmFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);
        static const DwmFn dwm = []() -> DwmFn {
            const HMODULE module = ::LoadLibraryW(L"dwmapi.dll");
            return module != nullptr
                ? reinterpret_cast<DwmFn>(::GetProcAddress(module, "DwmGetWindowAttribute"))
                : nullptr;
        }();
        s.dwmAvailable = dwm != nullptr;
        if (dwm != nullptr)
        {
            s.cloakedHr = dwm(hwnd, kDwmwaCloaked, &s.cloaked, sizeof(s.cloaked));
            s.cloakedKnown = SUCCEEDED(s.cloakedHr);
            s.frameHr = dwm(hwnd, kDwmwaExtendedFrameBounds, &s.frame, sizeof(s.frame));
            s.frameKnown = SUCCEEDED(s.frameHr);
        }

        s.gui.cbSize = sizeof(s.gui);
        ::SetLastError(ERROR_SUCCESS);
        s.guiKnown = ::GetGUIThreadInfo(s.tid, &s.gui) != FALSE;
        s.guiError = s.guiKnown ? ERROR_SUCCESS : ::GetLastError();
        s.foreground = ::GetForegroundWindow();

        ::SetLastError(ERROR_SUCCESS);
        s.affinityKnown = ::GetWindowDisplayAffinity(hwnd, &s.affinity) != FALSE;
        s.affinityError = s.affinityKnown ? ERROR_SUCCESS : ::GetLastError();

        ::SetLastError(ERROR_SUCCESS);
        s.layeredKnown = ::GetLayeredWindowAttributes(
            hwnd, &s.colorKey, &s.alpha, &s.layeredFlags) != FALSE;
        s.layeredError = s.layeredKnown ? ERROR_SUCCESS : ::GetLastError();

        if (s.rectKnown)
        {
            s.probe.x = s.rect.left + (s.rect.right - s.rect.left) / 2;
            s.probe.y = s.rect.top + (s.rect.bottom - s.rect.top) / 2;
            s.hit = ::WindowFromPoint(s.probe);
            s.hitRoot = s.hit != nullptr ? ::GetAncestor(s.hit, GA_ROOT) : nullptr;
            POINT client = s.probe;
            if (::ScreenToClient(hwnd, &client) != FALSE)
            {
                s.childHit = ::ChildWindowFromPointEx(hwnd, client, CWP_ALL);
                s.realChildHit = ::RealChildWindowFromPoint(hwnd, client);
            }
        }

        s.token = tokenInfo(s.pid);
        s.desktop = objectName(::GetThreadDesktop(s.tid));
        s.inspectorWindowStation = objectName(::GetProcessWindowStation());
        return s;
    }

    QString rectText(const RECT& r)
    {
        return QStringLiteral("[%1,%2,%3,%4]")
            .arg(r.left).arg(r.top).arg(r.right).arg(r.bottom);
    }

    QString keyFlags(const Snapshot& s)
    {
        if (!s.style.ok || !s.exStyle.ok)
        {
            return QStringLiteral("<样式读取失败>");
        }
        const quint64 style = static_cast<quint64>(s.style.value);
        const quint64 ex = static_cast<quint64>(s.exStyle.value);
        QStringList flags;
        if ((style & WS_VISIBLE) != 0) flags << QStringLiteral("WS_VISIBLE");
        if ((style & WS_CHILD) != 0) flags << QStringLiteral("WS_CHILD");
        if ((style & WS_POPUP) != 0) flags << QStringLiteral("WS_POPUP");
        if ((ex & WS_EX_TOPMOST) != 0) flags << QStringLiteral("WS_EX_TOPMOST");
        if ((ex & WS_EX_TOOLWINDOW) != 0) flags << QStringLiteral("WS_EX_TOOLWINDOW");
        if ((ex & WS_EX_LAYERED) != 0) flags << QStringLiteral("WS_EX_LAYERED");
        if ((ex & WS_EX_TRANSPARENT) != 0) flags << QStringLiteral("WS_EX_TRANSPARENT");
        if ((ex & WS_EX_NOACTIVATE) != 0) flags << QStringLiteral("WS_EX_NOACTIVATE");
#ifdef WS_EX_NOREDIRECTIONBITMAP
        if ((ex & WS_EX_NOREDIRECTIONBITMAP) != 0) flags << QStringLiteral("WS_EX_NOREDIRECTIONBITMAP");
#endif
        return flags.isEmpty() ? QStringLiteral("<无关键标志>") : flags.join(QStringLiteral(" | "));
    }

    QString snapshotText(const Snapshot& s, DWORD initialPid, DWORD initialTid, const QString& initialClass)
    {
        QStringList out;
        out << QStringLiteral("CapturedAt: %1").arg(s.time.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
        out << QStringLiteral("HWND: %1").arg(hwndText(s.hwnd));
        out << QStringLiteral("Valid: %1").arg(yesNo(s.valid));
        if (!s.valid)
        {
            out << QStringLiteral("警告: 目标 HWND 已失效。");
            return out.join(QChar::LineFeed);
        }

        const bool reused = s.pid != initialPid || s.tid != initialTid || s.cls != initialClass;
        out << QStringLiteral("Title: %1").arg(s.title.isEmpty() ? QStringLiteral("<空>") : s.title);
        out << QStringLiteral("Class: %1").arg(s.cls);
        out << QStringLiteral("PID/TID: %1 / %2").arg(s.pid).arg(s.tid);
        out << QStringLiteral("Visible/Enabled: %1 / %2").arg(yesNo(s.visible), yesNo(s.enabled));
        out << QStringLiteral("WindowRect: %1").arg(s.rectKnown ? rectText(s.rect) : QStringLiteral("<失败>"));
        out << QStringLiteral("HWND identity changed: %1").arg(yesNo(reused));
        if (reused) out << QStringLiteral("警告: HWND 可能已销毁并被复用。");

        out << QString() << QStringLiteral("[Window Band / Z-order]");
        if (!s.band.available)
            out << QStringLiteral("GetWindowBand: <API 不可用>");
        else if (!s.band.ok)
            out << QStringLiteral("GetWindowBand: <失败: %1>").arg(errorText(s.band.error));
        else
            out << QStringLiteral("GetWindowBand: %1 / %2 (%3)")
                .arg(s.band.value).arg(hexText(s.band.value), bandName(s.band.value));
        out << QStringLiteral("注意: ZBID 数字是标识符，不是可按大小排序的置顶高度。");
        out << QStringLiteral("Top-level Z index: %1").arg(s.z);
        out << QStringLiteral("GetTopWindow(NULL): %1").arg(hwndText(s.top));
        out << QStringLiteral("GW_HWNDPREV / NEXT: %1 / %2").arg(hwndText(s.previous), hwndText(s.next));

        out << QString() << QStringLiteral("[Styles / error-aware reads]");
        out << QStringLiteral("GWL_STYLE: %1").arg(longPtrText(s.style));
        out << QStringLiteral("GWL_EXSTYLE: %1").arg(longPtrText(s.exStyle));
        out << QStringLiteral("GWLP_WNDPROC: %1").arg(longPtrText(s.wndProc));
        out << QStringLiteral("GWLP_USERDATA: %1").arg(longPtrText(s.userData));
        out << QStringLiteral("GWLP_HINSTANCE: %1").arg(longPtrText(s.hInstance));
        out << QStringLiteral("关键标志: %1").arg(keyFlags(s));

        out << QString() << QStringLiteral("[Relationships]");
        out << QStringLiteral("GetParent: %1").arg(hwndText(s.parent));
        out << QStringLiteral("GW_OWNER: %1").arg(hwndText(s.owner));
        out << QStringLiteral("GA_ROOT: %1").arg(hwndText(s.root));
        out << QStringLiteral("GA_ROOTOWNER: %1").arg(hwndText(s.rootOwner));

        out << QString() << QStringLiteral("[DWM]");
        if (!s.dwmAvailable)
            out << QStringLiteral("DwmGetWindowAttribute: <API 不可用>");
        else
        {
            out << QStringLiteral("DWMWA_CLOAKED: %1")
                .arg(s.cloakedKnown ? hexText(s.cloaked)
                                    : QStringLiteral("<失败 HRESULT=%1>").arg(hexText(static_cast<quint64>(s.cloakedHr))));
            out << QStringLiteral("DWMWA_EXTENDED_FRAME_BOUNDS: %1")
                .arg(s.frameKnown ? rectText(s.frame)
                                  : QStringLiteral("<失败 HRESULT=%1>").arg(hexText(static_cast<quint64>(s.frameHr))));
        }

        out << QString() << QStringLiteral("[GUI thread]");
        out << QStringLiteral("ForegroundWindow: %1").arg(hwndText(s.foreground));
        if (s.guiKnown)
        {
            out << QStringLiteral("Active: %1").arg(hwndText(s.gui.hwndActive));
            out << QStringLiteral("Focus: %1").arg(hwndText(s.gui.hwndFocus));
            out << QStringLiteral("Capture: %1").arg(hwndText(s.gui.hwndCapture));
            out << QStringLiteral("Caret: %1").arg(hwndText(s.gui.hwndCaret));
            out << QStringLiteral("MenuOwner: %1").arg(hwndText(s.gui.hwndMenuOwner));
        }
        else out << QStringLiteral("GetGUIThreadInfo: <失败: %1>").arg(errorText(s.guiError));

        out << QString() << QStringLiteral("[Security / desktop]");
        if (!s.token.opened)
            out << QStringLiteral("Process token: <失败: %1>").arg(errorText(s.token.error));
        else
        {
            out << QStringLiteral("Integrity: %1").arg(s.token.integrity.isEmpty() ? QStringLiteral("<未知>") : s.token.integrity);
            out << QStringLiteral("TokenUIAccess: %1").arg(s.token.uiAccessKnown ? yesNo(s.token.uiAccess) : QStringLiteral("<未知>"));
            out << QStringLiteral("AppContainer: %1").arg(s.token.appContainerKnown ? yesNo(s.token.appContainer) : QStringLiteral("<未知>"));
            out << QStringLiteral("SessionId: %1").arg(s.token.sessionKnown ? QString::number(s.token.sessionId) : QStringLiteral("<未知>"));
        }
        out << QStringLiteral("Target desktop: %1").arg(s.desktop.isEmpty() ? QStringLiteral("<未知/无权限>") : s.desktop);
        out << QStringLiteral("Inspector window station: %1").arg(s.inspectorWindowStation.isEmpty() ? QStringLiteral("<未知>") : s.inspectorWindowStation);
        out << QStringLiteral("Target window station: <Win32 无稳定通用跨进程查询接口>");

        out << QString() << QStringLiteral("[Composition / hit test]");
        out << QStringLiteral("DisplayAffinity: %1")
            .arg(s.affinityKnown ? hexText(s.affinity) : QStringLiteral("<失败: %1>").arg(errorText(s.affinityError)));
        out << QStringLiteral("LayeredAttributes: %1")
            .arg(s.layeredKnown
                ? QStringLiteral("Alpha=%1 ColorKey=%2 Flags=%3").arg(s.alpha).arg(hexText(s.colorKey), hexText(s.layeredFlags))
                : QStringLiteral("<不可用/非 Layered: %1>").arg(errorText(s.layeredError)));
        out << QStringLiteral("ProbePoint: [%1,%2]").arg(s.probe.x).arg(s.probe.y);
        out << QStringLiteral("WindowFromPoint / root: %1 / %2").arg(hwndText(s.hit), hwndText(s.hitRoot));
        out << QStringLiteral("ChildWindowFromPointEx: %1").arg(hwndText(s.childHit));
        out << QStringLiteral("RealChildWindowFromPoint: %1").arg(hwndText(s.realChildHit));
        return out.join(QChar::LineFeed);
    }

    QStringList diff(const Snapshot& before, const Snapshot& after)
    {
        QStringList out;
        auto add = [&out](const QString& name, const QString& a, const QString& b) {
            if (a != b) out << QStringLiteral("%1: %2 -> %3").arg(name, a, b);
        };
        add(QStringLiteral("Valid"), yesNo(before.valid), yesNo(after.valid));
        add(QStringLiteral("Visible"), yesNo(before.visible), yesNo(after.visible));
        add(QStringLiteral("Band"), before.band.ok ? QString::number(before.band.value) : QStringLiteral("<失败>"),
            after.band.ok ? QString::number(after.band.value) : QStringLiteral("<失败>"));
        add(QStringLiteral("Style"), longPtrText(before.style), longPtrText(after.style));
        add(QStringLiteral("ExStyle"), longPtrText(before.exStyle), longPtrText(after.exStyle));
        add(QStringLiteral("ZIndex"), QString::number(before.z), QString::number(after.z));
        add(QStringLiteral("Owner"), hwndText(before.owner), hwndText(after.owner));
        add(QStringLiteral("Foreground"), hwndText(before.foreground), hwndText(after.foreground));
        add(QStringLiteral("Cloaked"), before.cloakedKnown ? hexText(before.cloaked) : QStringLiteral("<未知>"),
            after.cloakedKnown ? hexText(after.cloaked) : QStringLiteral("<未知>"));
        return out;
    }

    std::optional<HWND> parseHwnd(QString text)
    {
        text = text.trimmed();
        int base = 10;
        if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            text = text.mid(2);
            base = 16;
        }
        bool ok = false;
        const qulonglong value = text.toULongLong(&ok, base);
        if (!ok || value == 0) return std::nullopt;
        return reinterpret_cast<HWND>(static_cast<quintptr>(value));
    }

    QString compareText(const Snapshot& a, const Snapshot& b)
    {
        QStringList out;
        out << QStringLiteral("A: %1 [%2] PID/TID=%3/%4").arg(hwndText(a.hwnd), a.cls).arg(a.pid).arg(a.tid);
        out << QStringLiteral("B: %1 [%2] PID/TID=%3/%4").arg(hwndText(b.hwnd), b.cls).arg(b.pid).arg(b.tid);
        out << QStringLiteral("A Band: %1").arg(a.band.ok ? QStringLiteral("%1 (%2)").arg(a.band.value).arg(bandName(a.band.value)) : QStringLiteral("<失败>"));
        out << QStringLiteral("B Band: %1").arg(b.band.ok ? QStringLiteral("%1 (%2)").arg(b.band.value).arg(bandName(b.band.value)) : QStringLiteral("<失败>"));
        out << QStringLiteral("Band ID 不按数值大小比较。");
        out << QStringLiteral("A/B Z index: %1 / %2").arg(a.z).arg(b.z);
        out << QStringLiteral("Same desktop: %1").arg(yesNo(!a.desktop.isEmpty() && a.desktop == b.desktop));
        out << QStringLiteral("Same session: %1")
            .arg(a.token.sessionKnown && b.token.sessionKnown ? yesNo(a.token.sessionId == b.token.sessionId) : QStringLiteral("<未知>"));

        if (!a.rectKnown || !b.rectKnown)
        {
            out << QStringLiteral("Overlap test: <矩形不可用>");
            return out.join(QChar::LineFeed);
        }
        RECT r{};
        r.left = std::max(a.rect.left, b.rect.left);
        r.top = std::max(a.rect.top, b.rect.top);
        r.right = std::min(a.rect.right, b.rect.right);
        r.bottom = std::min(a.rect.bottom, b.rect.bottom);
        if (r.left >= r.right || r.top >= r.bottom)
        {
            out << QStringLiteral("Overlap test: 当前无重叠区域。");
            return out.join(QChar::LineFeed);
        }

        POINT p{ r.left + (r.right - r.left) / 2, r.top + (r.bottom - r.top) / 2 };
        const HWND hit = ::WindowFromPoint(p);
        const HWND root = hit != nullptr ? ::GetAncestor(hit, GA_ROOT) : nullptr;
        out << QStringLiteral("Overlap rect: %1").arg(rectText(r));
        out << QStringLiteral("Probe: [%1,%2], hit=%3, root=%4").arg(p.x).arg(p.y).arg(hwndText(hit), hwndText(root));
        if (root == a.root || root == a.hwnd) out << QStringLiteral("实际命中: A 覆盖采样点。");
        else if (root == b.root || root == b.hwnd) out << QStringLiteral("实际命中: B 覆盖采样点。");
        else out << QStringLiteral("实际命中: 被第三个窗口覆盖，无法判定 A/B。");
        return out.join(QChar::LineFeed);
    }

    QJsonArray zOrderJson()
    {
        QJsonArray array;
        QSet<quintptr> visited;
        HWND hwnd = ::GetTopWindow(nullptr);
        for (int index = 0; hwnd != nullptr && index < kWalkLimit; ++index)
        {
            const quintptr raw = reinterpret_cast<quintptr>(hwnd);
            if (visited.contains(raw)) break;
            visited.insert(raw);

            DWORD pid = 0;
            const DWORD tid = ::GetWindowThreadProcessId(hwnd, &pid);
            const BandResult band = readBand(hwnd);
            QJsonObject item;
            item.insert(QStringLiteral("index"), index);
            item.insert(QStringLiteral("hwnd"), hwndText(hwnd));
            item.insert(QStringLiteral("pid"), static_cast<double>(pid));
            item.insert(QStringLiteral("tid"), static_cast<double>(tid));
            item.insert(QStringLiteral("class"), className(hwnd));
            item.insert(QStringLiteral("title"), windowTitle(hwnd));
            item.insert(QStringLiteral("visible"), ::IsWindowVisible(hwnd) != FALSE);
            item.insert(QStringLiteral("style"), longPtrText(readLongPtr(hwnd, GWL_STYLE)));
            item.insert(QStringLiteral("exStyle"), longPtrText(readLongPtr(hwnd, GWL_EXSTYLE)));
            item.insert(QStringLiteral("owner"), hwndText(::GetWindow(hwnd, GW_OWNER)));
            item.insert(QStringLiteral("bandSuccess"), band.ok);
            item.insert(QStringLiteral("band"), static_cast<double>(band.value));
            item.insert(QStringLiteral("bandName"), bandName(band.value));
            item.insert(QStringLiteral("desktop"), objectName(::GetThreadDesktop(tid)));
            array.append(item);
            hwnd = ::GetWindow(hwnd, GW_HWNDNEXT);
        }
        return array;
    }

    QString winEventName(DWORD event)
    {
        switch (event)
        {
        case EVENT_SYSTEM_FOREGROUND: return QStringLiteral("EVENT_SYSTEM_FOREGROUND");
        case EVENT_SYSTEM_MINIMIZESTART: return QStringLiteral("EVENT_SYSTEM_MINIMIZESTART");
        case EVENT_SYSTEM_MINIMIZEEND: return QStringLiteral("EVENT_SYSTEM_MINIMIZEEND");
        case EVENT_OBJECT_CREATE: return QStringLiteral("EVENT_OBJECT_CREATE");
        case EVENT_OBJECT_DESTROY: return QStringLiteral("EVENT_OBJECT_DESTROY");
        case EVENT_OBJECT_SHOW: return QStringLiteral("EVENT_OBJECT_SHOW");
        case EVENT_OBJECT_HIDE: return QStringLiteral("EVENT_OBJECT_HIDE");
        case EVENT_OBJECT_REORDER: return QStringLiteral("EVENT_OBJECT_REORDER");
        case EVENT_OBJECT_STATECHANGE: return QStringLiteral("EVENT_OBJECT_STATECHANGE");
        case EVENT_OBJECT_LOCATIONCHANGE: return QStringLiteral("EVENT_OBJECT_LOCATIONCHANGE");
        default: return QStringLiteral("EVENT_%1").arg(hexText(event));
        }
    }

    class Page;
    QMutex& hookMutex() { static QMutex mutex; return mutex; }
    QHash<quintptr, QPointer<Page>>& hookOwners()
    {
        static QHash<quintptr, QPointer<Page>> owners;
        return owners;
    }

    void CALLBACK winEventProc(HWINEVENTHOOK, DWORD, HWND, LONG, LONG, DWORD, DWORD);

    class Page final : public QWidget
    {
    public:
        explicit Page(HWND target, QWidget* parent = nullptr)
            : QWidget(parent), m_target(target)
        {
            m_initialTid = ::GetWindowThreadProcessId(m_target, &m_initialPid);
            m_initialClass = className(m_target);
            buildUi();
            refresh(QStringLiteral("初始快照"));
        }

        ~Page() override { stopTracking(); }

        void onWinEvent(DWORD event, HWND eventHwnd, LONG objectId, LONG childId, DWORD eventTid, DWORD eventTime)
        {
            if (!m_tracking) return;
            bool relevant = event == EVENT_SYSTEM_FOREGROUND;
            if (!relevant && eventHwnd != nullptr)
            {
                relevant = eventHwnd == m_target ||
                    ::GetAncestor(eventHwnd, GA_ROOT) == m_target ||
                    ::GetAncestor(eventHwnd, GA_ROOTOWNER) == m_target;
            }
            if (!relevant) return;

            const Snapshot now = capture(m_target);
            QStringList lines;
            lines << QStringLiteral("[%1] %2 hwnd=%3 object=%4 child=%5 tid=%6 time=%7")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")))
                .arg(winEventName(event), hwndText(eventHwnd))
                .arg(objectId).arg(childId).arg(eventTid).arg(eventTime);
            if (m_eventSnapshot.has_value())
            {
                const QStringList changes = diff(*m_eventSnapshot, now);
                if (changes.isEmpty()) lines << QStringLiteral("change: <无关键字段变化>");
                else for (const QString& change : changes) lines << QStringLiteral("change: %1").arg(change);
            }
            m_eventSnapshot = now;
            m_events->appendPlainText(lines.join(QChar::LineFeed) + QStringLiteral("\n"));
            while (m_events->document()->blockCount() > kEventBlockLimit)
            {
                QTextCursor cursor(m_events->document());
                cursor.movePosition(QTextCursor::Start);
                cursor.select(QTextCursor::BlockUnderCursor);
                cursor.removeSelectedText();
                cursor.deleteChar();
            }
        }

    private:
        void buildUi()
        {
            auto* root = new QVBoxLayout(this);
            root->setContentsMargins(8, 8, 8, 8);
            auto* warning = new QLabel(
                QStringLiteral("Band ID 是标识符，不是线性高度。本页分别展示 Band、Band 内 Z 序和实际命中。"), this);
            warning->setWordWrap(true);
            root->addWidget(warning);

            auto* actions = new QHBoxLayout();
            actions->addWidget(new QLabel(QStringLiteral("锁定 HWND: %1").arg(hwndText(m_target)), this), 1);
            auto* refreshButton = new QPushButton(QStringLiteral("刷新"), this);
            auto* delayedButton = new QPushButton(QStringLiteral("3 秒后快照"), this);
            auto* copyButton = new QPushButton(QStringLiteral("复制"), this);
            auto* exportButton = new QPushButton(QStringLiteral("导出快照"), this);
            auto* exportZButton = new QPushButton(QStringLiteral("导出完整 Z 序"), this);
            m_trackButton = new QPushButton(QStringLiteral("开始事件追踪"), this);
            actions->addWidget(refreshButton);
            actions->addWidget(delayedButton);
            actions->addWidget(copyButton);
            actions->addWidget(exportButton);
            actions->addWidget(exportZButton);
            actions->addWidget(m_trackButton);
            root->addLayout(actions);

            auto* compareRow = new QHBoxLayout();
            compareRow->addWidget(new QLabel(QStringLiteral("对比 HWND:"), this));
            m_compare = new QLineEdit(this);
            m_compare->setPlaceholderText(QStringLiteral("0x104DE 或十进制"));
            auto* pickButton = new QPushButton(QStringLiteral("取鼠标下顶层窗口"), this);
            auto* compareButton = new QPushButton(QStringLiteral("对比"), this);
            auto* delayedCompareButton = new QPushButton(QStringLiteral("3 秒后对比"), this);
            compareRow->addWidget(m_compare, 1);
            compareRow->addWidget(pickButton);
            compareRow->addWidget(compareButton);
            compareRow->addWidget(delayedCompareButton);
            root->addLayout(compareRow);

            m_status = new QLabel(this);
            m_status->setWordWrap(true);
            root->addWidget(m_status);

            auto* tabs = new QTabWidget(this);
            m_output = new QPlainTextEdit(tabs);
            m_events = new QPlainTextEdit(tabs);
            for (QPlainTextEdit* edit : { m_output, m_events })
            {
                edit->setReadOnly(true);
                edit->setLineWrapMode(QPlainTextEdit::NoWrap);
                edit->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            }
            tabs->addTab(m_output, QStringLiteral("快照 / 对比"));
            tabs->addTab(m_events, QStringLiteral("事件时间线"));
            root->addWidget(tabs, 1);

            connect(refreshButton, &QPushButton::clicked, this, [this]() { refresh(QStringLiteral("手动刷新")); });
            connect(delayedButton, &QPushButton::clicked, this, [this, delayedButton]() {
                delayedButton->setEnabled(false);
                m_status->setText(QStringLiteral("3 秒后抓取；现在回到输入框并让候选框出现。"));
                QTimer::singleShot(3000, this, [this, delayedButton]() {
                    refresh(QStringLiteral("延迟快照"));
                    delayedButton->setEnabled(true);
                    QApplication::beep();
                });
            });
            connect(copyButton, &QPushButton::clicked, this, [this]() {
                QApplication::clipboard()->setText(m_output->toPlainText());
                m_status->setText(QStringLiteral("已复制。"));
            });
            connect(exportButton, &QPushButton::clicked, this, [this]() { exportSnapshot(); });
            connect(exportZButton, &QPushButton::clicked, this, [this]() { exportZOrder(); });
            connect(m_trackButton, &QPushButton::clicked, this, [this]() {
                m_tracking ? stopTracking() : startTracking();
            });
            connect(pickButton, &QPushButton::clicked, this, [this]() {
                const QPoint qpoint = QCursor::pos();
                POINT point{ qpoint.x(), qpoint.y() };
                HWND hwnd = ::WindowFromPoint(point);
                const HWND root = hwnd != nullptr ? ::GetAncestor(hwnd, GA_ROOT) : nullptr;
                if (root != nullptr) hwnd = root;
                if (hwnd != nullptr) m_compare->setText(hwndText(hwnd));
            });
            connect(compareButton, &QPushButton::clicked, this, [this]() { compareNow(); });
            connect(delayedCompareButton, &QPushButton::clicked, this, [this, delayedCompareButton]() {
                delayedCompareButton->setEnabled(false);
                m_status->setText(QStringLiteral("3 秒后对比；请恢复待测遮挡状态。"));
                QTimer::singleShot(3000, this, [this, delayedCompareButton]() {
                    compareNow();
                    delayedCompareButton->setEnabled(true);
                    QApplication::beep();
                });
            });
        }

        void refresh(const QString& reason)
        {
            m_current = capture(m_target);
            m_output->setPlainText(snapshotText(*m_current, m_initialPid, m_initialTid, m_initialClass));
            m_status->setText(QStringLiteral("%1完成：%2")
                .arg(reason, m_current->time.toString(QStringLiteral("HH:mm:ss.zzz"))));
        }

        void compareNow()
        {
            const std::optional<HWND> other = parseHwnd(m_compare->text());
            if (!other.has_value() || ::IsWindow(*other) == FALSE)
            {
                m_status->setText(QStringLiteral("对比 HWND 无效或已销毁。"));
                return;
            }
            const Snapshot a = capture(m_target);
            const Snapshot b = capture(*other);
            m_current = a;
            m_output->setPlainText(
                compareText(a, b) +
                QStringLiteral("\n\n========== A ==========\n") +
                snapshotText(a, m_initialPid, m_initialTid, m_initialClass) +
                QStringLiteral("\n\n========== B ==========\n") +
                snapshotText(b, b.pid, b.tid, b.cls));
            m_status->setText(QStringLiteral("A/B 对比完成。"));
        }

        void exportSnapshot()
        {
            if (!m_current.has_value()) refresh(QStringLiteral("导出前刷新"));
            const QString path = QFileDialog::getSaveFileName(
                this, QStringLiteral("导出窗口层级快照"),
                QStringLiteral("window-layer-%1.json").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))),
                QStringLiteral("JSON (*.json)"));
            if (path.isEmpty()) return;

            QJsonObject root;
            root.insert(QStringLiteral("schemaVersion"), 1);
            root.insert(QStringLiteral("capturedAt"), m_current->time.toString(Qt::ISODateWithMs));
            root.insert(QStringLiteral("hwnd"), hwndText(m_current->hwnd));
            root.insert(QStringLiteral("bandSuccess"), m_current->band.ok);
            root.insert(QStringLiteral("band"), static_cast<double>(m_current->band.value));
            root.insert(QStringLiteral("bandName"), bandName(m_current->band.value));
            root.insert(QStringLiteral("zOrderIndex"), m_current->z);
            root.insert(QStringLiteral("text"), snapshotText(*m_current, m_initialPid, m_initialTid, m_initialClass));
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            {
                QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件。"));
                return;
            }
            file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
            m_status->setText(QStringLiteral("快照已导出。"));
        }

        void exportZOrder()
        {
            const QString path = QFileDialog::getSaveFileName(
                this, QStringLiteral("导出完整顶层 Z 序"),
                QStringLiteral("window-z-order-%1.json").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))),
                QStringLiteral("JSON (*.json)"));
            if (path.isEmpty()) return;
            QJsonObject root;
            root.insert(QStringLiteral("generatedAt"), QDateTime::currentDateTime().toString(Qt::ISODateWithMs));
            root.insert(QStringLiteral("warning"), QStringLiteral("Band IDs are identifiers, not linear z-height."));
            root.insert(QStringLiteral("windows"), zOrderJson());
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            {
                QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件。"));
                return;
            }
            file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
            m_status->setText(QStringLiteral("完整 Z 序已导出。"));
        }

        void startTracking()
        {
            if (m_tracking) return;
            auto addHook = [this](DWORD first, DWORD last) {
                const HWINEVENTHOOK hook = ::SetWinEventHook(
                    first, last, nullptr, winEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
                if (hook == nullptr) return;
                {
                    QMutexLocker locker(&hookMutex());
                    hookOwners().insert(reinterpret_cast<quintptr>(hook), QPointer<Page>(this));
                }
                m_hooks.push_back(hook);
            };
            addHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND);
            addHook(EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND);
            addHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_LOCATIONCHANGE);
            m_tracking = !m_hooks.empty();
            m_eventSnapshot = capture(m_target);
            m_trackButton->setText(m_tracking ? QStringLiteral("停止事件追踪") : QStringLiteral("开始事件追踪"));
            m_status->setText(m_tracking ? QStringLiteral("事件追踪已启动。") : QStringLiteral("SetWinEventHook 失败。"));
        }

        void stopTracking()
        {
            for (HWINEVENTHOOK hook : m_hooks)
            {
                {
                    QMutexLocker locker(&hookMutex());
                    hookOwners().remove(reinterpret_cast<quintptr>(hook));
                }
                ::UnhookWinEvent(hook);
            }
            m_hooks.clear();
            m_tracking = false;
            m_eventSnapshot.reset();
            if (m_trackButton != nullptr) m_trackButton->setText(QStringLiteral("开始事件追踪"));
        }

        HWND m_target = nullptr;
        DWORD m_initialPid = 0;
        DWORD m_initialTid = 0;
        QString m_initialClass;
        QLabel* m_status = nullptr;
        QLineEdit* m_compare = nullptr;
        QPlainTextEdit* m_output = nullptr;
        QPlainTextEdit* m_events = nullptr;
        QPushButton* m_trackButton = nullptr;
        bool m_tracking = false;
        std::vector<HWINEVENTHOOK> m_hooks;
        std::optional<Snapshot> m_current;
        std::optional<Snapshot> m_eventSnapshot;
    };

    void CALLBACK winEventProc(
        HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG objectId,
        LONG childId, DWORD eventTid, DWORD eventTime)
    {
        QPointer<Page> owner;
        {
            QMutexLocker locker(&hookMutex());
            owner = hookOwners().value(reinterpret_cast<quintptr>(hook));
        }
        QCoreApplication* app = QCoreApplication::instance();
        if (owner.isNull() || app == nullptr) return;
        QMetaObject::invokeMethod(app, [owner, event, hwnd, objectId, childId, eventTid, eventTime]() {
            if (!owner.isNull()) owner->onWinEvent(event, hwnd, objectId, childId, eventTid, eventTime);
        }, Qt::QueuedConnection);
    }

    std::optional<HWND> targetFromDialog(const QDialog* dialog)
    {
        static const QRegularExpression pattern(QStringLiteral(R"(\((0[xX][0-9A-Fa-f]+)\)\s*$)"));
        const QRegularExpressionMatch match = pattern.match(dialog->windowTitle());
        return match.hasMatch() ? parseHwnd(match.captured(1)) : std::nullopt;
    }

    QTabWidget* hostTabs(QDialog* dialog)
    {
        QTabWidget* best = nullptr;
        int bestScore = -1;
        for (QTabWidget* tabs : dialog->findChildren<QTabWidget*>())
        {
            int score = tabs->count() + (tabs->parentWidget() == dialog ? 1000 : 0);
            if (score > bestScore)
            {
                best = tabs;
                bestScore = score;
            }
        }
        return best;
    }

    void attach(QDialog* dialog)
    {
        if (dialog == nullptr || dialog->property(kAttachedProperty).toBool()) return;
        const std::optional<HWND> target = targetFromDialog(dialog);
        QTabWidget* tabs = hostTabs(dialog);
        if (!target.has_value() || tabs == nullptr) return;
        tabs->addTab(new Page(*target, tabs), QStringLiteral("层级诊断"));
        dialog->setProperty(kAttachedProperty, true);
    }

    class Injector final : public QObject
    {
    public:
        explicit Injector(QObject* parent) : QObject(parent) {}

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event != nullptr && event->type() == QEvent::Show)
            {
                auto* dialog = qobject_cast<QDialog*>(watched);
                if (dialog != nullptr && dialog->objectName() == QStringLiteral("WindowDetailDialogRoot"))
                {
                    const QPointer<QDialog> safe(dialog);
                    QTimer::singleShot(0, dialog, [safe]() {
                        if (!safe.isNull()) attach(safe.data());
                    });
                }
            }
            return QObject::eventFilter(watched, event);
        }
    };

    void install()
    {
        QCoreApplication* app = QCoreApplication::instance();
        if (app == nullptr) return;
        auto* injector = new Injector(app);
        app->installEventFilter(injector);
    }
}

static void installKswordWindowLayerDiagnostics()
{
    ks::window::layerdiag::install();
}

Q_COREAPP_STARTUP_FUNCTION(installKswordWindowLayerDiagnostics)
