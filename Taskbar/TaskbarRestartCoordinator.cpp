#include "TaskbarRestartCoordinator.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QString>
#include <QStringList>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    constexpr auto RestartAfterPidArgument = "--restart-after-pid";

    QStringList successorArguments()
    {
        const QString restartArgument = QString::fromLatin1(RestartAfterPidArgument);
        const QStringList currentArguments = QCoreApplication::arguments();
        QStringList arguments;
        for (qsizetype argumentIndex = 1; argumentIndex < currentArguments.size(); ++argumentIndex)
        {
            if (currentArguments.at(argumentIndex) == restartArgument)
            {
                // 不把旧接替参数继续传给下一代；其后的 PID（若存在）一并丢弃。
                if (argumentIndex + 1 < currentArguments.size())
                {
                    ++argumentIndex;
                }
                continue;
            }
            arguments.append(currentArguments.at(argumentIndex));
        }

        arguments.append(restartArgument);
        arguments.append(QString::number(::GetCurrentProcessId()));
        return arguments;
    }

    bool requestedPredecessorPid(DWORD* predecessorPid)
    {
        if (predecessorPid == nullptr)
        {
            return false;
        }

        const QString restartArgument = QString::fromLatin1(RestartAfterPidArgument);
        const QStringList arguments = QCoreApplication::arguments();
        const qsizetype markerIndex = arguments.indexOf(restartArgument);
        if (markerIndex < 0)
        {
            *predecessorPid = 0;
            return true;
        }
        if (markerIndex + 1 >= arguments.size())
        {
            return false;
        }

        bool parsed = false;
        const qulonglong parsedPid = arguments.at(markerIndex + 1).toULongLong(&parsed, 10);
        if (!parsed || parsedPid == 0 || parsedPid > MAXDWORD ||
            parsedPid == ::GetCurrentProcessId())
        {
            return false;
        }

        *predecessorPid = static_cast<DWORD>(parsedPid);
        return true;
    }
}

bool TaskbarRestartCoordinator::scheduleAfterCurrentProcessExit()
{
    const QString programPath = QCoreApplication::applicationFilePath();
    const QFileInfo programFileInfo(programPath);
    if (programPath.isEmpty() || !programFileInfo.isFile())
    {
        return false;
    }

    return QProcess::startDetached(
        programPath,
        successorArguments(),
        programFileInfo.absolutePath());
}

bool TaskbarRestartCoordinator::waitForPredecessorIfRequested()
{
    DWORD predecessorPid = 0;
    if (!requestedPredecessorPid(&predecessorPid))
    {
        return false;
    }
    if (predecessorPid == 0)
    {
        return true;
    }

    HANDLE predecessorProcess = ::OpenProcess(SYNCHRONIZE, FALSE, predecessorPid);
    if (predecessorProcess == nullptr)
    {
        // startDetached 与 OpenProcess 之间旧进程可能已经完全退出；此时可以安全继续。
        return ::GetLastError() == ERROR_INVALID_PARAMETER;
    }

    const DWORD waitResult = ::WaitForSingleObject(predecessorProcess, INFINITE);
    ::CloseHandle(predecessorProcess);
    return waitResult == WAIT_OBJECT_0;
}
