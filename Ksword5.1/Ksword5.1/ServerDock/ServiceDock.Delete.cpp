#include "ServiceDock.Internal.h"
#include "../Framework/PrivilegeElevationPrompt.h"

#include <QCoreApplication>
#include <QRunnable>
#include <QSet>
#include <QThreadPool>

using namespace service_dock_detail;

namespace
{
    // kDeleteStopTimeoutMs 作用：组合删除时等待服务真正停止的最长时间。
    constexpr std::uint32_t kDeleteStopTimeoutMs = 10000;

    // LiveDeleteTarget 作用：保存破坏性操作开始后重新读取的实时目标身份。
    struct LiveDeleteTarget
    {
        QString serviceNameText;      // serviceNameText：经过规范化的服务短名。
        QString serviceFilePathText; // serviceFilePathText：实际应删除的 exe/sys/ServiceDll。
        DWORD serviceTypeValue = 0;  // serviceTypeValue：实时服务类型。
        DWORD currentState = 0;      // currentState：实时 SCM 状态；注册表独有项为 0。
        bool scmQueryable = false;   // scmQueryable：是否能通过 OpenService 查询目标。
    };

    // ServiceDeleteResult 作用：把后台删除的完整/部分/失败状态带回 UI 线程。
    struct ServiceDeleteResult
    {
        bool success = false;             // success：请求的全部阶段是否完成。
        bool partialSuccess = false;      // partialSuccess：服务已删但文件删除失败。
        bool registrationDeleted = false; // registrationDeleted：服务注册已删除或标记删除。
        bool fileDeleted = false;         // fileDeleted：目标文件已删除或原本不存在。
        DWORD errorCode = ERROR_SUCCESS;  // errorCode：失败阶段 Win32 错误码。
        QString serviceFilePathText;      // serviceFilePathText：实际复核后的文件路径。
        QString detailText;               // detailText：用户可读失败/成功细节。
    };

    // pendingDeleteServiceNameSet 作用：阻止同一服务被重复派发删除任务。
    // 入参：无。
    // 返回：只在 UI 线程读写的大小写归一化服务名集合。
    QSet<QString>& pendingDeleteServiceNameSet()
    {
        static QSet<QString> pendingNameSet;
        return pendingNameSet;
    }

    // normalizedServiceFilePath 作用：按服务类型选择真正属于服务的文件。
    // 入参：共享进程服务优先选择 ServiceDll，其余选择 BinaryPath 镜像。
    // 返回：可供文件身份比较的规范化路径；无法安全确定时返回空。
    QString normalizedServiceFilePath(
        const DWORD serviceTypeValue,
        const QString& binaryPathText,
        const QString& serviceDllPathText)
    {
        if ((serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            return normalizeServiceImagePath(serviceDllPathText);
        }
        return normalizeServiceImagePath(binaryPathText);
    }

    // selectedServiceFilePath 作用：从列表缓存选择确认框中展示的文件路径。
    // 入参：entry 为用户右键选中的缓存行。
    // 返回：共享进程服务的 ServiceDll，或独立服务/驱动的镜像路径。
    QString selectedServiceFilePath(const ServiceDock::ServiceEntry& entry)
    {
        if ((entry.serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            return normalizeServiceImagePath(entry.serviceDllPathText);
        }
        return normalizeServiceImagePath(entry.imagePathText);
    }

    // comparablePathKey 作用：生成 Windows 路径的大小写无关比较键。
    // 入参：filePathText 为已提取的服务文件路径。
    // 返回：清理分隔符和点段后的小写路径。
    QString comparablePathKey(const QString& filePathText)
    {
        return QDir::cleanPath(QDir::toNativeSeparators(filePathText.trimmed())).toLower();
    }

    // setDeleteFailure 作用：统一填充后台删除失败结果。
    // 入参：resultOut 为结果；errorCode/detailText 描述失败阶段。
    // 返回：固定返回 false，便于调用链直接退出。
    bool setDeleteFailure(
        ServiceDeleteResult* resultOut,
        const DWORD errorCode,
        const QString& detailText)
    {
        if (resultOut != nullptr)
        {
            resultOut->errorCode = errorCode;
            resultOut->detailText = detailText;
        }
        return false;
    }

    // queryLiveDeleteTarget 作用：在删除前从 SCM/注册表重新建立目标身份。
    // 入参：cachedEntry 提供来源预期；targetOut 接收实时状态与文件路径。
    // 返回：SCM 可查询，或确认是注册表独有服务时返回 true。
    bool queryLiveDeleteTarget(
        const ServiceDock::ServiceEntry& cachedEntry,
        LiveDeleteTarget* targetOut,
        ServiceDeleteResult* resultOut)
    {
        if (targetOut == nullptr || resultOut == nullptr)
        {
            return false;
        }

        const QString serviceNameText = cachedEntry.serviceNameText.trimmed();
        ks::service::ServiceRecord scmRecord;
        std::string scmErrorText;
        std::uint32_t scmErrorCode = ERROR_SUCCESS;
        const bool scmQuerySucceeded = ks::service::QueryServiceRecord(
            serviceNameText.toStdWString(),
            &scmRecord,
            &scmErrorText,
            &scmErrorCode);

        RegistryServiceSnapshot registrySnapshot;
        QString registryErrorText;
        DWORD registryErrorCode = ERROR_SUCCESS;
        const bool registryQuerySucceeded = queryRegistryServiceSnapshot(
            serviceNameText,
            &registrySnapshot,
            &registryErrorText,
            &registryErrorCode);

        LiveDeleteTarget target;
        target.serviceNameText = serviceNameText;
        if (scmQuerySucceeded)
        {
            target.scmQueryable = true;
            target.serviceTypeValue = static_cast<DWORD>(scmRecord.config.serviceType);
            target.currentState = static_cast<DWORD>(scmRecord.status.currentState);
            const QString binaryPathText = QString::fromStdWString(
                scmRecord.config.binaryPath).trimmed();
            const QString serviceDllPathText = registryQuerySucceeded
                ? registrySnapshot.serviceDllPathText
                : cachedEntry.serviceDllPathText;
            target.serviceFilePathText = normalizedServiceFilePath(
                target.serviceTypeValue,
                binaryPathText,
                serviceDllPathText);
        }
        else if (!cachedEntry.scmRecordPresent && registryQuerySucceeded)
        {
            target.scmQueryable = false;
            target.serviceTypeValue = registrySnapshot.serviceTypeValue;
            target.currentState = 0;
            target.serviceFilePathText = normalizedServiceFilePath(
                target.serviceTypeValue,
                registrySnapshot.binaryPathText,
                registrySnapshot.serviceDllPathText);
        }
        else
        {
            const QString scmDetailText = QString::fromUtf8(scmErrorText.c_str());
            return setDeleteFailure(
                resultOut,
                static_cast<DWORD>(scmErrorCode),
                QStringLiteral("删除前无法重新查询 SCM 服务：%1").arg(scmDetailText));
        }

        const QString cachedFilePathText = selectedServiceFilePath(cachedEntry);
        if (!cachedFilePathText.isEmpty()
            && !target.serviceFilePathText.isEmpty()
            && comparablePathKey(cachedFilePathText)
                != comparablePathKey(target.serviceFilePathText))
        {
            return setDeleteFailure(
                resultOut,
                ERROR_RETRY,
                QStringLiteral("服务文件路径在枚举后发生变化，已拒绝删除陈旧目标。\n原路径：%1\n当前路径：%2")
                    .arg(cachedFilePathText, target.serviceFilePathText));
        }

        *targetOut = std::move(target);
        return true;
    }

    // collectOtherFileReferences 作用：从 SCM 与注册表双源复核同一文件的其它引用。
    // 入参：targetNameText/targetFilePathText 指定目标；referenceListOut 接收其它服务名。
    // 返回：双源扫描均完整时返回 true；扫描不完整时安全失败。
    bool collectOtherFileReferences(
        const QString& targetNameText,
        const QString& targetFilePathText,
        QStringList* referenceListOut,
        ServiceDeleteResult* resultOut)
    {
        if (referenceListOut == nullptr || resultOut == nullptr)
        {
            return false;
        }
        referenceListOut->clear();

        const QString targetPathKeyText = comparablePathKey(targetFilePathText);
        const QString targetNameKeyText = targetNameText.trimmed().toLower();
        QSet<QString> referenceNameKeySet;
        QHash<QString, QString> displayNameByKey;

        std::vector<RegistryServiceSnapshot> registrySnapshotList;
        QString registryErrorText;
        DWORD registryErrorCode = ERROR_SUCCESS;
        if (!enumerateRegistryServiceSnapshots(
            &registrySnapshotList,
            &registryErrorText,
            &registryErrorCode))
        {
            return setDeleteFailure(
                resultOut,
                registryErrorCode,
                QStringLiteral("无法完成服务文件共享引用的注册表复核：%1")
                    .arg(registryErrorText));
        }

        for (const RegistryServiceSnapshot& snapshot : registrySnapshotList)
        {
            if (!snapshot.keyReadable)
            {
                return setDeleteFailure(
                    resultOut,
                    ERROR_ACCESS_DENIED,
                    QStringLiteral("存在不可读的服务注册表键，无法安全证明目标文件为独占引用：%1")
                        .arg(snapshot.serviceNameText));
            }

            const QString serviceFilePathText = normalizedServiceFilePath(
                snapshot.serviceTypeValue,
                snapshot.binaryPathText,
                snapshot.serviceDllPathText);
            const QString serviceNameKeyText = snapshot.serviceNameText.toLower();
            if (!serviceFilePathText.isEmpty()
                && serviceNameKeyText != targetNameKeyText
                && comparablePathKey(serviceFilePathText) == targetPathKeyText)
            {
                referenceNameKeySet.insert(serviceNameKeyText);
                displayNameByKey.insert(serviceNameKeyText, snapshot.serviceNameText);
            }
        }

        std::vector<ks::service::ServiceRecord> scmRecordList;
        std::string scmErrorText;
        std::uint32_t scmErrorCode = ERROR_SUCCESS;
        if (!ks::service::EnumerateServiceRecords(
            SERVICE_TYPE_ALL,
            SERVICE_STATE_ALL,
            &scmRecordList,
            &scmErrorText,
            &scmErrorCode))
        {
            return setDeleteFailure(
                resultOut,
                static_cast<DWORD>(scmErrorCode),
                QStringLiteral("无法完成服务文件共享引用的 SCM 复核：%1")
                    .arg(QString::fromUtf8(scmErrorText.c_str())));
        }

        for (const ks::service::ServiceRecord& scmRecord : scmRecordList)
        {
            if (!scmRecord.hasConfig)
            {
                continue;
            }
            const QString serviceNameText = QString::fromStdWString(
                scmRecord.serviceName).trimmed();
            const QString serviceNameKeyText = serviceNameText.toLower();
            const QString serviceFilePathText = normalizeServiceImagePath(
                QString::fromStdWString(scmRecord.config.binaryPath));
            const bool sharedProcessService =
                (scmRecord.config.serviceType & SERVICE_WIN32_SHARE_PROCESS) != 0;
            if (!sharedProcessService
                && !serviceFilePathText.isEmpty()
                && serviceNameKeyText != targetNameKeyText
                && comparablePathKey(serviceFilePathText) == targetPathKeyText)
            {
                referenceNameKeySet.insert(serviceNameKeyText);
                displayNameByKey.insert(serviceNameKeyText, serviceNameText);
            }
        }

        for (const QString& referenceNameKeyText : referenceNameKeySet)
        {
            referenceListOut->push_back(displayNameByKey.value(referenceNameKeyText));
        }
        referenceListOut->sort(Qt::CaseInsensitive);
        return true;
    }

    // stopAndRevalidateScmTarget 作用：组合删除前严格等待停止并复核路径身份。
    // 入参：cachedEntry 为旧快照；targetInOut 接收停止后的新状态。
    // 返回：SERVICE_STOPPED、路径未变且共享引用仍为零时返回 true。
    bool stopAndRevalidateScmTarget(
        const ServiceDock::ServiceEntry& cachedEntry,
        LiveDeleteTarget* targetInOut,
        ServiceDeleteResult* resultOut)
    {
        if (targetInOut == nullptr || resultOut == nullptr)
        {
            return false;
        }

        if (targetInOut->currentState != SERVICE_STOPPED)
        {
            ks::service::ServiceStatus finalStatus;
            std::string stopErrorText;
            std::uint32_t stopErrorCode = ERROR_SUCCESS;
            const bool stopSucceeded = ks::service::StopServiceByName(
                targetInOut->serviceNameText.toStdWString(),
                kDeleteStopTimeoutMs,
                SERVICE_STOPPED,
                &finalStatus,
                &stopErrorText,
                &stopErrorCode);
            if (!stopSucceeded
                || finalStatus.currentState != SERVICE_STOPPED)
            {
                const DWORD finalErrorCode = stopSucceeded
                    ? ERROR_TIMEOUT
                    : static_cast<DWORD>(stopErrorCode);
                const QString stopDetailText = stopSucceeded
                    ? QStringLiteral("服务未在超时内到达 SERVICE_STOPPED，未删除服务注册或文件。")
                    : QString::fromUtf8(stopErrorText.c_str());
                return setDeleteFailure(resultOut, finalErrorCode, stopDetailText);
            }
        }

        LiveDeleteTarget revalidatedTarget;
        if (!queryLiveDeleteTarget(cachedEntry, &revalidatedTarget, resultOut))
        {
            return false;
        }
        if (!revalidatedTarget.scmQueryable
            || revalidatedTarget.currentState != SERVICE_STOPPED)
        {
            return setDeleteFailure(
                resultOut,
                ERROR_BUSY,
                QStringLiteral("停止后复核未确认 SERVICE_STOPPED，未删除服务注册或文件。"));
        }
        if (comparablePathKey(revalidatedTarget.serviceFilePathText)
            != comparablePathKey(targetInOut->serviceFilePathText))
        {
            return setDeleteFailure(
                resultOut,
                ERROR_RETRY,
                QStringLiteral("停止后服务文件路径发生变化，未删除服务注册或文件。"));
        }

        *targetInOut = std::move(revalidatedTarget);
        return true;
    }

    // performServiceDeletion 作用：执行“仅服务”或“服务+文件”的完整后台事务。
    // 入参：cachedEntry 为确认时快照；deleteBinaryFile 决定是否执行文件阶段。
    // 返回：包含部分成功语义的值类型结果。
    ServiceDeleteResult performServiceDeletion(
        const ServiceDock::ServiceEntry& cachedEntry,
        const bool deleteBinaryFile)
    {
        ServiceDeleteResult result;
        LiveDeleteTarget liveTarget;
        if (!queryLiveDeleteTarget(cachedEntry, &liveTarget, &result))
        {
            return result;
        }
        result.serviceFilePathText = liveTarget.serviceFilePathText;

        QStringList sharedReferenceList;
        if (deleteBinaryFile)
        {
            const QFileInfo serviceFileInfo(liveTarget.serviceFilePathText);
            if (liveTarget.serviceFilePathText.isEmpty()
                || !serviceFileInfo.isAbsolute()
                || !serviceFileInfo.exists()
                || serviceFileInfo.isDir())
            {
                setDeleteFailure(
                    &result,
                    ERROR_FILE_NOT_FOUND,
                    QStringLiteral("无法把服务文件复核为存在的绝对文件，未执行删除：%1")
                        .arg(liveTarget.serviceFilePathText));
                return result;
            }

            if (!collectOtherFileReferences(
                liveTarget.serviceNameText,
                liveTarget.serviceFilePathText,
                &sharedReferenceList,
                &result))
            {
                return result;
            }
            if (!sharedReferenceList.isEmpty())
            {
                setDeleteFailure(
                    &result,
                    ERROR_SHARING_VIOLATION,
                    QStringLiteral("目标文件仍被其它服务引用，未删除任何内容：%1")
                        .arg(sharedReferenceList.join(QStringLiteral(", "))));
                return result;
            }
        }

        if (liveTarget.scmQueryable)
        {
            if (deleteBinaryFile
                && !stopAndRevalidateScmTarget(cachedEntry, &liveTarget, &result))
            {
                return result;
            }

            if (deleteBinaryFile)
            {
                sharedReferenceList.clear();
                if (!collectOtherFileReferences(
                    liveTarget.serviceNameText,
                    liveTarget.serviceFilePathText,
                    &sharedReferenceList,
                    &result))
                {
                    return result;
                }
                if (!sharedReferenceList.isEmpty())
                {
                    setDeleteFailure(
                        &result,
                        ERROR_SHARING_VIOLATION,
                        QStringLiteral("停止后发现目标文件新增共享引用，未删除任何内容：%1")
                            .arg(sharedReferenceList.join(QStringLiteral(", "))));
                    return result;
                }
            }

            std::string deleteErrorText;
            std::uint32_t deleteErrorCode = ERROR_SUCCESS;
            const bool deleteServiceSucceeded = ks::service::DeleteServiceByName(
                liveTarget.serviceNameText.toStdWString(),
                !deleteBinaryFile,
                kDeleteStopTimeoutMs,
                &deleteErrorText,
                &deleteErrorCode);
            if (!deleteServiceSucceeded)
            {
                setDeleteFailure(
                    &result,
                    static_cast<DWORD>(deleteErrorCode),
                    QStringLiteral("DeleteService 失败：%1")
                        .arg(QString::fromUtf8(deleteErrorText.c_str())));
                return result;
            }
        }
        else
        {
            RegistryServiceSnapshot currentRegistrySnapshot;
            QString registryQueryErrorText;
            DWORD registryQueryErrorCode = ERROR_SUCCESS;
            if (!queryRegistryServiceSnapshot(
                liveTarget.serviceNameText,
                &currentRegistrySnapshot,
                &registryQueryErrorText,
                &registryQueryErrorCode))
            {
                setDeleteFailure(
                    &result,
                    registryQueryErrorCode,
                    QStringLiteral("删除前无法复核幽灵服务注册表键：%1")
                        .arg(registryQueryErrorText));
                return result;
            }

            const QString currentFilePathText = normalizedServiceFilePath(
                currentRegistrySnapshot.serviceTypeValue,
                currentRegistrySnapshot.binaryPathText,
                currentRegistrySnapshot.serviceDllPathText);
            if (deleteBinaryFile
                && comparablePathKey(currentFilePathText)
                    != comparablePathKey(liveTarget.serviceFilePathText))
            {
                setDeleteFailure(
                    &result,
                    ERROR_RETRY,
                    QStringLiteral("幽灵服务文件路径在确认后发生变化，未删除任何内容。"));
                return result;
            }

            QString registryDeleteErrorText;
            DWORD registryDeleteErrorCode = ERROR_SUCCESS;
            if (!deleteRegistryServiceKey(
                liveTarget.serviceNameText,
                &registryDeleteErrorText,
                &registryDeleteErrorCode))
            {
                setDeleteFailure(
                    &result,
                    registryDeleteErrorCode,
                    registryDeleteErrorText);
                return result;
            }
        }
        result.registrationDeleted = true;

        if (!deleteBinaryFile)
        {
            result.success = true;
            result.detailText = QStringLiteral("服务注册已删除或已标记删除。文件未被修改。");
            return result;
        }

        const std::wstring filePathWide = liveTarget.serviceFilePathText.toStdWString();
        if (::DeleteFileW(filePathWide.c_str()) == FALSE)
        {
            const DWORD deleteFileErrorCode = ::GetLastError();
            if (deleteFileErrorCode != ERROR_FILE_NOT_FOUND)
            {
                result.partialSuccess = true;
                result.errorCode = deleteFileErrorCode;
                result.detailText = QStringLiteral("服务注册已删除，但 DeleteFileW 失败：%1")
                    .arg(QString::fromUtf8(
                        ks::service::FormatWin32ErrorText(deleteFileErrorCode).c_str()));
                return result;
            }
        }

        result.fileDeleted = true;
        result.success = true;
        result.detailText = QStringLiteral("服务注册与服务文件均已删除。");
        return result;
    }
}

void ServiceDock::deleteSelectedService()
{
    deleteSelectedServiceInternal(false);
}

void ServiceDock::deleteSelectedServiceAndFile()
{
    deleteSelectedServiceInternal(true);
}

void ServiceDock::deleteSelectedServiceInternal(const bool deleteBinaryFile)
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    if (selectedIndex < 0 || selectedIndex >= static_cast<int>(m_serviceList.size()))
    {
        return;
    }

    const ServiceEntry selectedEntry = m_serviceList[static_cast<std::size_t>(selectedIndex)];
    const QString serviceNameText = selectedEntry.serviceNameText.trimmed();
    const QString serviceFilePathText = selectedServiceFilePath(selectedEntry);
    if (deleteBinaryFile && serviceFilePathText.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("无法确定该服务独有的文件路径，未执行删除。共享进程服务必须具有 ServiceDll。"));
        return;
    }

    if (!ks::ui::requestAdministratorRestartForFeature(
        this,
        deleteBinaryFile
            ? QStringLiteral("删除服务及其文件")
            : QStringLiteral("删除服务")))
    {
        return;
    }

    const QString actionText = deleteBinaryFile
        ? QStringLiteral("删除服务并删除其文件")
        : QStringLiteral("删除服务");
    const QString riskDetailText = deleteBinaryFile
        ? QStringLiteral("该操作不可逆。程序会先重新查询配置、确认文件没有被其它服务引用，并严格等待 SCM 服务停止；只有服务注册删除成功后才会删除文件。\n\n服务：%1\n文件：%2\n来源：%3")
            .arg(serviceNameText, serviceFilePathText, selectedEntry.sourceStatusText)
        : QStringLiteral("该操作不可逆。SCM 可查询时将调用 DeleteService；仅注册表可见时将删除对应 Services 键树。服务文件不会被修改。\n\n服务：%1\n来源：%2")
            .arg(serviceNameText, selectedEntry.sourceStatusText);
    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        QStringLiteral("高风险动作确认"),
        QStringLiteral("确认执行“%1”？\n\n%2").arg(actionText, riskDetailText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmButton != QMessageBox::Yes)
    {
        return;
    }

    const QString pendingNameKeyText = serviceNameText.toLower();
    if (pendingDeleteServiceNameSet().contains(pendingNameKeyText))
    {
        QMessageBox::information(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("该服务的删除任务正在执行，请等待当前任务完成。"));
        return;
    }

    pendingDeleteServiceNameSet().insert(pendingNameKeyText);
    const int progressPid = kPro.add(
        this,
        "服务管理",
        actionText.toStdString() + std::string(" - ") + serviceNameText.toStdString());
    kPro.set(progressPid, "重新验证服务身份", 0, 20.0f);

    const kLogEvent deleteEvent;
    info << deleteEvent
        << "[ServiceDock] 开始删除服务, service="
        << serviceNameText.toStdString()
        << ", deleteFile="
        << deleteBinaryFile
        << eol;

    const QPointer<ServiceDock> guardedSelf(this);
    QRunnable* const deleteTask = QRunnable::create(
        [guardedSelf,
            selectedEntry,
            serviceNameText,
            pendingNameKeyText,
            deleteBinaryFile,
            actionText,
            progressPid,
            deleteEvent]()
        {
            kPro.set(progressPid, "停止并删除服务", 0, 55.0f);
            const ServiceDeleteResult result = performServiceDeletion(
                selectedEntry,
                deleteBinaryFile);

            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                appInstance,
                [guardedSelf,
                    serviceNameText,
                    pendingNameKeyText,
                    deleteBinaryFile,
                    actionText,
                    progressPid,
                    deleteEvent,
                    result]()
                {
                    pendingDeleteServiceNameSet().remove(pendingNameKeyText);
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }

                    guardedSelf->requestAsyncRefresh(true);
                    if (result.success)
                    {
                        info << deleteEvent
                            << "[ServiceDock] 删除服务完成, service="
                            << serviceNameText.toStdString()
                            << ", deleteFile="
                            << deleteBinaryFile
                            << eol;
                        kPro.set(progressPid, "删除完成", 0, 100.0f);
                        QMessageBox::information(
                            guardedSelf.data(),
                            QStringLiteral("服务管理"),
                            QStringLiteral("%1完成。\n\n服务：%2%3\n%4")
                                .arg(
                                    actionText,
                                    serviceNameText,
                                    deleteBinaryFile
                                        ? QStringLiteral("\n文件：%1").arg(result.serviceFilePathText)
                                        : QString(),
                                    result.detailText));
                        return;
                    }

                    const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                        guardedSelf.data(),
                        actionText,
                        result.errorCode);
                    err << deleteEvent
                        << "[ServiceDock] 删除服务失败, service="
                        << serviceNameText.toStdString()
                        << ", partial="
                        << result.partialSuccess
                        << ", error="
                        << result.errorCode
                        << ", detail="
                        << result.detailText.toStdString()
                        << eol;
                    kPro.set(
                        progressPid,
                        result.partialSuccess ? "部分成功" : "删除失败",
                        0,
                        100.0f);
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            guardedSelf.data(),
                            result.partialSuccess
                                ? QStringLiteral("部分成功")
                                : QStringLiteral("服务管理"),
                            QStringLiteral("%1未完全完成。\n\n服务：%2\n文件：%3\nWin32：%4\n%5")
                                .arg(actionText)
                                .arg(serviceNameText)
                                .arg(result.serviceFilePathText.isEmpty()
                                    ? QStringLiteral("未涉及")
                                    : result.serviceFilePathText)
                                .arg(result.errorCode)
                                .arg(result.detailText));
                    }
                },
                Qt::QueuedConnection);
        });
    deleteTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(deleteTask);
}
