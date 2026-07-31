#include "DiskMonitorStorageLeaseCoordinator.h"

#include <QDebug>
#include <QHash>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <system_error>
#include <thread>
#include <utility>

#include <winioctl.h>

namespace disk_monitor_storage_lease
{
    namespace
    {
        using RetirementClock = std::chrono::steady_clock;

        constexpr std::uint32_t kMaximumBackoffExponent = 7U;
        constexpr std::uint32_t kInitialBackoffMilliseconds = 250U;

        enum class LeaseSlotState
        {
            Active,
            Retiring
        };

        // LeaseSlot：
        // - 每个规范化卷 GUID 最多存在一个槽位；
        // - Active 阶段由采样线程使用 lease；
        // - Retiring 阶段由唯一 worker 串行补偿引用。
        struct LeaseSlot
        {
            LeasePointer lease;               // lease：活动与退役阶段共享的唯一所有权对象。
            LeaseSlotState state = LeaseSlotState::Active; // state：当前所有权阶段。
            QString retirementReason;         // retirementReason：触发退役的诊断原因。
            std::uint32_t failureAttempt = 0U; // failureAttempt：连续 OFF 失败次数。
            RetirementClock::time_point nextAttemptAt = RetirementClock::now(); // nextAttemptAt：下次允许重试时间。
        };

        using LeaseSlotPointer = std::shared_ptr<LeaseSlot>;

        // LeaseCoordinatorState：
        // - slotByVolumeGuid 同时承担 active reservation 和 retiring quarantine；
        // - workerThread 始终至多一个，不为每个卷创建线程；
        // - 对象故意保持到进程结束，避免 Qt 面板析构后 worker 访问失效状态。
        struct LeaseCoordinatorState
        {
            std::mutex mutex;                 // mutex：保护槽位、重试时间和 worker 所有权。
            std::condition_variable wakeCondition; // wakeCondition：新任务或更早任务到来时唤醒 worker。
            QHash<QString, LeaseSlotPointer> slotByVolumeGuid; // slotByVolumeGuid：每卷唯一状态槽。
            std::unique_ptr<std::thread> workerThread; // workerThread：进程期唯一、非 detached 的后台线程。
        };

        QString normalizedVolumeGuidName(const QString& volumeGuidName)
        {
            // normalizedName：统一分隔符、大小写与空白，确保同卷只占一个槽位。
            QString normalizedName = volumeGuidName.trimmed();
            normalizedName.replace(QLatin1Char('/'), QLatin1Char('\\'));
            return normalizedName.toUpper();
        }

        LeaseCoordinatorState& coordinatorState()
        {
            // state：进程期账本不能先于后台 worker 析构，因此有意不注册静态析构。
            static auto* state = new LeaseCoordinatorState();
            return *state;
        }

        void logRetiredLeaseDiagnostic(
            const Lease& lease,
            const QString& reason,
            const QString& action,
            const DWORD errorCode,
            const std::uint32_t attempt)
        {
            qWarning().noquote()
                << QStringLiteral(
                    "[DiskMonitorStorage] retired lease %1: guid=%2 refs=%3 "
                    "error=%4 attempt=%5 lastQueryError=%6 "
                    "consecutiveQueryFailures=%7 reason=%8")
                    .arg(action)
                    .arg(lease.volumeGuidName)
                    .arg(lease.ownedEnableReferenceCount)
                    .arg(errorCode)
                    .arg(attempt)
                    .arg(lease.lastQueryError)
                    .arg(lease.consecutiveQueryFailureCount)
                    .arg(reason);
        }

        bool hasRetiringSlotLocked(const LeaseCoordinatorState& state)
        {
            // slot：只要存在一个 Retiring 槽位，就需要确保唯一 worker 存活。
            for (auto slotIterator = state.slotByVolumeGuid.constBegin();
                 slotIterator != state.slotByVolumeGuid.constEnd();
                 ++slotIterator)
            {
                const LeaseSlotPointer& slot = slotIterator.value();
                if (slot != nullptr &&
                    slot->state == LeaseSlotState::Retiring)
                {
                    return true;
                }
            }
            return false;
        }

        void runRetiredLeaseWorker(LeaseCoordinatorState* state)
        {
            if (state == nullptr)
            {
                return;
            }

            for (;;)
            {
                LeaseSlotPointer selectedSlot;
                QString selectedVolumeGuid;
                {
                    std::unique_lock<std::mutex> lock(state->mutex);
                    while (selectedSlot == nullptr)
                    {
                        const RetirementClock::time_point now =
                            RetirementClock::now();
                        RetirementClock::time_point earliestAttempt =
                            RetirementClock::time_point::max();

                        // 每轮只选择一个到期卷；单 worker 串行 OFF，
                        // 因此阻塞驱动不会放大为每卷一个永久线程。
                        for (auto slotIterator =
                                 state->slotByVolumeGuid.constBegin();
                             slotIterator !=
                                 state->slotByVolumeGuid.constEnd();
                             ++slotIterator)
                        {
                            const LeaseSlotPointer& candidateSlot =
                                slotIterator.value();
                            if (candidateSlot == nullptr ||
                                candidateSlot->state !=
                                    LeaseSlotState::Retiring)
                            {
                                continue;
                            }
                            if (candidateSlot->nextAttemptAt <= now)
                            {
                                selectedSlot = candidateSlot;
                                selectedVolumeGuid = slotIterator.key();
                                break;
                            }
                            earliestAttempt = std::min(
                                earliestAttempt,
                                candidateSlot->nextAttemptAt);
                        }

                        if (selectedSlot != nullptr)
                        {
                            break;
                        }
                        if (earliestAttempt ==
                            RetirementClock::time_point::max())
                        {
                            state->wakeCondition.wait(lock);
                        }
                        else
                        {
                            state->wakeCondition.wait_until(
                                lock,
                                earliestAttempt);
                        }
                    }
                }

                Lease& lease = *selectedSlot->lease;
                DWORD releaseError = ERROR_SUCCESS;
                const bool releasedReference =
                    turnOffOneReference(&lease, &releaseError);
                const bool retirementCompleted =
                    lease.ownedEnableReferenceCount == 0U;

                // CloseHandle 也只在后台 worker 执行；槽位在关闭完成前保持
                // quarantine，避免同卷在旧句柄尚未收尾时重新打开。
                if (retirementCompleted &&
                    lease.volumeHandle != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(lease.volumeHandle);
                    lease.volumeHandle = INVALID_HANDLE_VALUE;
                }

                QString action;
                std::uint32_t diagnosticAttempt = 0U;
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    auto slotIterator =
                        state->slotByVolumeGuid.find(selectedVolumeGuid);
                    if (slotIterator ==
                            state->slotByVolumeGuid.end() ||
                        slotIterator.value() != selectedSlot)
                    {
                        continue;
                    }

                    if (retirementCompleted)
                    {
                        action = QStringLiteral("closed");
                        diagnosticAttempt =
                            selectedSlot->failureAttempt;
                        state->slotByVolumeGuid.erase(slotIterator);
                    }
                    else if (releasedReference)
                    {
                        action = QStringLiteral("released-one");
                        selectedSlot->failureAttempt = 0U;
                        selectedSlot->nextAttemptAt =
                            RetirementClock::now();
                    }
                    else
                    {
                        action = QStringLiteral("retry");
                        if (selectedSlot->failureAttempt <
                            std::numeric_limits<std::uint32_t>::max())
                        {
                            ++selectedSlot->failureAttempt;
                        }
                        diagnosticAttempt =
                            selectedSlot->failureAttempt;
                        const std::uint32_t backoffExponent =
                            std::min(
                                selectedSlot->failureAttempt,
                                kMaximumBackoffExponent);
                        const std::uint32_t backoffMilliseconds =
                            kInitialBackoffMilliseconds *
                            (1U << backoffExponent);
                        selectedSlot->nextAttemptAt =
                            RetirementClock::now() +
                            std::chrono::milliseconds(
                                backoffMilliseconds);
                    }
                }

                logRetiredLeaseDiagnostic(
                    lease,
                    selectedSlot->retirementReason,
                    action,
                    releasedReference
                        ? ERROR_SUCCESS
                        : releaseError,
                    diagnosticAttempt);
            }
        }

        void ensureWorkerStarted()
        {
            LeaseCoordinatorState& state = coordinatorState();
            QString startErrorText;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                if (state.workerThread != nullptr ||
                    !hasRetiringSlotLocked(state))
                {
                    return;
                }

                try
                {
                    // workerThread：协调器保留 joinable 对象到进程退出，
                    // 不 detach，也不依赖任一 QWidget/QObject 的生命周期。
                    LeaseCoordinatorState* const statePointer = &state;
                    state.workerThread =
                        std::make_unique<std::thread>(
                            [statePointer]()
                            {
                                runRetiredLeaseWorker(statePointer);
                            });
                }
                catch (const std::system_error& error)
                {
                    startErrorText =
                        QString::fromStdString(error.what());
                }
            }

            if (!startErrorText.isEmpty())
            {
                qWarning().noquote()
                    << QStringLiteral(
                        "[DiskMonitorStorage] retirement worker start "
                        "failed; bounded ledger retained for next retry: %1")
                        .arg(startErrorText);
            }
        }
    }

    LeasePointer tryAcquireActiveLease(
        const QString& volumeGuidName)
    {
        const QString volumeGuidKey =
            normalizedVolumeGuidName(volumeGuidName);
        if (volumeGuidKey.isEmpty())
        {
            return {};
        }

        LeaseCoordinatorState& state = coordinatorState();
        bool blockedByRetirement = false;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            const auto existingIterator =
                state.slotByVolumeGuid.constFind(volumeGuidKey);
            if (existingIterator !=
                state.slotByVolumeGuid.constEnd())
            {
                const LeaseSlotPointer& existingSlot =
                    existingIterator.value();
                blockedByRetirement =
                    existingSlot != nullptr &&
                    existingSlot->state ==
                        LeaseSlotState::Retiring;
            }
            else
            {
                LeasePointer lease = std::make_shared<Lease>();
                lease->volumeGuidName = volumeGuidKey;

                LeaseSlotPointer slot =
                    std::make_shared<LeaseSlot>();
                slot->lease = lease;
                slot->state = LeaseSlotState::Active;
                state.slotByVolumeGuid.insert(
                    volumeGuidKey,
                    std::move(slot));
                return lease;
            }
        }

        // worker 创建失败时不丢账本；后续 1 Hz 采样只会重试启动
        // 同一个 worker，不会为该卷创建新 lease、句柄或任务。
        if (blockedByRetirement)
        {
            ensureWorkerStarted();
        }
        return {};
    }

    bool releaseUnusedActiveLease(
        const LeasePointer& lease)
    {
        if (lease == nullptr)
        {
            return false;
        }

        const QString volumeGuidKey =
            normalizedVolumeGuidName(lease->volumeGuidName);
        LeaseCoordinatorState& state = coordinatorState();
        std::lock_guard<std::mutex> lock(state.mutex);
        auto slotIterator =
            state.slotByVolumeGuid.find(volumeGuidKey);
        if (slotIterator ==
                state.slotByVolumeGuid.end() ||
            slotIterator.value() == nullptr ||
            slotIterator.value()->lease != lease ||
            slotIterator.value()->state !=
                LeaseSlotState::Active)
        {
            return false;
        }

        state.slotByVolumeGuid.erase(slotIterator);
        return true;
    }

    bool retireLeaseAsync(
        const LeasePointer& lease,
        const QString& reason)
    {
        if (lease == nullptr)
        {
            return false;
        }

        const QString volumeGuidKey =
            normalizedVolumeGuidName(lease->volumeGuidName);
        LeaseCoordinatorState& state = coordinatorState();
        Lease diagnosticSnapshot;
        bool newlyRetired = false;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            auto slotIterator =
                state.slotByVolumeGuid.find(volumeGuidKey);
            if (slotIterator ==
                    state.slotByVolumeGuid.end() ||
                slotIterator.value() == nullptr ||
                slotIterator.value()->lease != lease)
            {
                return false;
            }

            LeaseSlotPointer& slot = slotIterator.value();
            if (slot->state == LeaseSlotState::Active)
            {
                // diagnosticSnapshot：在切换为 Retiring 前按值冻结诊断；
                // worker 后续修改引用数/句柄时不会与日志读取产生竞争。
                diagnosticSnapshot = *lease;
                slot->state = LeaseSlotState::Retiring;
                slot->retirementReason = reason;
                slot->failureAttempt = 0U;
                slot->nextAttemptAt = RetirementClock::now();
                newlyRetired = true;
            }
        }

        if (newlyRetired)
        {
            logRetiredLeaseDiagnostic(
                diagnosticSnapshot,
                reason,
                QStringLiteral("queued"),
                ERROR_SUCCESS,
                0U);
        }
        ensureWorkerStarted();
        state.wakeCondition.notify_one();
        return true;
    }

    bool turnOffOneReference(
        Lease* lease,
        DWORD* errorOut)
    {
        if (errorOut != nullptr)
        {
            *errorOut = ERROR_SUCCESS;
        }
        if (lease == nullptr ||
            lease->ownedEnableReferenceCount == 0U)
        {
            return true;
        }
        if (lease->volumeHandle == INVALID_HANDLE_VALUE)
        {
            if (errorOut != nullptr)
            {
                *errorOut = ERROR_INVALID_HANDLE;
            }
            return false;
        }

        DWORD returnedBytes = 0U;
        const BOOL releaseOk = DeviceIoControl(
            lease->volumeHandle,
            IOCTL_DISK_PERFORMANCE_OFF,
            nullptr,
            0U,
            nullptr,
            0U,
            &returnedBytes,
            nullptr);
        if (!releaseOk)
        {
            if (errorOut != nullptr)
            {
                *errorOut = GetLastError();
            }
            return false;
        }

        --lease->ownedEnableReferenceCount;
        return true;
    }
}
