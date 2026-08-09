#include "ServiceView.h"

#include "ServiceActions.h"
#include "ServiceEnumerator.h"
#include "ServiceModel.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::Service {
namespace {

constexpr wchar_t kServiceViewClass[] = L"KswordARKLight.Service.FeatureView";

constexpr int kRefreshButtonId = 64001;
constexpr int kStartButtonId = 64002;
constexpr int kStopButtonId = 64003;
constexpr int kPauseButtonId = 64004;
constexpr int kContinueButtonId = 64005;
constexpr int kStartTypeComboId = 64006;
constexpr int kApplyStartTypeButtonId = 64007;
constexpr int kSortComboId = 64008;
constexpr int kFilterBarId = 64009;
constexpr int kServiceListId = 64010;
constexpr int kDetailListId = 64011;
constexpr int kLoadingOverlayId = 64012;

constexpr UINT kMenuStart = 64601;
constexpr UINT kMenuStop = 64602;
constexpr UINT kMenuPause = 64603;
constexpr UINT kMenuContinue = 64604;
constexpr UINT kMenuCopyRow = 64605;
constexpr UINT kMenuCopyVisible = 64606;
constexpr UINT kMenuCopyDetail = 64607;
constexpr UINT kMenuRefresh = 64608;

constexpr UINT kMsgRefreshCompleted = WM_APP + 640;
constexpr UINT kMsgFilterCompleted = WM_APP + 641;
constexpr UINT kMsgActionCompleted = WM_APP + 642;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 200;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 7;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct ServiceFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct ServiceActionTaskResult final {
    ServiceActionResult action;
    bool refreshRequired = false;
};

struct ServiceViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;
    HWND pauseButton = nullptr;
    HWND continueButton = nullptr;
    HWND startTypeCombo = nullptr;
    HWND applyStartTypeButton = nullptr;
    HWND sortCombo = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView serviceList;
    ServiceModel model;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待服务快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    bool actionInProgress = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ServiceEnumerationResult>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ServiceFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ServiceActionTaskResult>> actionTask;
};

void AddColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void SetDetailText(HWND list, int row, int column, const std::wstring& text) {
    if (column == 0) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(text.c_str());
        ListView_InsertItem(list, &item);
        return;
    }
    ListView_SetItemText(list, row, column, const_cast<LPWSTR>(text.c_str()));
}

bool CopyText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), bytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

int SelectedModelIndex(const ServiceViewState& state) {
    const HWND list = state.serviceList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.serviceList.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t modelIndex = visible[static_cast<std::size_t>(selected)];
    return modelIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(modelIndex) : -1;
}

const ServiceEntry* SelectedEntry(const ServiceViewState& state) {
    return state.model.entryAt(SelectedModelIndex(state));
}

std::wstring StableKeyFromListItem(const ServiceViewState& state, int item) {
    const auto& visible = state.serviceList.visibleIndexes();
    const auto& rows = state.serviceList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t sourceIndex = visible[static_cast<std::size_t>(item)];
    return sourceIndex < rows.size() ? rows[sourceIndex].stableKey : std::wstring{};
}

void ShowDetail(ServiceViewState& state, int modelIndex) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const ServiceEntry* entry = state.model.entryAt(modelIndex);
    if (!entry) {
        SetDetailText(state.detailList, 0, 0, L"选择");
        SetDetailText(state.detailList, 0, 1, L"未选择服务");
        return;
    }
    const std::vector<ServiceProperty> properties = state.model.propertiesForEntry(*entry);
    for (int row = 0; row < static_cast<int>(properties.size()); ++row) {
        SetDetailText(state.detailList, row, 0, properties[static_cast<std::size_t>(row)].name);
        SetDetailText(state.detailList, row, 1, properties[static_cast<std::size_t>(row)].value);
    }
}

// UpdateActionButtons keeps each button's enabled state tied to what the SCM
// would actually accept right now. Offering a control the service does not
// implement only produces an error dialog after the fact.
void UpdateActionButtons(ServiceViewState& state) {
    const ServiceEntry* entry = state.actionInProgress ? nullptr : SelectedEntry(state);
    const bool canStart = entry != nullptr && ServiceCanStart(*entry);
    const bool canStop = entry != nullptr && ServiceCanStop(*entry);
    const bool canPause = entry != nullptr && ServiceCanPause(*entry);
    const bool canContinue = entry != nullptr && ServiceCanContinue(*entry);
    if (state.startButton) {
        ::EnableWindow(state.startButton, canStart);
    }
    if (state.stopButton) {
        ::EnableWindow(state.stopButton, canStop);
    }
    if (state.pauseButton) {
        ::EnableWindow(state.pauseButton, canPause);
    }
    if (state.continueButton) {
        ::EnableWindow(state.continueButton, canContinue);
    }
    const bool canApplyStartType = entry != nullptr && entry->hasConfig && !state.actionInProgress;
    if (state.applyStartTypeButton) {
        ::EnableWindow(state.applyStartTypeButton, canApplyStartType);
    }
    if (state.startTypeCombo) {
        ::EnableWindow(state.startTypeCombo, canApplyStartType);
    }
}

// SyncStartTypeCombo points the combo at the selected service's current setting
// so "apply" without touching the combo is a no-op rather than a silent change
// to whatever option happened to be showing.
void SyncStartTypeCombo(ServiceViewState& state) {
    if (!state.startTypeCombo) {
        return;
    }
    const ServiceEntry* entry = SelectedEntry(state);
    int index = -1;
    if (entry != nullptr && entry->hasConfig) {
        switch (entry->startType) {
        case SERVICE_AUTO_START:
            index = entry->delayedAutoStart ? 1 : 0;
            break;
        case SERVICE_DEMAND_START:
            index = 2;
            break;
        case SERVICE_DISABLED:
            index = 3;
            break;
        default:
            // Boot and system start have no combo entry: they are driver-only
            // settings this page deliberately does not offer to set.
            index = -1;
            break;
        }
    }
    ::SendMessageW(state.startTypeCombo, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
}

void RefreshSelectionDependentUi(ServiceViewState& state) {
    ShowDetail(state, SelectedModelIndex(state));
    SyncStartTypeCombo(state);
    UpdateActionButtons(state);
}

void ApplyServiceFilter(ServiceViewState& state, ServiceFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.serviceList.hwnd()) {
        return;
    }

    state.serviceList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.serviceList.visibleIndexes();
    const auto& rows = state.serviceList.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t sourceIndex = visible[item];
        if (sourceIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && rows[sourceIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && rows[sourceIndex].stableKey == result.topStableKey) {
            topItem = static_cast<int>(item);
        }
    }

    HWND list = state.serviceList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    RefreshSelectionDependentUi(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestServiceFilter(ServiceViewState& state,
    std::wstring query,
    std::wstring selectedStableKey,
    std::wstring topStableKey) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const auto rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery,
            selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            ServiceFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ServiceFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"服务筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            ApplyServiceFilter(state, std::move(*result));
        });
}

void BuildRows(ServiceViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    const auto& entries = state.model.entries();
    rows.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const ServiceEntry& entry = entries[index];
        Ksword::Ui::VirtualListRow row{};
        // The short name alone identifies a service on one machine, so it is a
        // stable key across refreshes even as state and PID change.
        row.stableKey = entry.serviceName;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount + 4);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(state.model.textForColumn(entry, column));
        }
        // Detail-only text joins the filter input without becoming a column, so
        // searching for a binary path or a description works from the same box.
        row.cells.push_back(entry.binaryPath);
        row.cells.push_back(entry.description);
        row.cells.push_back(entry.dependencies);
        row.cells.push_back(entry.diagnosticText);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.serviceList.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void BeginServiceRefresh(ServiceViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool firstLoad = state.serviceList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"服务刷新已排队，等待当前快照完成…" : L"正在后台枚举服务…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (firstLoad) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在加载服务列表…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return EnumerateServices(); },
        [&state](std::uint64_t, std::optional<ServiceEnumerationResult>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"服务刷新异常结束，请检查访问权限。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"服务枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring selectedStableKey =
                StableKeyFromListItem(state, ListView_GetNextItem(state.serviceList.hwnd(), -1, LVNI_SELECTED));
            const std::wstring topStableKey =
                StableKeyFromListItem(state, ListView_GetTopIndex(state.serviceList.hwnd()));
            const std::size_t total = snapshot->entries.size();
            std::size_t running = 0;
            std::size_t risky = 0;
            for (const ServiceEntry& entry : snapshot->entries) {
                if (entry.currentState == SERVICE_RUNNING) {
                    ++running;
                }
                if (!entry.riskText.empty()) {
                    ++risky;
                }
            }
            state.model.setEntries(std::move(snapshot->entries));
            BuildRows(state);
            state.statusText = L"共 " + std::to_wstring(total) + L" 个服务，运行中 " + std::to_wstring(running) +
                L"，带风险标签 " + std::to_wstring(risky) + L"。";
            RequestServiceFilter(state,
                state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery,
                selectedStableKey,
                topStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

// ConfirmStop is the one prompt on this page. Starting, pausing and continuing
// are recoverable by doing the opposite; stopping a running service takes work
// away from whatever depends on it, and the SCM does not put it back. The
// default button is 否 so a stray Enter cannot stop a service.
bool ConfirmStop(HWND owner, const ServiceEntry& entry) {
    const std::wstring text =
        L"将停止服务：" + entry.displayName + L"（" + entry.serviceName + L"）\n\n" +
        L"依赖该服务的组件会一并受影响，系统不会自动恢复它们。\n\n是否继续？";
    return ::MessageBoxW(owner, text.c_str(), L"停止服务", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

ServiceActionTaskResult ExecuteAction(const std::wstring& serviceName, int commandId) {
    ServiceActionTaskResult result{};
    switch (commandId) {
    case kStartButtonId:
        result.action = StartServiceEntry(serviceName);
        break;
    case kStopButtonId:
        result.action = StopServiceEntry(serviceName);
        break;
    case kPauseButtonId:
        result.action = PauseServiceEntry(serviceName);
        break;
    case kContinueButtonId:
        result.action = ContinueServiceEntry(serviceName);
        break;
    default:
        result.action = { false, L"未知服务操作。" };
        break;
    }
    // Every transition changes the state column, so the table is always stale
    // afterwards -- including after a failure, where the service may have moved
    // partway before erroring out.
    result.refreshRequired = true;
    return result;
}

void RunAction(ServiceViewState& state, int commandId) {
    const ServiceEntry* selected = SelectedEntry(state);
    if (!selected) {
        state.statusText = L"未选择服务。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"服务操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (commandId == kStopButtonId && !ConfirmStop(state.hwnd, *selected)) {
        state.statusText = L"已取消停止服务。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const std::wstring serviceName = selected->serviceName;
    state.actionInProgress = true;
    UpdateActionButtons(state);
    state.statusText = L"正在后台执行服务操作，最长等待 30 秒…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [serviceName, commandId] { return ExecuteAction(serviceName, commandId); },
        [&state](std::uint64_t, std::optional<ServiceActionTaskResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            if (error || !result.has_value()) {
                state.statusText = L"服务操作异常结束。";
                UpdateActionButtons(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.statusText = result->action.message;
            if (result->refreshRequired) {
                BeginServiceRefresh(state);
                return;
            }
            UpdateActionButtons(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void RunApplyStartType(ServiceViewState& state) {
    const ServiceEntry* selected = SelectedEntry(state);
    if (!selected || !state.startTypeCombo) {
        state.statusText = L"未选择服务。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"服务操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const LRESULT selection = ::SendMessageW(state.startTypeCombo, CB_GETCURSEL, 0, 0);
    if (selection == CB_ERR) {
        state.statusText = L"请先选择要应用的启动类型。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    ServiceStartTypeChoice choice = ServiceStartTypeChoice::Manual;
    switch (static_cast<int>(selection)) {
    case 0: choice = ServiceStartTypeChoice::Automatic; break;
    case 1: choice = ServiceStartTypeChoice::AutomaticDelayed; break;
    case 2: choice = ServiceStartTypeChoice::Manual; break;
    case 3: choice = ServiceStartTypeChoice::Disabled; break;
    default: break;
    }

    const std::wstring serviceName = selected->serviceName;
    state.actionInProgress = true;
    UpdateActionButtons(state);
    state.statusText = L"正在写入服务启动类型…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [serviceName, choice] {
            ServiceActionTaskResult result{};
            result.action = ApplyServiceStartType(serviceName, choice);
            result.refreshRequired = result.action.success;
            return result;
        },
        [&state](std::uint64_t, std::optional<ServiceActionTaskResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            if (error || !result.has_value()) {
                state.statusText = L"启动类型写入异常结束。";
                UpdateActionButtons(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.statusText = result->action.message;
            if (result->refreshRequired) {
                BeginServiceRefresh(state);
                return;
            }
            UpdateActionButtons(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring RowsAsText(const ServiceViewState& state, bool visibleRows) {
    const auto& rows = state.serviceList.rows();
    const auto& visible = state.serviceList.visibleIndexes();
    const HWND list = state.serviceList.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows &&
            (!list || (ListView_GetItemState(list, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t rowIndex = visible[item];
        if (rowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[rowIndex].cells;
        for (std::size_t column = 0; column < (std::min)(static_cast<std::size_t>(kColumnCount), cells.size()); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

std::wstring DetailAsText(const ServiceViewState& state) {
    const ServiceEntry* entry = SelectedEntry(state);
    if (!entry) {
        return {};
    }
    std::wstring text;
    for (const ServiceProperty& property : state.model.propertiesForEntry(*entry)) {
        text += property.name + L"\t" + property.value + L"\r\n";
    }
    return text;
}

void ShowServiceContextMenu(ServiceViewState& state, POINT screenPoint) {
    const ServiceEntry* entry = SelectedEntry(state);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool busy = state.actionInProgress;
    const UINT startFlags = MF_STRING | ((entry && ServiceCanStart(*entry) && !busy) ? MF_ENABLED : MF_GRAYED);
    const UINT stopFlags = MF_STRING | ((entry && ServiceCanStop(*entry) && !busy) ? MF_ENABLED : MF_GRAYED);
    const UINT pauseFlags = MF_STRING | ((entry && ServiceCanPause(*entry) && !busy) ? MF_ENABLED : MF_GRAYED);
    const UINT continueFlags = MF_STRING | ((entry && ServiceCanContinue(*entry) && !busy) ? MF_ENABLED : MF_GRAYED);
    ::AppendMenuW(menu, startFlags, kMenuStart, L"启动");
    ::AppendMenuW(menu, stopFlags, kMenuStop, L"停止");
    ::AppendMenuW(menu, pauseFlags, kMenuPause, L"暂停");
    ::AppendMenuW(menu, continueFlags, kMenuContinue, L"继续");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(command)) {
    case kMenuStart:
        RunAction(state, kStartButtonId);
        break;
    case kMenuStop:
        RunAction(state, kStopButtonId);
        break;
    case kMenuPause:
        RunAction(state, kPauseButtonId);
        break;
    case kMenuContinue:
        RunAction(state, kContinueButtonId);
        break;
    case kMenuCopyRow:
        state.statusText = CopyText(state.hwnd, RowsAsText(state, false)) ? L"已复制选中行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyVisible:
        state.statusText = CopyText(state.hwnd, RowsAsText(state, true)) ? L"已复制可见行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyDetail:
        state.statusText = CopyText(state.hwnd, DetailAsText(state)) ? L"已复制详情。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuRefresh:
        BeginServiceRefresh(state);
        break;
    default:
        break;
    }
}

void LayoutView(ServiceViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    int cursorX = kGap;
    const int firstRowY = kGap;
    const auto place = [&cursorX, firstRowY](HWND control, int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, firstRowY, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    place(state.refreshButton, 64);
    place(state.startButton, 64);
    place(state.stopButton, 64);
    place(state.pauseButton, 64);
    place(state.continueButton, 64);
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.startTypeCombo) {
        ::MoveWindow(state.startTypeCombo, cursorX, firstRowY, 120, kRowHeight * 8, TRUE);
    }
    cursorX += 120 + kGap;
    if (state.applyStartTypeButton) {
        ::MoveWindow(state.applyStartTypeButton, cursorX, firstRowY, 96, kRowHeight, TRUE);
    }

    const int secondRowY = firstRowY + kRowHeight + kGap;
    if (state.sortCombo) {
        ::MoveWindow(state.sortCombo, kGap, secondRowY, 140, kRowHeight * 6, TRUE);
    }
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap + 140 + kGap, secondRowY,
            (std::max)(120, width - (kGap * 3) - 140), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int detailTop = (std::max)(listTop, height - kStatusHeight - kDetailHeight);
    const int listHeight = (std::max)(0, detailTop - listTop - kGap);
    if (HWND list = state.serviceList.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.detailList) {
        ::MoveWindow(state.detailList, kGap, detailTop, (std::max)(0, width - kGap * 2),
            (std::max)(0, height - kStatusHeight - detailTop - kGap), TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

bool CreateChildControls(ServiceViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.startButton = Ksword::Ui::CreateButton(hwnd, kStartButtonId, L"启动", 0, 0, 0, 0);
    state.stopButton = Ksword::Ui::CreateButton(hwnd, kStopButtonId, L"停止", 0, 0, 0, 0);
    state.pauseButton = Ksword::Ui::CreateButton(hwnd, kPauseButtonId, L"暂停", 0, 0, 0, 0);
    state.continueButton = Ksword::Ui::CreateButton(hwnd, kContinueButtonId, L"继续", 0, 0, 0, 0);
    state.applyStartTypeButton = Ksword::Ui::CreateButton(hwnd, kApplyStartTypeButtonId, L"应用启动类型", 0, 0, 0, 0);

    state.startTypeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kStartTypeComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.sortCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSortComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.startTypeCombo || !state.sortCombo) {
        return false;
    }
    for (const wchar_t* label : { L"自动", L"自动(延迟)", L"手动", L"禁用" }) {
        ::SendMessageW(state.startTypeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    for (const wchar_t* label : { L"名称升序", L"运行中优先", L"自动启动优先" }) {
        ::SendMessageW(state.sortCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.sortCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = Ksword::Ui::CreateFilterBar(
        hwnd, kFilterBarId, L"筛选服务名、显示名、状态、账户、路径与描述", 0, 0, 0, 0);

    if (!state.serviceList.create(hwnd, kServiceListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.serviceList.addColumns({
        { 0, 180, LVCFMT_LEFT, L"服务名" },
        { 1, 240, LVCFMT_LEFT, L"显示名" },
        { 2, 90, LVCFMT_LEFT, L"状态" },
        { 3, 100, LVCFMT_LEFT, L"启动类型" },
        { 4, 70, LVCFMT_RIGHT, L"PID" },
        { 5, 170, LVCFMT_LEFT, L"账户" },
        { 6, 180, LVCFMT_LEFT, L"风险" },
    });
    if (HWND list = state.serviceList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    }

    state.detailList = Ksword::Ui::CreateReportListView(hwnd, kDetailListId, 0, 0, 1, 1, LVS_SINGLESEL);
    if (state.detailList) {
        AddColumn(state.detailList, 0, L"属性", 160);
        AddColumn(state.detailList, 1, L"值", 700);
        ListView_SetExtendedListViewStyle(state.detailList,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.refreshButton || !state.startButton || !state.stopButton || !state.pauseButton ||
        !state.continueButton || !state.applyStartTypeButton || !state.filterBar || !state.detailList ||
        !state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK ServiceViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ServiceViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<ServiceViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ServiceEnumerationResult>>(hwnd, kMsgRefreshCompleted);
            state->filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ServiceFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ServiceActionTaskResult>>(hwnd, kMsgActionCompleted);
            LayoutView(*state);
            ShowDetail(*state, -1);
            UpdateActionButtons(*state);
            BeginServiceRefresh(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (id == kFilterBarId && notification == EN_CHANGE) {
                RequestServiceFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (id == kSortComboId && notification == CBN_SELCHANGE) {
                const LRESULT selection = ::SendMessageW(state->sortCombo, CB_GETCURSEL, 0, 0);
                ServiceSortMode mode = ServiceSortMode::NameAscending;
                if (selection == 1) {
                    mode = ServiceSortMode::RunningFirst;
                } else if (selection == 2) {
                    mode = ServiceSortMode::AutoStartFirst;
                }
                // Re-sorting reorders the model, so the row snapshot and every
                // cached visible index derived from it have to be rebuilt.
                const std::wstring selectedStableKey =
                    StableKeyFromListItem(*state, ListView_GetNextItem(state->serviceList.hwnd(), -1, LVNI_SELECTED));
                state->model.setSortMode(mode);
                BuildRows(*state);
                RequestServiceFilter(*state,
                    Ksword::Ui::GetFilterBarText(state->filterBar), selectedStableKey, {});
                return 0;
            }
            if (notification == BN_CLICKED) {
                switch (id) {
                case kRefreshButtonId:
                    BeginServiceRefresh(*state);
                    return 0;
                case kStartButtonId:
                case kStopButtonId:
                case kPauseButtonId:
                case kContinueButtonId:
                    RunAction(*state, id);
                    return 0;
                case kApplyStartTypeButtonId:
                    RunApplyStartType(*state);
                    return 0;
                default:
                    break;
                }
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->serviceList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->serviceList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        RefreshSelectionDependentUi(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->serviceList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowServiceContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, Ksword::Ui::AppTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            Ksword::Ui::DrawTextLine(dc, state->statusText, statusRect,
                Ksword::Ui::AppTheme().mutedTextColor, Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    default:
        if (state) {
            if (msg == kMsgRefreshCompleted && state->refreshTask) {
                state->refreshTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgActionCompleted && state->actionTask) {
                state->actionTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before destruction so a completion callback cannot run
            // against a half-torn-down state.
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->actionTask) {
                state->actionTask->cancel();
            }
            state->serviceList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureServiceViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = ServiceViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kServiceViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateServiceView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureServiceViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kServiceViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::Service
