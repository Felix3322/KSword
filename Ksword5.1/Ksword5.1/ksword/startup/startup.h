#pragma once

// ============================================================
// ksword/startup/startup.h
// Namespace: ks::startup
// Purpose:
// - Provide a non-UI startup persistence enumeration backend.
// - Keep records in UTF-8 std::string fields so Qt and non-Qt callers can adapt them.
// - Avoid UI framework dependencies in this layer.
// ============================================================

#include <cstdint> // std::uint32_t: Win32 result and status placeholders.
#include <string>  // std::string: UTF-8 text fields exposed across layers.
#include <vector>  // std::vector: startup record and catalog containers.

namespace ks::startup
{
    // StartupCategory describes the logical startup source family.
    enum class StartupCategory : int
    {
        All = 0,
        Logon,
        Services,
        Drivers,
        Tasks,
        Registry,
        Wmi
    };

    // StartupActionKind identifies a reversible backend operation without parsing display text.
    enum class StartupActionKind : int
    {
        None = 0,
        RegistryRunValue,
        StartupFolderFile,
        ScheduledTask
    };

    // StartupRegistryRoot is deliberately limited to roots accepted by reversible Run actions.
    enum class StartupRegistryRoot : int
    {
        None = 0,
        CurrentUser,
        LocalMachine
    };

    // StartupRiskLevel lets UI layers select warning treatment without parsing diagnostics.
    enum class StartupRiskLevel : int
    {
        Normal = 0,
        Elevated,
        Critical
    };

    // StartupActionLocator contains machine-readable action coordinates.
    // Only fields relevant to actionKind are populated.
    struct StartupActionLocator
    {
        StartupRegistryRoot registryRoot = StartupRegistryRoot::None;
        std::string registrySubKeyText;
        std::string registryValueNameText;
        bool registryValueSnapshotValid = false;
        std::uint32_t registryValueType = 0;
        std::vector<std::uint8_t> registryRawData;
        std::string originalFilePathText;
        std::string parkedFilePathText;
        bool fileIdentitySnapshotValid = false;
        std::uint64_t fileVolumeSerial = 0;
        std::uint64_t fileIndex = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t fileLastWriteTime = 0;
        std::string taskPathText;
        std::string taskNameText;
        std::string taskDefinitionSha256Text;
        std::string backupIdText;
    };

    // StartupEntry is the unified backend record used by every enumerator.
    // All text is UTF-8. UI layers may convert it to their own view model.
    struct StartupEntry
    {
        std::string uniqueIdText;          // Stable identity for cache, deletion, or diagnostics.
        StartupCategory category = StartupCategory::All; // Logical category of this entry.
        std::string categoryText;          // Display-ready category text.
        std::string itemNameText;          // Entry display name.
        std::string publisherText;         // Signature/company placeholder or resolved publisher.
        std::string imagePathText;         // Normalized image path when one can be inferred.
        std::string commandText;           // Raw command, registry data, or action text.
        std::string locationText;          // Source location: registry key, SCM name, task path, etc.
        std::string locationGroupText;     // Registry tree group location when applicable.
        std::string registryValueNameText; // Real registry value name for deletion.
        std::string userText;              // User/context text.
        std::string detailText;            // Additional diagnostics or source details.
        std::string sourceTypeText;        // Source subtype such as Run, ScheduledTask, WMI-EventFilter.
        StartupActionKind actionKind = StartupActionKind::None; // Reversible backend operation.
        StartupActionLocator actionLocator; // Structured coordinates consumed by action APIs.
        bool enabled = true;               // Whether the source is enabled.
        bool canEnable = false;             // Whether SetStartupEntryEnabled(entry, true) is supported.
        bool canDisable = false;            // Whether SetStartupEntryEnabled(entry, false) is supported.
        bool isProtected = true;            // Protected entries reject enable/disable/delete operations.
        StartupRiskLevel riskLevel = StartupRiskLevel::Elevated; // Structured warning severity.
        // Stable i18n codes: registry_user, registry_machine, startup_folder,
        // scheduled_task, backup_record, service, driver, critical_registry,
        // policy, winsock, wmi, unsupported_source.
        std::string riskReasonCode;
        std::string riskReasonText;         // Stable backend reason for protection or elevated risk.
        bool canOpenFileLocation = false;  // Whether imagePathText can be opened in Explorer.
        bool canOpenRegistryLocation = false; // Whether locationText points to a registry location.
        bool canDelete = false;            // Whether the caller can delete this source entry.
        bool deleteRegistryTree = false;   // True when deletion should remove the whole subkey.
        bool imagePathExists = false;      // Existence placeholder for UI filtering/future checks.
        bool signatureTrusted = false;     // Signature trust placeholder; publisherText is display text.
        std::uint32_t lastErrorCode = 0;   // Optional Win32 error for synthetic/error records.
    };

    // StartupActionStatus is a caller-facing classification for reversible startup actions.
    enum class StartupActionStatus : int
    {
        Success = 0,
        NoChange,
        InvalidEntry,
        NotSupported,
        ProtectedEntry,
        Conflict,
        NotFound,
        AccessDenied,
        WriteFailed,
        VerificationFailed,
        RollbackFailed,
        ProcessFailed
    };

    // ActionResult reports the primary outcome and whether a failed mutation was rolled back.
    struct ActionResult
    {
        StartupActionStatus status = StartupActionStatus::InvalidEntry;
        bool success = false;
        bool changed = false;
        bool rollbackAttempted = false;
        bool rollbackSucceeded = false;
        std::uint32_t errorCode = 0;
        std::string messageText;
    };

    // CategoryToText returns a stable Chinese display label for a category.
    std::string CategoryToText(StartupCategory category);

    // NormalizeFilePathText extracts an executable/library/driver path from a command line.
    std::string NormalizeFilePathText(const std::string& commandText);

    // QueryPublisherTextByPath returns a publisher/signature display string, or empty on failure.
    std::string QueryPublisherTextByPath(const std::string& filePathText);

    // NormalizeRegistryLocationLine fixes one raw Autoruns-style registry catalog line.
    std::string NormalizeRegistryLocationLine(const std::string& rawLineText);

    // BuildKnownStartupRegistryLocationList normalizes and de-duplicates raw catalog lines.
    std::vector<std::string> BuildKnownStartupRegistryLocationList(
        const std::vector<std::string>& rawLineList);

    // EnumerateLogonEntries returns Run/RunOnce/RunOnceEx and Startup Folder records.
    std::vector<StartupEntry> EnumerateLogonEntries();

    // EnumerateServiceEntries returns auto-start Win32 service records.
    std::vector<StartupEntry> EnumerateServiceEntries();

    // EnumerateDriverEntries returns boot/system/auto-start driver service records.
    std::vector<StartupEntry> EnumerateDriverEntries();

    // EnumerateTaskEntries returns Scheduled Task records collected through PowerShell.
    std::vector<StartupEntry> EnumerateTaskEntries();

    // EnumerateAdvancedRegistryEntries returns Explorer/Winlogon/LSA/COM style registry persistence.
    std::vector<StartupEntry> EnumerateAdvancedRegistryEntries();

    // EnumerateWinsockEntries returns Winsock provider/catalog registry records.
    std::vector<StartupEntry> EnumerateWinsockEntries();

    // EnumerateWmiEntries returns WMI permanent event persistence records.
    std::vector<StartupEntry> EnumerateWmiEntries();

    // EnumerateAllStartupEntries runs every backend enumerator in the standard StartupDock order.
    std::vector<StartupEntry> EnumerateAllStartupEntries();

    // SetStartupEntryEnabled performs a reversible operation using actionKind/actionLocator only.
    ActionResult SetStartupEntryEnabled(const StartupEntry& entry, bool enabled);
}
