#pragma once

#include "../../Core/Win32Lean.h"

#include <string>
#include <vector>

namespace Ksword::Features::Privilege {

// PrivilegeProperty is one detail-pane name/value pair.
struct PrivilegeProperty {
    std::wstring name;
    std::wstring value;
};

// PrivilegeEntry is one row of the process token's privilege array. The LUID is
// carried along so an enable/disable can address the privilege without a second
// name lookup, which would otherwise re-resolve it on the local machine.
struct PrivilegeEntry {
    std::wstring name;          // Constant form, e.g. SeDebugPrivilege.
    std::wstring displayName;   // Localized name from LookupPrivilegeDisplayNameW.
    LUID luid{};
    bool enabled = false;
    bool enabledByDefault = false;
    bool removed = false;       // SE_PRIVILEGE_REMOVED: gone for this token's life.
    std::wstring description;   // What holding this privilege actually allows.
    std::wstring riskText;      // Non-empty for privileges that bypass access checks.
};

// TokenSummary describes the process token itself, which is the context every
// privilege row has to be read in: the same privilege list means something very
// different in an elevated token than in a filtered one.
struct TokenSummary {
    std::wstring userName;
    std::wstring userSid;
    std::wstring integrityLevel;
    std::wstring tokenType;
    bool elevated = false;
    bool uiAccess = false;
    std::vector<std::wstring> groups;
};

// PrivilegeSnapshot is one full read of the current process token.
struct PrivilegeSnapshot {
    bool success = false;
    std::wstring diagnosticText;
    TokenSummary token;
    std::vector<PrivilegeEntry> privileges;
};

// PrivilegeModel stores the latest snapshot and prepares display text.
class PrivilegeModel final {
public:
    PrivilegeModel() = default;

    void setSnapshot(PrivilegeSnapshot snapshot);

    const std::vector<PrivilegeEntry>& privileges() const noexcept;
    const TokenSummary& token() const noexcept;

    const PrivilegeEntry* entryAt(int index) const;

    // textForColumn returns list text. Columns are name, display name, state and
    // risk.
    std::wstring textForColumn(const PrivilegeEntry& entry, int column) const;

    std::vector<PrivilegeProperty> propertiesForEntry(const PrivilegeEntry& entry) const;

    // tokenProperties expands the token summary for the detail pane when no
    // privilege row is selected.
    std::vector<PrivilegeProperty> tokenProperties() const;

private:
    PrivilegeSnapshot snapshot_;
};

// PrivilegeStateText formats the enabled/default/removed combination into one
// readable state instead of three separate columns of booleans.
std::wstring PrivilegeStateText(const PrivilegeEntry& entry);

// DescribePrivilege returns the plain-language meaning of a well-known privilege
// constant. Input is the constant name; output is empty for privileges this
// table has no text for, which is preferable to inventing one.
std::wstring DescribePrivilege(const std::wstring& privilegeName);

// PrivilegeRiskText marks the privileges that let a holder step around normal
// access checks -- the ones worth noticing on an audit. Output is empty for the
// ordinary ones.
std::wstring PrivilegeRiskText(const std::wstring& privilegeName);

} // namespace Ksword::Features::Privilege
