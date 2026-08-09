#pragma once

#include "NetToolsModel.h"

namespace Ksword::Features::NetTools {

// EnumerateConnections reads the four extended TCP/UDP tables and attaches the
// owning process name to every row. There is no input; processing runs entirely
// on the calling thread and blocks for as long as IP Helper needs, so it is only
// ever called from a worker; output is one snapshot plus a diagnostic string.
//
// A table that fails is reported in the diagnostic instead of aborting the pass:
// IPv6 tables are unavailable on some hardened images, and losing every IPv4 row
// because of that would hide exactly what the page exists to show.
ConnectionEnumerationResult EnumerateConnections();

// EnumerateFirewallRules reads the Windows Defender Firewall rule store through
// INetFwPolicy2. There is no input; processing initializes COM for the calling
// thread, walks the rule collection once, and releases everything before
// returning; output is the rule list plus the per-profile on/off summary.
//
// This is a read-only pass by design. The page never adds, edits or deletes a
// rule: a mistaken write here silently changes the machine's exposure, and the
// firewall's own UI already exists for that.
FirewallEnumerationResult EnumerateFirewallRules();

} // namespace Ksword::Features::NetTools
