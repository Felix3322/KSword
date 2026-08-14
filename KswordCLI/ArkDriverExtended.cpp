#include "ArkDriverExtended.h"

#pragma comment(lib, "Setupapi.lib")

// This translation unit is populated with CLI bindings for the ArkDriverClient
// APIs that are currently exposed only by the desktop application.
int commandArkDriverExtended(const int, wchar_t* const[])
{
    return 1;
}
