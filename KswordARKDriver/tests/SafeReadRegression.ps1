[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'

function Get-CFunctionBody {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name
    )

    $text = Get-Content -LiteralPath $Path -Raw
    $signatureIndex = $text.IndexOf("$Name(", [StringComparison]::Ordinal)
    if ($signatureIndex -lt 0) {
        throw "Function '$Name' was not found in '$Path'."
    }
    $bodyStart = $text.IndexOf('{', $signatureIndex)
    if ($bodyStart -lt 0) {
        throw "Function '$Name' has no body in '$Path'."
    }

    $depth = 0
    for ($index = $bodyStart; $index -lt $text.Length; ++$index) {
        switch ($text[$index]) {
            '{' { ++$depth }
            '}' {
                --$depth
                if ($depth -eq 0) {
                    return $text.Substring($bodyStart, $index - $bodyStart + 1)
                }
            }
        }
    }
    throw "Function '$Name' has an unterminated body in '$Path'."
}

function Assert-Matches {
    param(
        [Parameter(Mandatory)] [string]$Text,
        [Parameter(Mandatory)] [string]$Pattern,
        [Parameter(Mandatory)] [string]$FailureMessage
    )
    if ($Text -notmatch $Pattern) {
        throw $FailureMessage
    }
}

function Assert-DoesNotMatch {
    param(
        [Parameter(Mandatory)] [string]$Text,
        [Parameter(Mandatory)] [string]$Pattern,
        [Parameter(Mandatory)] [string]$FailureMessage
    )
    if ($Text -match $Pattern) {
        throw $FailureMessage
    }
}

$wrappers = @(
    @{
        Path = Join-Path $RepositoryRoot 'KswordARKDriver\src\features\kernel\driver_image_editor_list.c'
        Name = 'KswordARKDriverImageReadMemory'
    },
    @{
        Path = Join-Path $RepositoryRoot 'KswordARKDriver\src\platform\dyndata_fallback_resolver.c'
        Name = 'KswordARKDriverFallbackReadMemory'
    }
)

foreach ($wrapper in $wrappers) {
    $body = Get-CFunctionBody -Path $wrapper.Path -Name $wrapper.Name
    Assert-Matches `
        -Text $body `
        -Pattern '\bKswordARKRuntimeReadMemory\s*\(' `
        -FailureMessage "$($wrapper.Name) must delegate untrusted kernel reads to KswordARKRuntimeReadMemory."
    Assert-DoesNotMatch `
        -Text $body `
        -Pattern '\b(?:RtlCopyMemory|memcpy|memmove)\s*\(' `
        -FailureMessage "$($wrapper.Name) must not directly copy from an untrusted kernel address."
}

$runtimeReader = Join-Path $RepositoryRoot 'KswordARKDriver\src\platform\runtime_signature_scan.c'
$runtimeBody = Get-CFunctionBody -Path $runtimeReader -Name 'KswordARKRuntimeReadMemory'
Assert-Matches `
    -Text $runtimeBody `
    -Pattern '\bKeGetCurrentIrql\s*\(\s*\)\s*>\s*APC_LEVEL' `
    -FailureMessage 'KswordARKRuntimeReadMemory must reject calls above APC_LEVEL.'
Assert-Matches `
    -Text $runtimeBody `
    -Pattern '\bMmCopyMemory\s*\(' `
    -FailureMessage 'KswordARKRuntimeReadMemory must use MmCopyMemory for fault-contained reads.'
Assert-Matches `
    -Text $runtimeBody `
    -Pattern '\bbytesTransferred\s*==\s*Size' `
    -FailureMessage 'KswordARKRuntimeReadMemory must require the complete requested range.'
Assert-DoesNotMatch `
    -Text $runtimeBody `
    -Pattern '\b(?:RtlCopyMemory|memcpy|memmove)\s*\(' `
    -FailureMessage 'KswordARKRuntimeReadMemory must not regress to a direct copy.'

$bgpSource = Join-Path $RepositoryRoot 'KswordARKDriver\src\features\bugcheck\bugcheck_bgp.c'
$bgpViewBody = Get-CFunctionBody -Path $bgpSource -Name 'KswordARKBugcheckBgpInitializeImageView'
$bgpAddressBody = Get-CFunctionBody -Path $bgpSource -Name 'KswordARKBugcheckBgpAddressInSection'
$bgpScanBody = Get-CFunctionBody -Path $bgpSource -Name 'KswordARKBugcheckBgpScanSignatures'
$bgpDecodeBody = Get-CFunctionBody -Path $bgpSource -Name 'KswordARKBugcheckBgpDecodeRelativeCallAt'

Assert-Matches `
    -Text $bgpViewBody `
    -Pattern '\bKswordARKRuntimeReadMemory\s*\(' `
    -FailureMessage 'The BGP PE parser must read live kernel headers through the fault-contained reader.'
Assert-Matches `
    -Text $bgpAddressBody `
    -Pattern '\bIMAGE_SCN_MEM_DISCARDABLE\b' `
    -FailureMessage 'BGP target validation must reject discardable executable sections.'
Assert-Matches `
    -Text $bgpScanBody `
    -Pattern '\bIMAGE_SCN_MEM_DISCARDABLE\b' `
    -FailureMessage 'The BGP scanner must skip discardable executable sections before reading them.'
Assert-Matches `
    -Text $bgpScanBody `
    -Pattern '\bKswordARKRuntimeReadMemory\s*\(' `
    -FailureMessage 'The BGP scanner must snapshot each bounded window with the fault-contained reader.'
$discardableCheck = $bgpScanBody.IndexOf('IMAGE_SCN_MEM_DISCARDABLE', [StringComparison]::Ordinal)
$snapshotRead = $bgpScanBody.IndexOf('KswordARKRuntimeReadMemory(', [StringComparison]::Ordinal)
if ($discardableCheck -lt 0 -or $snapshotRead -lt 0 -or $discardableCheck -gt $snapshotRead) {
    throw 'The BGP scanner must reject discardable sections before its first snapshot read.'
}
Assert-Matches `
    -Text $bgpDecodeBody `
    -Pattern '\bMAXULONG_PTR\b' `
    -FailureMessage 'BGP relative-call decoding must reject pointer addition overflow.'
Assert-Matches `
    -Text $bgpDecodeBody `
    -Pattern '-\(LONGLONG\)displacement' `
    -FailureMessage 'BGP relative-call decoding must handle LONG_MIN without signed overflow.'

$bgpResolveBody = Get-CFunctionBody -Path $bgpSource -Name 'KswordARKBugcheckBgpResolveFunctions'
$bgpBeginDrawBody = Get-CFunctionBody -Path $bgpSource -Name 'KswordARKBugcheckBgpBeginDraw'
Assert-Matches `
    -Text $bgpResolveBody `
    -Pattern '\bInterlockedExchange\s*\(\s*&g_KswordArkBgp\.ResolvedSnapshotReady\s*,\s*1\s*\)' `
    -FailureMessage 'The BGP resolver must publish an explicit ready snapshot only after validation.'
Assert-Matches `
    -Text $bgpBeginDrawBody `
    -Pattern '\bResolvedSnapshotReady\b' `
    -FailureMessage 'The crash-time BGP draw path must reject an unpublished resolver snapshot.'

$bugcheckRuntime = Join-Path $RepositoryRoot 'KswordARKDriver\src\features\bugcheck\bugcheck_runtime.c'
$bugcheckCallbackBody = Get-CFunctionBody -Path $bugcheckRuntime -Name 'KswordARKBugcheckReasonCallback'
Assert-DoesNotMatch `
    -Text $bugcheckCallbackBody `
    -Pattern '\b(?:KswordARKBugcheckBgpScanSignatures|KswordARKBugcheckBgpResolveFunctions|KswordARKRuntimeReadMemory)\s*\(' `
    -FailureMessage 'The bugcheck callback must consume only prepared state and never scan or read the live kernel image.'

$bugcheckHeader = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'KswordARKDriver\include\ark\ark_bugcheck.h') -Raw
Assert-Matches `
    -Text $bugcheckHeader `
    -Pattern '(?s)#ifndef\s+KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED.*?#define\s+KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED\s+0' `
    -FailureMessage 'Driver-side bugcheck diagnostics must remain an explicit opt-in and default to disabled.'

Write-Host 'safe-read regression passed: fallback and BGP scanners use fault-contained reads; discardable sections and crash-time rescans stay blocked.'
