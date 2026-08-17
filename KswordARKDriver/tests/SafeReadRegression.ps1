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

Write-Host 'safe-read regression passed: fallback readers use fault-contained, complete MmCopyMemory reads.'
