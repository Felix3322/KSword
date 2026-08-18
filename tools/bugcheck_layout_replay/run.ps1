param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$outputRoot = Join-Path $repositoryRoot 'output'
$source = Join-Path $PSScriptRoot 'bugcheck_layout_replay.c'
$object = Join-Path $outputRoot 'bugcheck_layout_replay.obj'
$executable = Join-Path $outputRoot 'bugcheck_layout_replay.exe'
$incrementalLink = Join-Path $outputRoot 'bugcheck_layout_replay.ilk'
$programDatabase = Join-Path $outputRoot 'bugcheck_layout_replay.pdb'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$kitRoot = 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0'
$kmInclude = Join-Path $kitRoot 'km'
$sharedInclude = Join-Path $kitRoot 'shared'
$ucrtInclude = Join-Path $kitRoot 'ucrt'

if ($Clean) {
    Remove-Item -LiteralPath @(
        $object,
        $executable,
        $incrementalLink,
        $programDatabase
    ) -Force -ErrorAction SilentlyContinue
    exit 0
}

foreach ($required in @($vcvars, $kmInclude, $sharedInclude, $ucrtInclude, $source)) {
    if (!(Test-Path -LiteralPath $required)) {
        throw "Required build input not found: $required"
    }
}

$stubInclude = Join-Path $PSScriptRoot 'stubs'
$compile = @(
    'call', ('"{0}"' -f $vcvars), '>', 'nul', '&&',
    'cl.exe', '/nologo', '/W4', '/WX-', '/Od', '/Zi', '/TC',
    '/D_AMD64_', '/DAMD64',
    ('/I"{0}"' -f $stubInclude),
    ('/I"{0}"' -f $kmInclude),
    ('/I"{0}"' -f $sharedInclude),
    ('/I"{0}"' -f $ucrtInclude),
    ('/Fo"{0}"' -f $object),
    ('/Fe"{0}"' -f $executable),
    ('"{0}"' -f $source)
) -join ' '

cmd.exe /d /s /c $compile
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $executable
exit $LASTEXITCODE
