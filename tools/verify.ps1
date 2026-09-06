# local verification.

$ErrorActionPreference = 'Stop'

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,

        [Parameter(Mandatory = $true)]
        [string[]] $ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        $rendered = $ArgumentList -join ' '
        throw "$FilePath $rendered failed with exit code $LASTEXITCODE"
    }
}

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory

Push-Location -LiteralPath $repositoryRoot
try {
    $rustVersion = & rustc --version
    if ($LASTEXITCODE -ne 0) {
        throw "rustc --version failed with exit code $LASTEXITCODE"
    }
    if ($rustVersion -notmatch '^rustc 1\.97\.1 ') {
        throw "expected rustc 1.97.1 from rust-toolchain.toml; found: $rustVersion"
    }

    & (Join-Path $scriptDirectory 'check-toolchain.ps1')
    & (Join-Path $scriptDirectory 'check-scope.ps1')
    & (Join-Path $scriptDirectory 'check-vmx.ps1')
    & (Join-Path $scriptDirectory 'check-ept.ps1')
    & (Join-Path $scriptDirectory 'check-views.ps1')
    & (Join-Path $scriptDirectory 'check-rendezvous.ps1')
    & (Join-Path $scriptDirectory 'check-lifecycle.ps1')
    & (Join-Path $scriptDirectory 'check-driver.ps1')
    & (Join-Path $scriptDirectory 'check-vmexit.ps1')
    Invoke-NativeChecked cargo @('fmt', '--all', '--', '--check')
    Invoke-NativeChecked cargo @('clippy', '--locked', '--workspace', '--all-targets', '--all-features', '--no-deps', '--', '-D', 'warnings')
    Invoke-NativeChecked cargo @('test', '--locked', '-p', 'hypervisor', '--lib')
    Invoke-NativeChecked cargo @('test', '--locked', '-p', 'driver', '--lib')
    Invoke-NativeChecked cargo @('check', '--locked', '-p', 'hypervisor')
    Invoke-NativeChecked cargo @('check', '--locked', '-p', 'driver')
    Invoke-NativeChecked cargo @('build', '--locked', '-p', 'driver', '--release')

    # cargo calls a cdylib a .dll. inspect the actual kernel pe as well.
    $driverArtifact = Join-Path $repositoryRoot 'target\release\driver.dll'
    if (-not (Test-Path -LiteralPath $driverArtifact -PathType Leaf)) {
        throw "release driver artifact is missing: $driverArtifact"
    }
    if ((Get-Item -LiteralPath $driverArtifact).Length -eq 0) {
        throw "release driver artifact is empty: $driverArtifact"
    }

    $llvmReadObj = Join-Path $env:LIBCLANG_PATH 'llvm-readobj.exe'
    $peMetadata = & $llvmReadObj --file-headers --coff-exports $driverArtifact
    if ($LASTEXITCODE -ne 0) {
        throw "llvm-readobj failed with exit code $LASTEXITCODE"
    }
    $peText = $peMetadata -join "`n"
    if ($peText -notmatch 'Format: COFF-x86-64') {
        throw 'release driver is not a 64-bit x86 COFF image'
    }
    if ($peText -notmatch 'Subsystem: IMAGE_SUBSYSTEM_NATIVE') {
        throw 'release driver PE subsystem is not IMAGE_SUBSYSTEM_NATIVE'
    }
    if ($peText -notmatch '(?m)^\s*Name: DriverEntry\s*$') {
        throw 'release driver does not export DriverEntry'
    }

    & (Join-Path $scriptDirectory 'check-state-artifact.ps1')
    & (Join-Path $scriptDirectory 'check-research.ps1')
}
finally {
    Pop-Location
}
