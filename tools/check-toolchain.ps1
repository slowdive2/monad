# Fail clearly if the pinned wdk is missing. the installed product includes
# Qfe 10.1.26100.6584; its kit directories use
# The build-family path 10.0.26100.0.

$ErrorActionPreference = 'Stop'

$productVersion = '10.1.26100.6584'
$kitVersion = '10.0.26100.0'
$kitsRoot = 'C:\Program Files (x86)\Windows Kits\10'
$llvmVersion = '17.0.6'
$libclangDirectory = 'C:\Program Files\LLVM\bin'
$libclangPath = Join-Path $libclangDirectory 'libclang.dll'
$clangPath = Join-Path $libclangDirectory 'clang.exe'
$llvmReadObjPath = Join-Path $libclangDirectory 'llvm-readobj.exe'
$requiredPaths = @(
    (Join-Path $kitsRoot "Include\$kitVersion\km\crt"),
    (Join-Path $kitsRoot "Include\$kitVersion\km\ntddk.h"),
    (Join-Path $kitsRoot "Lib\$kitVersion\km\x64\ntoskrnl.lib"),
    $libclangPath,
    $clangPath,
    $llvmReadObjPath
)

$missingPaths = @($requiredPaths | Where-Object {
    -not (Test-Path -LiteralPath $_)
})

$wdkRegistrations = @(
    Get-ItemProperty @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -eq "Windows Driver Kit - Windows 10.0.26100.6584" -and
        $_.DisplayVersion -eq $productVersion
    }
)

if ($missingPaths.Count -ne 0 -or $wdkRegistrations.Count -eq 0) {
    $missing = if ($missingPaths.Count -eq 0) { 'none' } else { $missingPaths -join ', ' }
    $registration = if ($wdkRegistrations.Count -eq 0) { 'exact WDK product registration' } else { 'none' }
    throw "WDK $productVersion or LLVM $llvmVersion is incomplete or absent. Missing paths: $missing. Missing registration: $registration. Install the WDK with: winget install --id Microsoft.WindowsWDK.10.0.26100 --exact --version $productVersion --force --silent --accept-source-agreements --accept-package-agreements --disable-interactivity. Install LLVM with: winget install --id LLVM.LLVM --exact --version $llvmVersion --force --silent --accept-source-agreements --accept-package-agreements --disable-interactivity"
}

$clangVersionOutput = & $clangPath --version
if ($LASTEXITCODE -ne 0) {
    throw "clang --version failed with exit code $LASTEXITCODE"
}
$clangVersionLine = $clangVersionOutput | Select-Object -First 1
if ($clangVersionLine -notmatch "clang version $([regex]::Escape($llvmVersion))(?:\s|$)") {
    throw "expected LLVM clang $llvmVersion at $clangPath; found: $clangVersionLine"
}

# Bindgen 0.69 misses libclang in the winget location sometimes.
# Set it here so cargo and its build scripts inherit it.
$env:LIBCLANG_PATH = $libclangDirectory
