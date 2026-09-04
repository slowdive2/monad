# intel vmx checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$sourceRoot = Join-Path $repositoryRoot 'hypervisor\src'
$intelRoot = Join-Path $sourceRoot 'arch\intel'

$requiredArchitectureFiles = @(
    'caps.rs',
    'control.rs',
    'invept.rs',
    'state.rs',
    'vmcs.rs',
    'vmx.rs'
)
foreach ($name in $requiredArchitectureFiles) {
    $path = Join-Path $intelRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "VMX architecture module is missing: $path"
    }
}

$requiredTests = @(
    'control_adjustment_table',
    'capability_each_required_bit_missing',
    'capability_competing_hypervisor',
    'address_range_boundaries',
    'generation_and_reserved_validation',
    'cpu_set_validation',
    'vmx_status_decode',
    'descriptor_bounds_and_unusable_segments',
    'guest_state_normalization',
    'xsave_layout',
    'pre_vmxon_failpoint_stops_launch'
)
$allSource = Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Filter '*.rs'
$sourceText = ($allSource | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
foreach ($testName in $requiredTests) {
    if ($sourceText -notmatch "(?m)\b$([regex]::Escape($testName))\b") {
        throw "required VMX test is missing: $testName"
    }
}

$outsideArchitecture = @(
    $allSource | Where-Object {
        -not $_.FullName.StartsWith($intelRoot, [System.StringComparison]::OrdinalIgnoreCase)
    }
)
$rawIntrinsicMatches = @(
    $outsideArchitecture | Select-String -Pattern 'x86::bits64::vmx::'
)
if ($rawIntrinsicMatches.Count -ne 0) {
    $locations = $rawIntrinsicMatches | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "raw VMX intrinsic exists outside arch::intel:`n$($locations -join "`n")"
}

$rawArchitecturePattern = '(?:core::arch|x86::(?:bits64|controlregs|debugregs|dtables|segmentation)::|x86::msr::(?:rdmsr|wrmsr))'
$rawArchitectureMatches = @(
    $outsideArchitecture | Select-String -Pattern $rawArchitecturePattern
)
if ($rawArchitectureMatches.Count -ne 0) {
    $locations = $rawArchitectureMatches | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "raw architecture primitive exists outside arch::intel:`n$($locations -join "`n")"
}

foreach ($file in $outsideArchitecture) {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    if ($text -match '(?s)(?:asm|global_asm)!\s*\(') {
        throw "inline architecture assembly exists outside arch::intel: $($file.FullName)"
    }
}

$lintAllowances = @(
    $allSource | Select-String -Pattern '#!?\s*\[\s*allow\s*\('
)
if ($lintAllowances.Count -ne 0) {
    $locations = $lintAllowances | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "lint allowance exists in Monad source:`n$($locations -join "`n")"
}

$ignoredResultPattern = '(?im)\blet\s+_\s*=\s*(?:unsafe\s*\{\s*)?(?:vmxon|vmxoff|vmclear|vmptrld|vmread|vmwrite|vmlaunch|vmresume|invept_single|invept_all)\s*\('
$ignoredResults = @(
    $allSource | Select-String -Pattern $ignoredResultPattern
)
if ($ignoredResults.Count -ne 0) {
    $locations = $ignoredResults | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "ignored VMX-wrapper result found:`n$($locations -join "`n")"
}

$vmxSource = Get-Content -LiteralPath (Join-Path $intelRoot 'vmx.rs') -Raw
$failpointIndex = $vmxSource.IndexOf('pre_vmxon_failpoint()?')
$instructionIndex = $vmxSource.IndexOf('x86::bits64::vmx::vmxon(region)')
if ($failpointIndex -lt 0 -or $instructionIndex -lt 0 -or $failpointIndex -gt $instructionIndex) {
    throw 'pre-VMXON failpoint is missing or occurs after the VMXON intrinsic'
}

Write-Output 'VMX architecture layout: pass'
Write-Output 'raw VMX boundary: pass'
Write-Output 'VMX result consumption: pass'
Write-Output 'pre-VMXON failpoint ordering: pass'
