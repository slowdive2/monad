# ept builder checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$eptRoot = Join-Path $repositoryRoot 'hypervisor\src\ept'

$requiredModules = @(
    'address.rs',
    'entry.rs',
    'mtrr.rs',
    'page.rs',
    'builder.rs',
    'walker.rs'
)
$moduleFiles = @()
foreach ($name in $requiredModules) {
    $path = Join-Path $eptRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "EPT module is missing: $path"
    }
    $moduleFiles += Get-Item -LiteralPath $path
}

$requiredTests = @(
    'entry_encoding_table',
    'mtrr_fixed_precedence',
    'mtrr_uc_dominance',
    'mtrr_wb_wt',
    'mtrr_unsupported_mix',
    'mtrr_exact_cover',
    'aperture_inventory',
    'builder_leaf_choice',
    'builder_allocation_failure_each_depth',
    'walker_rejects_corruption',
    'builder_matches_4k_oracle'
)
$moduleText = ($moduleFiles | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw
}) -join "`n"
foreach ($testName in $requiredTests) {
    if ($moduleText -notmatch "(?m)\b$([regex]::Escape($testName))\b") {
        throw "required EPT test is missing: $testName"
    }
}

$offlineFiles = @(
    'address.rs',
    'mtrr.rs',
    'page.rs',
    'builder.rs',
    'walker.rs'
) | ForEach-Object { Get-Item -LiteralPath (Join-Path $eptRoot $_) }
$hardwareMatches = @(
    $offlineFiles | Select-String -Pattern '(?i)\b(?:vmwrite|vmread|vmcs|vmlaunch|vmresume|vmxon|eptp_full)\b'
)
if ($hardwareMatches.Count -ne 0) {
    $locations = $hardwareMatches | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "offline EPT code touches live VMX state:`n$($locations -join "`n")"
}

$builderText = Get-Content -LiteralPath (Join-Path $eptRoot 'builder.rs') -Raw
if ($builderText -notmatch 'pub struct VerifiedBaseView') {
    throw 'verified base-view output is missing'
}
if ($builderText -match '(?m)^\s*pub\s+(?:const\s+)?fn\s+(?:root|eptp)\b') {
    throw 'verified output exposes installable root or EPTP state'
}
if ($moduleText -notmatch '0x4d33_0000u64\.\.0x4d33_0020') {
    throw 'deterministic EPT property-test seed range is missing'
}

$guardCount = ([regex]::Matches($moduleText, 'EptpWriteGuard::new\(\)')).Count
if ($guardCount -ne $requiredTests.Count) {
    throw "each offline EPT test needs an EPTP-write guard; found $guardCount for $($requiredTests.Count) tests"
}
$vmxPath = Join-Path $repositoryRoot 'hypervisor\src\arch\intel\vmx.rs'
$vmxText = Get-Content -LiteralPath $vmxPath -Raw
if ($vmxText -notmatch 'field\s*==\s*x86::vmx::vmcs::control::EPTP_FULL' -or
    $vmxText -notmatch 'EPTP_WRITE_COUNT\.fetch_add') {
    throw 'test-only EPTP-write spy is missing'
}

$legacyEntryNames = '(?:EptPointer|EptTableEntry|Ept4KbPageEntry|Ept2MbPageEntry|EptPageDirectoryEntry)'
$newPathFiles = @('mtrr.rs', 'page.rs', 'builder.rs', 'walker.rs') | ForEach-Object {
    Get-Item -LiteralPath (Join-Path $eptRoot $_)
}
$legacyMatches = @($newPathFiles | Select-String -Pattern $legacyEntryNames)
if ($legacyMatches.Count -ne 0) {
    $locations = $legacyMatches | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "EPT code uses a legacy raw entry type:`n$($locations -join "`n")"
}

$entryText = Get-Content -LiteralPath (Join-Path $eptRoot 'entry.rs') -Raw
foreach ($name in @('EptPml4Entry', 'EptPdptEntry', 'EptPdEntry')) {
    if ($entryText -notmatch "table_entry!\($name\)") {
        throw "checked EPT entry wrapper has a public or unexpected raw shape: $name"
    }
}
if ($entryText -notmatch 'pub struct EptPtEntry\(u64\);') {
    throw 'checked EPT entry wrapper has a public or unexpected raw shape: EptPtEntry'
}

foreach ($file in $moduleFiles) {
    $productionText = Get-Content -LiteralPath $file.FullName -Raw
    $productionText = [regex]::Replace(
        $productionText,
        '(?s)#\[cfg\(test\)\]\s*(?:pub\(super\)\s+)?mod\s+(?:tests|fake)\s*\{.*$',
        ''
    )
    if ($productionText -match '\b(?:unwrap|expect)\s*\(|panic!|todo!|unimplemented!') {
        throw "EPT production path can panic or contains unfinished code: $($file.FullName)"
    }
}

$allocationTest = [regex]::Match(
    $builderText,
    '(?s)fn\s+builder_allocation_failure_each_depth\(\).*?\n\s*}\n\s*}'
).Value
if ($allocationTest -notmatch 'stats\.allocated\.get\(\)' -or
    $allocationTest -notmatch 'stats\.freed\.get\(\)') {
    throw 'EPT allocation-failure test does not prove zero live pages'
}

Write-Output 'EPT module and test surface: pass'
Write-Output 'offline EPT hardware boundary: pass'
Write-Output 'EPTP-write spy coverage: pass'
Write-Output 'EPT allocation teardown: pass'
Write-Output 'checked EPT entry and production surface: pass'
