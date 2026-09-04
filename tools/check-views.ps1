# view build and publish checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$eptRoot = Join-Path $repositoryRoot 'hypervisor\src\ept'
$requiredModules = @('backing.rs', 'view.rs', 'manager.rs')
$moduleFiles = @()
foreach ($name in $requiredModules) {
    $path = Join-Path $eptRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "EPT view module is missing: $path"
    }
    $moduleFiles += Get-Item -LiteralPath $path
}

$moduleText = ($moduleFiles | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw
}) -join "`n"
$requiredTests = @(
    'deep_clone_has_no_table_aliases',
    'clone_mapping_equivalence',
    'split_1g_to_2m_equivalence',
    'split_2m_to_4k_equivalence',
    'edit_range_crosses_leaf_boundaries',
    'batch_failure_is_atomic',
    'stale_wrong_session_and_capacity',
    'backing_lifetime',
    'published_mutation_impossible'
)
foreach ($testName in $requiredTests) {
    if ($moduleText -notmatch "(?m)\b$([regex]::Escape($testName))\b") {
        throw "required EPT view test is missing: $testName"
    }
}

$hardwareMatches = @(
    $moduleFiles | Select-String -Pattern '(?i)\b(?:vmwrite|vmread|vmlaunch|vmresume|vmxon|vmxoff|invept)\b'
)
if ($hardwareMatches.Count -ne 0) {
    $locations = $hardwareMatches | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "offline view code touches live VMX state:`n$($locations -join "`n")"
}

if ($moduleText -match '&mut\s+PublishedView' -or
    $moduleText -match '(?m)^\s*pub\s+fn\s+\w+\s*\(&mut\s+self[^\r\n]*PublishedView') {
    throw 'published view exposes mutation'
}
if ($moduleText -notmatch 'MAX_PUBLISHED_VIEWS:\s*usize\s*=\s*8' -or
    $moduleText -notmatch 'MAX_DRAFT_VIEWS:\s*usize\s*=\s*2' -or
    $moduleText -notmatch 'MAX_BATCH_EDITS:\s*usize\s*=\s*64' -or
    $moduleText -notmatch 'MAX_BACKING_PAGES:\s*usize\s*=\s*4096') {
    throw 'view capacities do not match the specification'
}
if ($moduleText -notmatch 'try_clone_as\(EptPageOwner::Draft\)' -or
    $moduleText -notmatch 'child tables are complete|write_entry\(child' -or
    $moduleText -notmatch 'mark_published') {
    throw 'view ownership or child-before-parent construction surface is missing'
}

$guardCount = ([regex]::Matches($moduleText, 'EptpWriteGuard::new\(\)')).Count
if ($guardCount -ne $requiredTests.Count) {
    throw "each offline view test needs an EPTP-write guard; found $guardCount for $($requiredTests.Count) tests"
}

foreach ($file in $moduleFiles) {
    $productionText = Get-Content -LiteralPath $file.FullName -Raw
    $productionText = [regex]::Replace(
        $productionText,
        '(?s)#\[cfg\(test\)\]\s*(?:pub\(super\)\s+)?mod\s+tests\s*\{.*$',
        ''
    )
    if ($productionText -match '\b(?:unwrap|expect)\s*\(|panic!|todo!|unimplemented!') {
        throw "view production path can panic or contains unfinished code: $($file.FullName)"
    }
}

Write-Output 'EPT view module and test surface: pass'
Write-Output 'immutable view publication boundary: pass'
Write-Output 'offline view hardware boundary: pass'
Write-Output 'view ownership and capacity surface: pass'
