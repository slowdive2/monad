# mailbox and view-switch checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$rendezvousRoot = Join-Path $repositoryRoot 'hypervisor\src\rendezvous'
$requiredModules = @('mailbox.rs', 'transaction.rs')
$moduleFiles = @()
foreach ($name in $requiredModules) {
    $path = Join-Path $rendezvousRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "rendezvous module is missing: $path"
    }
    $moduleFiles += Get-Item -LiteralPath $path
}

$vmmPath = Join-Path $repositoryRoot 'hypervisor\src\vmm.rs'
$vmcallPath = Join-Path $repositoryRoot 'hypervisor\src\exit\vmcall.rs'
$moduleText = ($moduleFiles | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw
}) -join "`n"
$vmmText = Get-Content -LiteralPath $vmmPath -Raw
$vmcallText = Get-Content -LiteralPath $vmcallPath -Raw
$allText = "$moduleText`n$vmmText`n$vmcallText"
$requiredTests = @(
    'mailbox_transition_table',
    'shared_base_eptp',
    'transaction_success',
    'failure_each_switch_step_rolls_back',
    'recovery_failure_cannot_cross_the_production_resume_boundary',
    'mailbox_commit_failure_is_terminal_after_hardware_commit',
    'barrier_timeout_is_fatal',
    'nontargets_remain_at_barrier',
    'no_active_table_write',
    'interleaving_model'
)
foreach ($testName in $requiredTests) {
    if ($moduleText -notmatch "(?m)\b$([regex]::Escape($testName))\b") {
        throw "required rendezvous test is missing: $testName"
    }
}

foreach ($state in @('Idle', 'Prepared', 'Executing', 'Completed', 'Failed')) {
    if ($moduleText -notmatch "(?m)\b$state\b") {
        throw "mailbox state is missing: $state"
    }
}
if ($moduleText -notmatch 'compare_exchange\(' -or
    $moduleText -notmatch 'Ordering::Release' -or
    $moduleText -notmatch 'Ordering::Acquire') {
    throw 'mailbox release/acquire transition is missing'
}
if ($vmmText -notmatch '(?s)KeIpiGenericCall\(\s*Some\(activate_cpu\)' -or
    $moduleText -notmatch 'participant_count' -or
    $allText -notmatch 'rollback_finished') {
    throw 'all-processor activation rendezvous is missing'
}
if ($vmcallText -notmatch 'vmwrite\(vmcs::control::EPTP_FULL' -or
    $vmcallText -notmatch 'invept_single\(eptp\)') {
    throw 'EPTP switch or single-context invalidation is missing'
}
if ($moduleText -match '\b(?:write_entry|entries_mut|bytes_mut|set_owner_all)\b' -or
    $vmcallText -match '\b(?:write_entry|entries_mut|bytes_mut|set_owner_all)\b') {
    throw 'active path can mutate an EPT hierarchy'
}
if ($vmcallText -match '(?i)magic|service selector|guest.*pointer.*use') {
    throw 'VMCALL path contains a public control surface'
}
$callbackText = [regex]::Match(
    $vmmText,
    '(?ms)^unsafe extern "C" fn activate_cpu\b.*?^}'
).Value
if (-not $callbackText) { throw 'activation callback extraction was empty' }
if ($callbackText -match '\b(?:Vec|Box|try_reserve|push)\b') {
    throw 'rendezvous callback contains dynamic transaction growth'
}

Write-Output 'mailbox and transaction surface: pass'
Write-Output 'release/acquire ordering surface: pass'
Write-Output 'view switch and rollback source shape: pass'
Write-Output 'active hierarchy immutability: pass'
