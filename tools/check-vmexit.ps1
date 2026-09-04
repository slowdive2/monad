# vm-exit fault and telemetry checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$required = @(
    'event_record_layout_and_zero_reserved',
    'ring_wrap_drop_and_snapshot',
    'exit_context_validity',
    'fault_access_decode',
    'fault_disposition_table',
    'identical_fault_limit',
    'injection_uses_explicit_fresh_state',
    'ept_fault_never_advances_or_writes_tables',
    'root_path_contract'
)

Push-Location -LiteralPath $repositoryRoot
try {
    foreach ($path in @(
        'hypervisor/src/telemetry/record.rs',
        'hypervisor/src/telemetry/ring.rs',
        'hypervisor/src/exit/context.rs',
        'hypervisor/src/exit/ept_fault.rs'
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "VM-exit module is missing: $path"
        }
    }

    $surface = ''
    foreach ($path in @(
        'hypervisor/src/telemetry/record.rs',
        'hypervisor/src/telemetry/ring.rs',
        'hypervisor/src/exit/context.rs',
        'hypervisor/src/exit/ept.rs',
        'hypervisor/src/exit/ept_fault.rs',
        'hypervisor/src/exit/eventinjection.rs'
    )) {
        $surface += Get-Content -LiteralPath $path -Raw
    }
    foreach ($name in $required) {
        if ($surface -notmatch [regex]::Escape("fn $name")) {
            throw "VM-exit test is missing: $name"
        }
    }

    $rootFiles = @(
        'hypervisor/src/exit/ept.rs',
        'hypervisor/src/exit/ept_fault.rs',
        'hypervisor/src/exit/vmexit.rs'
    )
    foreach ($path in $rootFiles) {
        $source = (Get-Content -LiteralPath $path -Raw) -split '#\[cfg\(test\)\]', 2
        if ($source[0] -match 'log::|format!|String::|Vec::|Box::|write_entry|entries_mut|apply_batch|KeIpiGenericCall') {
            throw "root-path contract violation: $path"
        }
    }
    if ($surface -match 'set_ept_fault_policy|install_ept_fault_policy|IOCTL_.*FAULT') {
        throw 'fault policy has a runtime replacement surface'
    }
    if ((Get-Content -LiteralPath 'hypervisor/src/exit/ept.rs' -Raw) -match 'ResumeAndAdvance') {
        throw 'EPT-violation path can request RIP advancement'
    }
    Write-Host 'VM-exit fault policy and root-path surface: pass'
}
finally {
    Pop-Location
}
