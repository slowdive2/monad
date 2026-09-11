# lifecycle and teardown checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$lifecyclePath = Join-Path $repositoryRoot 'hypervisor\src\lifecycle.rs'
$vmmPath = Join-Path $repositoryRoot 'hypervisor\src\vmm.rs'
$vmxPath = Join-Path $repositoryRoot 'hypervisor\src\arch\intel\vmx.rs'
$statePath = Join-Path $repositoryRoot 'hypervisor\src\arch\intel\state.rs'
$msrPath = Join-Path $repositoryRoot 'hypervisor\src\exit\msr.rs'
foreach ($path in @($lifecyclePath, $vmmPath, $vmxPath, $statePath, $msrPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "lifecycle source is missing: $path"
    }
}

$lifecycleText = Get-Content -LiteralPath $lifecyclePath -Raw
$vmmText = Get-Content -LiteralPath $vmmPath -Raw
$vmxText = Get-Content -LiteralPath $vmxPath -Raw
$stateText = Get-Content -LiteralPath $statePath -Raw
$msrText = Get-Content -LiteralPath $msrPath -Raw
$allText = "$lifecycleText`n$vmmText`n$vmxText`n$stateText`n$msrText"
$requiredTests = @(
    'lifecycle_transition_table',
    'shutdown_requires_registered_cpl0_trampoline',
    'partial_shutdown_is_fatal',
    'mtrr_write_is_fatal',
    'native_return_reads_current_descriptor_and_base_state',
    'native_control_admission_rejects_lossy_or_unimplemented_state',
    'instance_sequence_does_not_repeat_or_wrap'
)
foreach ($testName in $requiredTests) {
    if ($allText -notmatch "(?m)\b$([regex]::Escape($testName))\b") {
        throw "required lifecycle test is missing: $testName"
    }
}

foreach ($state in @('Absent', 'Preparing', 'Launching', 'Running', 'Quiescing', 'Stopping', 'Fatal')) {
    if ($lifecycleText -notmatch "(?m)\b$state\b") {
        throw "lifecycle state is missing: $state"
    }
}
if ($vmmText -notmatch '(?s)KeIpiGenericCall\(\s*Some\(launch_cpu\)' -or
    $vmmText -notmatch '(?s)activate_base\(ctx\).*?Quiescing, LifecycleState::Stopping') {
    throw 'launch or shutdown transaction ordering is missing'
}
if ($vmxText -notmatch '\bxsaves64\b' -or $vmxText -notmatch '\bxrstors64\b') {
    throw 'complete extended-state save and restore is missing'
}
$exitAssembly = [regex]::Match(
    $vmxText,
    '(?s)vmexit_entry:.*?call\s+vmexit_handler'
).Value
if ($exitAssembly -notmatch '\bxsaves64\b' -or $exitAssembly -match '\bmovaps\b') {
    throw 'VM-exit entry still uses an XMM-only save'
}
foreach ($register in @('dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7')) {
    if ($stateText -notmatch "(?m)\b$register\b") {
        throw "debug-state coverage is missing: $register"
    }
}
if ($msrText -notmatch 'MtrrChangedWhileRunning' -or
    $msrText -notmatch 'variable_count as u32' -or
    $vmmText -notmatch 'write_bytes\(msr_bitmap, 0, PAGE_SIZE\)' -or
    $vmmText -notmatch 'is_mtrr_write\(msr,') {
    throw 'MTRR-write interception is missing'
}
$fatalText = [regex]::Match(
    $vmmText,
    '(?ms)^unsafe fn fatal_vmexit\b.*?^}'
).Value
if (-not $fatalText) { throw 'fatal function extraction was empty' }
if ($fatalText -match '\bvmxoff\s*\(') {
    throw 'fatal path attempts local VMXOFF'
}


# These are source-shape guards. Production panic checks run through rustc/clippy
# with cfg(not(test)); do not truncate source at the first cfg(test) import.
foreach ($crate in @('hypervisor', 'driver')) {
    $crateText = Get-Content -LiteralPath (Join-Path $repositoryRoot "$crate/src/lib.rs") -Raw
    foreach ($lint in @('clippy::unwrap_used', 'clippy::expect_used', 'clippy::panic')) {
        if ($crateText -notmatch [regex]::Escape($lint)) { throw "missing production lint: $crate $lint" }
    }
}
$initText = [regex]::Match($vmmText, '(?ms)^unsafe fn init_cpu\b.*?^}').Value
if (-not $initText) { throw 'init_cpu extraction was empty' }
if ($initText -match 'log::|DbgPrint') { throw 'IPI launch callback contains formatted logging' }
if ($exitAssembly -notmatch '(?s)sub\s+r15,\s*\{vcpu_regs\}.*?\{vcpu_xsave_area\}.*?xsaves64') {
    throw 'VM-exit save does not restore the VCPU base before whole-object offsets'
}
$nativeText = [regex]::Match($vmxText, '(?s)restore_guest:.*?ret\s*').Value
if (-not $nativeText -or $nativeText -match 'movaps|call\s' -or
    $nativeText -notmatch '(?s)xrstors64.*?xsetbv.*?mov\s+cr0') {
    throw 'native restoration source ordering is missing'
}
Write-Output 'lifecycle source-shape guards: pass (hardware restoration remains unqualified)'
