# research tool checks.

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
    foreach ($path in @(
        'research/src/lib.rs',
        'monadctl/src/main.rs',
        'schemas/experiment-pack-v1.schema.json',
        'examples/permission-ab.example.json'
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "research-platform artifact is missing: $path"
        }
    }

    $abi = Get-Content -LiteralPath 'driver/src/ioctl.rs' -Raw
    if ($abi -notmatch 'pub const ABI_VERSION: u16 = 2;' -or
        $abi -notmatch 'DevicePhysicalRangeWire') {
        throw 'research-platform launch inventory is not present in abi v2'
    }

    $telemetry = Get-Content -LiteralPath 'hypervisor/src/telemetry/record.rs' -Raw
    foreach ($field in @('schema_version', 'record_size', 'activation_epoch', 'run_id')) {
        if ($telemetry -notmatch [regex]::Escape("pub $($field):")) {
            throw "research-platform telemetry provenance field is missing: $field"
        }
    }

    $memory = Get-Content -LiteralPath 'hypervisor/src/memory.rs' -Raw
    $vmm = Get-Content -LiteralPath 'hypervisor/src/vmm.rs' -Raw
    if ($memory -notmatch 'MmGetPhysicalMemoryRangesEx2' -or
        $vmm -match '(?s)PhysicalInventory::ingest\(\s*&\[PhysicalRange') {
        throw 'research-platform physical inventory is not collected from explicit sources'
    }

    $source = @(
        Get-Content -LiteralPath 'hypervisor/src/arch/intel/control.rs' -Raw
        Get-Content -LiteralPath 'hypervisor/src/arch/intel/caps.rs' -Raw
        Get-Content -LiteralPath 'hypervisor/src/exit/eventinjection.rs' -Raw
        Get-Content -LiteralPath 'driver/src/device.rs' -Raw
        Get-Content -LiteralPath 'research/src/lib.rs' -Raw
    ) -join [Environment]::NewLine
    foreach ($test in @(
        'native_instruction_controls_are_requested_explicitly',
        'guest_cpuid_features_have_matching_execution_controls',
        'vectoring_event_is_reinjected_losslessly',
        'device_inventory_adapter_rejects_malformed_ranges',
        'valid_pack_compiles_to_stable_identity',
        'malformed_pack_reports_multiple_paths',
        'source_digest_must_match_before_bundle_creation'
    )) {
        if ($source -notmatch [regex]::Escape("fn $test")) {
            throw "research-platform test is missing: $test"
        }
    }

    Invoke-NativeChecked cargo @('test', '--locked', '-p', 'monad-research', '--lib')
    Invoke-NativeChecked cargo @(
        'run',
        '--locked',
        '-p',
        'monadctl',
        '--',
        'validate',
        'examples/permission-ab.example.json'
    )
    Write-Output 'research-platform source gate: pass'
}
finally {
    Pop-Location
}
