# driver checks.

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
$required = @(
    'abi_layout',
    'header_validation_matrix',
    'session_exclusivity_and_close_race',
    'operation_state_matrix',
    'no_pointer_or_hpa_exposure',
    'fuzz_buffered_requests',
    'device_acl',
    'typed_adapter_conversion'
)

Push-Location -LiteralPath $repositoryRoot
try {
    foreach ($path in @('driver/src/device.rs', 'driver/src/session.rs', 'driver/src/ioctl.rs')) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "driver module is missing: $path"
        }
    }

    $ioctl = Get-Content -LiteralPath 'driver/src/ioctl.rs' -Raw
    $publicAbi = ($ioctl -split '#\[cfg\(test\)\]', 2)[0]
    $device = Get-Content -LiteralPath 'driver/src/device.rs' -Raw
    $session = Get-Content -LiteralPath 'driver/src/session.rs' -Raw
    foreach ($name in $required) {
        if (($ioctl + $device + $session) -notmatch [regex]::Escape("fn $name")) {
            throw "driver test is missing: $name"
        }
    }
    if ($device -notmatch [regex]::Escape('D:P(A;;GA;;;SY)(A;;GA;;;BA)')) {
        throw 'device SDDL is not exact'
    }
    if ($device -notmatch 'WdmlibIoCreateDeviceSecure' -or $device -notmatch 'FILE_DEVICE_SECURE_OPEN') {
        throw 'secure device construction is missing'
    }
    if ($ioctl -match 'METHOD_NEITHER|METHOD_IN_DIRECT|METHOD_OUT_DIRECT') {
        throw 'public ABI contains a non-buffered transfer method'
    }
    foreach ($adapter in @(
        'execute_allocate_backing',
        'execute_write_backing',
        'execute_free_backing',
        'execute_create_draft',
        'execute_apply_edit_batch',
        'execute_discard_draft',
        'execute_publish_view',
        'execute_query_mapping',
        'execute_list_views',
        'execute_activate_view',
        'execute_read_events',
        'execute_get_vcpu_state'
    )) {
        if ($device -notmatch [regex]::Escape("fn $adapter")) {
            throw "typed request adapter is missing: $adapter"
        }
    }
    if ($device -notmatch 'output\.fill\(0\)' -or $ioctl -notmatch 'abi_layout!\(') {
        throw 'output scrubbing or exact layout checks are missing'
    }
    if ($publicAbi -match '(?i)host_physical|\bhpa\b|user_va|kernel_pointer|\*mut\s+c_void') {
        throw 'public ABI exposes an address or pointer field'
    }

    Invoke-NativeChecked cargo @('test', '--locked', '-p', 'driver', '--lib')
}
finally {
    Pop-Location
}
