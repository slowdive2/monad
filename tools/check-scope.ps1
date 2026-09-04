# stale code checks.

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent $scriptDirectory
$forbiddenPattern = '(?i)(?:decoder|hook|watch_exec|trap_opcode|monitor_trap|execute_monitor|\bmtf\b|live_shadow|shadow_page|shadow_exec|orig_lstar|hypercall_|vmmclientguard|vmm_accepting_clients|vmm_clients|current_cpu_virtualized)'
$sourceFiles = @(
    foreach ($root in @('hypervisor', 'driver')) {
        Get-ChildItem -LiteralPath (Join-Path $repositoryRoot $root) -Recurse -File | Where-Object {
            $_.Extension -in @('.rs', '.h', '.hpp') -or $_.Name -eq 'Cargo.toml'
        }
    }
    Get-Item -LiteralPath (Join-Path $repositoryRoot 'Cargo.toml')
    Get-Item -LiteralPath (Join-Path $repositoryRoot 'Cargo.lock')
)

$forbiddenPaths = @(
    $sourceFiles | Where-Object {
        $_.FullName.Substring($repositoryRoot.Length).TrimStart('\') -match $forbiddenPattern
    }
)
if ($forbiddenPaths.Count -ne 0) {
    $locations = $forbiddenPaths | ForEach-Object {
        $_.FullName.Substring($repositoryRoot.Length).TrimStart('\')
    }
    throw "removed_surface_scan failed on path:`n$($locations -join "`n")"
}

$forbiddenMatches = @(
    $sourceFiles | Select-String -Pattern $forbiddenPattern
)
if ($forbiddenMatches.Count -ne 0) {
    $locations = $forbiddenMatches | ForEach-Object {
        "$($_.Path):$($_.LineNumber): $($_.Line.Trim())"
    }
    throw "removed_surface_scan failed:`n$($locations -join "`n")"
}

$tripleFaultPath = Join-Path $repositoryRoot 'hypervisor\src\exit\triplefault.rs'
$resetMatches = @(Select-String -LiteralPath $tripleFaultPath -Pattern '(?i)(?:\boutb\b|0x0*cf9)')
if ($resetMatches.Count -ne 0) {
    throw 'triple_fault_never_uses_reset_port failed: reset-port operation remains'
}

Write-Output 'removed_surface_scan: pass'
Write-Output 'triple_fault_never_uses_reset_port source check: pass'
