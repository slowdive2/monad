# Check the linked optimized artifact, not a separate assembly sample.
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$artifact = Join-Path $repositoryRoot 'target/release/driver.dll'
$llvmDirectory = $env:LIBCLANG_PATH
if (-not $llvmDirectory) { $llvmDirectory = 'C:\Program Files\LLVM\bin' }
$listing = & (Join-Path $llvmDirectory 'llvm-objdump.exe') -d --no-show-raw-insn --x86-asm-syntax=intel $artifact
if ($LASTEXITCODE -ne 0) { throw 'linked-driver disassembly failed' }
$instructions = ($listing | ForEach-Object {
    if ($_ -match '^\s*[0-9a-f]+:\s+(.+)$') { ($Matches[1] -replace '\s+', ' ').Trim() }
}) -join "`n"

function Assert-StateBoundary([string] $text) {
    $entry = [regex]::Match($text, '(?s)push r15\nmov r15, qword ptr \[rsp \+ 0x8\]\nadd r15, (?<base>0x[0-9a-f]+)\n.*?\nint3').Value
    if (-not $entry) { throw 'linked VM-exit entry was not found' }
    $base = [regex]::Match($entry, 'add r15, (0x[0-9a-f]+)').Groups[1].Value
    if ($entry -notmatch ('(?s)sub r15, ' + [regex]::Escape($base) + '\nxor ecx, ecx\nxgetbv.*?xsetbv\nmov r14, qword ptr \[r15 \+ (?<area>0x[0-9a-f]+)\]\nmov rax, qword ptr \[r15 \+ (?<mask>0x[0-9a-f]+)\].*?xsaves64 \[r14\]\nmov rcx, r15\nsub rsp, 0x20\ncall ')) {
        throw 'linked VM-exit save uses the wrong base or save ordering'
    }
    $area = $Matches['area']; $mask = $Matches['mask']
    $launch = [regex]::Match($text, '(?s)mov r13, r15\nsub r13, 0x[0-9a-f]+\n.*?xrstors64 \[r12\].*?xsetbv').Value
    if (-not $launch -or $launch -notmatch ('sub r13, ' + [regex]::Escape($base) + '\n') -or
        $launch -notmatch ('mov r12, qword ptr \[r13 \+ ' + [regex]::Escape($area) + '\]') -or
        $launch -notmatch ('mov rax, qword ptr \[r13 \+ ' + [regex]::Escape($mask) + '\]')) {
        throw 'launch and exit disagree about the compiled VCPU layout'
    }
    $native = [regex]::Match($text, '(?s)mov r15, rcx\nmov r13, r9\nmov r12, qword ptr \[rsp \+ 0x28\].*?\nret').Value
    if (-not $native -or $native -match '\b(?:call|xmm\d+|ymm\d+|zmm\d+)\b' -or
        $native -notmatch '(?s)xrstors64 \[r14\].*?xsetbv\nmov cr0, r12\n.*?popfq.*?\nret') {
        throw 'linked native return reloads stale state or has invalid restore ordering'
    }
}

Assert-StateBoundary $instructions
# Counterexamples must make this checker fail; an empty extraction cannot pass.
foreach ($bad in @(
    ($instructions -replace 'sub r15, 0x[0-9a-f]+\n', ''),
    ($instructions -replace 'xrstors64 \[r14\]', "xrstors64 [r14]`nmovaps xmm0, xmmword ptr [r15]")
)) {
    $rejected = $false
    try { Assert-StateBoundary $bad } catch { $rejected = $true }
    if (-not $rejected) { throw 'artifact checker accepted an original-defect counterexample' }
}
$imports = & (Join-Path $llvmDirectory 'llvm-readobj.exe') --coff-imports $artifact
if ($LASTEXITCODE -ne 0 -or ($imports -join "`n") -notmatch 'Symbol: PsInitialSystemProcess ') {
    throw 'system-process data import is absent from the linked image'
}
Write-Output 'linked state-boundary ordering, layout agreement, data import, and checker counterexamples: pass'
