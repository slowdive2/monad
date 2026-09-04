# monad

monad is an experimental Intel VT-x hypervisor for studying second-level
address translation on a running x86-64 Windows system.

the core rule is simple: build and verify a complete EPT view before a
processor can use it, then never edit that published hierarchy in place.

the current base includes:

- typed VMX, VMCS, CPU-state, and capability boundaries;
- MTRR-aware identity EPT construction and software verification;
- private draft views, checked backing pages, and immutable publication;
- bounded all-or-rollback view activation across processor sets;
- transactional launch, shutdown, and state restoration;
- a closed VM-exit dispatcher and source-compiled EPT-fault policy;
- fixed allocation-free per-vCPU telemetry;
- a versioned buffered Windows control interface;
- deterministic experiment-pack validation through `monad-research` and
  `monadctl`.

monad does not provide instruction hooks, executable shadow pages, monitor-trap
replay, a public VMCALL service, DMA isolation, or Hyper-V coexistence. it is
research software, and full real-hardware and long-duration qualification is
still pending.

## layout

- `hypervisor/src` contains the VMX, EPT, lifecycle, rendezvous, exit, and
  telemetry implementation.
- `driver/src` contains the Windows device, controller session, and IOCTL ABI.
- `research/src` validates and canonicalizes experiment packs.
- `monadctl/src` provides the user-mode experiment-pack tool.
- `schemas` and `experiments` contain the public pack format and a small example.
- `tools/verify.ps1` is the local source and release-build check.

## requirements

- 64-bit Windows 10 version 2004 or newer, or Windows 11;
- Rust 1.97.1 from `rust-toolchain.toml`;
- Visual Studio 2022 MSVC build tools;
- LLVM 17.0.6 at `C:\Program Files\LLVM\bin`;
- Windows SDK build family 10.0.26100.0;
- Windows Driver Kit product 10.1.26100.6584.

## verify

from PowerShell:

```powershell
./tools/verify.ps1
```

the verifier checks the source invariants, formatting, lint, host-side models,
all workspace tests, the optimized kernel driver, its native PE subsystem, and
its `DriverEntry` export.
