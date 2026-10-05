# Sentinal AI Minifilter Driver

## Phase 1.32 — Kernel Observation to Real User-Mode Transport Integration

This directory contains the Windows kernel-mode minifilter driver for Sentinal AI.

### Status

Phase 1.32 connects the kernel observation pipeline for **IRP_MJ_WRITE only** to the Filter Manager communication transport (`FltSendMessage`):

- `DriverEntry` — registers filter, starts filtering, creates communication port (`\SentinalPort`)
- `FLT_REGISTRATION` — pass-through operation table for `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION`
- `SentinalDriverUnload` — closes communication port and unregisters filter on unload
- `SentinalPreWrite` — acquires normalized Unicode path for `IRP_MJ_WRITE`, converts to Unicode protection request, and sends via `SentinalSendWriteObservation` (`FltSendMessage`)
- `SentinalSendWriteObservation` — bounded-timeout (1000 ms) message transport to user-mode client port; transport result is diagnostic only
- **Pass-through guarantee**: `SentinalPreWrite` **always** returns `FLT_PREOP_SUCCESS_NO_CALLBACK`. The filesystem write is never blocked, delayed, pended, or modified.
- **Enforcement status**: Filesystem enforcement is **NOT** implemented in Phase 1.32.
- **Development response**: The user-mode transport returns a deterministic development-only test response (`ALLOW`). No policy engine, evaluation engine, or enforcement service is invoked.
- **Runtime validation**: Runtime driver installation/loading has **NOT** been performed in this development environment (no test signing / kernel loader). All verification is performed via static validation, contract unit tests, INF validation, and MSBuild WDK builds.
- **Production hardening**: Production communication security, client authentication, and access control hardening remain pending future phases.

### Files

| File | Purpose |
|------|---------|
| `SentinalDriver.vcxproj` | WDK MSBuild project |
| `SentinalDriver.inf` | Driver installation descriptor |
| `include/sentinal_driver.h` | Internal kernel-mode declarations |
| `include/sentinal_communication_port.h` | Filter Manager communication port lifecycle & `SentinalSendWriteObservation` |
| `include/sentinal_message_transport.h` | Kernel/user message transport helper (`FltSendMessage`) & requestId generation |
| `include/sentinal_observation_event.h` | Kernel observation event model (`SENTINAL_OBSERVATION_EVENT`) |
| `include/sentinal_path_acquisition.h` | Normalized path acquisition (`FltGetFileNameInformation`) |
| `include/sentinal_driver_unicode_contract_adapter.h` | Event to Unicode request contract conversion adapter |
| `src/driver_entry.c` | DriverEntry, FLT_REGISTRATION, pre-op callbacks |
| `src/communication_port.c` | Port lifecycle, client connection tracking, `SentinalSendWriteObservation` |
| `src/message_transport.c` | `SentinalSendProtectionRequest`, `SentinalPortMessageNotify`, `SentinalGenerateRequestId` |
| `src/observation_event.c` | Observation event construction and validation |
| `src/path_acquisition.c` | Safe kernel path acquisition at IRQL <= APC_LEVEL |
| `src/driver_unicode_contract_adapter.c` | Adapts kernel observation event to Unicode driver request |

### Build Requirements

- Windows Driver Kit (WDK) 10.0.26100.0 or later
- Visual Studio 2022 with "Desktop development with C++" workload
- WDK Visual Studio extension

### Build Commands

```powershell
# Debug (kernel test environment)
msbuild driver\SentinalDriver.vcxproj /p:Configuration=Debug /p:Platform=x64

# Release
msbuild driver\SentinalDriver.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Test Signing

The driver is not production-signed. To load it on a test machine:

```powershell
# Enable test signing (requires admin; reboot after)
bcdedit /set testsigning on
```

Or use a kernel debugger with a VM.

### Altitude

The INF uses placeholder altitude `321000` (FSFilter Anti-Virus range).
A unique altitude must be obtained from Microsoft before production deployment:
https://docs.microsoft.com/windows-hardware/drivers/ifs/allocated-altitudes

### CMake Integration

The driver is **not** built by CMake. The user-mode CMake build (`cmake --build build`)
builds only the service and tests. The driver uses WDK/MSBuild toolchain exclusively.
