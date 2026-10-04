# Sentinal AI Minifilter Driver

## Phase 1.24 — Windows Minifilter Foundation

This directory contains the Windows kernel-mode minifilter driver for Sentinal AI.

### Status

Phase 1.24 establishes the minifilter skeleton:

- `DriverEntry` — registers the filter, starts filtering, handles failure cleanly
- `FLT_REGISTRATION` — valid descriptor with pass-through operation table
- `SentinalDriverUnload` — unregisters filter on unload
- Pass-through `SentinalPreOperationCallback` — reserved for future policy phases

No file blocking, no policy evaluation, no communication port, no user-mode messaging.

### Files

| File | Purpose |
|------|---------|
| `SentinalDriver.vcxproj` | WDK MSBuild project |
| `SentinalDriver.inf` | Driver installation descriptor |
| `include/sentinal_driver.h` | Internal kernel-mode declarations |
| `src/driver_entry.c` | DriverEntry, FLT_REGISTRATION, lifecycle |

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
