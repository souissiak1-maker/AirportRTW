# Release packaging

The Release configuration keeps both RTW88 and RTW89 HALs, all PCI matching,
and all embedded firmware. `AirportRTWDiagnostics.h` compiles logging calls
out without evaluating their arguments. The C archives use the same policy
as the C++ frontend. Debug builds retain logging.

Release builds omit periodic HAL diagnostic property publication, the RTW89
receive trace callback, and WCL incomplete-join history. Connection recovery,
protocol state, normal network statistics, and hardware support remain active.

`scripts/build_release_kexts.sh` strips debug and local symbols from packaged
built executables. It retains global symbols needed by the kernel
extension loader. The separate build dSYM is not included in the kext ZIP.

Most executable bytes are embedded firmware and hardware tables. Removing
diagnostics cannot eliminate those bytes while preserving chip support.
