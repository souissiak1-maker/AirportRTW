# Native RTW89 manual-visit transmit drain

Before restoring a manual AWDL visit from its active channel, the native
bridge now requires a checked PCI data/management DMA drain followed by the
chip generation's MAC queue-empty query, then a second checked DMA drain.
Firmware command channel 12 and chip-masked DMA channels are excluded.

The caller must already own the primary producer gate and serialize secondary
submissions on its native workloop and Wiphy lock. This is the existing manual
reservation contract. It is not a general-purpose flush with active producers.

PCI polling uses the driver's initialized ring index addresses. Missing MMIO
(`0xffffffff`), stopped hardware, and exhausted polls return errors. The MAC
query comes from `chip->mac_def`, covering AX and BE instead of using the
AX-specific void flush. A failed drain returns before channel restore, leaving
the manual ROC and primary producer gate owned for retry or device recovery.
An already-restored visit does not inspect queues; a restore retry after a PS
wake failure does not need to repeat the pre-retune drain.

The bounded loops limit polling attempts, not total MMIO time. Queue empty is
not an RF acknowledgment or proof of successful peer reception. Other firmware
or compatibility producers still require an integration audit. No AWDL data
transmission capability or AirDrop support is advertised by this change.

`tests/rtw_awdl_tx_drain_test.py` executes the production PCI and MAC drain
functions under ASan/UBSan with delayed queues, excluded channels, permanent
backlog, missing MMIO, power loss and missing callbacks. The production ROC
restore test verifies that a drain timeout causes no retune and retains the
reservation until a successful retry.
