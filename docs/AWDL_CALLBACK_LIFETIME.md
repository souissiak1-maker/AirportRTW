# RTW89 callback lifetime and secondary-role removal

The RTW89 compatibility layer now uses owned thread-call metadata instead of
implementing synchronous cancellation as a 500-microsecond delay. Each accepted
submission owns an outstanding reference before XNU can enter the trampoline.
Cancellation either removes a pending reference or waits for completion,
including the interval after dequeue but before trampoline entry. The cancellation
gate rejects callback rearming during a synchronous drain. Calls use XNU's ONCE
option so the same callback cannot execute concurrently with itself.

Handles are private to `rtw88_compat.c`; they must never be passed directly to
XNU elsewhere. Metadata survives cancelled reusable Linux timers and is reclaimed
at compatibility shutdown. A failed raw call release retains its metadata rather
than freeing a live callback. External producers must stop before callback-owner
teardown. Synchronous self-cancellation, or waiting while holding a callback's
required lock, is prohibited.

Wiphy work uses one stable dispatcher and timer per wiphy. Embedded VIF/station
work nodes live only in its pending list. The dispatcher acquires the wiphy mutex
before taking a node. Cancellation removes a node while the caller holds that
mutex and never waits for a dispatcher blocked on it. Flush executes the removed
node inline under the caller's mutex. Shutdown stops new work, removes pending
nodes, releases the mutex, and drains both timer and dispatcher before releasing
the per-wiphy queue. Queue allocation failure fails hardware allocation.

Read sections now track actual readers, including RX/NAPI. Pointer publication
is atomic. Reclamation waits for active readers after unlinking; deferred frees
run on the compatibility workqueue after that grace period. Allocation failure
in deferred reclamation retains the target. This is a small HAL-specific grace
period implementation, not a complete Linux RCU subsystem. Writers must not
synchronize from inside a read section. Native peer/VIF reclamation explicitly
waits after removing lookup references.

This work changes RTW89 compatibility code across macOS targets. RTW88's worker
implementation remains separate. The shared VIF helper now requests its HAL's
reader grace period before releasing memory.

Evidence: `rtw_managed_call_test.c`, `rtw_wiphy_work_test.py`,
`rtw_workqueue_test.py`, `rtw_awdl_peer_pool_test.py`,
`rtw_awdl_peer_shutdown_test.py` and `rtw_awdl_linux_interface_test.cpp` exercise
production source with host adapters and address/undefined-behavior sanitizers.
These do not establish RF interoperability or validate sleep/wake on hardware.

API references: [Apple Mach KPI exports](https://github.com/apple-oss-distributions/xnu/blob/main/config/Mach.exports)
and [XNU thread-call implementation](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/thread_call.c).
The implementation uses public allocation/enter/cancel/free calls; it does not
import the private synchronous cancellation symbol or patch the kernel.
