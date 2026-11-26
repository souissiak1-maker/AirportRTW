#!/usr/bin/env python3
"""Execute both production completion headers with deterministic host lock/clock shims."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <cassert>
#include <climits>
struct IOLock { bool held = false; };
static IOLock *IOLockAlloc() { return new IOLock; }
static void IOLockLock(IOLock *l) { assert(!l->held); l->held = true; }
static void IOLockUnlock(IOLock *l) { assert(l->held); l->held = false; }
static void IOLockWakeup(IOLock *, void *, bool) {}
static void IOLockSleep(IOLock *, void *, int) { assert(false); }
#define THREAD_UNINT 0
static unsigned long tick = 0;
#define jiffies tick
static bool time_after_eq(unsigned long a, unsigned long b) { return long(a-b) >= 0; }
static void (*sleepHook)() = nullptr;
static void IOSleep(unsigned n) { tick += n; if (sleepHook) sleepHook(); }
#include "completion-under-test.h"
static completion *target;
static void signalOnSleep() { sleepHook = nullptr; complete(target); }
int main() {
    completion c; init_completion(&c); target = &c;
    for (unsigned n = 0; n != 1000; ++n) {
        assert(wait_for_completion_timeout(&c, n % 5) == 0);
        assert(!c.lock->held); // Timed-out scan must not poison subsequent scans.
        complete(&c); // A late firmware response must also be safe.
        assert(wait_for_completion_timeout(&c, 0) == 1);
        assert(c.done == 0 && !c.lock->held);
        reinit_completion(&c);
    }
    sleepHook = signalOnSleep;
    assert(wait_for_completion_timeout(&c, 5) == 1);
    assert(c.done == 0 && !c.lock->held);
    complete_all(&c);
    for (int n = 0; n != 3; ++n) {
        assert(wait_for_completion_timeout(&c, 0) == 1);
        assert(c.done == UINT_MAX && !c.lock->held);
    }
    reinit_completion(&c);
    tick = ULONG_MAX - 1;
    assert(wait_for_completion_timeout(&c, 3) == 0);
    assert(!c.lock->held);
    delete c.lock;
}
'''

with tempfile.TemporaryDirectory(prefix="rtw-completion-test-") as tmp:
    folder = Path(tmp)
    (folder / "test.cpp").write_text(HARNESS)
    for family in ("88", "89"):
        path = f"rtw/hal_rtw{family}/compat/linux/completion.h"
        fixed = (ROOT / path).read_text()
        baseline = fixed.replace(
            "if (time_after_eq(jiffies, deadline)) return 0;",
            "if (time_after_eq(jiffies, deadline)) { IOLockLock(c->lock); return 0; }")
        assert baseline != fixed, "timeout regression fixture no longer matches production header"
        for name, header in (("baseline", baseline), ("fixed", fixed)):
            # Replace only kernel includes; execute the production function bodies unchanged.
            (folder / "completion-under-test.h").write_text(
                re.sub(r'^#include[^\n]*$', '', header, flags=re.MULTILINE))
            exe = folder / "test"
            subprocess.run(["xcrun", "clang++", "-std=c++14", "-fsanitize=address,undefined",
                            str(folder / "test.cpp"), "-o", str(exe)], check=True)
            result = subprocess.run([str(exe)], capture_output=True, text=True)
            if name == "baseline":
                assert result.returncode != 0 and "!c.lock->held" in result.stderr, result.stderr
                print(f"RTW{family}: reproduced baseline lock leak")
            else:
                assert result.returncode == 0, result.stderr
                print(f"RTW{family}: PASS timeout, late response, repeated scans, success, complete_all, clock wrap")
