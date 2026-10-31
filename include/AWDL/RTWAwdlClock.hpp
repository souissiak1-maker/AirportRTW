/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_CLOCK_HPP
#define RTW_AWDL_CLOCK_HPP
#include <stdint.h>

namespace RTWAwdl {
// A radio timestamp is not the host monotonic clock. This tracks a relative
// radio timeline only; a separate calibration is required before comparing it
// with host deadlines. Caller serializes all operations on its work queue.
class RadioClock32 {
public:
    bool sample(uint32_t low, uint64_t hostUs, bool valid, uint64_t &expanded) {
        expanded = 0;
        if (!valid) return false;
        if (!initialized_) {
            initialized_ = true; low_ = low; host_ = hostUs; radio_ = low;
            expanded = radio_;
            return true;
        }
        // Long gaps are ambiguous: multiple wraps cannot be reconstructed.
        if (hostUs < host_ || hostUs - host_ >= (uint64_t(1) << 31)) {
            reset(); return false;
        }
        const uint32_t delta = low - low_;
        if (delta >= (uint32_t(1) << 31) || radio_ > UINT64_MAX - delta)
            return false; // Out-of-order sample: retain the last good anchor.
        radio_ += delta; low_ = low; host_ = hostUs; expanded = radio_;
        return true;
    }
    void reset() { initialized_ = false; low_ = 0; host_ = radio_ = 0; }
private:
    bool initialized_ {false};
    uint32_t low_ {0};
    uint64_t host_ {0}, radio_ {0};
};

// Availability-window arithmetic. The frontend/synchronization engine supplies
// an accepted epoch and counter in one clock domain. This does not choose a
// master, accept an untrusted peer's clock, arm timers or switch the radio.
class AvailabilityClock {
public:
    struct Window {
        uint16_t counter;
        uint32_t phaseUs;
        uint32_t untilBoundaryUs;
        uint64_t startUs;
        bool available;
        bool txAllowed;
    };
    bool configure(uint64_t epochUs, uint16_t counter, uint16_t periodTu,
                   uint16_t availableTu, uint32_t guardUs) {
        const uint32_t period = uint32_t(periodTu) * 1024;
        const uint32_t available = uint32_t(availableTu) * 1024;
        if (!period || !available || available > period || guardUs >= available ||
            guardUs >= available - guardUs) return false;
        epoch_ = epochUs; counter_ = counter;
        period_ = period; available_ = available; guard_ = guardUs; valid_ = true;
        return true;
    }
    bool at(uint64_t nowUs, Window &out) const {
        out = {};
        if (!valid_ || nowUs < epoch_) return false;
        const uint64_t elapsed = nowUs - epoch_;
        const uint64_t windows = elapsed / period_;
        const uint32_t phase = uint32_t(elapsed % period_);
        out.counter = uint16_t(counter_ + uint16_t(windows));
        out.phaseUs = phase;
        out.startUs = nowUs - phase;
        out.untilBoundaryUs = period_ - phase;
        out.available = phase < available_;
        out.txAllowed = phase >= guard_ && phase < available_ - guard_;
        return true;
    }
    // Refuse overflow instead of scheduling a timer in the distant past.
    bool nextBoundary(uint64_t nowUs, uint64_t &deadlineUs) const {
        deadlineUs = 0;
        Window window {};
        if (!at(nowUs, window) || nowUs > UINT64_MAX - window.untilBoundaryUs)
            return false;
        deadlineUs = nowUs + window.untilBoundaryUs;
        return true;
    }
    void reset() {
        valid_ = false; epoch_ = 0; counter_ = 0;
        period_ = available_ = guard_ = 0;
    }
private:
    bool valid_ {false};
    uint64_t epoch_ {0};
    uint16_t counter_ {0};
    uint32_t period_ {0}, available_ {0}, guard_ {0};
};
} // namespace RTWAwdl
#endif
