/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_STARTUP_PROBE_HPP
#define RTW_AWDL_STARTUP_PROBE_HPP
#include <stdint.h>
namespace RTWAwdl {
// Bounded diagnostic use of the same secondary-VIF contract as the native
// backend. No native capability advertisement, peer creation, TX or retuning.
// All control calls are serialized on the controller workloop, before HAL off.
class StartupProbeDriver {
public:
    virtual ~StartupProbeDriver() = default;
    virtual bool primaryReady() const = 0;
    virtual uint32_t capacity() const = 0;
    virtual bool open() = 0;
    virtual bool bind() = 0;
    virtual bool radioReady() const = 0;
    virtual void unbind() = 0; // synchronous RX-registration barrier
    virtual bool close() = 0; // retains failed HAL ownership for recovery
};
class StartupProbe {
public:
    enum class Stage : uint32_t {
        Idle, Waiting, Opening, Binding, Listening, Complete,
        Unavailable, OpenFailed, BindFailed, RadioFailed, CleanupFailed,
        Cancelled, TimedOut
    };
    explicit StartupProbe(StartupProbeDriver &driver):driver_(driver) {}
    bool arm() {
        // Power-off before the first hardware attempt may cancel waiting.
        // Re-enable can resume it; an actual test attempt is never repeated.
        if (stage_ != Stage::Idle && !(stage_==Stage::Cancelled && !tested_)) return false;
        stage_=Stage::Waiting;return true;
    }
    bool tick() {
        if (stage_ == Stage::Waiting) {
            // Waiting is passive and has no boot deadline. Only the actual
            // hardware test is bounded; login/auto-join may happen much later.
            if (waits_ != UINT32_MAX) ++waits_;
            if (!driver_.primaryReady()) return true;
            capacity_=driver_.capacity();
            if (!capacity_) {stage_=Stage::Unavailable;return false;}
            stage_=Stage::Opening;attempted_=true;tested_=true;
            if (!driver_.open()) {finish(Stage::OpenFailed);return false;}
            stage_=Stage::Binding;
            if (!driver_.bind()) {finish(Stage::BindFailed);return false;}
            if (!driver_.radioReady()) {finish(Stage::RadioFailed);return false;}
            stage_=Stage::Listening;
            return true;
        }
        if (stage_ == Stage::Listening) {
            if (!driver_.primaryReady() || !driver_.radioReady()) {
                finish(Stage::RadioFailed);return false;
            }
            if (++listens_ < 10) return true;
            finish(Stage::Complete);
        }
        return false;
    }
    void stop() {
        if (attempted_) finish(Stage::Cancelled);
        else if (stage_==Stage::Waiting) stage_=Stage::Cancelled;
    }
    Stage stage() const {return stage_;}
    Stage result() const {return result_;}
    uint32_t waits() const {return waits_;}
    uint32_t listens() const {return listens_;}
    uint32_t peerCapacity() const {return capacity_;}
    bool cleanupSucceeded() const {return cleaned_;}
private:
    void finish(Stage result) {
        result_=result;
        driver_.unbind();
        // The HAL owns failed firmware/VIF cleanup. Do not retry from a timer,
        // free its pool, or resume a retained radio gate after a failed close.
        const bool okay=driver_.close();
        attempted_=false;cleaned_=okay;
        stage_=okay ? result : Stage::CleanupFailed;
    }
    StartupProbeDriver &driver_;
    Stage stage_{Stage::Idle},result_{Stage::Idle};
    uint32_t waits_{0},listens_{0},capacity_{0};
    bool attempted_{false},cleaned_{false},tested_{false};
};
}
#endif
