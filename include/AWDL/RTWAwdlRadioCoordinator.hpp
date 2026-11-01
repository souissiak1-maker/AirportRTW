/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_RADIO_COORDINATOR_HPP
#define RTW_AWDL_RADIO_COORDINATOR_HPP
#include <stdint.h>

namespace RTWAwdl {
// Shared asynchronous radio-lease bookkeeping. HAL callbacks perform switches;
// this class never calls them under a lock or assumes a switch has completed.
// All calls must be serialized by the owning work queue. Token generations
// invalidate callbacks after stop, scan, suspend or an infrastructure join.
class RadioCoordinator {
public:
    enum class State : uint8_t { Stopped, Home, SwitchingOut, Away, Returning, Failed };
    struct Request { uint64_t token; uint16_t channel; };
    bool start(uint16_t home, uint32_t maximumAwayUs, bool concurrentStation) {
        if (state_ != State::Stopped || !home || !maximumAwayUs ||
            maximumAwayUs > 100000) return false;
        nextGeneration();
        home_ = home; maximumAway_ = maximumAwayUs;
        concurrent_ = concurrentStation; state_ = State::Home;
        return true;
    }
    // allowed comes from the effective HAL regulatory domain, not peer input.
    bool request(uint16_t channel, uint32_t durationUs, uint64_t nowUs,
                 bool allowed, bool stationAssociated, Request &out) {
        out = {};
        if (state_ != State::Home || !allowed || !channel || !durationUs ||
            durationUs > maximumAway_ || (stationAssociated && !concurrent_) ||
            nowUs > UINT64_MAX - durationUs) return false;
        nextGeneration();
        target_ = channel; deadline_ = nowUs + durationUs;
        state_ = State::SwitchingOut;
        out = {generation_, target_};
        return true;
    }
    bool switched(uint64_t token, bool success, uint64_t nowUs) {
        if (token != generation_) return false;
        if (state_ == State::SwitchingOut) {
            // A failed switch leaves RF state uncertain. Caller must restore
            // home through beginReturn(), including an expired completion.
            state_ = success && nowUs < deadline_ ? State::Away : State::Failed;
            return true;
        }
        if (state_ == State::Returning) {
            state_ = success ? State::Home : State::Failed;
            return true;
        }
        return false;
    }
    bool due(uint64_t nowUs) const {
        return (state_ == State::SwitchingOut || state_ == State::Away) && nowUs >= deadline_;
    }
    bool beginReturn(Request &out) {
        out = {};
        if (state_ != State::SwitchingOut && state_ != State::Away && state_ != State::Failed)
            return false;
        nextGeneration(); state_ = State::Returning;
        out = {generation_, home_};
        return true;
    }
    // Caller must quiesce outstanding HAL commands and restore RF before stop;
    // software invalidation cannot cancel a channel command already in flight.
    void stop() {
        nextGeneration(); state_ = State::Stopped;
        home_ = target_ = 0; deadline_ = 0; maximumAway_ = 0; concurrent_ = false;
    }
    State state() const { return state_; }
    uint64_t token() const { return generation_; }
private:
    void nextGeneration() { if (!++generation_) ++generation_; }
    State state_ {State::Stopped};
    uint64_t generation_ {0}, deadline_ {0};
    uint16_t home_ {0}, target_ {0};
    uint32_t maximumAway_ {0};
    bool concurrent_ {false};
};
} // namespace RTWAwdl
#endif
