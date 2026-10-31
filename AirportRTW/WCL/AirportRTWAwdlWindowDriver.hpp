/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_WINDOW_DRIVER_HPP
#define AIRPORTRTW_AWDL_WINDOW_DRIVER_HPP
#include "AirportRTWAwdlInterface.hpp"
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <HAL/RTWAwdlRadio.hpp>
#include <AWDL/RTWAwdlWindowScheduler.hpp>
#include <Airport/apple80211_var.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <mach/mach_time.h>
namespace AirportRTWAwdl {
// Production transport for the shared scheduler. Owner must keep the radio and
// native interface alive, serialize scheduling on nativeWorkLoop(), and stop /
// recover the scheduler before closing the VIF. This class does not publish
// capabilities or stand in for the still-required peer/data backend.
class WindowDriver final : public RTWAwdl::WindowDriver {
public:
    WindowDriver(RTWAwdl::Radio &radio, AirportRTWAwdlInterface &interface)
        : radio_(radio), interface_(interface) {}
    uint64_t nowUs() const override {
        uint64_t ns=0;
        absolutetime_to_nanoseconds(mach_absolute_time(),&ns);
        return ns/1000;
    }
    bool ready() const override {
        const auto state=radio_.awdlRadioState();
        return state.ready && state.frequency;
    }
    bool channelAllowed(uint8_t channel) const override {
        const uint16_t frequency=frequencyFor(channel);
        return frequency && radio_.awdlChannelAllowed(frequency);
    }
    uint8_t currentChannel() const override {
        const auto state=radio_.awdlRadioState();
        return state.ready ? channelFor(state.frequency) : 0;
    }
    Reservation reserve(uint8_t channel,uint32_t durationMs) override {
        const uint16_t frequency=frequencyFor(channel);
        if (!frequency || !durationMs || durationMs>100) return Reservation::Rejected;
        switch (radio_.reserveAwdlRadio(frequency,durationMs)) {
        case RTWAwdl::RadioReservation::Granted: return Reservation::Granted;
        case RTWAwdl::RadioReservation::RecoveryRequired: return Reservation::RecoveryRequired;
        case RTWAwdl::RadioReservation::Rejected: return Reservation::Rejected;
        }
        return Reservation::RecoveryRequired;
    }
    bool restore() override { return radio_.restoreAwdlRadio(); }
    // This adapter uses a software monotonic microsecond domain for native timestamps,
    // wrapping at 32 bits. RX staging below uses exactly the same clock; raw
    // device TSF/free-run values must never be substituted for this domain.
    bool wireTime(uint64_t hostUs,uint32_t &wireUs) const override {
        if (hostUs>nowUs()) return false;
        wireUs=uint32_t(hostUs); return true;
    }
    bool armTimer(uint64_t deadlineUs,uint64_t nowUs) override {
        return interface_.armWindowTimer(deadlineUs,nowUs);
    }
    void cancelTimer() override { interface_.cancelWindowTimer(); }
    bool windowStart(const RTWAwdl::ScheduledWindow &window,uint32_t wireUs) override {
        apple80211_channel channel {};
        if (!describe(window.channel,channel) || currentChannel()!=window.channel ||
            nowUs()>=window.endUs) return false;
        return interface_.postWindowStart(window.counter,window.role,window.parent,
                                         window.root,channel,wireUs);
    }
    bool windowEnd(const RTWAwdl::ScheduledWindow &,uint32_t wireUs) override {
        // End must still be delivered if policy/readiness changed mid-window.
        return interface_.postWindowEnd(wireUs);
    }
    // NAPI-safe metadata staging only. The owning backend must quiesce RX before
    // releasing this object/interface and process election input on its workloop.
    bool queueAction(const uint8_t *frame,size_t length,uint16_t frequency,int32_t rssi) {
        const uint8_t number=channelFor(frequency);
        if (!number) return false;
        apple80211_channel channel {};
        // RX on a passive channel is not a transmit authorization. Avoid HAL
        // calls here: the receive registration lock forbids re-entering the HAL.
        describeUnchecked(number,channel);
        return interface_.queueRadioAction(frame,length,channel,rssi,uint32_t(nowUs()),true);
    }
    static uint16_t frequencyFor(uint8_t channel) {
        if (channel>=1 && channel<=13) return uint16_t(2407+5*channel);
        if (channel>=36 && channel<=177) return uint16_t(5000+5*channel);
        return 0;
    }
    static uint8_t channelFor(uint16_t frequency) {
        if (frequency>=2412 && frequency<=2472 && (frequency-2407)%5==0)
            return uint8_t((frequency-2407)/5);
        if (frequency>=5180 && frequency<=5885 && frequency%5==0)
            return uint8_t((frequency-5000)/5);
        return 0;
    }
private:
    static void describeUnchecked(uint8_t number,apple80211_channel &channel) {
        channel={};channel.version=APPLE80211_VERSION;channel.channel=number;
        channel.flags=APPLE80211_C_FLAG_20MHZ |
            (number<=13 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ);
    }
    bool describe(uint8_t number,apple80211_channel &channel) const {
        if (!channelAllowed(number)) return false;
        describeUnchecked(number,channel);
        channel.flags|=APPLE80211_C_FLAG_ACTIVE;return true;
    }
    RTWAwdl::Radio &radio_;
    AirportRTWAwdlInterface &interface_;
};
}
#endif
#endif
