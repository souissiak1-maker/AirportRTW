/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_RADIO_HPP
#define RTW_AWDL_RADIO_HPP
#include <stdint.h>
#include <HAL/RTWAwdlRadioStatus.h>
namespace RTWAwdl {
// One serialized owner on the controller workloop. Frequencies are MHz; no
// Apple or Linux channel structures cross the shared HAL boundary.
struct RadioState {
    uint16_t frequency {0};
    // recoveryRequired means restoration is owed, including a live visit.
    bool ready {false}, recoveryRequired {false};
    uint32_t blockers {RTW_AWDL_RADIO_UNAVAILABLE};
};
enum class RadioReservation { Granted, Rejected, RecoveryRequired };
class Radio {
public:
    virtual ~Radio() = default;
    // Defaults describe a HAL without bounded off-channel scheduling. This is
    // deliberately independent of action RX/TX and must not imply AWDL support.
    virtual RadioState awdlRadioState() const { return {}; }
    // Synchronize primary authorization before starting secondary scheduling.
    // This never grants a visit or permits TX on its own.
    virtual bool prepareAwdlRadio() {const auto s=awdlRadioState();return s.ready && s.frequency && !s.recoveryRequired;}
    virtual bool awdlChannelAllowed(uint16_t) const { return false; }
    virtual RadioReservation reserveAwdlRadio(uint16_t, uint32_t) {
        return RadioReservation::Rejected;
    }
    virtual bool restoreAwdlRadio() { return false; }
};
}
#endif
