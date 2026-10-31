/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_OBSERVER_HPP
#define RTW_AWDL_OBSERVER_HPP
#include "RTWAwdlFrame.hpp"
namespace RTWAwdl {
// Passive Debug-only observer. Never consumes frames or changes radio state.
// No peer addresses, payloads or key material are retained.
struct Observer {
    volatile uint64_t actionFrames {0}, vendorActions {0}, appleVendorActions {0};
    volatile uint64_t valid {0}, malformed {0}, syncEnvelopes {0}, channelEnvelopes {0};
    volatile uint64_t timedActions {0};
    volatile uint32_t lastRadioTimestamp {0};
    volatile uint32_t lastFrequency {0}, lastVersion {0}, lastSubtype {0};
    void observe(const uint8_t *frame, size_t length, uint16_t frequency,
                 uint32_t radioTimestamp = 0, bool radioTimestampValid = false) {
        if (frame && length >= 24 && frame[0] == 0xd0) {
            __sync_fetch_and_add(&actionFrames, 1);
            if (!(frame[1] & 0x40) && length >= 25 && frame[24] == 127) {
                __sync_fetch_and_add(&vendorActions, 1);
                if (length >= 28 && frame[25] == 0 && frame[26] == 0x17 && frame[27] == 0xf2)
                    __sync_fetch_and_add(&appleVendorActions, 1);
            }
        }
        ActionInfo info;
        const auto result = parseFrame(frame, length, info);
        if (result == ParseResult::Malformed) {
            __sync_fetch_and_add(&malformed, 1);
        } else if (result == ParseResult::Valid) {
            __sync_fetch_and_add(&valid, 1);
            if (radioTimestampValid) {
                __sync_fetch_and_add(&timedActions, 1);
                lastRadioTimestamp = radioTimestamp;
            }
            if (info.tlvTypes & (uint64_t(1) << 4)) __sync_fetch_and_add(&syncEnvelopes, 1);
            if (info.tlvTypes & ((uint64_t(1) << 18) | (uint64_t(1) << 32)))
                __sync_fetch_and_add(&channelEnvelopes, 1);
            lastFrequency = frequency; lastVersion = info.version; lastSubtype = info.subtype;
        }
    }
};
} // namespace RTWAwdl
#endif
