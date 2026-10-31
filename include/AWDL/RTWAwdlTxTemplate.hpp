/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_TX_TEMPLATE_HPP
#define RTW_AWDL_TX_TEMPLATE_HPP
#include "RTWAwdlFrame.hpp"

namespace RTWAwdl {
// Owned action body supplied by the frontend's peer manager. The caller must
// serialize replace/build/clear on its work queue. No pointers into ioctl memory
// survive replace(). Wire time fields are opaque LE32 values supplied by radio;
// their clock domain must be established before enabling action transmission.
class TxTemplate {
public:
    static constexpr size_t capacity = 4096;
    bool replace(const uint8_t *body, size_t length) {
        ActionInfo info;
        if (parseAction(body, length, info) != ParseResult::Valid ||
            (info.subtype != 0 && info.subtype != 3)) return false;
        for (size_t i = 0; i < length; ++i) bytes[i] = body[i];
        for (size_t i = length; i < used; ++i) bytes[i] = 0;
        used = length;
        return true;
    }
    void clear() {
        for (size_t i = 0; i < used; ++i) bytes[i] = 0;
        used = 0;
    }
    size_t size() const { return used; }
    // No FCS: hardware owns it. Caller supplies AWDL destination/BSSID/source,
    // never the infrastructure station's address by implicit fallback.
    bool build(uint8_t *out, size_t available, const uint8_t destination[6],
               const uint8_t source[6], const uint8_t bssid[6], uint16_t sequence,
               uint32_t phyTime, uint32_t targetTime, size_t &written) const {
        written = 0;
        if (!out || !destination || !source || !bssid || !used ||
            available < 24 + used || (source[0] & 1)) return false;
        uint8_t nonzero = 0;
        for (size_t i = 0; i < 6; ++i) nonzero |= source[i];
        if (!nonzero) return false;
        for (size_t i = 0; i < 24; ++i) out[i] = 0;
        out[0] = 0xd0;
        for (size_t i = 0; i < 6; ++i) {
            out[4 + i] = destination[i]; out[10 + i] = source[i]; out[16 + i] = bssid[i];
        }
        const uint16_t control = uint16_t((sequence & 0x0fff) << 4);
        out[22] = uint8_t(control); out[23] = uint8_t(control >> 8);
        for (size_t i = 0; i < used; ++i) out[24 + i] = bytes[i];
        for (unsigned i = 0; i < 4; ++i) {
            out[32 + i] = uint8_t(phyTime >> (8 * i));
            out[36 + i] = uint8_t(targetTime >> (8 * i));
        }
        written = 24 + used;
        return true;
    }
private:
    uint8_t bytes[capacity] {};
    size_t used {0};
};
} // namespace RTWAwdl
#endif
