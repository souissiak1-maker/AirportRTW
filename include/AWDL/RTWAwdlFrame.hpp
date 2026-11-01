/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_FRAME_HPP
#define RTW_AWDL_FRAME_HPP
#include <stddef.h>
#include <stdint.h>

// Protocol framing only. No Apple object offsets, radio policy or allocations.
namespace RTWAwdl {
enum class ParseResult : uint8_t { NotAwdl, Malformed, Valid };
struct ActionInfo {
    uint8_t version {0};
    uint8_t subtype {0};
    uint16_t tlvCount {0};
    uint64_t tlvTypes {0}; // Types >= 64 are accepted but not represented.
};
struct Tlv { uint8_t type; const uint8_t *data; size_t length; };
class TlvCursor {
public:
    TlvCursor(const uint8_t *data, size_t length) : bytes(data), remaining(length) {}
    bool next(Tlv &out) {
        out = {};
        if (!remaining || malformed) return false;
        if (!bytes || remaining < 3) { malformed = true; return false; }
        const size_t length = size_t(bytes[1]) | (size_t(bytes[2]) << 8);
        if (length > remaining - 3) { malformed = true; return false; }
        out = {bytes[0], bytes + 3, length};
        bytes += 3 + length;
        remaining -= 3 + length;
        return true;
    }
    bool failed() const { return malformed; }
private:
    const uint8_t *bytes;
    size_t remaining;
    bool malformed {false};
};
// Input is an unencrypted vendor action body, starting with its category.
// Fixed AWDL envelope is 16 bytes; TLVs have type:u8, length:LE16.
inline ParseResult parseAction(const uint8_t *body, size_t length, ActionInfo &out) {
    out = {};
    if (!body || length < 5 || body[0] != 127 || body[1] != 0 ||
        body[2] != 0x17 || body[3] != 0xf2 || body[4] != 8)
        return ParseResult::NotAwdl;
    if (length < 16 || length > 4096 || body[5] == 0)
        return ParseResult::Malformed;
    ActionInfo parsed;
    parsed.version = body[5]; parsed.subtype = body[6];
    TlvCursor cursor(body + 16, length - 16);
    Tlv tlv {};
    while (cursor.next(tlv)) {
        ++parsed.tlvCount;
        if (tlv.type < 64) parsed.tlvTypes |= uint64_t(1) << tlv.type;
    }
    if (cursor.failed()) return ParseResult::Malformed;
    out = parsed;
    return ParseResult::Valid;
}
// Complete 802.11 management header + body, without hardware FCS.
// Fragmentation/reassembly and protected management are owned by net80211.
inline ParseResult parseFrame(const uint8_t *frame, size_t length, ActionInfo &out) {
    out = {};
    if (!frame || length < 24 || frame[0] != 0xd0 ||
        (frame[1] & (0x03 | 0x04 | 0x40 | 0x80)) || (frame[22] & 15))
        return ParseResult::NotAwdl;
    return parseAction(frame + 24, length - 24, out);
}
} // namespace RTWAwdl
#endif
