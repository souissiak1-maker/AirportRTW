/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlObserver.hpp>
#include <cassert>
#include <cstring>
#include <cstdint>
#include <initializer_list>
using namespace RTWAwdl;
int main() {
    uint8_t frame[512] = {};
    frame[0] = 0xd0;
    uint8_t *b = frame + 24;
    b[0] = 127; b[2] = 0x17; b[3] = 0xf2; b[4] = 8; b[5] = 1; b[6] = 3;
    ActionInfo out;
    assert(parseFrame(frame, 40, out) == ParseResult::Valid && out.tlvCount == 0);
    b[16] = 4; b[17] = 2; b[18] = 0; b[19] = 0xaa; b[20] = 0xbb;
    b[21] = 18; b[22] = 0; b[23] = 0;
    assert(parseFrame(frame, 48, out) == ParseResult::Valid && out.tlvCount == 2);
    assert(out.tlvTypes == ((uint64_t(1) << 4) | (uint64_t(1) << 18)));
    Observer observer; observer.observe(frame, 48, 2437);
    assert(observer.valid == 1 && observer.syncEnvelopes == 1 && observer.channelEnvelopes == 1);
    assert(observer.lastFrequency == 2437 && observer.lastSubtype == 3);
    // Every prefix must be bounded, including partial headers and TLVs.
    for (size_t n = 0; n < 48; ++n) {
        const auto r = parseFrame(frame, n, out);
        if (r != ParseResult::Valid) assert(out.tlvCount == 0);
    }
    b[17] = 255; b[18] = 255;
    assert(parseFrame(frame, 48, out) == ParseResult::Malformed && out.tlvCount == 0);
    observer.observe(frame, 48, 2437); assert(observer.malformed == 1 && observer.valid == 1 && observer.actionFrames == 2 && observer.vendorActions == 2 && observer.appleVendorActions == 2);
    b[17] = 2; b[18] = 0;
    // Unknown and repeated TLVs are safely skipped, including zero-length TLVs.
    b[21] = 255; assert(parseFrame(frame, 48, out) == ParseResult::Valid && out.tlvCount == 2);
    b[21] = 4; assert(parseFrame(frame, 48, out) == ParseResult::Valid && out.tlvCount == 2);
    b[5] = 0; assert(parseFrame(frame, 48, out) == ParseResult::Malformed); b[5] = 2;
    assert(parseFrame(frame, 48, out) == ParseResult::Valid && out.version == 2);
    b[1] = 1; assert(parseFrame(frame, 48, out) == ParseResult::NotAwdl); b[1] = 0;
    b[0] = 4; assert(parseFrame(frame, 48, out) == ParseResult::NotAwdl); b[0] = 127;
    // Protected/fragmented/ordered or non-management traffic is not parsed.
    for (uint8_t flag : {uint8_t(1), uint8_t(4), uint8_t(64), uint8_t(128)}) {
        frame[1] = flag; assert(parseFrame(frame, 48, out) == ParseResult::NotAwdl);
    }
    frame[1] = 0; frame[22] = 1; assert(parseFrame(frame, 48, out) == ParseResult::NotAwdl);
    frame[22] = 0; frame[0] = 0x08; assert(parseFrame(frame, 48, out) == ParseResult::NotAwdl);
    assert(parseFrame(nullptr, 500, out) == ParseResult::NotAwdl);
    Tlv tlv {}; TlvCursor nullCursor(nullptr, 3);
    assert(!nullCursor.next(tlv) && nullCursor.failed());
    uint32_t random = 0x12345678;
    for (unsigned attempt = 0; attempt < 20000; ++attempt) {
        for (auto &byte : frame) { random ^= random << 13; random ^= random >> 17; random ^= random << 5; byte = uint8_t(random); }
        // Keep a valid envelope to exercise randomized TLV lengths under sanitizers.
        frame[0] = 0xd0; frame[1] = 0; frame[22] &= 0xf0;
        b[0] = 127; b[1] = 0; b[2] = 0x17; b[3] = 0xf2; b[4] = 8; b[5] = 1;
        parseFrame(frame, random % sizeof(frame), out);
    }
}
