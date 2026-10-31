/* SPDX-License-Identifier: GPL-2.0-only
 * Adapted from RTW88AWDLProtocol.hpp in X1REN41L/RTL88WiFi,
 * revision 8cebe79209d05e8760e17603af6a344941920381.
 * Original source SPDX: GPL-2.0 OR BSD-3-Clause; used here under GPL-2.0.
 * Changes: shared TLV cursor, explicit decode outcomes, owning records,
 * preserved operating classes/counters and conflicting-sequence rejection.
 * Wire layout cross-check: seemoo-lab/owl src/frame.h (facts only, no code).
 */
#ifndef RTW_AWDL_SYNC_HPP
#define RTW_AWDL_SYNC_HPP
#include "RTWAwdlFrame.hpp"
namespace RTWAwdl {
enum class SyncDecode : uint8_t { Valid, NotSynchronization, Unsupported, Malformed };
struct ChannelSequence {
    uint8_t channel[16] {};
    // Operating class for encoding 3; opaque flags byte for encoding 1.
    uint8_t auxiliary[16] {};
    uint8_t encoding {0}, stride {0}, count {0};
};
struct SyncMessage {
    ChannelSequence sequence;
    uint32_t phyTxTime {0}, targetTxTime {0}; // Sender's clock, not host time.
    uint16_t periodTu {0}, actionPeriodTu {0}, countdownTu {0};
    uint16_t commonTu {0}, counter {0}, remainingTu {0}, apAlignment {0};
    uint8_t subtype {0}, presence {0}, guardTu {0};
    uint8_t nextChannel {0}, masterChannel {0}, master[6] {}, syncMaster[6] {}, syncAddress[6] {};
    uint32_t masterCounter {0}, selfCounter {0}, masterMetric {0}, selfMetric {0}, height {0};
    bool electionPresent {false}, versionPresent {false};
    uint8_t version {0}, deviceClass {0};
};
namespace SyncDetail {
inline uint16_t le16(const uint8_t *p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
inline uint32_t le32(const uint8_t *p) { return uint32_t(le16(p)) | (uint32_t(le16(p + 2)) << 16); }
inline bool unicast(const uint8_t *p) {
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= p[i];
    return bits && !(p[0] & 1);
}
inline bool sameSequence(const ChannelSequence &a, const ChannelSequence &b) {
    if (a.count != b.count || a.stride != b.stride) return false;
    for (unsigned i = 0; i < a.count; ++i)
        if (a.channel[i] != b.channel[i] ||
            (a.encoding == 3 && b.encoding == 3 && a.auxiliary[i] != b.auxiliary[i])) return false;
    return true;
}
}
// Supported wire subset: full 16-entry list, no duplication, no fill expansion.
// Unknown encodings are unsupported, not malformed. No channel is authorized
// by decoding: the HAL must validate band/operating class/regulatory policy.
inline SyncDecode decodeChannelSequence(const uint8_t *p, size_t n, ChannelSequence &out) {
    out = {};
    if (!p || n < 6) return SyncDecode::Malformed;
    const unsigned width = p[1] == 0 ? 1 : (p[1] == 1 || p[1] == 3 ? 2 : 0);
    if (!width || p[0] != 15 || p[2] != 0 || p[3] > 15 ||
        SyncDetail::le16(p + 4) != 0xffff) return SyncDecode::Unsupported;
    const size_t used = 6 + 16 * width;
    if (n < used || n - used > 3) return SyncDecode::Malformed;
    for (size_t i=used;i<n;++i) if (p[i]) return SyncDecode::Malformed;
    ChannelSequence decoded;
    decoded.count = 16; decoded.encoding = p[1]; decoded.stride = uint8_t(p[3] + 1);
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t *entry = p + 6 + i * width;
        const uint8_t channel = entry[p[1] == 1 ? 1 : 0];
        if (channel > 196) return SyncDecode::Unsupported; // No channel-255 retune.
        decoded.channel[i] = channel; // Zero is an unavailable slot.
        if (width == 2) decoded.auxiliary[i] = entry[p[1] == 1 ? 0 : 1];
        if (p[1] == 3 && channel) {
            const uint8_t opclass=decoded.auxiliary[i];
            // Do not reinterpret a 6 GHz operating class as a 2/5 GHz
            // channel with the same numeric value. HAL authorization remains
            // separate from this wire-format check.
            if (channel<=14 ? (opclass<81 || opclass>84) :
                              (opclass<115 || opclass>130))
                return SyncDecode::Unsupported;
        }
    }
    out = decoded;
    return SyncDecode::Valid;
}
// Action body only (no 802.11 header/FCS). Decodes into an owning record only
// after every TLV validates. It does not accept a clock, elect/admit a peer,
// publish native state, arm a timer or retune the radio.
inline SyncDecode decodeSyncAction(const uint8_t *body, size_t length, SyncMessage &out) {
    out = {};
    ActionInfo envelope;
    const auto framed = parseAction(body, length, envelope);
    if (framed == ParseResult::NotAwdl) return SyncDecode::NotSynchronization;
    if (framed != ParseResult::Valid) return SyncDecode::Malformed;
    if (envelope.version != 0x10 || (envelope.subtype != 0 && envelope.subtype != 3))
        return SyncDecode::Unsupported;
    SyncMessage decoded;
    decoded.subtype = envelope.subtype;
    decoded.phyTxTime = SyncDetail::le32(body + 8);
    decoded.targetTxTime = SyncDetail::le32(body + 12);
    bool haveSync = false, haveSequence = false, haveEmbedded = false;
    ChannelSequence embedded;
    uint8_t electedMaster[6] {};
    TlvCursor cursor(body + 16, length - 16);
    Tlv tlv {};
    while (cursor.next(tlv)) {
        const auto *p = tlv.data;
        if (tlv.type == 4) {
            if (haveSync || tlv.length < 33) return SyncDecode::Malformed;
            haveSync = true;
            decoded.nextChannel = p[0]; decoded.countdownTu = SyncDetail::le16(p + 1);
            decoded.masterChannel = p[3]; decoded.guardTu = p[4];
            decoded.periodTu = SyncDetail::le16(p + 5);
            decoded.actionPeriodTu = SyncDetail::le16(p + 7);
            decoded.commonTu = SyncDetail::le16(p + 13);
            decoded.remainingTu = SyncDetail::le16(p + 15);
            for (unsigned i = 0; i < 6; ++i)
                decoded.syncMaster[i] = decoded.master[i] = p[21 + i];
            decoded.presence = p[27]; decoded.counter = SyncDetail::le16(p + 29);
            decoded.apAlignment = SyncDetail::le16(p + 31);
            if (!decoded.periodTu || !decoded.actionPeriodTu ||
                !decoded.presence || decoded.presence > 16 ||
                (decoded.presence & (decoded.presence - 1)) ||
                decoded.countdownTu > uint32_t(decoded.periodTu) * decoded.presence ||
                decoded.commonTu > uint32_t(decoded.periodTu) * decoded.presence ||
                !SyncDetail::unicast(decoded.master)) return SyncDecode::Malformed;
            if (decoded.periodTu > 1024 || decoded.actionPeriodTu > 4096)
                return SyncDecode::Unsupported;
            if (tlv.length > 33) {
                auto status = decodeChannelSequence(p + 33, tlv.length - 33, embedded);
                if (status != SyncDecode::Valid) return status;
                haveEmbedded = true;
            }
        } else if (tlv.type == 18) {
            if (haveSequence) return SyncDecode::Malformed;
            auto status = decodeChannelSequence(p, tlv.length, decoded.sequence);
            if (status != SyncDecode::Valid) return status;
            haveSequence = true;
        } else if (tlv.type == 24) {
            if (decoded.electionPresent || tlv.length < 40) return SyncDecode::Malformed;
            decoded.electionPresent = true;
            for (unsigned i = 0; i < 6; ++i) {
                electedMaster[i] = p[i]; decoded.syncAddress[i] = p[6 + i];
            }
            decoded.masterCounter = SyncDetail::le32(p + 12);
            decoded.height = SyncDetail::le32(p + 16);
            decoded.masterMetric = SyncDetail::le32(p + 20);
            decoded.selfMetric = SyncDetail::le32(p + 24);
            decoded.selfCounter = SyncDetail::le32(p + 36);
            if (!SyncDetail::unicast(electedMaster) || !SyncDetail::unicast(decoded.syncAddress))
                return SyncDecode::Malformed;
        } else if (tlv.type == 21) {
            if (decoded.versionPresent || tlv.length < 2) return SyncDecode::Malformed;
            decoded.versionPresent = true; decoded.version = p[0]; decoded.deviceClass = p[1];
        }
    }
    if (cursor.failed()) return SyncDecode::Malformed;
    if (!haveSync) return SyncDecode::NotSynchronization;
    // The clock advertisement and election root may differ during a tree
    // transition. Preserve both; election/admission must reject loops rather
    // than discarding the complete synchronization observation here.
    if (decoded.electionPresent)
        for (unsigned i = 0; i < 6; ++i) decoded.master[i] = electedMaster[i];
    if (!haveSequence && !haveEmbedded) return SyncDecode::Unsupported;
    if (haveSequence && haveEmbedded) {
        if (decoded.sequence.count != embedded.count || decoded.sequence.stride != embedded.stride)
            return SyncDecode::Malformed;
        // Captured iPhone PSFs carry legacy center-channel 151 in the
        // embedded encoding-1 list and primary 149/opclass 128 in TLV 18.
        // Prefer the explicit operating-class list for this pairing only.
        if (!(embedded.encoding == 1 && decoded.sequence.encoding == 3) &&
            !SyncDetail::sameSequence(decoded.sequence, embedded))
            return SyncDecode::Malformed;
    }
    if (!haveSequence) decoded.sequence = embedded;
    if (decoded.sequence.stride != decoded.presence) return SyncDecode::Malformed;
    out = decoded;
    return SyncDecode::Valid;
}
}
#endif
