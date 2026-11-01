/* SPDX-License-Identifier: GPL-2.0-only
 * Adapted from MtkWireless rust/mtk-wlan/src/awdl/protocol.rs,
 * revision 98d9442076939dd3a0360eed27bdcfb5681c3078 (Wi-Fi GPL-2.0).
 * Per-stream duplicate windows, learned 12/16-bit rollover and idle restart.
 * This is an MSDU duplicate filter, not cryptographic replay protection.
 */
#ifndef RTW_AWDL_DATA_REPLAY_HPP
#define RTW_AWDL_DATA_REPLAY_HPP
#include <stdint.h>
namespace RTWAwdl {
struct DataReplayWindow {
    uint64_t bitmap{0},lastRx{0};
    uint16_t sequence{0};
    bool active{false};
    uint8_t sequenceBits{0};
    bool accept(uint16_t seq,uint64_t now) {
        if (!active || now<lastRx || now-lastRx>3000000) {
            active=true;sequence=seq;bitmap=1;lastRx=now;
            sequenceBits=seq>0xfff ? 16 : 0;return true;
        }
        lastRx=now;
        if (seq>0xfff) sequenceBits=16;
        else if (!sequenceBits && sequence>=0xfc0 && seq<0x800) sequenceBits=12;
        const uint32_t mask=sequenceBits==12 ? 0xfff : 0xffff;
        const uint32_t forward=(uint32_t(seq)-sequence)&mask;
        const int32_t delta=forward<=mask/2 ? int32_t(forward) : int32_t(forward)-int32_t(mask+1);
        if (delta>0) {
            bitmap=delta>=64 ? 1 : (bitmap<<unsigned(delta))|1;
            sequence=seq;return true;
        }
        const uint32_t back=(uint32_t(sequence)-seq)&mask;
        if (back>=64 || (bitmap&(uint64_t(1)<<back))) return false;
        bitmap|=uint64_t(1)<<back;return true;
    }
};
}
#endif
