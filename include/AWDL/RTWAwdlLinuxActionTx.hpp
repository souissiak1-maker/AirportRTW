/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_LINUX_ACTION_TX_HPP
#define RTW_AWDL_LINUX_ACTION_TX_HPP
#include <AWDL/RTWAwdlFrame.hpp>
namespace RTWAwdl {
// Internal linkage is required: each HAL compiles different compat functions
// (RTW88 is namespaced). Cross-HAL weak-inline coalescing would be incorrect.
// Call under hardware serialization, with a live registered secondary VIF.
// This submits only on its current channel. A future scheduler must establish
// and verify the RF lease before calling; this does not perform a channel switch.
// Submitted means the driver owns the copied skb, not that an RF ACK occurred.
enum class ActionSubmission { Rejected, NoMemory, Submitted };
static inline ActionSubmission submitLinuxAction(ieee80211_hw *hw, ieee80211_vif *vif,
    const uint8_t *frame, size_t length, uint16_t expectedFrequency)
{
    ActionInfo action;
    if (!hw || !hw->ops || !hw->ops->tx || !vif || !vif->no_beacon ||
        vif->type != NL80211_IFTYPE_ADHOC || length > 4096 ||
        parseFrame(frame, length, action) != ParseResult::Valid ||
        (action.subtype != 0 && action.subtype != 3))
        return ActionSubmission::Rejected;
    auto *channel = hw->conf.chandef.chan;
    if (!channel || !expectedFrequency || channel->center_freq != expectedFrequency ||
        vif->bss_conf.chandef_chan != channel ||
        (channel->band == NL80211_BAND_2GHZ &&
         (expectedFrequency < 2412 || expectedFrequency > 2472)) ||
        (channel->band != NL80211_BAND_2GHZ && channel->band != NL80211_BAND_5GHZ) ||
        (channel->flags & (IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR |
                          IEEE80211_CHAN_RADAR | IEEE80211_CHAN_NO_OFDM)))
        return ActionSubmission::Rejected;
    static const uint8_t bssid[6] = {0x00,0x25,0x00,0xff,0x94,0x73};
    static const uint8_t broadcast[6] = {255,255,255,255,255,255};
    uint8_t sourceBits = 0, destinationBits = 0;
    for (unsigned i = 0; i < 6; ++i) {
        sourceBits |= vif->addr[i]; destinationBits |= frame[4+i];
    }
    const bool group = (frame[4] & 1) != 0;
    if (!sourceBits || (vif->addr[0] & 1) || !destinationBits ||
        memcmp(frame+10, vif->addr, 6) || memcmp(frame+16, bssid, 6) ||
        (group && memcmp(frame+4, broadcast, 6)))
        return ActionSubmission::Rejected;
    auto *skb = alloc_skb(static_cast<u32>(length + 128), GFP_ATOMIC);
    if (!skb) return ActionSubmission::NoMemory;
    skb_reserve(skb,128);
    skb_put_data(skb,frame,static_cast<u32>(length));
    auto *info = IEEE80211_SKB_CB(skb);
    memset(info,0,sizeof(*info));
    info->flags = IEEE80211_TX_CTL_FIRST_FRAGMENT | IEEE80211_TX_CTL_INJECTED |
        (group ? IEEE80211_TX_CTL_NO_ACK : IEEE80211_TX_CTL_REQ_TX_STATUS);
    info->band = channel->band;
    info->control.vif = vif;
    // Band-relative legacy rate indices: OFDM 6 Mbps, 20 MHz, one stream.
    info->control.rates[0].idx = channel->band == NL80211_BAND_2GHZ ? 4 : 0;
    info->control.rates[0].count = 1;
    for (unsigned i = 1; i < IEEE80211_TX_MAX_RATES; ++i)
        info->control.rates[i].idx = -1;
    skb_set_queue_mapping(skb,IEEE80211_AC_VO);
    ieee80211_tx_control control = {};
    hw->ops->tx(hw,&control,skb);
    return ActionSubmission::Submitted;
}
}
#endif
