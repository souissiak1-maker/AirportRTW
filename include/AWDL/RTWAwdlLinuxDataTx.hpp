/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_LINUX_DATA_TX_HPP
#define RTW_AWDL_LINUX_DATA_TX_HPP
#include <AWDL/RTWAwdlData.hpp>
namespace RTWAwdl {
enum class DataSubmission { Rejected, NoMemory, Submitted };
// Include after the HAL's mac80211 declarations. Internal linkage prevents
// RTW88/89 compat symbol coalescing. Caller owns the live manual radio lease,
// producer gate and hardware/peer serialization through tx(). Deadline limits
// software submission, not RF delivery or acknowledgment. Restore/peer teardown
// must drain DMA and MAC queues before retuning/freeing the referenced station.
static inline DataSubmission submitLinuxData(ieee80211_hw *hw,ieee80211_vif *vif,
    ieee80211_sta *peer,const uint8_t *frame,size_t length,uint16_t frequency,
    const ieee80211_channel *channel,uint64_t deadlineUs,uint64_t (*nowUs)())
{
    DataCodec::View view;
    if (!hw || !hw->ops || !hw->ops->tx || !vif || !vif->no_beacon ||
        vif->type!=NL80211_IFTYPE_ADHOC || length>DataCodec::maximumFrame ||
        !DataCodec::inspect(frame,length,view) || frame[0]!=0x88 || frame[1] ||
        frame[24] || frame[25] || memcmp(view.source,vif->addr,6) ||
        !channel || !frequency || channel->center_freq!=frequency ||
        vif->bss_conf.chandef_chan!=channel || !nowUs || !deadlineUs ||
        (channel->band==NL80211_BAND_2GHZ && (frequency<2412 || frequency>2472)) ||
        (channel->band!=NL80211_BAND_2GHZ && channel->band!=NL80211_BAND_5GHZ) ||
        (channel->flags & (IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR |
                          IEEE80211_CHAN_RADAR | IEEE80211_CHAN_NO_OFDM)))
        return DataSubmission::Rejected;
    const bool group=(view.destination[0]&1)!=0;
    if (group) {
        // IPv6 multicast maps to 33:33 plus the destination's low 32 bits.
        if (peer || view.destination[0]!=0x33 || view.destination[1]!=0x33 ||
            view.payload[24]!=0xff || memcmp(view.destination+2,view.payload+36,4))
            return DataSubmission::Rejected;
    } else {
        uint8_t bits=0;for (unsigned i=0;i<6;++i) bits|=view.destination[i];
        if (!bits || !peer || memcmp(peer->addr,view.destination,6) ||
            !memcmp(view.destination,vif->addr,6) || view.payload[24]==0xff)
            return DataSubmission::Rejected;
    }
    // Leave a baseline 6 Mbps frame airtime plus a guard. This is admission
    // headroom only: contention/retries are not a hard RF-time guarantee.
    const uint64_t guardUs=2048+(uint64_t(length)*8+5)/6;
    auto timely=[&]() {
        const uint64_t now=nowUs();
        return deadlineUs>now && deadlineUs-now<=100000 && deadlineUs-now>guardUs;
    };
    if (!timely()) return DataSubmission::Rejected;
    auto *skb=alloc_skb(static_cast<u32>(length+128),GFP_ATOMIC);
    if (!skb) return DataSubmission::NoMemory;
    skb_reserve(skb,128);skb_put_data(skb,frame,static_cast<u32>(length));
    auto *info=IEEE80211_SKB_CB(skb);memset(info,0,sizeof(*info));
    info->flags=IEEE80211_TX_CTL_FIRST_FRAGMENT | IEEE80211_TX_CTL_INJECTED |
        IEEE80211_TX_CTL_TX_OFFCHAN |
        (group ? IEEE80211_TX_CTL_NO_ACK : IEEE80211_TX_CTL_REQ_TX_STATUS);
    info->band=channel->band;info->control.vif=vif;
    info->control.rates[0].idx=channel->band==NL80211_BAND_2GHZ ? 4 : 0;
    info->control.rates[0].count=1;
    for(unsigned i=1;i<IEEE80211_TX_MAX_RATES;++i)info->control.rates[i].idx=-1;
    skb_set_queue_mapping(skb,IEEE80211_AC_BE);
    if (!timely()) {kfree_skb(skb);return DataSubmission::Rejected;}
    ieee80211_tx_control control={};control.sta=peer;
    // TX_OFFCHAN is essential: otherwise rtw89 parks unicast in roc_queue
    // and submits it after returning home, outside the intended AWDL visit.
    hw->ops->tx(hw,&control,skb);
    return DataSubmission::Submitted;
}
}
#endif
