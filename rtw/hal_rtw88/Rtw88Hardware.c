/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Hardware-only RTW88 entry points. MLME remains in native net80211. */
#include "compat/rtw88_compat.h"
#include "driver/main.h"
#include "driver/pci.h"
extern const struct rtw_chip_info rtw8822c_hw_spec;
extern const struct rtw_chip_info rtw8822b_hw_spec;
extern const struct rtw_chip_info rtw8821c_hw_spec;
extern const struct rtw_chip_info rtw8723d_hw_spec;
extern const struct rtw_chip_info rtw8814a_hw_spec;

unsigned rtw88_hw_get_nss(struct ieee80211_hw *hw)
{
    struct rtw_dev *device = hw ? hw->priv : NULL;
    return device && device->efuse.hw_cap.nss ? device->efuse.hw_cap.nss : 1;
}

int airportrtw88_probe(struct pci_dev *pdev)
{
    struct pci_device_id id = {0};
    if (!pdev || pdev->vendor != 0x10ec) return -ENODEV;
    switch (pdev->device) {
    case 0xc822: case 0xc82f: id.driver_data = (kernel_ulong_t)&rtw8822c_hw_spec; break;
    case 0xb822: id.driver_data = (kernel_ulong_t)&rtw8822b_hw_spec; break;
    case 0xc821: case 0xb821:
        id.driver_data = (kernel_ulong_t)&rtw8821c_hw_spec; break;
    case 0xd723: id.driver_data = (kernel_ulong_t)&rtw8723d_hw_spec; break;
    case 0x8813: id.driver_data = (kernel_ulong_t)&rtw8814a_hw_spec; break;
    default: return -ENODEV;
    }
    id.vendor = pdev->vendor;
    id.device = pdev->device;
    return rtw_pci_probe(pdev, &id);
}

static int ampdu(struct ieee80211_vif *vif, struct ieee80211_sta *sta,
                 u8 tid, u16 ssn, u16 window, int action)
{
    struct ieee80211_hw *hw = rtw88_get_hw();
    struct ieee80211_ampdu_params params = {0};
    if (!hw || !vif || !sta || tid >= IEEE80211_NUM_TIDS || !sta->txq[tid])
        return -EINVAL;
    params.action = action;
    params.sta = sta;
    params.tid = tid;
    params.ssn = &ssn;
    params.buf_size = window;
    return hw->ops->ampdu_action(hw, vif, &params);
}
int rtw88_tx_ampdu_start(struct ieee80211_vif *vif, struct ieee80211_sta *sta,
                         u8 tid, u16 window)
{
    return ampdu(vif, sta, tid, 0, window, IEEE80211_AMPDU_TX_OPERATIONAL);
}
void rtw88_tx_ampdu_stop(struct ieee80211_vif *vif, struct ieee80211_sta *sta, u8 tid)
{
    (void)ampdu(vif, sta, tid, 0, 0, IEEE80211_AMPDU_TX_STOP_FLUSH);
}
int rtw88_rx_ampdu_start(struct ieee80211_sta *sta, u8 tid, u16 ssn, u16 window)
{
    return ampdu(sta && tid < IEEE80211_NUM_TIDS && sta->txq[tid] ? sta->txq[tid]->vif : NULL,
                 sta, tid, ssn, window, IEEE80211_AMPDU_RX_START);
}
void rtw88_rx_ampdu_stop(struct ieee80211_sta *sta, u8 tid)
{
    (void)ampdu(sta && tid < IEEE80211_NUM_TIDS && sta->txq[tid] ? sta->txq[tid]->vif : NULL,
                sta, tid, 0, 0, IEEE80211_AMPDU_RX_STOP);
}

/* Share the station iteration lock with C2H RA updates and station teardown. */
#include "../../include/HAL/RTWTxRate.h"
static void copy_tx_rate(void *opaque, struct ieee80211_sta *sta)
{
    struct RTWTxRate *out = opaque;
    const struct rtw_sta_info *si = (const void *)sta->drv_priv;
    const struct rate_info *report = &si->ra_report.txrate;
    if (!si->ra_report.bit_rate) return;
    out->shortGI = (report->flags & RATE_INFO_FLAGS_SHORT_GI) != 0;
    out->guardIntervalNs = out->shortGI ? 400 : 800;
    if (report->flags & RATE_INFO_FLAGS_VHT_MCS) {
        out->mode = RTW_RATE_VHT;
        out->mcs = report->mcs;
        out->nss = report->nss;
    } else if (report->flags & RATE_INFO_FLAGS_MCS) {
        out->mode = RTW_RATE_HT;
        out->mcs = report->mcs;
        out->nss = report->mcs / 8 + 1;
    } else {
        out->mode = RTW_RATE_LEGACY;
        out->nss = 1;
        out->bitrate100Kbps = report->legacy;
    }
    switch (report->bw) {
    case RATE_INFO_BW_20: out->widthMHz = 20; break;
    case RATE_INFO_BW_40: out->widthMHz = 40; break;
    case RATE_INFO_BW_80: out->widthMHz = 80; break;
    case RATE_INFO_BW_160: out->widthMHz = 160; break;
    default: return;
    }
    out->bitrate100Kbps = rtw_tx_rate_calculate(out);
    out->valid = out->bitrate100Kbps != 0;
}

void rtw88_hw_get_tx_rate(struct ieee80211_hw *hw, struct RTWTxRate *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (hw) ieee80211_iterate_stations_atomic(hw, copy_tx_rate, out);
}
