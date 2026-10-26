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
