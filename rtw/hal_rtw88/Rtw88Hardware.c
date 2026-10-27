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

#include "Rtw88CountryCodes.h"

#include "../../include/HAL/RTWLocale.h"

unsigned int airportrtw88_get_locale(struct ieee80211_hw *hw)
{
    const struct rtw_dev *dev = hw ? hw->priv : NULL;
    const struct rtw_regulatory *reg = dev ? dev->regd.regulatory : NULL;
    if (!reg || (reg->alpha2[0] == '0' && reg->alpha2[1] == '0')) return RTW_LOCALE_UNKNOWN;
    if (reg->txpwr_regd_2g != reg->txpwr_regd_5g) return RTW_LOCALE_ROW;
    switch (reg->txpwr_regd_2g) {
    case RTW_REGD_FCC: return RTW_LOCALE_FCC;
    case RTW_REGD_ETSI: case RTW_REGD_UK: return RTW_LOCALE_ETSI;
    case RTW_REGD_MKK: return RTW_LOCALE_JAPAN;
    case RTW_REGD_KCC: return RTW_LOCALE_KOREA;
    case RTW_REGD_WW: return RTW_LOCALE_UNKNOWN;
    default: return RTW_LOCALE_ROW;
    }
}

static bool country_known(const char cc[2])
{
    unsigned int i;
    if (!cc || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z')
        return false;
    for (i = 0; i < ARRAY_SIZE(rtw88_country_codes); ++i)
        if (!memcmp(rtw88_country_codes[i], cc, 2)) return true;
    return false;
}

/* Caller serializes with wiphy; notifier takes the device mutex itself.
 * mode: 0 restore world, 1 AP hint, 2 OS hint. Never relax channel flags.
 */
bool airportrtw88_apply_country(struct ieee80211_hw *hw, const char *cc, int mode)
{
    struct rtw_dev *dev;
    struct regulatory_request request = {0};
    const char world[2] = {'0', '0'};
    if (!hw || !hw->priv || !hw->wiphy || !hw->wiphy->reg_notifier ||
        mode < 0 || mode > 2) return false;
    dev = hw->priv;
    if (mode && !country_known(cc)) return false;
    if (!mode) cc = world;
    if (dev->regd.state == RTW_REGD_STATE_PROGRAMMED)
        return mode == 2 && dev->regd.regulatory &&
            !memcmp(dev->regd.regulatory->alpha2, cc, 2);
    if (mode != 2 && (dev->regd.state == RTW_REGD_STATE_SETTING ||
        (hw->wiphy->regulatory_flags & REGULATORY_COUNTRY_IE_IGNORE)))
        return false;
    request.alpha2[0] = cc[0]; request.alpha2[1] = cc[1];
    request.initiator = mode == 2 ? NL80211_REGDOM_SET_BY_USER :
        mode == 1 ? NL80211_REGDOM_SET_BY_COUNTRY_IE : NL80211_REGDOM_SET_BY_CORE;
    request.dfs_region = NL80211_DFS_UNSET;
    hw->wiphy->reg_notifier(hw->wiphy, &request);
    return dev->regd.regulatory && !memcmp(dev->regd.regulatory->alpha2, cc, 2);
}

/* Apply a programmed-domain hint after hardware start. */
int airportrtw88_apply_driver_hint(struct wiphy *wiphy, const char *cc)
{
    struct regulatory_request request = {0};
    if (!wiphy || !wiphy->reg_notifier || !country_known(cc)) return -EINVAL;
    request.alpha2[0] = cc[0]; request.alpha2[1] = cc[1];
    request.initiator = NL80211_REGDOM_SET_BY_DRIVER;
    request.dfs_region = NL80211_DFS_UNSET;
    wiphy->reg_notifier(wiphy, &request);
    return 0;
}

void airportrtw88_init_country(struct ieee80211_hw *hw)
{
    struct rtw_dev *dev = hw ? hw->priv : NULL;
    if (dev && dev->regd.state == RTW_REGD_STATE_PROGRAMMED)
        airportrtw88_apply_driver_hint(hw->wiphy, dev->efuse.country_code);
}

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
