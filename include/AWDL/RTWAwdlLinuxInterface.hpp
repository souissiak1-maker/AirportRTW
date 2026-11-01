/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_LINUX_INTERFACE_HPP
#define RTW_AWDL_LINUX_INTERFACE_HPP
#include <HAL/RTWAwdlInterfaceState.hpp>
namespace RTWAwdl {
// Internal linkage is required: each HAL compiles different compat functions
// (RTW88 is namespaced). Cross-HAL weak-inline coalescing would be incorrect.
// Included after the HAL's Linux compat headers. Call under WiphyGuard; hardware
// must be running. The caller must stop all producers before remove. In
// particular this helper does not make outstanding TX/ROC callbacks safe.
static inline void removeLinuxInterface(ieee80211_hw *hw, InterfaceState &state)
{
    auto *vif = static_cast<ieee80211_vif *>(state.vif);
    if (!vif) return;
    if (state.registered) rtw88_remove_vif(vif);
    state.registered = false;
    if (state.hardwareAdded) hw->ops->remove_interface(hw, vif);
    state.hardwareAdded = false;
    synchronize_rcu(); // registered readers must finish before VIF reclamation
    if (vif->txq) IOFree(vif->txq, state.txqAllocationSize);
    IOFree(vif, state.allocationSize);
    state = {};
}
static inline bool addLinuxInterface(ieee80211_hw *hw, InterfaceState &state,
                             const uint8_t mac[6], const uint8_t primary[6],
                             bool needsTxq)
{
    if (!hw || !hw->ops || !hw->ops->add_interface ||
        !hw->ops->remove_interface ||
        (!hw->ops->link_info_changed && !hw->ops->bss_info_changed) ||
        state.vif || !mac || !primary ||
        (mac[0] & 1) || !memcmp(mac, primary, 6)) return false;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= mac[i];
    const size_t vifPrivateSize = hw->vif_data_size;
    const size_t txqPrivateSize = hw->txq_data_size;
    if (!bits || vifPrivateSize > SIZE_MAX - sizeof(ieee80211_vif) ||
        txqPrivateSize > SIZE_MAX - sizeof(ieee80211_txq)) return false;
    InterfaceState pending = {};
    pending.allocationSize = sizeof(ieee80211_vif) + hw->vif_data_size;
    pending.txqAllocationSize = sizeof(ieee80211_txq) + hw->txq_data_size;
    auto *vif = static_cast<ieee80211_vif *>(IOMallocZero(pending.allocationSize));
    if (!vif) return false;
    pending.vif = vif;
    vif->type = NL80211_IFTYPE_ADHOC;
    // AWDL uses action frames for synchronization, not ordinary IBSS beacons.
    vif->no_beacon = true;
    memcpy(vif->addr, mac, 6);
    memcpy(vif->bss_conf.addr, mac, 6);
    static const uint8_t bssid[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    memcpy(vif->bss_conf.bssid_buf, bssid, 6);
    vif->bss_conf.bssid = vif->bss_conf.bssid_buf;
    vif->link_conf[0] = &vif->bss_conf;
    vif->bss_conf.chandef_chan = hw->conf.chandef.chan;
    vif->bss_conf.chandef_width = hw->conf.chandef.width;
    if (needsTxq) {
        vif->txq = static_cast<ieee80211_txq *>(IOMallocZero(pending.txqAllocationSize));
        if (!vif->txq) { removeLinuxInterface(hw, pending); return false; }
        vif->txq->vif = vif; vif->txq->tid = 16; vif->txq->ac = 2;
    }
    if (hw->ops->add_interface(hw, vif)) {
        // Failed add_interface must unwind its own hardware allocations.
        removeLinuxInterface(hw, pending); return false;
    }
    pending.hardwareAdded = true;
    if (!rtw88_add_vif(vif)) { removeLinuxInterface(hw, pending); return false; }
    pending.registered = true;
    if (hw->ops->link_info_changed)
        hw->ops->link_info_changed(hw, vif, &vif->bss_conf, BSS_CHANGED_BSSID);
    else if (hw->ops->bss_info_changed)
        hw->ops->bss_info_changed(hw, vif, &vif->bss_conf, BSS_CHANGED_BSSID);
    state = pending;
    return true;
}
}
#endif
