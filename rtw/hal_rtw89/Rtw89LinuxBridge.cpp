/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "Rtw89LinuxBridge.hpp"
#include "Rtw89PciTransport.hpp"
#include "Rtw89RxLayout.hpp"
#include "Rtw89LinkPolicy.hpp"
#include <net80211/ieee80211_he_policy.hpp>

#include <IOKit/IOLib.h>

extern "C" {
#include "compat/rtw88_compat.h"
#include "compat/linux/pci.h"
#include "compat/net/mac80211.h"

int rtw_pci_probe(struct pci_dev *, const struct pci_device_id *);
void rtw_pci_remove(struct pci_dev *);
struct ieee80211_hw *rtw88_get_hw(void);
void rtw88_register_vif(struct ieee80211_vif *);
void rtw88_unregister_vif(void);
void rtw89_macos_flush_rx_ba(struct ieee80211_sta *);
void rtw89_macos_get_tx_rate(struct ieee80211_hw *, struct RTWTxRate *);
void rtw89_macos_peer_audit(struct ieee80211_hw *, struct ieee80211_vif *, uint32_t *);
}

namespace {
static Rtw89LinuxContext *activeContext;
static const size_t managementHeaderLength = 24;

static void resumeTransmit()
{
    if (activeContext && activeContext->txResume)
        activeContext->txResume(activeContext->nativeOwner);
}

static void receiveFrame(void *opaque, struct sk_buff *skb)
{
    auto *context = static_cast<Rtw89LinuxContext *>(opaque);
    if (!skb)
        return;
    struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
    if (context && context->traceReceive)
        context->traceReceive(context->nativeOwner, 1, skb->data, skb->len,
            (status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC)) ? 1 : 0);
    // Linux mac80211 removes the hardware FCS before handing frames to MLME.
    // Our bridge bypasses mac80211, so perform that step here. Otherwise the
    // CRC is parsed as trailing IEs and WCL rejects valid beacon results.
    auto *hw = context ? static_cast<struct ieee80211_hw *>(context->hardware) : nullptr;
    if (hw && ieee80211_hw_check(hw, RX_INCLUDES_FCS)) {
        const unsigned int fcsLength = 4;
        if (skb->len < 10 + fcsLength) {
            kfree_skb(skb);
            return;
        }
        skb_trim(skb, skb->len - fcsLength);
    }

    // Count only downlink data from our associated AP, addressed to this
    // station or a group. Global protected-frame counts include other BSSes.
    auto *vif = context ? static_cast<ieee80211_vif *>(context->vif) : nullptr;
    const bool connectionData = vif && vif->cfg.assoc && skb->len >= 24 &&
        (skb->data[0] & 0x0c) == 0x08 && (skb->data[1] & 3) == 2 &&
        !memcmp(skb->data + 10, vif->cfg.ap_addr, 6) &&
        ((skb->data[4] & 1) || !memcmp(skb->data + 4, vif->addr, 6));
    if (connectionData) {
        if (skb->data[1] & 0x40) {
            __sync_fetch_and_add(&context->rxConnectionProtectedCount, 1);
            if (!(status->flag & RX_FLAG_DECRYPTED))
                __sync_fetch_and_add(&context->rxConnectionUndecryptedCount, 1);
        }
        if (status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC))
            __sync_fetch_and_add(&context->rxConnectionInvalidCount, 1);
    }

    // rtw89 leaves both CCMP IV and MIC in hardware-decrypted data. The
    // net80211 hardware-decrypt path validates PN and removes the IV, but
    // explicitly requires the HAL to remove the MIC beforehand.
    if (context && skb->data && skb->len >= 24 &&
        !(status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC))) {
        if (status->flag & RX_FLAG_DECRYPTED) {
            __sync_fetch_and_add(&context->rxHardwareDecryptedCount, 1);
            if (!(status->flag & (RX_FLAG_IV_STRIPPED | RX_FLAG_MIC_STRIPPED)) &&
                (skb->data[0] & 0x0c) == 0x08 && (skb->data[1] & 0x40)) {
                const size_t headerLength = Rtw89Rx::dataHeaderLength(skb->data, skb->len);
                if (!headerLength || skb->len < headerLength + 4) {
                    kfree_skb(skb);
                    return;
                }
                {
                    unsigned keyID = skb->data[headerLength + 3] >> 6;
                    bool multicast = (skb->data[4] & 1) != 0;
                    auto key = static_cast<ieee80211_key_conf *>(context->keys[keyID + (multicast ? 0 : 6)]);
                    if (key && key->cipher == WLAN_CIPHER_SUITE_CCMP) {
                        Rtw89Rx::CCMPLayout layout;
                        if (!Rtw89Rx::ccmpLayout(skb->data, skb->len, layout)) {
                            kfree_skb(skb);
                            return;
                        }
                        skb_trim(skb, skb->len - 8);
                        status->flag |= RX_FLAG_MIC_STRIPPED;
                        __sync_fetch_and_add(&context->rxCCMPMICStrippedCount, 1);
                    }
                }
            }
        } else if (skb->data[1] & 0x40) {
            __sync_fetch_and_add(&context->rxProtectedSoftwareCount, 1);
        }
    }

    if (connectionData && !(status->flag &
        (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC)) &&
        (!(skb->data[1] & 0x40) || (status->flag & RX_FLAG_DECRYPTED))) {
        size_t payload = Rtw89Rx::dataHeaderLength(skb->data, skb->len);
        if ((skb->data[1] & 0x40) && !(status->flag & RX_FLAG_IV_STRIPPED)) {
            if (payload && skb->len >= payload + 4) {
                const unsigned keyID = skb->data[payload + 3] >> 6;
                auto *key = static_cast<ieee80211_key_conf *>(context->keys[
                    keyID + ((skb->data[4] & 1) ? 0 : 6)]);
                payload = key ? payload + key->iv_len : 0;
            } else {
                payload = 0;
            }
        }
        if (payload && skb->len >= payload + 8 &&
            !memcmp(skb->data + payload, "\xaa\xaa\x03\x00\x00\x00", 6)) {
            __sync_fetch_and_add(&context->rxConnectionSNAPCount, 1);
            const uint8_t *llc = skb->data + payload;
            if (llc[6] == 0x08 && llc[7] == 0x00 &&
                skb->len >= payload + 8 + 20) {
                const uint8_t *ip = llc + 8;
                const size_t ihl = (ip[0] & 15) * 4;
                if ((ip[0] >> 4) == 4 && ihl >= 20 && ip[9] == 17 &&
                    skb->len >= payload + 8 + ihl + 8 &&
                    ip[ihl] == 0 && ip[ihl + 1] == 67 &&
                    ip[ihl + 2] == 0 && ip[ihl + 3] == 68)
                    __sync_fetch_and_add(&context->rxConnectionDHCPCount, 1);
            }
        }
    }

    if (context && skb->data && skb->len >= sizeof(struct ieee80211_hdr)) {
        const struct ieee80211_hdr *header =
            reinterpret_cast<const struct ieee80211_hdr *>(skb->data);
        const uint16_t fc = le16_to_cpu(header->frame_control);
        if ((fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT) {
            const uint16_t subtype = fc & IEEE80211_FCTL_STYPE;
            if (subtype == IEEE80211_STYPE_AUTH)
                __sync_fetch_and_add(&context->authRxCount, 1);
            else if (subtype == IEEE80211_STYPE_ASSOC_RESP)
                __sync_fetch_and_add(&context->assocRxCount, 1);
            else if (subtype == IEEE80211_STYPE_ACTION &&
                     skb->len >= managementHeaderLength + 2) {
                const uint8_t *action = skb->data + managementHeaderLength;
                __sync_fetch_and_add(&context->actionRxCount, 1);
                context->lastActionRxCategory = action[0];
                context->lastActionRxCode = action[1];
                context->lastActionRxToken = skb->len > managementHeaderLength + 2
                    ? action[2] : 0xff;
                context->lastActionRxStatus = skb->len > managementHeaderLength + 4
                    ? (uint32_t)(action[3] | ((uint32_t)action[4] << 8)) : 0xffff;
            }
        }
    }
    if (context && context->receive && skb->data && skb->len >= 10 &&
        !(status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC))) {
        if (context->traceReceive)
            context->traceReceive(context->nativeOwner, 2, skb->data, skb->len, 0);
        context->receive(context->nativeOwner, skb->data, skb->len,
                         status->signal, status->freq,
                         (status->flag & RX_FLAG_DECRYPTED) != 0,
                         (status->flag & RX_FLAG_IV_STRIPPED) != 0);
    }
    kfree_skb(skb);
}

static void completeTransmit(void *opaque, struct sk_buff *skb)
{
    auto *context = static_cast<Rtw89LinuxContext *>(opaque);
    if (context && skb && skb->data &&
        skb->len >= sizeof(struct ieee80211_hdr)) {
        const struct ieee80211_hdr *header =
            reinterpret_cast<const struct ieee80211_hdr *>(skb->data);
        const uint16_t fc = le16_to_cpu(header->frame_control);
        const bool acked =
            (IEEE80211_SKB_CB(skb)->flags & IEEE80211_TX_STAT_ACK) != 0;
        if (skb->protocol == cpu_to_be16(ETH_P_PAE) && acked)
            __sync_fetch_and_add(&context->eapolTxAcked, 1);
        if (skb->pkt_type == 0xD0 && acked)
            __sync_fetch_and_add(&context->dhcpTxAckCount, 1);
        else if (skb->pkt_type == 0xA0 && acked)
            __sync_fetch_and_add(&context->arpTxAckCount, 1);
        if ((fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT) {
            const uint16_t subtype = fc & IEEE80211_FCTL_STYPE;
            if (subtype == IEEE80211_STYPE_AUTH) {
                __sync_fetch_and_add(&context->authTxCount, 1);
                if (acked)
                    __sync_fetch_and_add(&context->authTxAckCount, 1);
            } else if (subtype == IEEE80211_STYPE_ASSOC_REQ) {
                __sync_fetch_and_add(&context->assocTxCount, 1);
                if (acked)
                    __sync_fetch_and_add(&context->assocTxAckCount, 1);
            } else if (subtype == IEEE80211_STYPE_ACTION &&
                       skb->len >= managementHeaderLength + 2) {
                const uint8_t *action = skb->data + managementHeaderLength;
                __sync_fetch_and_add(&context->actionTxCount, 1);
                if (acked)
                    __sync_fetch_and_add(&context->actionTxAckCount, 1);
                context->lastActionTxCategory = action[0];
                context->lastActionTxCode = action[1];
                context->lastActionTxToken = skb->len > managementHeaderLength + 2
                    ? action[2] : 0xff;
                /* Preserve the complete nine-byte ADDBA request body and its
                 * decoded little-endian fields for read-only IORegistry
                 * diagnostics.  Do not alter or regenerate the frame. */
                if (action[0] == 3 && action[1] == 0 &&
                    skb->len >= managementHeaderLength + 9) {
                    uint64_t bytes0To7 = 0;
                    for (unsigned int i = 0; i < 8; i++)
                        bytes0To7 |= (uint64_t)action[i] << (i * 8);
                    context->lastAddbaTxBytes0To7 = bytes0To7;
                    context->lastAddbaTxByte8 = action[8];
                    context->lastAddbaTxParams =
                        (uint32_t)action[3] | ((uint32_t)action[4] << 8);
                    context->lastAddbaTxTimeout =
                        (uint32_t)action[5] | ((uint32_t)action[6] << 8);
                    context->lastAddbaTxStartSeqControl =
                        (uint32_t)action[7] | ((uint32_t)action[8] << 8);
                }
            }
        }
    }
    kfree_skb(skb);
}

static void completeScan(void *, bool) {}

static struct rtw88_hw_callbacks hardwareCallbacks = {
    receiveFrame, completeTransmit, completeScan
};

class WiphyGuard {
public:
    explicit WiphyGuard(struct ieee80211_hw *hardware) : hw(hardware)
    {
        if (hw && hw->wiphy && hw->wiphy->serialize_lock.m) {
            mutex_lock(&hw->wiphy->serialize_lock);
            locked = true;
        }
    }
    ~WiphyGuard()
    {
        if (locked)
            mutex_unlock(&hw->wiphy->serialize_lock);
    }
private:
    struct ieee80211_hw *hw;
    bool locked {false};
};

static struct ieee80211_channel *findChannel(struct ieee80211_hw *hw,
                                              uint16_t channel)
{
    if (!hw || !hw->wiphy)
        return nullptr;
    const enum nl80211_band band = channel <= 14 ? NL80211_BAND_2GHZ
                                                  : NL80211_BAND_5GHZ;
    struct ieee80211_supported_band *supported = hw->wiphy->bands[band];
    if (!supported)
        return nullptr;
    for (int index = 0; index < supported->n_channels; ++index) {
        if (supported->channels[index].hw_value == channel)
            return &supported->channels[index];
    }
    return nullptr;
}

static void releaseStation(Rtw89LinuxContext *context)
{
    if (!context) return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    WiphyGuard guard(hw);
    if (!context->station) return;
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    auto *sta = static_cast<struct ieee80211_sta *>(context->station);
    rtw88_unregister_sta();
    // Linux mac80211 stops every RX BA session before sta_state teardown.
    // The native bridge owns that ordering: CAM entries live in the device
    // but their list head lives inside sta. Never free sta with entries linked.
    if (context->stationState >= IEEE80211_STA_NONE)
        rtw89_macos_flush_rx_ba(sta);
    if (hw && hw->ops && vif && hw->ops->sta_state) {
        while (context->stationState > IEEE80211_STA_NOTEXIST) {
            auto oldState = static_cast<ieee80211_sta_state>(context->stationState);
            auto nextState = static_cast<ieee80211_sta_state>(context->stationState - 1);
            hw->ops->sta_state(hw, vif, sta, oldState, nextState);
            context->stationState = nextState;
        }
    }
    IOFree(sta, context->stationAllocationSize);
    context->station = nullptr;
    context->stationAllocationSize = 0;
    context->stationState = IEEE80211_STA_NOTEXIST;
}
}

extern "C" void rtw89_macos_trace_rx(const uint8_t *frame, size_t length, unsigned flags)
{
    if (activeContext && activeContext->traceReceive)
        activeContext->traceReceive(activeContext->nativeOwner, 0, frame, length, flags);
}

bool rtw89LinuxAttach(Rtw89PciTransport *transport,
                      Rtw89LinuxContext *context)
{
    if (!transport || !context)
        return false;
    bzero(context, sizeof(*context));
    struct ieee80211_hw *hw = nullptr;
    struct ieee80211_vif *vif = nullptr;

    RTW_LOG("AirportRTW-RTW89: entering rtw89 PCI probe\n");
    transport->recordAttachStage("rtw_pci_probe");
    const int probeResult = rtw_pci_probe(transport->linuxDevice(), nullptr);
    transport->recordProbeResult(probeResult);
    if (probeResult != 0) {
        RTW_LOG("AirportRTW-RTW89: rtw89 PCI probe failed\n");
        return false;
    }
    RTW_LOG("AirportRTW-RTW89: rtw89 PCI probe returned successfully\n");
    context->probed = true;

    transport->recordAttachStage("Linux hardware/ops/wiphy validation");
    hw = rtw88_get_hw();
    if (!hw || !hw->ops || !hw->wiphy)
        goto fail;
    context->hardware = hw;
    context->device = hw->priv;
    rtw88_set_hw_callbacks(&hardwareCallbacks, context);
    activeContext = context;
    rtw88_set_tx_resume_cb(resumeTransmit);
    rtw88_force_wifi_only();
    memcpy(context->macAddress, hw->wiphy->perm_addr,
           sizeof(context->macAddress));

    /* Probe establishes the PCI/core object and permanent MAC address.
     * Keep firmware/MAC start and interface creation paired with enable(),
     * so an attached but administratively-down interface leaves hardware
     * quiesced and sleep/wake can reuse the same symmetric path. */
    context->vifAllocationSize = sizeof(struct ieee80211_vif) +
                                 hw->vif_data_size;
    transport->recordAttachStage("station vif allocation");
    vif = static_cast<struct ieee80211_vif *>(
        IOMallocZero(context->vifAllocationSize));
    if (!vif)
        goto fail;
    context->vif = vif;
    vif->type = NL80211_IFTYPE_STATION;
    memcpy(vif->addr, context->macAddress, sizeof(vif->addr));
    memcpy(vif->bss_conf.addr, context->macAddress,
           sizeof(vif->bss_conf.addr));
    vif->bss_conf.bssid = vif->bss_conf.bssid_buf;
    vif->link_conf[0] = &vif->bss_conf;

    return true;

fail:
    rtw89LinuxDetach(transport, context);
    return false;
}

void rtw89LinuxDetach(Rtw89PciTransport *transport,
                      Rtw89LinuxContext *context)
{
    if (!context)
        return;
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);

    rtw89LinuxPowerDown(context);

    if (vif) {
        IOFree(vif, context->vifAllocationSize);
        context->vif = nullptr;
        context->vifAllocationSize = 0;
    }
    if (context->probed && transport)
        rtw_pci_remove(transport->linuxDevice());
    context->probed = false;
    context->hardware = nullptr;
    context->device = nullptr;
    rtw88_set_tx_resume_cb(nullptr);
    if (activeContext == context)
        activeContext = nullptr;
    rtw88_set_hw_callbacks(nullptr, nullptr);
    bzero(context->macAddress, sizeof(context->macAddress));
}

bool rtw89LinuxSetMacAddress(Rtw89LinuxContext *context, const uint8_t address[6])
{
    if (!context || !address || context->started || context->interfaceAdded ||
        (address[0] & 1))
        return false;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i)
        bits |= address[i];
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!bits || !vif)
        return false;
    // add_interface copies these into the device's MAC table. The immutable
    // context->macAddress remains the permanent address read from efuse.
    memcpy(vif->addr, address, sizeof(vif->addr));
    memcpy(vif->bss_conf.addr, address, sizeof(vif->bss_conf.addr));
    return true;
}

bool rtw89LinuxPowerUp(Rtw89LinuxContext *context)
{
    if (!context)
        return false;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!hw || !hw->ops || !vif)
        return false;
    if (!context->started) {
        RTW_LOG("AirportRTW-RTW89: hardware start callback begin\n");
        WiphyGuard guard(hw);
        if (!hw->ops->start || hw->ops->start(hw) != 0) {
            RTW_LOG("AirportRTW-RTW89: hardware start callback failed\n");
            return false;
        }
        context->started = true;
        RTW_LOG("AirportRTW-RTW89: hardware start callback complete\n");
    }
    if (!context->interfaceAdded) {
        RTW_LOG("AirportRTW-RTW89: add-interface callback begin\n");
        int result;
        {
            WiphyGuard guard(hw);
            result = hw->ops->add_interface ? hw->ops->add_interface(hw, vif)
                                            : -EOPNOTSUPP;
        }
        if (result != 0) {
            RTW_LOG("AirportRTW-RTW89: add-interface callback failed (%d)\n",
                  result);
            if (hw->ops->stop) {
                WiphyGuard guard(hw);
                hw->ops->stop(hw, false);
            }
            context->started = false;
            return false;
        }
        rtw88_register_vif(vif);
        context->interfaceAdded = true;
        RTW_LOG("AirportRTW-RTW89: add-interface callback complete\n");
    }
    return true;
}

void rtw89LinuxPowerDown(Rtw89LinuxContext *context)
{
    if (!context)
        return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (context->scanning)
        rtw89LinuxScanEnd(context);
    rtw89LinuxDisassociate(context);
    if (context->interfaceAdded && hw && hw->ops && vif) {
        rtw88_unregister_vif();
        if (hw->ops->remove_interface) {
            WiphyGuard guard(hw);
            hw->ops->remove_interface(hw, vif);
        }
        context->interfaceAdded = false;
    }
    if (context->started && hw && hw->ops && hw->ops->stop) {
        WiphyGuard guard(hw);
        hw->ops->stop(hw, false);
        context->started = false;
    }
}

bool rtw89LinuxTransmit(Rtw89LinuxContext *context, const uint8_t *frame,
                        size_t length, bool management, bool softwareEncrypted)
{
    if (!context || !frame || length < sizeof(struct ieee80211_hdr) ||
        length > 4096)
        return false;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    auto *sta = static_cast<struct ieee80211_sta *>(context->station);
    if (!hw || !hw->ops || !hw->ops->tx || !vif)
        return false;

    const struct ieee80211_hdr *header =
        reinterpret_cast<const struct ieee80211_hdr *>(frame);
    const uint16_t frameControl = le16_to_cpu(header->frame_control);
    const bool data = (frameControl & IEEE80211_FCTL_FTYPE) ==
                      IEEE80211_FTYPE_DATA;
    if (data && memcmp(header->addr2, vif->addr, ETH_ALEN))
        __sync_fetch_and_add(&context->txAddressMismatchCount, 1);
    const bool qos = data && ieee80211_is_data_qos(header->frame_control);
    const size_t qosOffset = 24 +
        (((frameControl & IEEE80211_FCTL_TODS) &&
          (frameControl & IEEE80211_FCTL_FROMDS)) ? 6 : 0);
    const uint8_t tid = qos && length > qosOffset ? frame[qosOffset] & 0x0f : 0;
    static const uint8_t tidToAccessClass[8] = {2, 3, 3, 2, 1, 1, 0, 0};

    size_t headerLength = 24;
    if ((frameControl & IEEE80211_FCTL_TODS) &&
        (frameControl & IEEE80211_FCTL_FROMDS))
        headerLength += 6;
    if (qos)
        headerLength += 2;
    const bool eapol = data && length >= headerLength + 8 &&
        frame[headerLength] == 0xaa && frame[headerLength + 1] == 0xaa &&
        frame[headerLength + 2] == 0x03 && frame[headerLength + 6] == 0x88 &&
        frame[headerLength + 7] == 0x8e;
    uint16_t etherType = 0;
    if (data && length >= headerLength + 8 &&
        frame[headerLength] == 0xaa && frame[headerLength + 1] == 0xaa &&
        frame[headerLength + 2] == 0x03) {
        etherType = (uint16_t)((frame[headerLength + 6] << 8) |
                               frame[headerLength + 7]);
    }
    const bool arp = etherType == ETH_P_ARP;
    bool dhcp = false;
    if (etherType == ETH_P_IP && length >= headerLength + 8 + 20) {
        const size_t ipOffset = headerLength + 8;
        const size_t ipHeaderLength = (frame[ipOffset] & 0x0fU) * 4U;
        const size_t udpOffset = ipOffset + ipHeaderLength;
        if (ipHeaderLength >= 20 && frame[ipOffset + 9] == 17 &&
            length >= udpOffset + 8) {
            const uint16_t sourcePort =
                (uint16_t)((frame[udpOffset] << 8) | frame[udpOffset + 1]);
            const uint16_t destinationPort =
                (uint16_t)((frame[udpOffset + 2] << 8) |
                           frame[udpOffset + 3]);
            dhcp = (sourcePort == 67 || sourcePort == 68) &&
                   (destinationPort == 67 || destinationPort == 68);
        }
    }

    struct ieee80211_key_conf *txKey = nullptr;
    if ((frameControl & IEEE80211_FCTL_PROTECTED) && !softwareEncrypted) {
        const bool multicast = is_multicast_ether_addr(header->addr1);
        const uint8_t first = multicast ? 0 : 6;
        const uint8_t last = multicast ? 6 : 12;
        for (uint8_t slot = first; slot < last; ++slot) {
            if (context->keys[slot]) {
                txKey = static_cast<struct ieee80211_key_conf *>(
                    context->keys[slot]);
                break;
            }
        }
        if (!txKey)
            return false;
    }

    /* mac80211 reserves cipher IV bytes before handing a protected frame to
     * drivers whose key advertises GENERATE_IV.  This native bridge receives
     * an OpenBSD net80211 frame without that reservation, so create it here;
     * RTL8852A then fills the CCMP/TKIP/WEP header during hardware TX. */
    const size_t ivLength = txKey &&
        (txKey->flags & IEEE80211_KEY_FLAG_GENERATE_IV) ? txKey->iv_len : 0;
    if (data)
        __sync_fetch_and_add(&context->dataTxCount, 1);
    if (txKey) {
        __sync_fetch_and_add(&context->protectedTxCount, 1);
        context->lastTxCipher = txKey->cipher;
        context->lastTxKeyIndex = (uint32_t)(uint8_t)txKey->keyidx;
        context->lastTxIvLength = (uint32_t)ivLength;
    }
    if (length + ivLength > 4096)
        return false;
    struct sk_buff *skb = alloc_skb((u32)(length + ivLength) + 128,
                                    GFP_ATOMIC);
    if (!skb)
        return false;
    skb_reserve(skb, 128);
    if (ivLength) {
        skb_put_data(skb, frame, (u32)headerLength);
        uint8_t *iv = skb_put(skb, (u32)ivLength);
        memset(iv, 0, ivLength);
        if (txKey->cipher == WLAN_CIPHER_SUITE_CCMP && ivLength == 8) {
            const uint64_t pn = (uint64_t)atomic64_inc_return(&txKey->tx_pn);
            iv[0] = (uint8_t)pn;
            iv[1] = (uint8_t)(pn >> 8);
            iv[2] = 0;
            iv[3] = (uint8_t)(0x20 | ((txKey->keyidx & 3) << 6));
            iv[4] = (uint8_t)(pn >> 16);
            iv[5] = (uint8_t)(pn >> 24);
            iv[6] = (uint8_t)(pn >> 32);
            iv[7] = (uint8_t)(pn >> 40);
        }
        skb_put_data(skb, frame + headerLength,
                     (u32)(length - headerLength));
    } else {
        skb_put_data(skb, frame, (u32)length);
    }
    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->flags = IEEE80211_TX_CTL_FIRST_FRAGMENT;
    info->control.vif = vif;
    info->control.hw_key = txKey;
    info->band = hw->conf.chandef.chan ? hw->conf.chandef.chan->band : 0;
    skb->protocol = cpu_to_be16(etherType);
    if (dhcp) {
        skb->pkt_type = 0xD0;
        info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
        __sync_fetch_and_add(&context->dhcpTxCount, 1);
    } else if (arp) {
        skb->pkt_type = 0xA0;
        info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
        __sync_fetch_and_add(&context->arpTxCount, 1);
    }
    skb->priority = tid;
    skb_set_queue_mapping(skb, tidToAccessClass[tid & 7]);
    if (eapol) {
        // Local experiment: normal control-port descriptors rather than
        // injected-frame rate overrides. Keep protocol classification so the
        // core uses its EAPOL queue and excludes HE HTC and aggregation.
        info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS |
                       IEEE80211_TX_CTL_USE_MINRATE;
        info->control.flags |= IEEE80211_TX_CTRL_PORT_CTRL_PROTO;
        __sync_fetch_and_add(&context->eapolTxSubmitted, 1);
    }

    info->control.sta = management ? nullptr : sta;
    if (!eapol && qos && (context->txAmpduMask & (1U << tid)))
        info->flags |= IEEE80211_TX_CTL_AMPDU;
    struct ieee80211_tx_control control = {};
    control.sta = management ? nullptr : sta;
    hw->ops->tx(hw, &control, skb);
    return true;
}

bool rtw89LinuxTxAvailable(Rtw89LinuxContext *context)
{
    return rtw89LinuxTxAvailableSlots(context) > 4;
}

unsigned int rtw89LinuxTxAvailableSlots(Rtw89LinuxContext *context)
{
    return context && context->started ? rtw88_be_tx_avail() : 0;
}

bool rtw89LinuxAmpduStart(Rtw89LinuxContext *context, uint8_t tid,
                          bool receive, uint16_t sequence, uint16_t window)
{
    if (!context) return false;
    WiphyGuard guard(static_cast<struct ieee80211_hw *>(context->hardware));
    if (!context->vif || !context->station || tid >= 16)
        return false;
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    auto *sta = static_cast<struct ieee80211_sta *>(context->station);
    const bool success = receive
        ? rtw88_rx_ampdu_start(sta, tid, sequence, window) == 0
        : rtw88_tx_ampdu_start(vif, sta, tid, window) == 0;
    if (receive) {
        __sync_fetch_and_add(success ? &context->ampduRxStartCount
                                     : &context->ampduRxStartFailCount, 1);
    } else {
        __sync_fetch_and_add(success ? &context->ampduTxStartCount
                                     : &context->ampduTxStartFailCount, 1);
    }
    if (success && !receive)
        context->txAmpduMask |= (uint16_t)(1U << tid);
    return success;
}

void rtw89LinuxAmpduStop(Rtw89LinuxContext *context, uint8_t tid,
                         bool receive)
{
    if (!context) return;
    WiphyGuard guard(static_cast<struct ieee80211_hw *>(context->hardware));
    if (!context->vif || !context->station || tid >= 16)
        return;
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    auto *sta = static_cast<struct ieee80211_sta *>(context->station);
    if (receive)
    {
        rtw88_rx_ampdu_stop(sta, tid);
        __sync_fetch_and_add(&context->ampduRxStopCount, 1);
    }
    else {
        rtw88_tx_ampdu_stop(vif, sta, tid);
        context->txAmpduMask &= (uint16_t)~(1U << tid);
        __sync_fetch_and_add(&context->ampduTxStopCount, 1);
    }
}

bool rtw89LinuxConfigureQueue(Rtw89LinuxContext *context, uint8_t accessClass,
                              uint16_t cwMin, uint16_t cwMax, uint8_t aifs,
                              uint16_t txop, const uint8_t *muEdca)
{
    if (!context || accessClass >= 4)
        return false;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!hw || !vif || !hw->ops || !hw->ops->conf_tx)
        return false;
    struct ieee80211_tx_queue_params params = {};
    params.cw_min = cwMin;
    params.cw_max = cwMax;
    params.aifs = aifs;
    params.txop = txop;
    params.mu_edca = muEdca != nullptr;
    if (muEdca) memcpy(&params.mu_edca_param_rec, muEdca, 3);
    WiphyGuard guard(hw);
    return hw->ops->conf_tx(hw, vif, 0, accessClass, &params) == 0;
}

void rtw89LinuxUpdateSlot(Rtw89LinuxContext *context, bool shortSlot)
{
    if (!context)
        return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!hw || !vif || !hw->ops)
        return;
    vif->bss_conf.use_short_slot = shortSlot;
    WiphyGuard guard(hw);
    if (hw->ops->link_info_changed)
        hw->ops->link_info_changed(hw, vif, &vif->bss_conf,
                                   BSS_CHANGED_ERP_SLOT);
    else if (hw->ops->bss_info_changed)
        hw->ops->bss_info_changed(hw, vif, &vif->bss_conf,
                                  BSS_CHANGED_ERP_SLOT);
}

void rtw89LinuxSetAllMulticast(Rtw89LinuxContext *context, bool enabled)
{
    if (!context)
        return;
    context->allMulticast = enabled;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    if (!hw || !hw->ops || !hw->ops->configure_filter)
        return;
    unsigned int flags = enabled ? FIF_ALLMULTI : 0;
    WiphyGuard guard(hw);
    hw->ops->configure_filter(hw, FIF_ALLMULTI, &flags, 0);
}

bool rtw89LinuxSetChannel(Rtw89LinuxContext *context, uint16_t channel)
{
    if (!context)
        return false;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    struct ieee80211_channel *target = findChannel(hw, channel);
    if (!hw || !target)
        return false;

    target->band = channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
    hw->conf.chandef.chan = target;
    hw->conf.chandef.width = NL80211_CHAN_WIDTH_20;
    hw->conf.chandef.center_freq1 = target->center_freq;
    hw->conf.chandef.center_freq2 = 0;
    WiphyGuard guard(hw);
    rtw88_sw_scan_switch_channel(hw);
    return true;
}

bool rtw89LinuxPrepareConnection(Rtw89LinuxContext *context,
                                 const uint8_t bssid[6], uint16_t channel)
{
    if (!context || !bssid)
        return false;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    struct ieee80211_channel *target = findChannel(hw, channel);
    if (!hw || !vif || !target)
        return false;
    // A new authentication attempt owns a fresh station. Retrying or switching
    // peers must unwind only the firmware states actually reached.
    rtw89LinuxDisassociate(context);
    target->band = channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
    hw->conf.chandef.chan = target;
    hw->conf.chandef.width = NL80211_CHAN_WIDTH_20;
    hw->conf.chandef.center_freq1 = target->center_freq;
    hw->conf.chandef.center_freq2 = 0;
    rtw88_connect_hw_setup(hw, vif, bssid);
    vif->bss_conf.bssid = vif->bss_conf.bssid_buf;
    memcpy(vif->bss_conf.bssid_buf, bssid, ETH_ALEN);
    memcpy(vif->cfg.ap_addr, bssid, ETH_ALEN);
    context->stationAllocationSize = sizeof(struct ieee80211_sta) + hw->sta_data_size;
    auto *sta = static_cast<ieee80211_sta *>(IOMallocZero(context->stationAllocationSize));
    if (!sta) {
        context->stationAllocationSize = 0;
        return false;
    }
    context->station = sta;
    context->stationState = IEEE80211_STA_NOTEXIST;
    memcpy(sta->addr, bssid, ETH_ALEN);
    sta->link[0] = &sta->deflink;
    sta->deflink.sta = sta;
    memcpy(sta->deflink.addr, bssid, ETH_ALEN);
    sta->deflink.supp_rates[NL80211_BAND_2GHZ] = 0xfff;
    sta->deflink.supp_rates[NL80211_BAND_5GHZ] = 0xff;
    sta->deflink.rx_nss = 1;
    sta->deflink.bandwidth = IEEE80211_STA_RX_BW_20;
    int result;
    {
        WiphyGuard guard(hw);
        result = hw->ops && hw->ops->sta_state ?
            hw->ops->sta_state(hw, vif, sta, IEEE80211_STA_NOTEXIST,
                               IEEE80211_STA_NONE) : -EOPNOTSUPP;
        if (!result) context->stationState = IEEE80211_STA_NONE;
    }
    if (result) {
        releaseStation(context);
        return false;
    }
    rtw88_register_sta(sta);
    return true;
}

bool rtw89LinuxAuthenticateStation(Rtw89LinuxContext *context)
{
    if (!context || !context->station) return false;
    auto *hw = static_cast<ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<ieee80211_vif *>(context->vif);
    WiphyGuard guard(hw);
    if (context->stationState == IEEE80211_STA_AUTH) return true;
    if (!hw || !hw->ops || !hw->ops->sta_state ||
        context->stationState != IEEE80211_STA_NONE) return false;
    int result = hw->ops->sta_state(hw, vif,
        static_cast<ieee80211_sta *>(context->station),
        IEEE80211_STA_NONE, IEEE80211_STA_AUTH);
    if (!result) context->stationState = IEEE80211_STA_AUTH;
    return result == 0;
}

void rtw89LinuxScanBegin(Rtw89LinuxContext *context)
{
    if (!context)
        return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!hw || !vif)
        return;
    WiphyGuard guard(hw);
    if (hw->ops && hw->ops->configure_filter) {
        unsigned int flags = FIF_OTHER_BSS | FIF_BCN_PRBRESP_PROMISC |
                             (context->allMulticast ? FIF_ALLMULTI : 0);
        hw->ops->configure_filter(hw,
                                  FIF_OTHER_BSS | FIF_BCN_PRBRESP_PROMISC,
                                  &flags, 0);
    }
    rtw88_sw_scan_start(hw, vif);
    context->scanning = true;
}

void rtw89LinuxScanEnd(Rtw89LinuxContext *context)
{
    if (!context)
        return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!hw || !vif || !context->scanning)
        return;
    WiphyGuard guard(hw);
    rtw88_sw_scan_complete(hw, vif);
    if (hw->ops && hw->ops->configure_filter) {
        unsigned int flags = context->allMulticast ? FIF_ALLMULTI : 0;
        hw->ops->configure_filter(hw,
                                  FIF_OTHER_BSS | FIF_BCN_PRBRESP_PROMISC,
                                  &flags, 0);
    }
    context->scanning = false;
}

bool rtw89LinuxIsScanning(Rtw89LinuxContext *context)
{
    return context && rtw88_is_scanning();
}

void rtw89LinuxGetTxRate(Rtw89LinuxContext *context, RTWTxRate &rate)
{
    rate = {};
    auto *hw = context ? static_cast<ieee80211_hw *>(context->hardware) : nullptr;
    if (hw) rtw89_macos_get_tx_rate(hw, &rate);
}

bool rtw89LinuxGetCapabilities(Rtw89LinuxContext *context, bool fiveGHz,
                               Rtw89NativeCapabilities &caps)
{
    caps = {};
    auto *hw = context ? static_cast<ieee80211_hw *>(context->hardware) : nullptr;
    auto *band = hw && hw->wiphy ? hw->wiphy->bands[
        fiveGHz ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ] : nullptr;
    if (!band) return false;
    caps.ht = band->ht_cap.ht_supported;
    caps.htCaps = band->ht_cap.cap;
    caps.ampduParams = band->ht_cap.ampdu_factor |
                      (band->ht_cap.ampdu_density << 2);
    memcpy(caps.htMCS, band->ht_cap.mcs.rx_mask, sizeof(caps.htMCS));
    caps.vht = band->vht_cap.vht_supported;
    caps.vhtCaps = band->vht_cap.cap;
    caps.vhtRxMCS = le16_to_cpu(band->vht_cap.vht_mcs.rx_mcs_map);
    caps.vhtTxMCS = le16_to_cpu(band->vht_cap.vht_mcs.tx_mcs_map);
    const auto *he = ieee80211_get_he_iftype_cap(band, NL80211_IFTYPE_STATION);
    if (he && he->has_he) {
        caps.he = true;
        memcpy(caps.heMAC, he->he_cap_elem.mac_cap_info, sizeof(caps.heMAC));
        memcpy(caps.hePHY, he->he_cap_elem.phy_cap_info, sizeof(caps.hePHY));
        // This bridge supports contiguous channels up to 80 MHz.
        caps.hePHY[0] &= ~(0x08 | 0x10);
        caps.heRxMCS80 = le16_to_cpu(he->he_mcs_nss_supp.rx_mcs_80);
        caps.heTxMCS80 = le16_to_cpu(he->he_mcs_nss_supp.tx_mcs_80);
        memcpy(caps.hePPE, he->ppe_thres, sizeof(caps.hePPE));
    }
    return true;
}

bool rtw89LinuxAssociate(Rtw89LinuxContext *context,
                         const uint8_t bssid[6], uint16_t aid,
                         uint16_t capability, uint16_t channel,
                         uint16_t beaconInterval, uint8_t dtimPeriod,
                         bool qos, bool ht, bool vht, uint8_t rxNss,
                         const Rtw89NativePeer &peer)
{
    if (!context || !bssid || aid == 0 || aid > 2007)
        return false;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (!hw || !hw->ops || !hw->ops->sta_state || !vif ||
        !Rtw89Link::validChannel(channel == 14 ? 2484 :
            channel <= 13 ? 2407 + channel * 5 : 5000 + channel * 5,
            peer.centerFrequency, peer.widthMHz) ||
        !context->station || context->stationState != IEEE80211_STA_AUTH ||
        memcmp(static_cast<ieee80211_sta *>(context->station)->addr, bssid, ETH_ALEN))
        return false;

    // Preserve the station prepared before authentication. Only the negotiated
    // width and peer capabilities change here; do not recalibrate/recreate it.
    hw->conf.chandef.width = peer.widthMHz == 80 ? NL80211_CHAN_WIDTH_80 :
        peer.widthMHz == 40 ? NL80211_CHAN_WIDTH_40 : NL80211_CHAN_WIDTH_20;
    hw->conf.chandef.center_freq1 = peer.centerFrequency;
    if (hw->conf.chandef.width != NL80211_CHAN_WIDTH_20 ||
        hw->conf.chandef.center_freq1 != hw->conf.chandef.chan->center_freq)
        rtw88_connect_hw_setup(hw, vif, bssid);
    auto *sta = static_cast<ieee80211_sta *>(context->station);
    sta->aid = aid;
    sta->wme = qos;
    sta->deflink.bandwidth = peer.widthMHz == 80 ? IEEE80211_STA_RX_BW_80 :
        peer.widthMHz == 40 ? IEEE80211_STA_RX_BW_40 : IEEE80211_STA_RX_BW_20;
    sta->deflink.rx_nss = rxNss ? rxNss : 1;
    const enum nl80211_band band = channel <= 14 ? NL80211_BAND_2GHZ
                                                  : NL80211_BAND_5GHZ;
    struct ieee80211_supported_band *supported = hw->wiphy->bands[band];
    if (supported && ht) {
        sta->deflink.ht_cap = supported->ht_cap;
        sta->deflink.ht_cap.cap &= peer.caps.htCaps;
        sta->deflink.ht_cap.ampdu_factor = peer.caps.ampduParams & 3;
        sta->deflink.ht_cap.ampdu_density = (peer.caps.ampduParams >> 2) & 7;
        if (sta->deflink.ht_cap.ampdu_factor > supported->ht_cap.ampdu_factor)
            sta->deflink.ht_cap.ampdu_factor = supported->ht_cap.ampdu_factor;
        if (sta->deflink.ht_cap.ampdu_density < supported->ht_cap.ampdu_density)
            sta->deflink.ht_cap.ampdu_density = supported->ht_cap.ampdu_density;
        memcpy(sta->deflink.ht_cap.mcs.rx_mask, peer.caps.htMCS,
               sizeof(peer.caps.htMCS));
        for (unsigned i = 0; i < sizeof(peer.caps.htMCS); ++i)
            sta->deflink.ht_cap.mcs.rx_mask[i] &= supported->ht_cap.mcs.rx_mask[i];
        unsigned nss = 1;
        for (unsigned i = 0; i < 4; ++i)
            if (sta->deflink.ht_cap.mcs.rx_mask[i]) nss = i + 1;
        if (sta->deflink.rx_nss > nss) sta->deflink.rx_nss = nss;
    }
    if (supported && vht) {
        sta->deflink.vht_cap = supported->vht_cap;
        sta->deflink.vht_cap.cap &= peer.caps.vhtCaps;
        sta->deflink.vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(Rtw89Link::intersectMCS(
            le16_to_cpu(supported->vht_cap.vht_mcs.tx_mcs_map), peer.caps.vhtRxMCS));
        sta->deflink.vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(Rtw89Link::intersectMCS(
            le16_to_cpu(supported->vht_cap.vht_mcs.rx_mcs_map), peer.caps.vhtTxMCS));
    }
    if (peer.caps.he) {
        const auto *own = ieee80211_get_he_iftype_cap(supported, NL80211_IFTYPE_STATION);
        if (!own || !own->has_he || !Net80211HE::ratesValid(
            le16_to_cpu(own->he_mcs_nss_supp.rx_mcs_80),
            le16_to_cpu(own->he_mcs_nss_supp.tx_mcs_80),
            peer.caps.heRxMCS80, peer.caps.heTxMCS80, peer.heBasicMCS)) {
            releaseStation(context);
            return false;
        }
        auto &he = sta->deflink.he_cap;
        he.has_he = true;
        memcpy(he.he_cap_elem.mac_cap_info, peer.caps.heMAC, sizeof(peer.caps.heMAC));
        memcpy(he.he_cap_elem.phy_cap_info, peer.caps.hePHY, sizeof(peer.caps.hePHY));
        he.he_cap_elem.phy_cap_info[0] &= ~(0x08 | 0x10);
        he.he_mcs_nss_supp.rx_mcs_80 = cpu_to_le16(Net80211HE::intersect(
            le16_to_cpu(own->he_mcs_nss_supp.tx_mcs_80), peer.caps.heRxMCS80));
        he.he_mcs_nss_supp.tx_mcs_80 = cpu_to_le16(Net80211HE::intersect(
            le16_to_cpu(own->he_mcs_nss_supp.rx_mcs_80), peer.caps.heTxMCS80));
        he.he_mcs_nss_supp.rx_mcs_160 = he.he_mcs_nss_supp.tx_mcs_160 = cpu_to_le16(0xffff);
        he.he_mcs_nss_supp.rx_mcs_80p80 = he.he_mcs_nss_supp.tx_mcs_80p80 = cpu_to_le16(0xffff);
        memcpy(he.ppe_thres, peer.caps.hePPE, sizeof(peer.caps.hePPE));
        sta->deflink.rx_nss = Net80211HE::streams(le16_to_cpu(he.he_mcs_nss_supp.rx_mcs_80));
    }
    vif->bss_conf.he_support = sta->deflink.he_cap.has_he;
    vif->bss_conf.he_oper.params = peer.caps.he ? peer.heOperation : 0;
    vif->bss_conf.he_oper.nss_set = peer.caps.he ? peer.heBasicMCS : 0;
    vif->bss_conf.he_bss_color.color = (peer.heOperation >> 24) & 0x3f;
    vif->bss_conf.he_bss_color.partial = peer.caps.he && (peer.heOperation & (1U << 30));
    vif->bss_conf.he_bss_color.enabled = peer.caps.he && !(peer.heOperation & (1U << 31));
    vif->bss_conf.htc_trig_based_pkt_ext = peer.caps.he ? peer.heOperation & 7 : 0;
    vif->bss_conf.frame_time_rts_th = peer.caps.he ? (peer.heOperation >> 4) & 0x3ff : 0;
    // HE association callbacks consume the operating channel request.
    vif->bss_conf.chanreq.oper = hw->conf.chandef;
    vif->bss_conf.chandef_chan = hw->conf.chandef.chan;
    vif->bss_conf.chandef_width = hw->conf.chandef.width;

    int result = 0;
    {
        WiphyGuard guard(hw);
        result = hw->ops->sta_state(hw, vif, sta, IEEE80211_STA_AUTH,
                                    IEEE80211_STA_ASSOC);
        if (!result) context->stationState = IEEE80211_STA_ASSOC;
    }
    if (result) {
        releaseStation(context);
        return false;
    }
    struct ieee80211_bss_conf *bss = &vif->bss_conf;
    bss->assoc = true;
    bss->aid = aid;
    bss->qos = qos;
    bss->assoc_capability = capability;
    bss->use_short_preamble = (capability & 0x0020) != 0;
    bss->use_short_slot = (capability & 0x0400) != 0;
    bss->bssid = bss->bssid_buf;
    memcpy(bss->bssid_buf, bssid, ETH_ALEN);
    bss->beacon_int = beaconInterval ? beaconInterval : 100;
    bss->dtim_period = dtimPeriod ? dtimPeriod : 1;
    vif->cfg.assoc = true;
    vif->cfg.aid = aid;
    memcpy(vif->cfg.ap_addr, bssid, ETH_ALEN);

    {
        WiphyGuard guard(hw);
        if (hw->ops->link_info_changed)
            hw->ops->link_info_changed(hw, vif, bss, BSS_CHANGED_BSSID |
                (bss->he_support ? BSS_CHANGED_HE_BSS_COLOR : 0));
        if (hw->ops->vif_cfg_changed)
            hw->ops->vif_cfg_changed(hw, vif, BSS_CHANGED_ASSOC);
        else if (hw->ops->bss_info_changed)
            hw->ops->bss_info_changed(hw, vif, bss,
                                      BSS_CHANGED_ASSOC | BSS_CHANGED_QOS);
        RTW_DIAGNOSTIC(rtw89_macos_peer_audit(hw, vif, context->peerAudit));
    }
    return true;
}

void rtw89LinuxDisassociate(Rtw89LinuxContext *context)
{
    if (!context)
        return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    if (hw && hw->ops && vif && vif->cfg.assoc) {
        WiphyGuard guard(hw);
        vif->bss_conf.assoc = false;
        vif->cfg.assoc = false;
        if (hw->ops->vif_cfg_changed)
            hw->ops->vif_cfg_changed(hw, vif, BSS_CHANGED_ASSOC);
        else if (hw->ops->bss_info_changed)
            hw->ops->bss_info_changed(hw, vif, &vif->bss_conf,
                                      BSS_CHANGED_ASSOC);
    }
    for (uint8_t index = 0; index < 6; ++index) {
        rtw89LinuxDeleteKey(context, index, false);
        rtw89LinuxDeleteKey(context, index, true);
    }
    context->txAmpduMask = 0;
    releaseStation(context);
    if (vif) {
        vif->bss_conf.he_support = false;
        vif->bss_conf.he_oper = {};
        vif->bss_conf.he_bss_color = {};
        vif->bss_conf.htc_trig_based_pkt_ext = 0;
        vif->bss_conf.frame_time_rts_th = 0;
    }
}

bool rtw89LinuxSetKey(Rtw89LinuxContext *context, uint8_t keyIndex,
                      Rtw89NativeCipher cipher, bool pairwise,
                      const uint8_t *bytes, size_t length)
{
    if (!context || keyIndex >= 6 || !bytes || !length)
        return false;
    const uint8_t slot = keyIndex + (pairwise ? 6 : 0);
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    auto *sta = static_cast<struct ieee80211_sta *>(context->station);
    if (!hw || !hw->ops || !hw->ops->set_key || !vif || (pairwise && !sta))
        return false;
    rtw89LinuxDeleteKey(context, keyIndex, pairwise);

    uint32_t suite = 0;
    switch (cipher) {
    case Rtw89CipherWEP40: suite = WLAN_CIPHER_SUITE_WEP40; break;
    case Rtw89CipherTKIP: suite = WLAN_CIPHER_SUITE_TKIP; break;
    case Rtw89CipherCCMP: suite = WLAN_CIPHER_SUITE_CCMP; break;
    case Rtw89CipherWEP104: suite = WLAN_CIPHER_SUITE_WEP104; break;
    }
    if (length > sizeof(((struct ieee80211_key_conf *)0)->key))
        return false;
    auto *key = static_cast<struct ieee80211_key_conf *>(
        IOMallocZero(sizeof(struct ieee80211_key_conf)));
    if (!key)
        return false;
    key->cipher = suite;
    key->keyidx = keyIndex;
    key->link_id = -1;
    key->flags = pairwise ? IEEE80211_KEY_FLAG_PAIRWISE : 0;
    key->keylen = length;
    switch (cipher) {
    case Rtw89CipherWEP40:
    case Rtw89CipherWEP104:
        key->iv_len = 4;
        key->icv_len = 4;
        break;
    case Rtw89CipherTKIP:
        key->iv_len = 8;
        key->icv_len = 4;
        break;
    case Rtw89CipherCCMP:
        key->iv_len = 8;
        key->icv_len = 8;
        break;
    }
    memcpy(key->key, bytes, length);
    WiphyGuard guard(hw);
    if (hw->ops->set_key(hw, SET_KEY, vif, pairwise ? sta : nullptr, key)) {
        IOFree(key, sizeof(*key));
        return false;
    }
    context->keys[slot] = key;
    return true;
}

void rtw89LinuxDeleteKey(Rtw89LinuxContext *context, uint8_t keyIndex,
                         bool pairwise)
{
    if (!context || keyIndex >= 6)
        return;
    const uint8_t slot = keyIndex + (pairwise ? 6 : 0);
    if (!context->keys[slot])
        return;
    auto *hw = static_cast<struct ieee80211_hw *>(context->hardware);
    auto *vif = static_cast<struct ieee80211_vif *>(context->vif);
    auto *sta = static_cast<struct ieee80211_sta *>(context->station);
    auto *key = static_cast<struct ieee80211_key_conf *>(
        context->keys[slot]);
    if (hw && hw->ops && hw->ops->set_key && vif) {
        WiphyGuard guard(hw);
        hw->ops->set_key(hw, DISABLE_KEY, vif,
                         pairwise ? sta : nullptr, key);
    }
    IOFree(key, sizeof(*key));
    context->keys[slot] = nullptr;
}

/*
 * The imported RTW89 donor contains passive AirportRTW bring-up probes.
 * AirportRTW does not expose AirportRTW's IORegistry diagnostics, but the
 * donor still references these hooks.  Keep them resolved and inert here;
 * none of their callers use the returned value to drive hardware state.
 */
extern "C" bool rtw89_macos_assoc_stage_probe(unsigned int stage)
{
    if (activeContext && stage < 32)
        __sync_fetch_and_or(&activeContext->assocStageMask, 1U << stage);
    return false;
}

extern "C" void rtw89_macos_ra_audit_u32(unsigned int field,
                                           unsigned int value)
{
    if (activeContext && field < 50)
        activeContext->raAuditU32[field] = value;
}

extern "C" void rtw89_macos_ra_audit_u64(unsigned int field,
                                            unsigned long long value)
{
    if (activeContext && field < 1)
        activeContext->raAuditU64[field] = value;
}

extern "C" void rtw89_macos_tx_desc_audit(unsigned int useRate,
                                             unsigned int disableFallback,
                                             unsigned int hardwareRate,
                                             unsigned int bandwidth,
                                             unsigned int aggregationEnabled,
                                             unsigned int macId,
                                             unsigned int queueSelect)
{
    if (!activeContext)
        return;
    __sync_fetch_and_add(&activeContext->txDescDataCount, 1);
    activeContext->txDescUseRate = useRate;
    activeContext->txDescDisableFallback = disableFallback;
    activeContext->txDescHardwareRate = hardwareRate;
    activeContext->txDescBandwidth = bandwidth;
    activeContext->txDescAggregationEnabled = aggregationEnabled;
    activeContext->txDescMacId = macId;
    activeContext->txDescQueueSelect = queueSelect;
}

extern "C" void rtw89_macos_tx_report_audit(unsigned int status,
                                               unsigned int attempts)
{
    if (!activeContext)
        return;
    __sync_fetch_and_add(&activeContext->txReportCount, 1);
    activeContext->txReportStatus = status;
    activeContext->txReportAttempts = attempts;
}

extern "C" void rtw89_macos_set_null_ab_global_u32(unsigned int group,
                                                      unsigned int index,
                                                      unsigned int value)
{
    (void)group;
    (void)index;
    (void)value;
}

extern "C" void rtw89_macos_set_null_ab_variant_u32(unsigned int variant,
                                                       unsigned int field,
                                                       unsigned int value)
{
    (void)variant;
    (void)field;
    (void)value;
}

extern "C" void rtw89_macos_set_probe_stage(const char *stage, int code)
{
    Rtw89PciTransport::recordPCIProbeStage(stage, code);
}

extern "C" void rtw89_macos_chip_stage(const char *stage)
{
    Rtw89PciTransport::recordChipStage(stage);
}

extern "C" void rtw89_macos_poll_failure(unsigned int reg, unsigned int value,
                                        unsigned int mask, unsigned int expected)
{
    Rtw89PciTransport::recordPollFailure(reg, value, mask, expected);
}
