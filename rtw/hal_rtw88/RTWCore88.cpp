/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "RTWCore88.hpp"
#include "Rtw88PciTransport.hpp"
#include "Rtw88LinkPolicy.hpp"

#include <IOKit/IOLib.h>
#include <HAL/RealtekPciIds.hpp>

/* net80211 sources are compiled as C++ in this target. */
void ieee80211_recv_assoc_resp(struct ieee80211com *, mbuf_t,
                               struct ieee80211_node *, int);

#include <IOKit/network/IONetworkMedium.h>
#include <net80211/ieee80211_crypto.h>

#define super RTWCore
OSDefineMetaClassAndStructors(RTWCore88, RTWCore)

namespace {
constexpr UInt16 kRealtekVendor = 0x10ec;
constexpr UInt16 kRtl8822CE = 0xc822;
constexpr UInt16 kRtl8822CEAlternate = 0xc82f;
constexpr UInt16 kRtl8822BE = 0xb822;
constexpr UInt16 kRtl8821CE = 0xc821;
constexpr UInt16 kRtl8821CEAlternate = 0xb821;
constexpr UInt16 kRtl8723DE = 0xd723;
constexpr UInt16 kRtl8814AE = 0x8813;
constexpr uint32_t kRtw88TxQueueSize = 256;
}

bool RTWCore88::rtw88_match(IOPCIDevice *device)
{
    if (!device)
        return false;

    const UInt16 vendor = device->configRead16(kIOPCIConfigVendorID);
    const UInt16 product = device->configRead16(kIOPCIConfigDeviceID);
    return RealtekHal::family(vendor, product) == RealtekHal::Family::RTW88;
}

bool RTWCore88::attach(IOPCIDevice *device)
{
    RTW_LOG("AirportRTW: attach begin\n");
    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "PCI ID match"));
    if (!rtw88_match(device))
        return false;

    const UInt16 product = device->configRead16(kIOPCIConfigDeviceID);
    const char *firmware = "rtw88/rtw8822c_fw.bin";
    const char *chipName = "embedded RTL8822C";

    pciDevice = device;
    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "PCI transport initialization"));
    transport = Rtw88PciTransport::withDevice(device, getMainWorkLoop());
    if (!transport)
        goto fail;

    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "scan dwell timer"));
    scanDwellTimer = IOTimerEventSource::timerEventSource(
        this, &RTWCore88::scanDwellExpired);
    if (!scanDwellTimer)
        goto fail;
    if (getMainWorkLoop()->addEventSource(scanDwellTimer) != kIOReturnSuccess) {
        scanDwellTimer->release();
        scanDwellTimer = nullptr;
        goto fail;
    }

    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "association recovery timer"));
    associationRecoveryTimer = IOTimerEventSource::timerEventSource(
        this, &RTWCore88::associationRecoveryExpired);
    if (!associationRecoveryTimer)
        goto fail;
    if (getMainWorkLoop()->addEventSource(associationRecoveryTimer) !=
        kIOReturnSuccess) {
        associationRecoveryTimer->release();
        associationRecoveryTimer = nullptr;
        goto fail;
    }

    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "Linux PCI probe/context"));
    if (!rtw88LinuxAttach(transport, &linuxContext))
        goto fail;
    RTW_LOG("AirportRTW: Linux PCI probe complete\n");
    linuxContext.nativeOwner = this;
    linuxContext.receive = receive;
    linuxContext.txResume = resumeTransmit;
    sc.sc_hw = static_cast<struct ieee80211_hw *>(linuxContext.hardware);
    sc.sc_rtwdev = static_cast<struct rtw_dev *>(linuxContext.device);
    sc.sc_vif = static_cast<struct ieee80211_vif *>(linuxContext.vif);
    sc.sc_vif_size = linuxContext.vifAllocationSize;
    if (product == kRtl8822BE) { firmware = "rtw88/rtw8822b_fw.bin"; chipName = "embedded RTL8822B"; }
    if (product == kRtl8821CE || product == kRtl8821CEAlternate) { firmware = "rtw88/rtw8821c_fw.bin"; chipName = "embedded RTL8821C"; }
    if (product == kRtl8723DE) { firmware = "rtw88/rtw8723d_fw.bin"; chipName = "embedded RTL8723D"; }
    if (product == kRtl8814AE) { firmware = "rtw88/rtw8814a_fw.bin"; chipName = "embedded RTL8814A"; }
    strlcpy(sc.sc_fwname, firmware, sizeof(sc.sc_fwname));
    strlcpy(sc.sc_fwver, chipName, sizeof(sc.sc_fwver));
    strlcpy(sc.sc_country, "00", sizeof(sc.sc_country));
    sc.sc_noise = -95;

    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "net80211 attach"));
    if (!attachNet80211())
        goto fail_linux;
    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "interrupt enable"));
    transport->enableInterrupts();
    RTW_DIAGNOSTIC(getController()->setProperty("RTW88SoftwareCCMP", kOSBooleanFalse));
    sc.sc_flags |= RTW88_FLAG_ATTACHED;
    RTW_LOG("AirportRTW: attach complete\n");
    RTW_DIAGNOSTIC(device->setProperty("RTWHALStage", "HAL attach complete"));
    return true;

fail_linux:
    transport->disableInterrupts();
    rtw88LinuxDetach(transport, &linuxContext);
fail:
    RTW_LOG("AirportRTW: attach failed\n");
    if (associationRecoveryTimer) {
        associationRecoveryTimer->cancelTimeout();
        getMainWorkLoop()->removeEventSource(associationRecoveryTimer);
        associationRecoveryTimer->release();
        associationRecoveryTimer = nullptr;
    }
    if (scanDwellTimer) {
        scanDwellTimer->cancelTimeout();
        getMainWorkLoop()->removeEventSource(scanDwellTimer);
        scanDwellTimer->release();
        scanDwellTimer = nullptr;
    }
    if (associationRecoveryTimer) {
        associationRecoveryTimer->cancelTimeout();
        associationRecoveryTimer->disable();
        getMainWorkLoop()->removeEventSource(associationRecoveryTimer);
        associationRecoveryTimer->release();
        associationRecoveryTimer = nullptr;
    }
    if (transport) {
        transport->release();
        transport = nullptr;
    }
    pciDevice = nullptr;
    sc.sc_hw = nullptr;
    sc.sc_rtwdev = nullptr;
    return false;
}

void RTWCore88::detach(IOPCIDevice *device)
{
    (void)device;
    RTW_LOG("AirportRTW: detach begin\n");
    if (transport)
        transport->disableInterrupts();
    if (scanDwellTimer) {
        scanDwellTimer->cancelTimeout();
        scanDwellTimer->disable();
        getMainWorkLoop()->removeEventSource(scanDwellTimer);
        scanDwellTimer->release();
        scanDwellTimer = nullptr;
    }
    detachNet80211();
    if (transport)
        rtw88LinuxDetach(transport, &linuxContext);
    sc.sc_sta = nullptr;
    sc.sc_vif = nullptr;
    sc.sc_hw = nullptr;
    sc.sc_rtwdev = nullptr;
    sc.sc_flags = 0;
    if (transport) {
        transport->release();
        transport = nullptr;
    }
    pciDevice = nullptr;
}

IOReturn RTWCore88::enable(IONetworkInterface *interface)
{
    (void)interface;
    RTW_LOG("AirportRTW: Wi-Fi enable begin\n");
    if (!(sc.sc_flags & RTW88_FLAG_ATTACHED))
        return kIOReturnNotReady;
    if (sc.sc_flags & RTW88_FLAG_ENABLED)
        return kIOReturnSuccess;
#ifdef AIRPORT_WCL
    if (!rtw88LinuxSetMacAddress(&linuxContext, sc.sc_ic.ic_myaddr))
        return kIOReturnBadArgument;
    if (sc.sc_ic.ic_event_handler)
        sc.sc_ic.ic_event_handler(&sc.sc_ic, IEEE80211_EVT_DRIVER_RESET_BEGIN, nullptr);
#endif
    if (!rtw88LinuxPowerUp(&linuxContext)) {
#ifdef AIRPORT_WCL
        if (sc.sc_ic.ic_event_handler)
            sc.sc_ic.ic_event_handler(&sc.sc_ic, IEEE80211_EVT_DRIVER_STOPPED, nullptr);
#endif
        RTW_LOG("AirportRTW: Wi-Fi enable failed during power-up\n");
        return kIOReturnIOError;
    }
    sc.sc_flags |= RTW88_FLAG_ENABLED | RTW88_FLAG_FW_RUNNING |
                   RTW88_FLAG_INTERFACE;
    sc.sc_ic.ic_if.if_flags |= IFF_UP | IFF_RUNNING;
    /* AirportRTW rejects scan requests while net80211 remains in INIT.
     * Intel HALs enter the initial scan after their hardware init task; do
     * the same once RTW88 is powered and able to change channels. */
#ifdef AIRPORT_WCL
    // The native frontend owns association; an initial discovery must never
    // select a cached network before it submits a join request.
    sc.sc_ic.ic_flags &= ~IEEE80211_F_AUTO_JOIN;
    sc.sc_ic.ic_flags &= ~IEEE80211_F_HEON;
    if (sc.sc_ic.ic_event_handler)
        sc.sc_ic.ic_event_handler(&sc.sc_ic, IEEE80211_EVT_DRIVER_READY, nullptr);
#else
    ieee80211_begin_scan(&sc.sc_ic.ic_if);
#endif
    RTW_LOG("AirportRTW: Wi-Fi enable complete\n");
    return kIOReturnSuccess;
}

IOReturn RTWCore88::disable(IONetworkInterface *interface)
{
    (void)interface;
    RTW_LOG("AirportRTW: Wi-Fi disable begin\n");
    if (associationRecoveryTimer)
        associationRecoveryTimer->cancelTimeout();
    associationRecoveryPending = 0;
    associationRecoveryAttempted = 0;
    associationRecoveryAttemptActive = 0;
    associationRunWatchdogTicks = 0;
    if (sc.sc_ic.ic_state != IEEE80211_S_INIT)
        ieee80211_new_state(&sc.sc_ic, IEEE80211_S_INIT, -1);
    rtw88LinuxPowerDown(&linuxContext);
    sc.sc_ic.ic_if.if_flags &= ~(IFF_UP | IFF_RUNNING);
    sc.sc_sta = nullptr;
    sc.sc_flags &= ~(RTW88_FLAG_ENABLED | RTW88_FLAG_SCANNING |
                     RTW88_FLAG_FW_RUNNING | RTW88_FLAG_INTERFACE);
#ifdef AIRPORT_WCL
    if (scanDwellTimer)
        scanDwellTimer->cancelTimeout();
    if (sc.sc_ic.ic_event_handler)
        sc.sc_ic.ic_event_handler(&sc.sc_ic, IEEE80211_EVT_DRIVER_STOPPED, nullptr);
#endif
    RTW_LOG("AirportRTW: Wi-Fi disable complete\n");
    return kIOReturnSuccess;
}

void RTWCore88::free()
{
    ieee80211_sae_clear(&sc.sc_ic, true);
    detach(pciDevice);
    super::free();
}

int RTWCore88::getTxNSS()
{
    return rtw88LinuxGetNSS(&linuxContext);
}

bool RTWCore88::getTxRate(RTWTxRate &rate)
{
    rtw88LinuxGetTxRate(&linuxContext, rate);
    return true;
}

bool RTWCore88::is5GBandSupport()
{
    Rtw88NativeCapabilities caps = {};
    return rtw88LinuxGetCapabilities(&linuxContext, true, caps);
}

const char *RTWCore88::getFirmwareName()
{
    return sc.sc_fwname;
}

const char *RTWCore88::getFirmwareCountryCode()
{
    return sc.sc_country;
}

uint32_t RTWCore88::getTxQueueSize()
{
    return kRtw88TxQueueSize;
}

void RTWCore88::clearScanningFlags()
{
    sc.sc_flags &= ~RTW88_FLAG_SCANNING;
}

IOReturn RTWCore88::setMulticastList(IOEthernetAddress *addresses, int count)
{
    (void)addresses;
    rtw88LinuxSetAllMulticast(&linuxContext, count > 0);
    return kIOReturnSuccess;
}

bool RTWCore88::attachNet80211()
{
    if (!linuxContext.hardware)
        return false;

    struct ieee80211com *ic = &sc.sc_ic;
    struct _ifnet *ifp = &ic->ic_ac.ac_if;
    bzero(ic, sizeof(*ic));
    memcpy(ic->ic_myaddr, linuxContext.macAddress, ETHER_ADDR_LEN);
    ic->ic_opmode = IEEE80211_M_STA;
    ic->ic_phytype = IEEE80211_T_OFDM;
    ic->ic_curmode = IEEE80211_MODE_AUTO;
    ic->ic_state = IEEE80211_S_INIT;
    ic->ic_caps = IEEE80211_C_WEP | IEEE80211_C_RSN |
                  IEEE80211_C_SCANALL | IEEE80211_C_SCANALLBAND |
                  IEEE80211_C_SHSLOT | IEEE80211_C_SHPREAMBLE |
                  IEEE80211_C_QOS | IEEE80211_C_TX_AMPDU | IEEE80211_C_MFP;
    ic->ic_htcaps = IEEE80211_HTCAP_SGI20 |
                    IEEE80211_HTCAP_CBW20_40 | IEEE80211_HTCAP_SGI40 |
                    IEEE80211_HTCAP_LDPC |
                    (IEEE80211_HTCAP_SMPS_DIS << IEEE80211_HTCAP_SMPS_SHIFT);
    ic->ic_ampdu_params = IEEE80211_AMPDU_PARAM_SS_4 | 0x3;
    Rtw88NativeCapabilities caps2 = {}, caps5 = {};
    const bool has2GHz = rtw88LinuxGetCapabilities(&linuxContext, false, caps2);
    const bool has5GHz = rtw88LinuxGetCapabilities(&linuxContext, true, caps5);
    if (!has2GHz && !has5GHz) return false;
    const auto &htCaps = caps5.ht ? caps5 : caps2;
    if (htCaps.ht) {
        ic->ic_htcaps = htCaps.htCaps;
        ic->ic_ampdu_params = htCaps.ampduParams;
        memcpy(ic->ic_sup_mcs, htCaps.htMCS, sizeof(htCaps.htMCS));
        ic->ic_tx_mcs_set = IEEE80211_TX_MCS_SET_DEFINED;
    }
    if (caps5.vht) {
        // The current native channel bridge supports contiguous widths to 80.
        ic->ic_vhtcaps = caps5.vhtCaps &
            ~(IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_MASK | IEEE80211_VHTCAP_SHORT_GI_160);
        ic->ic_vht_rx_mcs_map = htole16(caps5.vhtRxMCS);
        ic->ic_vht_tx_mcs_map = htole16(caps5.vhtTxMCS);
        for (unsigned ss = 0; ss < 8; ++ss) {
            unsigned mcs = (caps5.vhtRxMCS >> (2 * ss)) & 3;
            ic->ic_vht_sup_mcs[ss] = mcs == 3 ? 0 : (1U << (8 + mcs)) - 1;
        }
        ic->ic_flags |= IEEE80211_F_VHTON;
    }
    ic->ic_max_rssi = 100;
    ic->ic_sup_rates[IEEE80211_MODE_11A] = ieee80211_std_rateset_11a;
    ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
    ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;

    static const uint8_t channels[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        36, 40, 44, 48, 52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
        149, 153, 157, 161, 165
    };
    for (size_t index = 0; index < nitems(channels); ++index) {
        const uint8_t channel = channels[index];
        if ((channel <= 14 && !has2GHz) || (channel > 14 && !has5GHz))
            continue;
        auto *entry = &ic->ic_channels[channel];
        entry->ic_freq = channel == 14 ? 2484
            : channel <= 13 ? 2407 + channel * 5 : 5000 + channel * 5;
        entry->ic_center_freq1 = entry->ic_freq;
        entry->ic_center_freq2 = 0;
        entry->ic_flags = channel <= 14
            ? IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN |
              IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_HT20
            : IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_HT20;
        const auto &bandCaps = channel <= 14 ? caps2 : caps5;
        if (bandCaps.ht && (bandCaps.htCaps & IEEE80211_HTCAP_CBW20_40)) {
            if (channel <= 13) {
                if (channel <= 9) entry->ic_flags |= IEEE80211_CHAN_HT40U;
                if (channel >= 5) entry->ic_flags |= IEEE80211_CHAN_HT40D;
            } else if (channel != 165) {
                entry->ic_flags |= (channel <= 144 ? (channel / 4) % 2 :
                    ((channel - 149) / 4 + 1) % 2)
                    ? IEEE80211_CHAN_HT40U : IEEE80211_CHAN_HT40D;
            }
        }
        if (channel > 14 && channel != 165 && bandCaps.vht)
            entry->ic_flags |= IEEE80211_CHAN_VHT80;
    }
    ic->ic_ibss_chan = &ic->ic_channels[1];

    ifp->if_softc = &sc;
    ifp->if_start = start;
    ifp->if_watchdog = watchdog;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
    strlcpy(ifp->if_xname, "rtw88", IFNAMSIZ);
    if_attach(ifp);
    ieee80211_ifattach(ifp, getController());
    ieee80211_media_init(ifp);
    if (!ic->ic_bss) {
        ieee80211_ifdetach(ifp);
        return false;
    }

    sc.sc_newstate = ic->ic_newstate;
    ic->ic_newstate = newstate;
    ic->ic_set_key = setKey;
    ic->ic_delete_key = deleteKey;
    ic->ic_updateslot = updateSlot;
    ic->ic_updateedca = updateEdca;
    ic->ic_ampdu_rx_start = ampduRxStart;
    ic->ic_ampdu_rx_stop = ampduRxStop;
    ic->ic_ampdu_tx_start = ampduTxStart;
    ic->ic_ampdu_tx_stop = ampduTxStop;
    return true;
}

void RTWCore88::watchdog(struct _ifnet *ifp)
{
    /* The Linux RTW88 core schedules its own periodic maintenance work.
     * AirportRTW still expects every HAL to expose a BSD watchdog hook. */
    auto *sc = ifp ? static_cast<struct rtw88_softc *>(ifp->if_softc) : nullptr;
    if (!sc)
        return;
    auto *owner = container_of(sc, RTWCore88, sc);
    if (sc->sc_ic.ic_state == IEEE80211_S_RUN) {
        if (owner->associationRunWatchdogTicks < 5)
            ++owner->associationRunWatchdogTicks;
        if (owner->associationRunWatchdogTicks == 5) {
            if (owner->associationRecoveryAttemptActive)
                __sync_fetch_and_add(&owner->associationRecoverySuccessCount, 1);
            owner->associationRecoveryPending = 0;
            owner->associationRecoveryAttempted = 0;
            owner->associationRecoveryAttemptActive = 0;
        }
    }
#if RTW_DIAGNOSTICS
    IOEthernetController *controller = owner->getController();
    if (!controller)
        return;
    RTW_DIAGNOSTIC(controller->setProperty("RTW88InterruptCount",
                            owner->transport ? owner->transport->getInterruptCount() : 0, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ScanChannelCount", owner->scanChannelCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RawReceiveCount", owner->rawReceiveCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AcceptedReceiveCount", owner->acceptedReceiveCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88BeaconProbeCount", owner->beaconProbeCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AuthTxCount", owner->linuxContext.authTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AuthTxAckCount", owner->linuxContext.authTxAckCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocTxCount", owner->linuxContext.assocTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocTxAckCount", owner->linuxContext.assocTxAckCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AuthRxCount", owner->linuxContext.authRxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocRxCount", owner->linuxContext.assocRxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ActionTxCount", owner->linuxContext.actionTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ActionTxAckCount",
                            owner->linuxContext.actionTxAckCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ActionRxCount", owner->linuxContext.actionRxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionTxCategory",
                            owner->linuxContext.lastActionTxCategory, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionTxCode",
                            owner->linuxContext.lastActionTxCode, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionTxToken",
                            owner->linuxContext.lastActionTxToken, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAddbaTxBytes0To7",
                            owner->linuxContext.lastAddbaTxBytes0To7, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAddbaTxByte8",
                            owner->linuxContext.lastAddbaTxByte8, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAddbaTxParams",
                            owner->linuxContext.lastAddbaTxParams, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAddbaTxTimeout",
                            owner->linuxContext.lastAddbaTxTimeout, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAddbaTxStartSeqControl",
                            owner->linuxContext.lastAddbaTxStartSeqControl, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionRxCategory",
                            owner->linuxContext.lastActionRxCategory, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionRxCode",
                            owner->linuxContext.lastActionRxCode, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionRxToken",
                            owner->linuxContext.lastActionRxToken, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastActionRxStatus",
                            owner->linuxContext.lastActionRxStatus, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88DataTxCount", owner->linuxContext.dataTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ProtectedTxCount", owner->linuxContext.protectedTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88DHCPTxCount", owner->linuxContext.dhcpTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88DHCPTxAckCount", owner->linuxContext.dhcpTxAckCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ARPTxCount", owner->linuxContext.arpTxCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88ARPTxAckCount", owner->linuxContext.arpTxAckCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastTxCipher", owner->linuxContext.lastTxCipher, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastTxKeyIndex", owner->linuxContext.lastTxKeyIndex, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastTxIvLength", owner->linuxContext.lastTxIvLength, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescDataCount",
                            owner->linuxContext.txDescDataCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescUseRate",
                            owner->linuxContext.txDescUseRate, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescDisableFallback",
                            owner->linuxContext.txDescDisableFallback, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescHardwareRate",
                            owner->linuxContext.txDescHardwareRate, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescBandwidth",
                            owner->linuxContext.txDescBandwidth, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescAggregationEnabled",
                            owner->linuxContext.txDescAggregationEnabled, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescMacId",
                            owner->linuxContext.txDescMacId, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxDescQueueSelect",
                            owner->linuxContext.txDescQueueSelect, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxAvailableSlots",
                            rtw88LinuxTxAvailableSlots(&owner->linuxContext), 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88OutputQueueLength",
                            (UInt64)ifq_len(&ifp->if_snd), 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88OutputQueueActive",
                            (UInt64)ifq_is_oactive(&ifp->if_snd), 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88StartCallCount", owner->startCallCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBackpressureCount",
                            owner->txBackpressureCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxAmpduMask",
                            owner->linuxContext.txAmpduMask, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AmpduTxStartCount",
                            owner->linuxContext.ampduTxStartCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AmpduTxStartFailCount",
                            owner->linuxContext.ampduTxStartFailCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AmpduTxStopCount",
                            owner->linuxContext.ampduTxStopCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AmpduRxStartCount",
                            owner->linuxContext.ampduRxStartCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AmpduRxStartFailCount",
                            owner->linuxContext.ampduRxStartFailCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AmpduRxStopCount",
                            owner->linuxContext.ampduRxStopCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocStageMask",
                            owner->linuxContext.assocStageMask, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RAAssocMode",
                            owner->linuxContext.raAuditU32[1], 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RAAssocBandwidth",
                            owner->linuxContext.raAuditU32[2], 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RAAssocSpatialStreams",
                            owner->linuxContext.raAuditU32[3] + 1, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RAAssocRxNss",
                            owner->linuxContext.raAuditU32[41], 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RAAssocTxNss",
                            owner->linuxContext.raAuditU32[42], 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RAAssocMask",
                            owner->linuxContext.raAuditU64[0], 64));
    RTWTxRate liveRate = {};
    owner->getTxRate(liveRate);
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveValid", liveRate.valid));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveMode", liveRate.mode, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveMcs", liveRate.mcs, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveBandwidth", liveRate.widthMHz, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveNss", liveRate.nss, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveShortGI", liveRate.shortGI));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RALiveBitrate100Kbps", liveRate.bitrate100Kbps, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAssocResponseLength",
                            owner->lastAssocResponseLength, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAssocResponseStatus",
                            owner->lastAssocResponseStatus, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAssocResponseAid",
                            owner->lastAssocResponseAid, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAssocResponseFirstIE",
                            owner->lastAssocResponseFirstIE, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocStatus", owner->sc.sc_ic.ic_assoc_status, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxCCMPReplays", owner->sc.sc_ic.ic_stats.is_ccmp_replays, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxCCMPIntegrityFailures", owner->sc.sc_ic.ic_stats.is_ccmp_dec_errs, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxHardwareDecrypted", owner->linuxContext.rxHardwareDecryptedCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxProtectedSoftware", owner->linuxContext.rxProtectedSoftwareCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxCCMPMICStripped", owner->linuxContext.rxCCMPMICStrippedCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxConnectionProtected", owner->linuxContext.rxConnectionProtectedCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxConnectionUndecrypted", owner->linuxContext.rxConnectionUndecryptedCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxConnectionInvalid", owner->linuxContext.rxConnectionInvalidCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxConnectionSNAP", owner->linuxContext.rxConnectionSNAPCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxConnectionDHCP", owner->linuxContext.rxConnectionDHCPCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxAddressMismatch", owner->linuxContext.txAddressMismatchCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxUnauthorized", owner->sc.sc_ic.ic_stats.is_rx_unauth, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxProtectionOff", owner->sc.sc_ic.ic_stats.is_rx_nowep, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88PortValid", owner->sc.sc_ic.ic_bss && owner->sc.sc_ic.ic_bss->ni_port_valid));
#ifdef AIRPORT_WCL
    uint64_t decryptedData = 0;
    for (unsigned ac = 0; ac < 4; ++ac)
        decryptedData += owner->sc.sc_ic.ic_wcl_rx_packets[ac];
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxDataAfterDecrypt", decryptedData, 64));
#endif
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxDecryptFailures", owner->sc.sc_ic.ic_stats.is_rx_wepfail, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxUnencrypted", owner->sc.sc_ic.ic_stats.is_rx_unencrypted, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxDecapFailures", owner->sc.sc_ic.ic_stats.is_rx_decap, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxMgmtDiscard",
                            owner->sc.sc_ic.ic_stats.is_rx_mgtdiscard, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxElementTooSmall",
                            owner->sc.sc_ic.ic_stats.is_rx_elem_toosmall, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxAssocNoRate",
                            owner->sc.sc_ic.ic_stats.is_rx_assoc_norate, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxDuplicate",
                            owner->sc.sc_ic.ic_stats.is_rx_dup, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxWrongDirection",
                            owner->sc.sc_ic.ic_stats.is_rx_wrongdir, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxTooShort",
                            owner->sc.sc_ic.ic_stats.is_rx_tooshort, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88RxBadVersion",
                            owner->sc.sc_ic.ic_stats.is_rx_badversion, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAssocResponseFC1",
                            owner->lastAssocResponseFC1, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastAssocResponseSequence",
                            owner->lastAssocResponseSequence, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocStateBeforeInput",
                            owner->assocStateBeforeInput, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocStateAfterInput",
                            owner->assocStateAfterInput, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssocStatusAfterInput",
                            owner->assocStatusAfterInput, 16));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88Net80211NodeCount",
                            (UInt64)owner->sc.sc_ic.ic_nnodes, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssociationRunWatchdogTicks",
                            owner->associationRunWatchdogTicks, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssociationRecoveryPending",
                            owner->associationRecoveryPending, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssociationRecoveryAttempted",
                            owner->associationRecoveryAttempted, 8));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssociationRecoveryTriggerCount",
                            owner->associationRecoveryTriggerCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssociationRecoveryAttemptCount",
                            owner->associationRecoveryAttemptCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88AssociationRecoverySuccessCount",
                            owner->associationRecoverySuccessCount, 64));
    RTW_DIAGNOSTIC(controller->setProperty("RTWSAEStage", owner->sc.sc_ic.ic_sae_stage, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWSAEError", owner->sc.sc_ic.ic_sae_error, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88Net80211State",
                            (UInt64)owner->sc.sc_ic.ic_state, 8));
    if (owner->sc.sc_ic.ic_bss) {
        struct ieee80211_node *node = owner->sc.sc_ic.ic_bss;
        RTW_DIAGNOSTIC(controller->setProperty("RTW88NodeFlags", (UInt64)node->ni_flags, 32));
        RTW_DIAGNOSTIC(controller->setProperty("RTW88NodeRsnProtocols",
                                (UInt64)node->ni_rsnprotos, 32));
        RTW_DIAGNOSTIC(controller->setProperty("RTW88InterfaceFlags",
                                (UInt64)owner->sc.sc_ic.ic_flags, 32));
        RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBaStateBE",
                                (UInt64)node->ni_tx_ba[EDCA_AC_BE].ba_state, 8));
        RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBaStateBK",
                                (UInt64)node->ni_tx_ba[EDCA_AC_BK].ba_state, 8));
        RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBaStateVI",
                                (UInt64)node->ni_tx_ba[EDCA_AC_VI].ba_state, 8));
        RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBaStateVO",
                                (UInt64)node->ni_tx_ba[EDCA_AC_VO].ba_state, 8));
    }
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBaAgreements",
                            owner->sc.sc_ic.ic_stats.is_ht_tx_ba_agreements, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88TxBaTimeouts",
                            owner->sc.sc_ic.ic_stats.is_ht_tx_ba_timeout, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastReceiveFrequency",
                            (UInt64)owner->lastReceiveFrequency, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTW88LastReceiveSignalRaw",
                            (UInt64)owner->lastReceiveSignalRaw, 8));
#endif
}

void RTWCore88::scanDwellExpired(OSObject *object, IOTimerEventSource *timer)
{
    auto *owner = OSDynamicCast(RTWCore88, object);
    if (!owner || timer != owner->scanDwellTimer ||
        !(owner->sc.sc_flags & RTW88_FLAG_ENABLED) ||
        owner->sc.sc_ic.ic_state != IEEE80211_S_SCAN)
        return;
    ieee80211_next_scan(&owner->sc.sc_ic.ic_if);
}

void RTWCore88::associationRecoveryExpired(OSObject *object,
                                           IOTimerEventSource *timer)
{
    auto *owner = OSDynamicCast(RTWCore88, object);
    if (!owner || timer != owner->associationRecoveryTimer ||
        !owner->associationRecoveryPending ||
        !(owner->sc.sc_flags & RTW88_FLAG_ENABLED) ||
        owner->sc.sc_ic.ic_state == IEEE80211_S_INIT ||
        owner->sc.sc_ic.ic_state == IEEE80211_S_RUN)
        return;

    owner->associationRecoveryPending = 0;
    owner->associationRecoveryAttempted = 1;
    owner->associationRecoveryAttemptActive = 1;
    __sync_fetch_and_add(&owner->associationRecoveryAttemptCount, 1);
    RTW_LOG("AirportRTW: retrying scan after short association\n");
    ieee80211_begin_scan(&owner->sc.sc_ic.ic_if);
}

void RTWCore88::start(struct _ifnet *ifp)
{
    auto *sc = static_cast<struct rtw88_softc *>(ifp->if_softc);
    if (!sc || !(ifp->if_flags & IFF_RUNNING))
        return;
    auto *owner = container_of(sc, RTWCore88, sc);
    __sync_fetch_and_add(&owner->startCallCount, 1);
    struct ieee80211com *ic = &sc->sc_ic;

    for (;;) {
        if (!rtw88LinuxTxAvailable(&owner->linuxContext)) {
            __sync_fetch_and_add(&owner->txBackpressureCount, 1);
            ifq_set_oactive(&ifp->if_snd);
            break;
        }
        mbuf_t m = mq_dequeue(&ic->ic_mgtq);
        struct ieee80211_node *node = nullptr;
        bool management = m != nullptr;
        if (m)
            node = reinterpret_cast<struct ieee80211_node *>(mbuf_pkthdr_rcvif(m));
        else {
            if (ic->ic_state != IEEE80211_S_RUN ||
                (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY))
                break;
            m = ifq_dequeue(&ifp->if_snd);
            if (!m)
                break;
            if ((m = ieee80211_encap(ifp, m, &node)) == nullptr) {
                ifp->netStat->outputErrors++;
                continue;
            }
        }

        bool softwareEncrypted = false;
        const auto header = mtod(m, const struct ieee80211_frame *);
        if (header->i_fc[1] & IEEE80211_FC1_PROTECTED) {
            auto key = node ? ieee80211_get_txkey(ic, header, node) : nullptr;
            if (!key) {
                ++ifp->netStat->outputErrors;
                mbuf_freem(m);
                if (node) ieee80211_release_node(ic, node);
                continue;
            }
            if (key->k_flags & IEEE80211_KEY_SWCRYPTO) {
                m = ieee80211_encrypt(ic, m, key);
                if (!m) {
                    ++ifp->netStat->outputErrors;
                    ieee80211_release_node(ic, node);
                    continue;
                }
                softwareEncrypted = true;
            }
        }
        const size_t length = mbuf_pkthdr_len(m);
        uint8_t *frame = static_cast<uint8_t *>(IOMalloc(length));
        if (!frame || mbuf_copydata(m, 0, length, frame) != 0 ||
            !rtw88LinuxTransmit(&owner->linuxContext, frame, length,
                                management, softwareEncrypted)) {
            ifp->netStat->outputErrors++;
        } else {
            ifp->netStat->outputPackets++;
#ifdef AIRPORT_WCL
            const auto wh = reinterpret_cast<const ieee80211_frame *>(frame);
            if (!management && !(wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_NODATA)) {
                unsigned ac = ieee80211_has_qos(wh)
                    ? ieee80211_wcl_ac(ieee80211_get_qos(wh) & IEEE80211_QOS_TID)
                    : EDCA_AC_BE;
                __sync_fetch_and_add(&ic->ic_wcl_tx_packets[ac], 1);
            }
#endif
        }
        if (frame)
            IOFree(frame, length);
        mbuf_freem(m);
        if (node)
            ieee80211_release_node(ic, node);
    }
}

void RTWCore88::resumeTransmit(void *opaque)
{
    auto *owner = static_cast<RTWCore88 *>(opaque);
    if (!owner || !(owner->sc.sc_flags & RTW88_FLAG_ENABLED))
        return;
    struct _ifnet *ifp = &owner->sc.sc_ic.ic_if;
    if (!ifq_is_oactive(&ifp->if_snd))
        return;
    ifq_clr_oactive(&ifp->if_snd);
    start(ifp);
}

void RTWCore88::receive(void *opaque, const uint8_t *frame, size_t length,
                       int32_t rssi, uint16_t frequency, bool decrypted,
                       bool ivStripped)
{
    auto *owner = static_cast<RTWCore88 *>(opaque);
    if (!owner || !frame || length < 2)
        return;
    const bool controlFrame = (frame[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL;
    if (length < (controlFrame ? 16 : sizeof(struct ieee80211_frame)))
        return;
    __sync_fetch_and_add(&owner->rawReceiveCount, 1);
    struct ieee80211com *ic = &owner->sc.sc_ic;
    auto *wh = reinterpret_cast<const struct ieee80211_frame *>(frame);
    const uint8_t frameType = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    const uint8_t frameSubtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    mbuf_t m = nullptr;
    /* The OpenBSD receive/decapsulation path and IO80211 use mtod() plus
     * mbuf_len() in several places, so normal management and data frames
     * must be contiguous.  Keep only large aggregates chain-capable. */
    unsigned int contiguousChunks = 1;
    unsigned int *maxChunks = length <= 4096 ? &contiguousChunks : nullptr;
    if (mbuf_allocpacket(MBUF_DONTWAIT, length, maxChunks, &m) != 0)
        return;
    size_t copied = 0;
    for (mbuf_t segment = m; segment && copied < length;
         segment = mbuf_next(segment)) {
        const size_t capacity = mbuf_maxlen(segment);
        const size_t segmentLength =
            capacity < length - copied ? capacity : length - copied;
        if (segmentLength == 0)
            continue;
        memcpy(mbuf_data(segment), frame + copied, segmentLength);
        mbuf_setlen(segment, segmentLength);
        copied += segmentLength;
    }
    if (copied != length) {
        mbuf_freem(m);
        return;
    }
    mbuf_pkthdr_setlen(m, length);
    if (decrypted && ivStripped && length >= 2) {
        uint8_t frameControl1 = 0;
        if (mbuf_copydata(m, 1, 1, &frameControl1) == 0) {
            frameControl1 &= ~IEEE80211_FC1_PROTECTED;
            mbuf_copyback(m, 1, 1, &frameControl1, MBUF_DONTWAIT);
        }
    }
    owner->lastReceiveFrequency = frequency;
    owner->lastReceiveSignalRaw = (uint8_t)rssi;
    if (frameType == IEEE80211_FC0_TYPE_MGT &&
        frameSubtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
        owner->lastAssocResponseLength = (UInt32)length;
        owner->lastAssocResponseFC1 = wh->i_fc[1];
        owner->lastAssocResponseSequence =
            (UInt32)(wh->i_seq[0] | ((UInt16)wh->i_seq[1] << 8));
        if (length >= sizeof(struct ieee80211_frame) + 6) {
            const uint8_t *body = frame + sizeof(struct ieee80211_frame);
            owner->lastAssocResponseStatus =
                (UInt32)(body[2] | ((UInt16)body[3] << 8));
            owner->lastAssocResponseAid =
                (UInt32)(body[4] | ((UInt16)body[5] << 8));
            owner->lastAssocResponseFirstIE =
                length >= sizeof(struct ieee80211_frame) + 8 ? body[6] : 0xffff;
        }
    }
    if (owner->sc.sc_flags & RTW88_FLAG_SCANNING &&
        frameType == IEEE80211_FC0_TYPE_MGT &&
        (frameSubtype == IEEE80211_FC0_SUBTYPE_BEACON ||
         frameSubtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)) {
        __sync_fetch_and_add(&owner->beaconProbeCount, 1);
        RTW_LOG("RTWCore88: scan RX subtype 0x%02x len %lu rssi %d freq %u\n",
              frameSubtype, (unsigned long)length, (int)rssi, frequency);
    }
    const int networkPriority = splnet();
    struct ieee80211_node *node = ieee80211_find_rxnode(ic, wh);
    if (!node) {
        splx(networkPriority);
        mbuf_freem(m);
        return;
    }
    __sync_fetch_and_add(&owner->acceptedReceiveCount, 1);
    struct ieee80211_rxinfo rxi = {};
    const int rssiDbm = static_cast<int8_t>(static_cast<uint8_t>(rssi));
    int relative = rssiDbm <= -110 ? 10 : rssiDbm + 100;
    if (relative < 0) relative = 0;
    if (relative > ic->ic_max_rssi) relative = ic->ic_max_rssi;
    rxi.rxi_rssi = relative;
    if (frequency == 2484)
        rxi.rxi_chan = 14;
    else if (frequency >= 2412 && frequency <= 2472)
        rxi.rxi_chan = (frequency - 2407) / 5;
    else if (frequency >= 5005 && frequency <= 5895)
        rxi.rxi_chan = (frequency - 5000) / 5;
    else if (ic->ic_bss && ic->ic_bss->ni_chan)
        rxi.rxi_chan = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
    if (decrypted)
        rxi.rxi_flags |= IEEE80211_RXI_HWDEC;
    struct mbuf_list list;
    ml_init(&list);
    const bool assocResponse = frameType == IEEE80211_FC0_TYPE_MGT &&
        frameSubtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
    // Native raw-management listeners can consume Block Ack actions before
    // net80211 sees them, just like association responses. Only dispatch
    // ordinary, unfragmented BA actions from our associated AP here. Frames
    // requiring management protection retain the normal validation path.
    const bool blockAckAction = frameType == IEEE80211_FC0_TYPE_MGT &&
        frameSubtype == IEEE80211_FC0_SUBTYPE_ACTION && length >= 26 &&
        frame[24] == IEEE80211_CATEG_BA && (wh->i_fc[0] & 3) == 0 &&
        wh->i_fc[1] == IEEE80211_FC1_DIR_NODS && (wh->i_seq[0] & 15) == 0 &&
        ic->ic_state == IEEE80211_S_RUN && node == ic->ic_bss &&
        (!(ic->ic_flags & IEEE80211_F_RSNON) || node->ni_port_valid) &&
        !(node->ni_flags & (IEEE80211_NODE_MFP | IEEE80211_NODE_RXMGMTPROT)) &&
        IEEE80211_ADDR_EQ(wh->i_addr1, ic->ic_myaddr) &&
        IEEE80211_ADDR_EQ(wh->i_addr2, node->ni_bssid) &&
        IEEE80211_ADDR_EQ(wh->i_addr3, node->ni_bssid);
    if (assocResponse) {
        owner->assocStateBeforeInput = (UInt32)ic->ic_state;
        /* IO80211's raw 802.11 BPF listener consumes this valid MLME frame
         * before net80211 dispatch.  RX length/FCS and node lookup have
         * already been validated, so deliver only association responses
         * directly to their concrete parser. */
        ieee80211_recv_assoc_resp(ic, m, node, 0);
        mbuf_freem(m);
        owner->assocStateAfterInput = (UInt32)ic->ic_state;
        owner->assocStatusAfterInput = (UInt32)ic->ic_assoc_status;
    } else if (blockAckAction) {
        ic->ic_recv_mgmt(ic, m, node, &rxi, frameSubtype);
        mbuf_freem(m);
    } else {
        ieee80211_inputm(&ic->ic_if, m, node, &rxi, &list);
        if_input(&ic->ic_if, &list);
    }
    ieee80211_release_node(ic, node);
    splx(networkPriority);
}

void RTWCore88::detachNet80211()
{
    if (!(sc.sc_flags & RTW88_FLAG_ATTACHED))
        return;
    ieee80211_ifdetach(&sc.sc_ic.ic_if);
    sc.sc_flags &= ~RTW88_FLAG_ATTACHED;
}

int RTWCore88::newstate(struct ieee80211com *ic,
                       enum ieee80211_state state, int arg)
{
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    if (!sc || !sc->sc_newstate)
        return ENXIO;
    auto *owner = container_of(sc, RTWCore88, sc);
    const enum ieee80211_state previous = ic->ic_state;
    struct ieee80211_node *node = ic->ic_bss;
    bool beganScan = false;
    bool endedScan = false;
    bool associated = false;
    const bool shortAssociationExit =
        previous == IEEE80211_S_RUN && state != IEEE80211_S_RUN &&
        state != IEEE80211_S_INIT &&
        owner->associationRunWatchdogTicks < 5 &&
        !owner->associationRecoveryAttempted;

    if (previous == IEEE80211_S_RUN && state != IEEE80211_S_RUN) {
        rtw88LinuxDisassociate(&owner->linuxContext);
        sc->sc_sta = nullptr;
    }

    if (state == IEEE80211_S_SCAN && previous != IEEE80211_S_SCAN) {
        rtw88LinuxScanBegin(&owner->linuxContext);
        sc->sc_flags |= RTW88_FLAG_SCANNING;
        beganScan = true;
    }

    // The first SCAN transition calls ieee80211_begin_scan(), which selects
    // a channel and re-enters this wrapper. Before that, ni_chan may be ANYC.
    // Program RF only for the per-channel SCAN -> SCAN transitions.
    if (state == IEEE80211_S_SCAN && previous == IEEE80211_S_SCAN &&
        node && node->ni_chan && node->ni_chan != IEEE80211_CHAN_ANYC) {
        const uint16_t channel = ieee80211_chan2ieee(ic, node->ni_chan);
        __sync_fetch_and_add(&owner->scanChannelCount, 1);
        RTW_LOG("RTWCore88: scan channel %u\n", channel);
        if (channel && !rtw88LinuxSetChannel(&owner->linuxContext, channel)) {
            if (beganScan) {
                rtw88LinuxScanEnd(&owner->linuxContext);
                sc->sc_flags &= ~RTW88_FLAG_SCANNING;
            }
            return EIO;
        }
    }

    /* rtw88 must leave software-scan mode before programming a chanctx or
     * transmitting authentication.  Keeping scan active here can leave the
     * PCI firmware on the scan channel while net80211 starts AUTH. */
    if (previous == IEEE80211_S_SCAN && state != IEEE80211_S_SCAN) {
        if (owner->scanDwellTimer)
            owner->scanDwellTimer->cancelTimeout();
        rtw88LinuxScanEnd(&owner->linuxContext);
        sc->sc_flags &= ~RTW88_FLAG_SCANNING;
        endedScan = true;
        if (state == IEEE80211_S_AUTH) {
            for (unsigned int attempt = 0;
                 attempt < 100 &&
                 rtw88LinuxIsScanning(&owner->linuxContext); ++attempt)
                IOSleep(50);
            /* Firmware can still own scan-mode RF state briefly after
             * its software flag clears.  Match the proven AirportRTW delay
             * before connect_hw_setup performs BB/RF register accesses. */
            IOSleep(500);
        }
    }

    if (state == IEEE80211_S_AUTH) {
        if (!node || !node->ni_chan) {
            if (endedScan) {
                rtw88LinuxScanBegin(&owner->linuxContext);
                sc->sc_flags |= RTW88_FLAG_SCANNING;
            }
            return EINVAL;
        }
        const uint16_t channel = ieee80211_chan2ieee(ic, node->ni_chan);
        if (!channel || !rtw88LinuxPrepareConnection(&owner->linuxContext,
                                                      node->ni_bssid, channel)) {
            if (endedScan) {
                rtw88LinuxScanBegin(&owner->linuxContext);
                sc->sc_flags |= RTW88_FLAG_SCANNING;
            } else if (beganScan) {
                rtw88LinuxScanEnd(&owner->linuxContext);
                sc->sc_flags &= ~RTW88_FLAG_SCANNING;
            }
            return EIO;
        }
    }

    if (state == IEEE80211_S_RUN) {
        if (!node || !node->ni_chan)
            return EINVAL;
        const uint16_t channel = ieee80211_chan2ieee(ic, node->ni_chan);
        const uint16_t aid = node->ni_associd & 0x3fff;
        const bool ht = (node->ni_flags & IEEE80211_NODE_HT) != 0;
        const bool vht = (node->ni_flags & IEEE80211_NODE_VHT) != 0;
        bool qos = (node->ni_flags & IEEE80211_NODE_QOS) != 0;
        /* HT data uses QoS headers and Block-Ack TIDs.  Some APs advertise
         * WMM in a form that the Apple-facing association bridge does not
         * preserve, leaving an otherwise valid HT node without NODE_QOS.
         * HT itself requires QoS, so restore that implied capability before
         * net80211 begins transmitting data. */
        if (ht && !qos) {
            node->ni_flags |= IEEE80211_NODE_QOS;
            ic->ic_flags |= IEEE80211_F_QOS;
            qos = true;
        }
        const uint8_t nss = Rtw88Link::htStreams(node->ni_rxmcs, sizeof(node->ni_rxmcs));
        Rtw88NativePeer peer = {};
        peer.caps.htCaps = node->ni_htcaps;
        peer.caps.ampduParams = node->ni_ampdu_param;
        memcpy(peer.caps.htMCS, node->ni_rxmcs, sizeof(peer.caps.htMCS));
        peer.caps.vhtCaps = node->ni_vhtcaps;
        peer.caps.vhtRxMCS = le16toh(node->ni_vht_mcsinfo.rx_mcs_map);
        peer.caps.vhtTxMCS = le16toh(node->ni_vht_mcsinfo.tx_mcs_map);
        peer.widthMHz = node->ni_chw == IEEE80211_CHAN_WIDTH_80 ? 80 :
            node->ni_chw == IEEE80211_CHAN_WIDTH_40 ? 40 : 20;
        peer.centerFrequency = peer.widthMHz == 20 ? node->ni_chan->ic_freq :
            node->ni_chan->ic_center_freq1;
        if (!rtw88LinuxAssociate(&owner->linuxContext, node->ni_bssid, aid,
                                 node->ni_capinfo, channel, node->ni_intval,
                                 node->ni_dtimperiod, qos, ht, vht, nss, peer)) {
            if (endedScan) {
                rtw88LinuxScanBegin(&owner->linuxContext);
                sc->sc_flags |= RTW88_FLAG_SCANNING;
            }
            return EIO;
        }
        associated = true;
        sc->sc_sta = static_cast<struct ieee80211_sta *>(
            owner->linuxContext.station);
    }

    const int result = sc->sc_newstate(ic, state, arg);
    if (result != 0) {
        if (associated) {
            rtw88LinuxDisassociate(&owner->linuxContext);
            sc->sc_sta = nullptr;
        }
        if (beganScan) {
            rtw88LinuxScanEnd(&owner->linuxContext);
            sc->sc_flags &= ~RTW88_FLAG_SCANNING;
        }
        if (endedScan) {
            rtw88LinuxScanBegin(&owner->linuxContext);
            sc->sc_flags |= RTW88_FLAG_SCANNING;
        }
        return result;
    }
    if (state == IEEE80211_S_RUN) {
        owner->associationRunWatchdogTicks = 0;
        owner->associationRecoveryPending = 0;
        if (owner->associationRecoveryTimer)
            owner->associationRecoveryTimer->cancelTimeout();
    } else if (shortAssociationExit && owner->associationRecoveryTimer) {
        owner->associationRecoveryPending = 1;
        __sync_fetch_and_add(&owner->associationRecoveryTriggerCount, 1);
        owner->associationRecoveryTimer->setTimeoutMS(1000);
    }
    /* The generic output-path trigger is not firing on the Apple-facing
     * interface even though HT, QoS and RSN are active.  Schedule the normal
     * net80211 ADDBA exchange once RUN is established.  Hardware aggregation
     * is still enabled only by ampduTxStart() after a successful AP response. */
    if (state == IEEE80211_S_RUN && node &&
        (node->ni_flags & IEEE80211_NODE_HT) &&
        (node->ni_flags & IEEE80211_NODE_QOS))
        ieee80211_node_trigger_addba_req(node, EDCA_AC_BE);
    if (state == IEEE80211_S_SCAN && owner->scanDwellTimer)
        owner->scanDwellTimer->setTimeoutMS(120);
    return 0;
}

int RTWCore88::setKey(struct ieee80211com *ic, struct ieee80211_node *node,
                     struct ieee80211_key *key)
{
    if (!ic || !key)
        return EINVAL;
    // Keep TKIP in net80211 software crypto; CCMP uses RTW88 security CAM.
    // The Linux bridge normalizes hardware-decrypted CCMP to net80211's
    // IV/replay/MIC contract without changing the shared crypto stack.
    if (key->k_cipher != IEEE80211_CIPHER_CCMP)
        return ieee80211_set_key(ic, node, key);
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    if (!sc)
        return ENXIO;
    auto *owner = container_of(sc, RTWCore88, sc);
    Rtw88NativeCipher cipher;
    switch (key->k_cipher) {
    case IEEE80211_CIPHER_WEP40: cipher = Rtw88CipherWEP40; break;
    case IEEE80211_CIPHER_TKIP: cipher = Rtw88CipherTKIP; break;
    case IEEE80211_CIPHER_CCMP: cipher = Rtw88CipherCCMP; break;
    case IEEE80211_CIPHER_WEP104: cipher = Rtw88CipherWEP104; break;
    default: return EINVAL;
    }
    const bool pairwise = (key->k_flags & IEEE80211_KEY_GROUP) == 0;
    if (!rtw88LinuxSetKey(&owner->linuxContext, key->k_id, cipher, pairwise,
                          key->k_key, key->k_len))
        return EIO;
    key->k_flags &= ~IEEE80211_KEY_SWCRYPTO;
    return 0;
}

void RTWCore88::deleteKey(struct ieee80211com *ic, struct ieee80211_node *node,
                         struct ieee80211_key *key)
{
    if (!ic || !key)
        return;
    if (key->k_flags & IEEE80211_KEY_SWCRYPTO) {
        ieee80211_delete_key(ic, node, key);
        return;
    }
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    if (!sc)
        return;
    auto *owner = container_of(sc, RTWCore88, sc);
    rtw88LinuxDeleteKey(&owner->linuxContext, key->k_id,
                        (key->k_flags & IEEE80211_KEY_GROUP) == 0);
}

void RTWCore88::updateSlot(struct ieee80211com *ic)
{
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, RTWCore88, sc);
    rtw88LinuxUpdateSlot(&owner->linuxContext,
                         (ic->ic_flags & IEEE80211_F_SHSLOT) != 0);
}
void RTWCore88::updateEdca(struct ieee80211com *ic)
{
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, RTWCore88, sc);
    /* OpenBSD order is BE/BK/VI/VO; mac80211 order is VO/VI/BE/BK. */
    static const uint8_t linuxAccessClass[EDCA_NUM_AC] = {
        2, 3, 1, 0
    };
    for (uint8_t ac = 0; ac < EDCA_NUM_AC; ++ac) {
        const struct ieee80211_edca_ac_params *params = &ic->ic_edca_ac[ac];
        rtw88LinuxConfigureQueue(&owner->linuxContext, linuxAccessClass[ac],
                                 (1U << params->ac_ecwmin) - 1,
                                 (1U << params->ac_ecwmax) - 1,
                                 params->ac_aifsn, params->ac_txoplimit);
    }
}

int RTWCore88::ampduRxStart(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    if (!ic || !node || tid >= IEEE80211_NUM_TID)
        return EINVAL;
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, RTWCore88, sc);
    struct ieee80211_rx_ba *ba = &node->ni_rx_ba[tid];
    return rtw88LinuxAmpduStart(&owner->linuxContext, tid, true,
                                ba->ba_winstart, ba->ba_winsize) ? 0 : EIO;
}

void RTWCore88::ampduRxStop(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    (void)node;
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, RTWCore88, sc);
    rtw88LinuxAmpduStop(&owner->linuxContext, tid, true);
}

int RTWCore88::ampduTxStart(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    if (!ic || !node || tid >= IEEE80211_NUM_TID)
        return EINVAL;
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, RTWCore88, sc);
    struct ieee80211_tx_ba *ba = &node->ni_tx_ba[tid];
    return rtw88LinuxAmpduStart(&owner->linuxContext, tid, false,
                                ba->ba_winstart, 64) ? 0 : EIO;
}

void RTWCore88::ampduTxStop(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    (void)node;
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw88_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, RTWCore88, sc);
    rtw88LinuxAmpduStop(&owner->linuxContext, tid, false);
}
