/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "ItlRtw89.hpp"
#include "Rtw89PciTransport.hpp"

#include <IOKit/IOLib.h>

/* net80211 sources are compiled as C++ in this target. */
void ieee80211_recv_assoc_resp(struct ieee80211com *, mbuf_t,
                               struct ieee80211_node *, int);

#include <IOKit/network/IONetworkMedium.h>
#include <net80211/ieee80211_crypto.h>

#define super ItlHalService
OSDefineMetaClassAndStructors(ItlRtw89, ItlHalService)

namespace {
constexpr UInt16 kRealtekVendor = 0x10ec;
constexpr UInt16 kRtl8852AE = 0x8852;
constexpr UInt16 kRtl8852AEAlternate = 0xa85a;
constexpr UInt16 kRtl8852BE = 0xb852;
constexpr UInt16 kRtl8852BEAlternate = 0xb85b;
constexpr UInt16 kRtl8851BE = 0xb851;
constexpr UInt16 kRtl8852BTE = 0xb520;
constexpr UInt16 kRtl8852CE = 0xc852;
constexpr UInt16 kRtl8922AE = 0x8922;
constexpr UInt16 kRtl8922AEVS = 0x892b;
constexpr uint32_t kRtw89TxQueueSize = 256;
}

bool ItlRtw89::rtw89_match(IOPCIDevice *device)
{
    if (!device)
        return false;

    const UInt16 vendor = device->configRead16(kIOPCIConfigVendorID);
    const UInt16 product = device->configRead16(kIOPCIConfigDeviceID);
    return vendor == kRealtekVendor &&
           (product == kRtl8852AE || product == kRtl8852AEAlternate ||
            product == kRtl8852BE || product == kRtl8852BEAlternate ||
            product == kRtl8851BE || product == kRtl8852BTE ||
            product == kRtl8852CE || product == kRtl8922AE ||
            product == kRtl8922AEVS);
}

bool ItlRtw89::attach(IOPCIDevice *device)
{
    IOLog("AirportRTW-RTW89: attach begin\n");
    if (!rtw89_match(device))
        return false;

    const UInt16 product = device->configRead16(kIOPCIConfigDeviceID);
    const char *firmware = "rtw89/rtw8852a_fw.bin";
    const char *chipName = "embedded RTL8852A";

    pciDevice = device;
    transport = Rtw89PciTransport::withDevice(device, getMainWorkLoop());
    if (!transport)
        goto fail;

    scanDwellTimer = IOTimerEventSource::timerEventSource(
        this, &ItlRtw89::scanDwellExpired);
    if (!scanDwellTimer)
        goto fail;
    if (getMainWorkLoop()->addEventSource(scanDwellTimer) != kIOReturnSuccess) {
        scanDwellTimer->release();
        scanDwellTimer = nullptr;
        goto fail;
    }

    associationRecoveryTimer = IOTimerEventSource::timerEventSource(
        this, &ItlRtw89::associationRecoveryExpired);
    if (!associationRecoveryTimer)
        goto fail;
    if (getMainWorkLoop()->addEventSource(associationRecoveryTimer) !=
        kIOReturnSuccess) {
        associationRecoveryTimer->release();
        associationRecoveryTimer = nullptr;
        goto fail;
    }

    if (!rtw89LinuxAttach(transport, &linuxContext))
        goto fail;
    IOLog("AirportRTW-RTW89: Linux PCI probe complete\n");
    linuxContext.nativeOwner = this;
    linuxContext.receive = receive;
    linuxContext.txResume = resumeTransmit;
    sc.sc_hw = static_cast<struct ieee80211_hw *>(linuxContext.hardware);
    sc.sc_rtwdev = static_cast<struct rtw89_dev *>(linuxContext.device);
    sc.sc_vif = static_cast<struct ieee80211_vif *>(linuxContext.vif);
    sc.sc_vif_size = linuxContext.vifAllocationSize;
    switch (product) {
    case kRtl8852BE:
    case kRtl8852BEAlternate:
        firmware = "rtw89/rtw8852b_fw-1.bin";
        chipName = "embedded RTL8852B";
        break;
    case kRtl8851BE:
        firmware = "rtw89/rtw8851b_fw.bin";
        chipName = "embedded RTL8851B";
        break;
    case kRtl8852BTE:
        firmware = "rtw89/rtw8852bt_fw.bin";
        chipName = "embedded RTL8852BT";
        break;
    case kRtl8852CE:
        firmware = "rtw89/rtw8852c_fw-2.bin";
        chipName = "embedded RTL8852C";
        break;
    case kRtl8922AE:
    case kRtl8922AEVS:
        firmware = "rtw89/rtw8922a_fw-4.bin";
        chipName = "embedded RTL8922A";
        break;
    default:
        break;
    }
    strlcpy(sc.sc_fwname, firmware, sizeof(sc.sc_fwname));
    strlcpy(sc.sc_fwver, chipName, sizeof(sc.sc_fwver));
    strlcpy(sc.sc_country, "00", sizeof(sc.sc_country));
    sc.sc_noise = -95;

    if (!attachNet80211())
        goto fail_linux;
    transport->enableInterrupts();
    sc.sc_flags |= RTW89_FLAG_ATTACHED;
    IOLog("AirportRTW-RTW89: attach complete\n");
    return true;

fail_linux:
    transport->disableInterrupts();
    rtw89LinuxDetach(transport, &linuxContext);
fail:
    IOLog("AirportRTW-RTW89: attach failed\n");
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

void ItlRtw89::detach(IOPCIDevice *device)
{
    (void)device;
    IOLog("AirportRTW-RTW89: detach begin\n");
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
        rtw89LinuxDetach(transport, &linuxContext);
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

IOReturn ItlRtw89::enable(IONetworkInterface *interface)
{
    (void)interface;
    IOLog("AirportRTW-RTW89: Wi-Fi enable begin\n");
    if (!(sc.sc_flags & RTW89_FLAG_ATTACHED))
        return kIOReturnNotReady;
    if (sc.sc_flags & RTW89_FLAG_ENABLED)
        return kIOReturnSuccess;
    if (!rtw89LinuxPowerUp(&linuxContext)) {
        IOLog("AirportRTW-RTW89: Wi-Fi enable failed during power-up\n");
        return kIOReturnIOError;
    }
    sc.sc_flags |= RTW89_FLAG_ENABLED | RTW89_FLAG_FW_RUNNING |
                   RTW89_FLAG_INTERFACE;
    sc.sc_ic.ic_if.if_flags |= IFF_UP | IFF_RUNNING;
    /* AirportRTW rejects scan requests while net80211 remains in INIT.
     * Intel HALs enter the initial scan after their hardware init task; do
     * the same once RTW89 is powered and able to change channels. */
    ieee80211_begin_scan(&sc.sc_ic.ic_if);
    IOLog("AirportRTW-RTW89: Wi-Fi enable complete\n");
    return kIOReturnSuccess;
}

IOReturn ItlRtw89::disable(IONetworkInterface *interface)
{
    (void)interface;
    IOLog("AirportRTW-RTW89: Wi-Fi disable begin\n");
    if (associationRecoveryTimer)
        associationRecoveryTimer->cancelTimeout();
    associationRecoveryPending = 0;
    associationRecoveryAttempted = 0;
    associationRecoveryAttemptActive = 0;
    associationRunWatchdogTicks = 0;
    if (sc.sc_ic.ic_state != IEEE80211_S_INIT)
        ieee80211_new_state(&sc.sc_ic, IEEE80211_S_INIT, -1);
    rtw89LinuxPowerDown(&linuxContext);
    sc.sc_ic.ic_if.if_flags &= ~(IFF_UP | IFF_RUNNING);
    sc.sc_sta = nullptr;
    sc.sc_flags &= ~(RTW89_FLAG_ENABLED | RTW89_FLAG_SCANNING |
                     RTW89_FLAG_FW_RUNNING | RTW89_FLAG_INTERFACE);
    IOLog("AirportRTW-RTW89: Wi-Fi disable complete\n");
    return kIOReturnSuccess;
}

void ItlRtw89::free()
{
    detach(pciDevice);
    super::free();
}

const char *ItlRtw89::getFirmwareVersion()
{
    return sc.sc_fwver;
}

int16_t ItlRtw89::getBSSNoise()
{
    /* AirportRTW's Apple80211 result path negates this HAL value.  Return
     * the positive magnitude so asr_noise is exported as -95 dBm. */
    return 95;
}

const char *ItlRtw89::getFirmwareName()
{
    return sc.sc_fwname;
}

UInt32 ItlRtw89::supportedFeatures()
{
    return kIONetworkFeatureMultiPages;
}

const char *ItlRtw89::getFirmwareCountryCode()
{
    return sc.sc_country;
}

uint32_t ItlRtw89::getTxQueueSize()
{
    return kRtw89TxQueueSize;
}

void ItlRtw89::clearScanningFlags()
{
    sc.sc_flags &= ~RTW89_FLAG_SCANNING;
}

IOReturn ItlRtw89::setMulticastList(IOEthernetAddress *addresses, int count)
{
    (void)addresses;
    rtw89LinuxSetAllMulticast(&linuxContext, count > 0);
    return kIOReturnSuccess;
}

bool ItlRtw89::attachNet80211()
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
                  IEEE80211_C_QOS | IEEE80211_C_TX_AMPDU;
    ic->ic_htcaps = IEEE80211_HTCAP_SGI20 |
                    IEEE80211_HTCAP_CBW20_40 | IEEE80211_HTCAP_SGI40 |
                    IEEE80211_HTCAP_LDPC |
                    (IEEE80211_HTCAP_SMPS_DIS << IEEE80211_HTCAP_SMPS_SHIFT);
    ic->ic_ampdu_params = IEEE80211_AMPDU_PARAM_SS_4 | 0x3;
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
        auto *entry = &ic->ic_channels[channel];
        entry->ic_freq = channel == 14 ? 2484
            : channel <= 13 ? 2407 + channel * 5 : 5000 + channel * 5;
        entry->ic_center_freq1 = entry->ic_freq;
        entry->ic_center_freq2 = 0;
        entry->ic_flags = channel <= 14
            ? IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN |
              IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_HT20
            : IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_HT20;
    }
    ic->ic_ibss_chan = &ic->ic_channels[1];

    ifp->if_softc = &sc;
    ifp->if_start = start;
    ifp->if_watchdog = watchdog;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
    strlcpy(ifp->if_xname, "rtw89", IFNAMSIZ);
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

void ItlRtw89::watchdog(struct _ifnet *ifp)
{
    /* The Linux RTW89 core schedules its own periodic maintenance work.
     * AirportRTW still expects every HAL to expose a BSD watchdog hook. */
    auto *sc = ifp ? static_cast<struct rtw89_softc *>(ifp->if_softc) : nullptr;
    if (!sc)
        return;
    auto *owner = container_of(sc, ItlRtw89, sc);
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
    IOEthernetController *controller = owner->getController();
    if (!controller)
        return;
    controller->setProperty("RTW89InterruptCount",
                            owner->transport ? owner->transport->getInterruptCount() : 0, 64);
    controller->setProperty("RTW89ScanChannelCount", owner->scanChannelCount, 64);
    controller->setProperty("RTW89RawReceiveCount", owner->rawReceiveCount, 64);
    controller->setProperty("RTW89AcceptedReceiveCount", owner->acceptedReceiveCount, 64);
    controller->setProperty("RTW89BeaconProbeCount", owner->beaconProbeCount, 64);
    controller->setProperty("RTW89AuthTxCount", owner->linuxContext.authTxCount, 64);
    controller->setProperty("RTW89AuthTxAckCount", owner->linuxContext.authTxAckCount, 64);
    controller->setProperty("RTW89AssocTxCount", owner->linuxContext.assocTxCount, 64);
    controller->setProperty("RTW89AssocTxAckCount", owner->linuxContext.assocTxAckCount, 64);
    controller->setProperty("RTW89AuthRxCount", owner->linuxContext.authRxCount, 64);
    controller->setProperty("RTW89AssocRxCount", owner->linuxContext.assocRxCount, 64);
    controller->setProperty("RTW89ActionTxCount", owner->linuxContext.actionTxCount, 64);
    controller->setProperty("RTW89ActionTxAckCount",
                            owner->linuxContext.actionTxAckCount, 64);
    controller->setProperty("RTW89ActionRxCount", owner->linuxContext.actionRxCount, 64);
    controller->setProperty("RTW89LastActionTxCategory",
                            owner->linuxContext.lastActionTxCategory, 32);
    controller->setProperty("RTW89LastActionTxCode",
                            owner->linuxContext.lastActionTxCode, 32);
    controller->setProperty("RTW89LastActionTxToken",
                            owner->linuxContext.lastActionTxToken, 32);
    controller->setProperty("RTW89LastAddbaTxBytes0To7",
                            owner->linuxContext.lastAddbaTxBytes0To7, 64);
    controller->setProperty("RTW89LastAddbaTxByte8",
                            owner->linuxContext.lastAddbaTxByte8, 32);
    controller->setProperty("RTW89LastAddbaTxParams",
                            owner->linuxContext.lastAddbaTxParams, 32);
    controller->setProperty("RTW89LastAddbaTxTimeout",
                            owner->linuxContext.lastAddbaTxTimeout, 32);
    controller->setProperty("RTW89LastAddbaTxStartSeqControl",
                            owner->linuxContext.lastAddbaTxStartSeqControl, 32);
    controller->setProperty("RTW89LastActionRxCategory",
                            owner->linuxContext.lastActionRxCategory, 32);
    controller->setProperty("RTW89LastActionRxCode",
                            owner->linuxContext.lastActionRxCode, 32);
    controller->setProperty("RTW89LastActionRxToken",
                            owner->linuxContext.lastActionRxToken, 32);
    controller->setProperty("RTW89LastActionRxStatus",
                            owner->linuxContext.lastActionRxStatus, 32);
    controller->setProperty("RTW89DataTxCount", owner->linuxContext.dataTxCount, 64);
    controller->setProperty("RTW89ProtectedTxCount", owner->linuxContext.protectedTxCount, 64);
    controller->setProperty("RTW89DHCPTxCount", owner->linuxContext.dhcpTxCount, 64);
    controller->setProperty("RTW89DHCPTxAckCount", owner->linuxContext.dhcpTxAckCount, 64);
    controller->setProperty("RTW89ARPTxCount", owner->linuxContext.arpTxCount, 64);
    controller->setProperty("RTW89ARPTxAckCount", owner->linuxContext.arpTxAckCount, 64);
    controller->setProperty("RTW89LastTxCipher", owner->linuxContext.lastTxCipher, 32);
    controller->setProperty("RTW89LastTxKeyIndex", owner->linuxContext.lastTxKeyIndex, 32);
    controller->setProperty("RTW89LastTxIvLength", owner->linuxContext.lastTxIvLength, 32);
    controller->setProperty("RTW89TxDescDataCount",
                            owner->linuxContext.txDescDataCount, 64);
    controller->setProperty("RTW89TxDescUseRate",
                            owner->linuxContext.txDescUseRate, 32);
    controller->setProperty("RTW89TxDescDisableFallback",
                            owner->linuxContext.txDescDisableFallback, 32);
    controller->setProperty("RTW89TxDescHardwareRate",
                            owner->linuxContext.txDescHardwareRate, 32);
    controller->setProperty("RTW89TxDescBandwidth",
                            owner->linuxContext.txDescBandwidth, 32);
    controller->setProperty("RTW89TxDescAggregationEnabled",
                            owner->linuxContext.txDescAggregationEnabled, 32);
    controller->setProperty("RTW89TxDescMacId",
                            owner->linuxContext.txDescMacId, 32);
    controller->setProperty("RTW89TxDescQueueSelect",
                            owner->linuxContext.txDescQueueSelect, 32);
    controller->setProperty("RTW89TxReportCount",
                            owner->linuxContext.txReportCount, 64);
    controller->setProperty("RTW89TxReportStatus",
                            owner->linuxContext.txReportStatus, 32);
    controller->setProperty("RTW89TxReportAttempts",
                            owner->linuxContext.txReportAttempts, 32);
    controller->setProperty("RTW89TxAvailableSlots",
                            rtw89LinuxTxAvailableSlots(&owner->linuxContext), 32);
    controller->setProperty("RTW89OutputQueueLength",
                            (UInt64)ifq_len(&ifp->if_snd), 32);
    controller->setProperty("RTW89OutputQueueActive",
                            (UInt64)ifq_is_oactive(&ifp->if_snd), 8);
    controller->setProperty("RTW89StartCallCount", owner->startCallCount, 64);
    controller->setProperty("RTW89TxBackpressureCount",
                            owner->txBackpressureCount, 64);
    controller->setProperty("RTW89TxAmpduMask",
                            owner->linuxContext.txAmpduMask, 16);
    controller->setProperty("RTW89AmpduTxStartCount",
                            owner->linuxContext.ampduTxStartCount, 64);
    controller->setProperty("RTW89AmpduTxStartFailCount",
                            owner->linuxContext.ampduTxStartFailCount, 64);
    controller->setProperty("RTW89AmpduTxStopCount",
                            owner->linuxContext.ampduTxStopCount, 64);
    controller->setProperty("RTW89AmpduRxStartCount",
                            owner->linuxContext.ampduRxStartCount, 64);
    controller->setProperty("RTW89AmpduRxStartFailCount",
                            owner->linuxContext.ampduRxStartFailCount, 64);
    controller->setProperty("RTW89AmpduRxStopCount",
                            owner->linuxContext.ampduRxStopCount, 64);
    controller->setProperty("RTW89AssocStageMask",
                            owner->linuxContext.assocStageMask, 32);
    controller->setProperty("RTW89RAAssocMode",
                            owner->linuxContext.raAuditU32[1], 32);
    controller->setProperty("RTW89RAAssocBandwidth",
                            owner->linuxContext.raAuditU32[2], 32);
    controller->setProperty("RTW89RAAssocSpatialStreams",
                            owner->linuxContext.raAuditU32[3] + 1, 32);
    controller->setProperty("RTW89RAAssocRxNss",
                            owner->linuxContext.raAuditU32[41], 32);
    controller->setProperty("RTW89RAAssocTxNss",
                            owner->linuxContext.raAuditU32[42], 32);
    controller->setProperty("RTW89RAAssocMask",
                            owner->linuxContext.raAuditU64[0], 64);
    controller->setProperty("RTW89RALiveMode",
                            owner->linuxContext.raAuditU32[43], 32);
    controller->setProperty("RTW89RALiveMcs",
                            owner->linuxContext.raAuditU32[44], 32);
    controller->setProperty("RTW89RALiveBandwidth",
                            owner->linuxContext.raAuditU32[45], 32);
    controller->setProperty("RTW89RALiveNss",
                            owner->linuxContext.raAuditU32[46], 32);
    controller->setProperty("RTW89RALiveFlags",
                            owner->linuxContext.raAuditU32[47], 32);
    controller->setProperty("RTW89RALiveBitrate100Kbps",
                            owner->linuxContext.raAuditU32[48], 32);
    controller->setProperty("RTW89RALiveHardwareRate",
                            owner->linuxContext.raAuditU32[49], 32);
    controller->setProperty("RTW89LastAssocResponseLength",
                            owner->lastAssocResponseLength, 32);
    controller->setProperty("RTW89LastAssocResponseStatus",
                            owner->lastAssocResponseStatus, 16);
    controller->setProperty("RTW89LastAssocResponseAid",
                            owner->lastAssocResponseAid, 16);
    controller->setProperty("RTW89LastAssocResponseFirstIE",
                            owner->lastAssocResponseFirstIE, 16);
    controller->setProperty("RTW89AssocStatus", owner->sc.sc_ic.ic_assoc_status, 16);
    controller->setProperty("RTW89RxMgmtDiscard",
                            owner->sc.sc_ic.ic_stats.is_rx_mgtdiscard, 32);
    controller->setProperty("RTW89RxElementTooSmall",
                            owner->sc.sc_ic.ic_stats.is_rx_elem_toosmall, 32);
    controller->setProperty("RTW89RxAssocNoRate",
                            owner->sc.sc_ic.ic_stats.is_rx_assoc_norate, 32);
    controller->setProperty("RTW89RxDuplicate",
                            owner->sc.sc_ic.ic_stats.is_rx_dup, 32);
    controller->setProperty("RTW89RxWrongDirection",
                            owner->sc.sc_ic.ic_stats.is_rx_wrongdir, 32);
    controller->setProperty("RTW89RxTooShort",
                            owner->sc.sc_ic.ic_stats.is_rx_tooshort, 32);
    controller->setProperty("RTW89RxBadVersion",
                            owner->sc.sc_ic.ic_stats.is_rx_badversion, 32);
    controller->setProperty("RTW89LastAssocResponseFC1",
                            owner->lastAssocResponseFC1, 8);
    controller->setProperty("RTW89LastAssocResponseSequence",
                            owner->lastAssocResponseSequence, 16);
    controller->setProperty("RTW89AssocStateBeforeInput",
                            owner->assocStateBeforeInput, 8);
    controller->setProperty("RTW89AssocStateAfterInput",
                            owner->assocStateAfterInput, 8);
    controller->setProperty("RTW89AssocStatusAfterInput",
                            owner->assocStatusAfterInput, 16);
    controller->setProperty("RTW89Net80211NodeCount",
                            (UInt64)owner->sc.sc_ic.ic_nnodes, 32);
    controller->setProperty("RTW89AssociationRunWatchdogTicks",
                            owner->associationRunWatchdogTicks, 32);
    controller->setProperty("RTW89AssociationRecoveryPending",
                            owner->associationRecoveryPending, 8);
    controller->setProperty("RTW89AssociationRecoveryAttempted",
                            owner->associationRecoveryAttempted, 8);
    controller->setProperty("RTW89AssociationRecoveryTriggerCount",
                            owner->associationRecoveryTriggerCount, 64);
    controller->setProperty("RTW89AssociationRecoveryAttemptCount",
                            owner->associationRecoveryAttemptCount, 64);
    controller->setProperty("RTW89AssociationRecoverySuccessCount",
                            owner->associationRecoverySuccessCount, 64);
    controller->setProperty("RTW89Net80211State",
                            (UInt64)owner->sc.sc_ic.ic_state, 8);
    if (owner->sc.sc_ic.ic_bss) {
        struct ieee80211_node *node = owner->sc.sc_ic.ic_bss;
        controller->setProperty("RTW89NodeFlags", (UInt64)node->ni_flags, 32);
        controller->setProperty("RTW89NodeRsnProtocols",
                                (UInt64)node->ni_rsnprotos, 32);
        controller->setProperty("RTW89InterfaceFlags",
                                (UInt64)owner->sc.sc_ic.ic_flags, 32);
        controller->setProperty("RTW89TxBaStateBE",
                                (UInt64)node->ni_tx_ba[EDCA_AC_BE].ba_state, 8);
        controller->setProperty("RTW89TxBaStateBK",
                                (UInt64)node->ni_tx_ba[EDCA_AC_BK].ba_state, 8);
        controller->setProperty("RTW89TxBaStateVI",
                                (UInt64)node->ni_tx_ba[EDCA_AC_VI].ba_state, 8);
        controller->setProperty("RTW89TxBaStateVO",
                                (UInt64)node->ni_tx_ba[EDCA_AC_VO].ba_state, 8);
    }
    controller->setProperty("RTW89TxBaAgreements",
                            owner->sc.sc_ic.ic_stats.is_ht_tx_ba_agreements, 32);
    controller->setProperty("RTW89TxBaTimeouts",
                            owner->sc.sc_ic.ic_stats.is_ht_tx_ba_timeout, 32);
    controller->setProperty("RTW89LastReceiveFrequency",
                            (UInt64)owner->lastReceiveFrequency, 32);
    controller->setProperty("RTW89LastReceiveSignalRaw",
                            (UInt64)owner->lastReceiveSignalRaw, 8);
}

void ItlRtw89::scanDwellExpired(OSObject *object, IOTimerEventSource *timer)
{
    auto *owner = OSDynamicCast(ItlRtw89, object);
    if (!owner || timer != owner->scanDwellTimer ||
        !(owner->sc.sc_flags & RTW89_FLAG_ENABLED) ||
        owner->sc.sc_ic.ic_state != IEEE80211_S_SCAN)
        return;
    ieee80211_next_scan(&owner->sc.sc_ic.ic_if);
}

void ItlRtw89::associationRecoveryExpired(OSObject *object,
                                           IOTimerEventSource *timer)
{
    auto *owner = OSDynamicCast(ItlRtw89, object);
    if (!owner || timer != owner->associationRecoveryTimer ||
        !owner->associationRecoveryPending ||
        !(owner->sc.sc_flags & RTW89_FLAG_ENABLED) ||
        owner->sc.sc_ic.ic_state == IEEE80211_S_INIT ||
        owner->sc.sc_ic.ic_state == IEEE80211_S_RUN)
        return;

    owner->associationRecoveryPending = 0;
    owner->associationRecoveryAttempted = 1;
    owner->associationRecoveryAttemptActive = 1;
    __sync_fetch_and_add(&owner->associationRecoveryAttemptCount, 1);
    IOLog("AirportRTW-RTW89: retrying scan after short association\n");
    ieee80211_begin_scan(&owner->sc.sc_ic.ic_if);
}

void ItlRtw89::start(struct _ifnet *ifp)
{
    auto *sc = static_cast<struct rtw89_softc *>(ifp->if_softc);
    if (!sc || !(ifp->if_flags & IFF_RUNNING))
        return;
    auto *owner = container_of(sc, ItlRtw89, sc);
    __sync_fetch_and_add(&owner->startCallCount, 1);
    struct ieee80211com *ic = &sc->sc_ic;

    for (;;) {
        if (!rtw89LinuxTxAvailable(&owner->linuxContext)) {
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

        const size_t length = mbuf_pkthdr_len(m);
        uint8_t *frame = static_cast<uint8_t *>(IOMalloc(length));
        if (!frame || mbuf_copydata(m, 0, length, frame) != 0 ||
            !rtw89LinuxTransmit(&owner->linuxContext, frame, length,
                                management)) {
            ifp->netStat->outputErrors++;
        } else {
            ifp->netStat->outputPackets++;
        }
        if (frame)
            IOFree(frame, length);
        mbuf_freem(m);
        if (node)
            ieee80211_release_node(ic, node);
    }
}

void ItlRtw89::resumeTransmit(void *opaque)
{
    auto *owner = static_cast<ItlRtw89 *>(opaque);
    if (!owner || !(owner->sc.sc_flags & RTW89_FLAG_ENABLED))
        return;
    struct _ifnet *ifp = &owner->sc.sc_ic.ic_if;
    if (!ifq_is_oactive(&ifp->if_snd))
        return;
    ifq_clr_oactive(&ifp->if_snd);
    start(ifp);
}

void ItlRtw89::receive(void *opaque, const uint8_t *frame, size_t length,
                       int32_t rssi, uint16_t frequency, bool decrypted,
                       bool ivStripped)
{
    auto *owner = static_cast<ItlRtw89 *>(opaque);
    if (!owner || !frame || length < sizeof(struct ieee80211_frame))
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
    if (owner->sc.sc_flags & RTW89_FLAG_SCANNING &&
        frameType == IEEE80211_FC0_TYPE_MGT &&
        (frameSubtype == IEEE80211_FC0_SUBTYPE_BEACON ||
         frameSubtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)) {
        __sync_fetch_and_add(&owner->beaconProbeCount, 1);
        IOLog("ItlRtw89: scan RX subtype 0x%02x len %lu rssi %d freq %u\n",
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
    } else {
        ieee80211_inputm(&ic->ic_if, m, node, &rxi, &list);
        if_input(&ic->ic_if, &list);
    }
    ieee80211_release_node(ic, node);
    splx(networkPriority);
}

void ItlRtw89::detachNet80211()
{
    if (!(sc.sc_flags & RTW89_FLAG_ATTACHED))
        return;
    ieee80211_ifdetach(&sc.sc_ic.ic_if);
    sc.sc_flags &= ~RTW89_FLAG_ATTACHED;
}

int ItlRtw89::newstate(struct ieee80211com *ic,
                       enum ieee80211_state state, int arg)
{
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    if (!sc || !sc->sc_newstate)
        return ENXIO;
    auto *owner = container_of(sc, ItlRtw89, sc);
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
        rtw89LinuxDisassociate(&owner->linuxContext);
        sc->sc_sta = nullptr;
    }

    if (state == IEEE80211_S_SCAN && previous != IEEE80211_S_SCAN) {
        rtw89LinuxScanBegin(&owner->linuxContext);
        sc->sc_flags |= RTW89_FLAG_SCANNING;
        beganScan = true;
    }

    if (state == IEEE80211_S_SCAN && node && node->ni_chan) {
        const uint16_t channel = ieee80211_chan2ieee(ic, node->ni_chan);
        __sync_fetch_and_add(&owner->scanChannelCount, 1);
        IOLog("ItlRtw89: scan channel %u\n", channel);
        if (channel && !rtw89LinuxSetChannel(&owner->linuxContext, channel)) {
            if (beganScan) {
                rtw89LinuxScanEnd(&owner->linuxContext);
                sc->sc_flags &= ~RTW89_FLAG_SCANNING;
            }
            return EIO;
        }
    }

    /* rtw89 must leave software-scan mode before programming a chanctx or
     * transmitting authentication.  Keeping scan active here can leave the
     * PCI firmware on the scan channel while net80211 starts AUTH. */
    if (previous == IEEE80211_S_SCAN && state != IEEE80211_S_SCAN) {
        if (owner->scanDwellTimer)
            owner->scanDwellTimer->cancelTimeout();
        rtw89LinuxScanEnd(&owner->linuxContext);
        sc->sc_flags &= ~RTW89_FLAG_SCANNING;
        endedScan = true;
        if (state == IEEE80211_S_AUTH) {
            for (unsigned int attempt = 0;
                 attempt < 100 &&
                 rtw89LinuxIsScanning(&owner->linuxContext); ++attempt)
                IOSleep(50);
            /* The 8852A firmware still owns scan-mode RF state briefly after
             * its software flag clears.  Match the proven AirportRTW delay
             * before connect_hw_setup performs BB/RF register accesses. */
            IOSleep(500);
        }
    }

    if (state == IEEE80211_S_AUTH) {
        if (!node || !node->ni_chan) {
            if (endedScan) {
                rtw89LinuxScanBegin(&owner->linuxContext);
                sc->sc_flags |= RTW89_FLAG_SCANNING;
            }
            return EINVAL;
        }
        const uint16_t channel = ieee80211_chan2ieee(ic, node->ni_chan);
        if (!channel || !rtw89LinuxPrepareConnection(&owner->linuxContext,
                                                      node->ni_bssid, channel)) {
            if (endedScan) {
                rtw89LinuxScanBegin(&owner->linuxContext);
                sc->sc_flags |= RTW89_FLAG_SCANNING;
            } else if (beganScan) {
                rtw89LinuxScanEnd(&owner->linuxContext);
                sc->sc_flags &= ~RTW89_FLAG_SCANNING;
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
        const uint8_t nss = node->ni_rxmcs[1] ? 2 : 1;
        if (!rtw89LinuxAssociate(&owner->linuxContext, node->ni_bssid, aid,
                                 node->ni_capinfo, channel, node->ni_intval,
                                 node->ni_dtimperiod, qos, ht, vht, nss)) {
            if (endedScan) {
                rtw89LinuxScanBegin(&owner->linuxContext);
                sc->sc_flags |= RTW89_FLAG_SCANNING;
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
            rtw89LinuxDisassociate(&owner->linuxContext);
            sc->sc_sta = nullptr;
        }
        if (beganScan) {
            rtw89LinuxScanEnd(&owner->linuxContext);
            sc->sc_flags &= ~RTW89_FLAG_SCANNING;
        }
        if (endedScan) {
            rtw89LinuxScanBegin(&owner->linuxContext);
            sc->sc_flags |= RTW89_FLAG_SCANNING;
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

int ItlRtw89::setKey(struct ieee80211com *ic, struct ieee80211_node *node,
                     struct ieee80211_key *key)
{
    if (!ic || !key)
        return EINVAL;
    /* RTL8852A advertises no hardware TKIP crypto.  Keep CCMP in the RTW89
     * security CAM, but let net80211 encrypt/decrypt TKIP group traffic in
     * software instead of passing a key the hardware will reject. */
    if (key->k_cipher == IEEE80211_CIPHER_TKIP)
        return ieee80211_set_key(ic, node, key);
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    if (!sc)
        return ENXIO;
    auto *owner = container_of(sc, ItlRtw89, sc);
    Rtw89NativeCipher cipher;
    switch (key->k_cipher) {
    case IEEE80211_CIPHER_WEP40: cipher = Rtw89CipherWEP40; break;
    case IEEE80211_CIPHER_TKIP: cipher = Rtw89CipherTKIP; break;
    case IEEE80211_CIPHER_CCMP: cipher = Rtw89CipherCCMP; break;
    case IEEE80211_CIPHER_WEP104: cipher = Rtw89CipherWEP104; break;
    default: return EINVAL;
    }
    const bool pairwise = (key->k_flags & IEEE80211_KEY_GROUP) == 0;
    if (!rtw89LinuxSetKey(&owner->linuxContext, key->k_id, cipher, pairwise,
                          key->k_key, key->k_len))
        return EIO;
    key->k_flags &= ~IEEE80211_KEY_SWCRYPTO;
    return 0;
}

void ItlRtw89::deleteKey(struct ieee80211com *ic, struct ieee80211_node *node,
                         struct ieee80211_key *key)
{
    if (!ic || !key)
        return;
    if (key->k_flags & IEEE80211_KEY_SWCRYPTO) {
        ieee80211_delete_key(ic, node, key);
        return;
    }
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    if (!sc)
        return;
    auto *owner = container_of(sc, ItlRtw89, sc);
    rtw89LinuxDeleteKey(&owner->linuxContext, key->k_id,
                        (key->k_flags & IEEE80211_KEY_GROUP) == 0);
}

void ItlRtw89::updateSlot(struct ieee80211com *ic)
{
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, ItlRtw89, sc);
    rtw89LinuxUpdateSlot(&owner->linuxContext,
                         (ic->ic_flags & IEEE80211_F_SHSLOT) != 0);
}
void ItlRtw89::updateEdca(struct ieee80211com *ic)
{
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, ItlRtw89, sc);
    /* OpenBSD order is BE/BK/VI/VO; mac80211 order is VO/VI/BE/BK. */
    static const uint8_t linuxAccessClass[EDCA_NUM_AC] = {
        2, 3, 1, 0
    };
    for (uint8_t ac = 0; ac < EDCA_NUM_AC; ++ac) {
        const struct ieee80211_edca_ac_params *params = &ic->ic_edca_ac[ac];
        rtw89LinuxConfigureQueue(&owner->linuxContext, linuxAccessClass[ac],
                                 (1U << params->ac_ecwmin) - 1,
                                 (1U << params->ac_ecwmax) - 1,
                                 params->ac_aifsn, params->ac_txoplimit);
    }
}

int ItlRtw89::ampduRxStart(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    if (!ic || !node || tid >= IEEE80211_NUM_TID)
        return EINVAL;
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, ItlRtw89, sc);
    struct ieee80211_rx_ba *ba = &node->ni_rx_ba[tid];
    return rtw89LinuxAmpduStart(&owner->linuxContext, tid, true,
                                ba->ba_winstart, ba->ba_winsize) ? 0 : EIO;
}

void ItlRtw89::ampduRxStop(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    (void)node;
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, ItlRtw89, sc);
    rtw89LinuxAmpduStop(&owner->linuxContext, tid, true);
}

int ItlRtw89::ampduTxStart(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    if (!ic || !node || tid >= IEEE80211_NUM_TID)
        return EINVAL;
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, ItlRtw89, sc);
    struct ieee80211_tx_ba *ba = &node->ni_tx_ba[tid];
    return rtw89LinuxAmpduStart(&owner->linuxContext, tid, false,
                                ba->ba_winstart, 64) ? 0 : EIO;
}

void ItlRtw89::ampduTxStop(struct ieee80211com *ic,
                           struct ieee80211_node *node, uint8_t tid)
{
    (void)node;
    if (!ic)
        return;
    auto *sc = static_cast<struct rtw89_softc *>(ic->ic_if.if_softc);
    auto *owner = container_of(sc, ItlRtw89, sc);
    rtw89LinuxAmpduStop(&owner->linuxContext, tid, false);
}
