#include <crypto/sha1.h>
#include <HAL/RTWLocale.h>
//
//  WCL.cpp
//  AirportRTW
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifdef AIRPORT_WCL
#include "AirportRTWNativeController.hpp"
#include "AirportRTWNativeInterface.hpp"
#include <kern/thread_call.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>

extern IOCommandGate *_fCommandGate;

// Preserve an incomplete join before automatic fallback resets live counters.
static void retainIncompleteJoin(IOService *controller, ieee80211com *ic, uint32_t auth)
{
#if RTW_DIAGNOSTICS
    if (!(ic->ic_flags & IEEE80211_F_RSNON)) return;
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinEarlyRx", ic->ic_join_rx_early,
                            sizeof(ic->ic_join_rx_early)));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinAuth", auth, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinStage", ic->ic_sae_stage, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinError", ic->ic_sae_error, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinData", ic->ic_sae_rx_data, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinEAPOL", ic->ic_sae_rx_eapol, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinEAPOLCalls", ic->ic_sae_eapol_calls, 32));
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinHeaders", ic->ic_sae_rx_headers,
                            sizeof(ic->ic_sae_rx_headers)));
    const auto *node = ic->ic_bss;
    RTW_DIAGNOSTIC(controller->setProperty("RTWLastIncompleteJoinPHY",
        ic->ic_state != IEEE80211_S_RUN || !node ? "not associated" :
        (node->ni_flags & IEEE80211_NODE_HE) ? "802.11ax" :
        (node->ni_flags & IEEE80211_NODE_VHT) ? "802.11ac" :
        (node->ni_flags & IEEE80211_NODE_HT) ? "802.11n" : "legacy"));
    // Keep each attempt, including retries. Publish a copied collection.
    auto old = OSDynamicCast(OSArray, controller->getProperty("RTWIncompleteJoins"));
    if (old && old->getCount()) {
        auto last = OSDynamicCast(OSDictionary, old->getObject(old->getCount() - 1));
        auto serial = last ? OSDynamicCast(OSNumber, last->getObject("Serial")) : nullptr;
        if (serial && serial->unsigned32BitValue() == ic->ic_join_serial) return;
    }
    auto history = old ? OSArray::withArray(old) : OSArray::withCapacity(8);
    auto record = OSDictionary::withCapacity(10);
    if (!history || !record) {
        if (history) history->release();
        if (record) record->release();
        return;
    }
    const char *fields[] = {"Auth", "Stage", "Error", "Data", "EAPOL", "EAPOLCalls",
                            "Headers", "PHY", "EarlyRx"};
    for (auto field : fields) {
        char key[80];
        snprintf(key, sizeof(key), "RTWLastIncompleteJoin%s", field);
        if (auto value = controller->getProperty(key)) record->setObject(field, value);
    }
    if (ic->ic_state == IEEE80211_S_RUN) {
        if (auto audit = controller->getProperty("RTW89PeerAudit"))
            record->setObject("PeerAudit", audit);
    }
    if (auto serial = OSNumber::withNumber(ic->ic_join_serial, 32)) {
        record->setObject("Serial", serial);
        serial->release();
    }
    if (history->getCount() >= 8) history->removeObject(0);
    history->setObject(record);
    RTW_DIAGNOSTIC(controller->setProperty("RTWIncompleteJoins", history));
    record->release();
    history->release();
#else
    (void)controller; (void)ic; (void)auth;
#endif
}


struct AirportRTWSkywalkInterface::CountryUpdate {
    AirportRTWSkywalkInterface *interface;
    AirportRTW *controller;
    IOCommandGate *gate;
    IO80211WorkQueue *queue;
    thread_call_t call;
};

void AirportRTWSkywalkInterface::deferWCLCountryUpdate()
{
    auto queue = instance->getWorkQueue();
    if (wclStopping || !_fCommandGate || !queue)
        return;
    auto update = static_cast<CountryUpdate *>(IOMalloc(sizeof(CountryUpdate)));
    if (!update)
        return;
    update->call = thread_call_allocate(wclCountryUpdateThread, update);
    if (!update->call) {
        IOFree(update, sizeof(*update));
        return;
    }
    update->interface = this;
    update->controller = instance;
    update->gate = _fCommandGate;
    update->queue = queue;
    retain();
    instance->retain();
    update->gate->retain();
    queue->retain();
    thread_call_enter(update->call);
}

void AirportRTWSkywalkInterface::wclCountryUpdateThread(void *arg, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    // Native country notifications synchronously query WCL. Holding the gate
    // is necessary, but executing on the driver's workloop thread is forbidden.
    update->gate->runAction(wclCountryUpdateGated, update);
    thread_call_free(update->call);
    update->interface->release();
    update->controller->release();
    update->gate->release();
    update->queue->release();
    IOFree(update, sizeof(*update));
}

IOReturn AirportRTWSkywalkInterface::wclCountryUpdateGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    if (update->interface->wclStopping)
        return kIOReturnNotReady;
    if (!update->queue->inGate() || update->queue->onThread())
        return kIOReturnNotPermitted;
    apple80211_country_code_data country = {};
    const IOReturn status = update->controller->getCOUNTRY_CODE(
        static_cast<OSObject *>(update->interface), &country);
    if (status != kIOReturnSuccess) return status;
    // Reflect the already-applied HAL domain in the native interface cache.
    char effective[3] = {char(country.cc[0]), char(country.cc[1]), 0};
    update->interface->setProperty(APPLE80211_REGKEY_COUNTRY_CODE, effective);
    const auto locale = update->interface->fHalService->getDriverInfo()->getRegulatoryLocale();
    update->interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, nullptr, 0, false);
    // Tahoe rebuilds IO80211Locale synchronously using its own small country
    // table, bypassing our HAL-aware getLOCALE. Publish the effective HAL
    // category after that refresh, retaining the actual applied country.
    update->interface->setProperty(APPLE80211_REGKEY_LOCALE, rtw_locale_name(locale));
    return kIOReturnSuccess;
}

bool AirportRTWSkywalkInterface::initWCL()
{
    joinTimer = IOTimerEventSource::timerEventSource(this, wclJoinTimeout);
    if (!joinTimer)
        return false;
    if (instance->getWorkQueue()->addEventSource(joinTimer) != kIOReturnSuccess)
        return false;
    wclJoinLock = IOSimpleLockAlloc();
    wclJoinMessageTimer = IOTimerEventSource::timerEventSource(this, drainWCLJoinMessages);
    return wclJoinLock && wclJoinMessageTimer &&
        instance->getWorkQueue()->addEventSource(wclJoinMessageTimer) == kIOReturnSuccess;
}

void AirportRTWSkywalkInterface::stopWCL()
{
    // Pending country tasks must observe shutdown under the same gate.
    if (_fCommandGate)
        _fCommandGate->runAction(stopWCLGated, this);
    wclStopping = true;
    if (joinTimer) {
        joinTimer->cancelTimeout();
        if (joinTimer->getWorkLoop())
            joinTimer->getWorkLoop()->removeEventSource(joinTimer);
        OSSafeReleaseNULL(joinTimer);
    }
    if (wclJoinLock) IOSimpleLockLock(wclJoinLock);
    auto messageTimer = wclJoinMessageTimer;
    wclJoinMessageTimer = nullptr;
    wclJoinCount = 0;
    if (wclJoinLock) IOSimpleLockUnlock(wclJoinLock);
    if (messageTimer) {
        messageTimer->cancelTimeout();
        if (messageTimer->getWorkLoop())
            messageTimer->getWorkLoop()->removeEventSource(messageTimer);
        messageTimer->release();
    }
    if (scanSource)
        scanSource->cancelTimeout();
    scanPending = joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    if (fHalService) {
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        ic->ic_wcl_scan_requested = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    }
}

IOReturn AirportRTWSkywalkInterface::stopWCLGated(
    OSObject *, void *arg, void *, void *, void *)
{
    static_cast<AirportRTWSkywalkInterface *>(arg)->wclStopping = true;
    return kIOReturnSuccess;
}

void AirportRTWSkywalkInterface::free()
{
    if (joinTimer)
        stopWCL();
    if (wclJoinLock) {
        IOSimpleLockFree(wclJoinLock);
        wclJoinLock = nullptr;
    }
    IO80211InfraProtocol::free();
}

IOReturn AirportRTWSkywalkInterface::wclCommand(OSObject *, void *a0, void *a1, void *a2, void *)
{
    auto self = static_cast<AirportRTWSkywalkInterface *>(a0);
    if (self->wclStopping)
        return kIOReturnNotReady;
    switch (uintptr_t(a1)) {
        case 13: return self->copyWCLChannels(a2);
        case 14: return self->copyWCLTrafficCounters(a2);
        case 12:
            self->handleWCLEvent(int(uintptr_t(a2)), nullptr);
            return kIOReturnSuccess;
        case 11: self->clearWCLPMKSA(); return kIOReturnSuccess;
        case 8: return self->installWCLKey(static_cast<apple80211_key *>(a2));
        case 9: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), true);
        case 10: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), false);
        case 0: return self->beginWCLScan(static_cast<apple80211ScanRequest *>(a2));
        case 1: return self->beginWCLJoin(static_cast<apple80211AssocCandidates *>(a2));
        case 2: return self->abortWCLJoin();
        case 3: return self->leaveWCLNetwork();
        case 6: return self->copyWCLExtendedBss(a2);
        case 7:
            if (!a2 || !self->wclBssValid || !self->wclAssociatedBeacons)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBeaconInfo, sizeof(self->wclBeaconInfo));
            return kIOReturnSuccess;
        case 5:
            if (!a2 || !self->wclBssValid)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBssInfo, sizeof(self->wclBssInfo));
            return kIOReturnSuccess;
        case 4:
            self->finishWCLScan(kIOReturnAborted);
            return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportRTWSkywalkInterface::setWCL_SCAN_REQ(apple80211ScanRequest *request)
{
    return _fCommandGate->runAction(wclCommand, this, nullptr, request);
}

IOReturn AirportRTWSkywalkInterface::setWCL_SCAN_ABORT(void *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(4));
}

IOReturn AirportRTWSkywalkInterface::setWCL_ASSOCIATE(apple80211AssocCandidates *request)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(1), request);
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn AirportRTWSkywalkInterface::setWCL_JOIN_ABORT(void *)
#else
IOReturn AirportRTWSkywalkInterface::setWCL_JOIN_ABORT(apple80211_wcl_abort_join *)
#endif
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(2));
}

IOReturn AirportRTWSkywalkInterface::setWCL_LEAVE_NETWORK(apple80211_leave_network *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(3));
}

IOReturn AirportRTWSkywalkInterface::beginWCLScan(apple80211ScanRequest *request)
{
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanRequestCount", ++wclScanRequestCount, 64));
    AirportWCL::ScanRequest scan;
    if (!AirportWCL::decodeScan(request, 0x1550, scan)) {
        RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanDecodeFailed", kOSBooleanTrue));
        return kIOReturnBadArgument;
    }
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanDecodeFailed", kOSBooleanFalse));
    ieee80211com *ic = fHalService->get80211Controller();
    if (!(ic->ic_if.if_flags & IFF_RUNNING))
        return kIOReturnNotReady;
    if (scanPending || joinPending || (ic->ic_flags & IEEE80211_F_BGSCAN))
        return kIOReturnBusy;
    if (ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC)
        return kIOReturnBusy;
    if (scan.channelCount) {
        bool usable = false;
        for (unsigned channel = 1; channel <= IEEE80211_CHAN_MAX; ++channel)
            if (ic->ic_channels[channel].ic_flags &&
                AirportWCL::scanChannelSelected(scan.channels, true, channel))
                usable = true;
        if (!usable)
            return kIOReturnUnsupported;
    }
    scanPending = true;
    scanCompleted = false;
    scanSkipCompletion = ic->ic_state == IEEE80211_S_SCAN &&
        ((scan.type != 2 && scan.ssidLength != 0) ||
         ic->ic_wcl_scan_ssid_length != 0 || ic->ic_des_esslen != 0);
    ic->ic_wcl_scan_requested = true;
    ic->ic_wcl_scan_active = scan.type != 2;
    ic->ic_wcl_scan_ssid_length = scan.type == 2 ? 0 : scan.ssidLength;
    memcpy(ic->ic_wcl_scan_ssid, scan.ssid, sizeof(scan.ssid));
    ic->ic_wcl_scan_restricted = scan.channelCount != 0;
    memcpy(ic->ic_wcl_scan_channels, scan.channels, sizeof(scan.channels));
    scanSource->setTimeoutMS(20000);
    if (ic->ic_state == IEEE80211_S_RUN) {
        if (!ic->ic_bgscan_start) {
            scanCompleted = true;
            finishWCLScan(kIOReturnSuccess);
            return kIOReturnSuccess;
        }
        ieee80211_begin_cache_bgscan(&ic->ic_if);
        if (!(ic->ic_flags & IEEE80211_F_BGSCAN)) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            return kIOReturnBusy;
        }
    } else if (ic->ic_state != IEEE80211_S_SCAN) {
        int error = ic->ic_newstate(ic, IEEE80211_S_SCAN, -1);
        if (error) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            return kIOReturnError;
        }
    }
    return kIOReturnSuccess;
}

void AirportRTWSkywalkInterface::finishWCLScan(IOReturn status)
{
    if (!scanPending)
        return;
    scanPending = false;
    scanCompleted = false;
    scanSource->cancelTimeout();
    auto ic = fHalService->get80211Controller();
    // RX callbacks run outside the native PostOffice gate. Replay the retained
    // scan cache here, in the same gated context that accepts ScanDone, and
    // always publish the results before the completion message.
    if (status == kIOReturnSuccess) {
        ieee80211_node *node;
        RB_FOREACH(node, ieee80211_tree, &ic->ic_tree) {
            if (!node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC ||
                !node->ni_rsnie_tlv || !node->ni_rsnie_tlv_len)
                continue;
            unsigned channel = ieee80211_chan2ieee(ic, node->ni_chan);
            if (!AirportWCL::scanChannelSelected(ic->ic_wcl_scan_channels,
                                                ic->ic_wcl_scan_restricted, channel))
                continue;
            if (ic->ic_wcl_scan_ssid_length &&
                (node->ni_esslen != ic->ic_wcl_scan_ssid_length ||
                 memcmp(node->ni_essid, ic->ic_wcl_scan_ssid, node->ni_esslen)))
                continue;
            publishWCLBeacon(node, node->ni_rsnie_tlv, node->ni_rsnie_tlv_len);
        }
    }
    ic->ic_wcl_scan_requested = false;
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLBeaconEventCount", wclBeaconEventCount, 64));
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanPublishCount", wclScanPublishCount, 64));
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanInvalidIECount", wclScanInvalidIECount, 64));
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanInvalidChannelCount", wclScanInvalidChannelCount, 64));
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanLastPostStatus", uint64_t(wclLastScanPostStatus), 32));
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanCompletionStatus", uint64_t(status), 32));
    IOReturn posted = instance->postMessage(this, AirportWCL::ScanDone, &status, sizeof(status), true);
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLScanDonePostStatus", uint64_t(posted), 32));
}

void AirportRTWSkywalkInterface::completeWCLScan()
{
    if (!wclStopping)
        finishWCLScan(scanCompleted ? kIOReturnSuccess : kIOReturnTimeout);
}

void AirportRTWSkywalkInterface::publishWCLBeacon(const ieee80211_node *node, const uint8_t *ies, size_t length)
{
    if (!node || node->ni_esslen > 32 || !AirportWCL::validIEs(ies, length)) {
        ++wclScanInvalidIECount;
        return;
    }
    ieee80211com *ic = fHalService->get80211Controller();
    if (!node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC) {
        ++wclScanInvalidChannelCount;
        return;
    }
    unsigned channel = ieee80211_chan2ieee(ic, node->ni_chan);
    if (!channel || channel > 196) {
        ++wclScanInvalidChannelCount;
        return;
    }
    size_t size = sizeof(AirportWCL::BeaconMetadata) + length;
    auto metadata = static_cast<AirportWCL::BeaconMetadata *>(IOMalloc(size));
    if (!metadata)
        return;
    *metadata = {};
    metadata->ieLength = uint32_t(length);
    metadata->channelSpec = uint16_t(channel | (IEEE80211_IS_CHAN_5GHZ(node->ni_chan) ? 0xd000 : 0x1000));
    metadata->channel = channel;
    metadata->ssidLength = node->ni_esslen;
    memcpy(metadata->ssid, node->ni_essid, node->ni_esslen);
    memcpy(metadata->bssid, node->ni_bssid, 6);
    metadata->rssi = RTW_MIN_DBM + node->ni_rssi;
    metadata->interval = node->ni_intval;
    metadata->capability = node->ni_capinfo;
    metadata->flags = AirportWCL::SSIDPresent | AirportWCL::RSSIValid;
    memcpy(metadata + 1, ies, length);
    metadata->ieLength = uint32_t(AirportWCL::selectWPA2TransitionMode(
        reinterpret_cast<uint8_t *>(metadata + 1), length));
    size_t messageSize = sizeof(*metadata) + metadata->ieLength;
    if (assocNotified && IEEE80211_ADDR_EQ(node->ni_bssid, joinBSSID)) {
        wclBssValid = messageSize <= sizeof(wclBssInfo);
        if (wclBssValid) {
            bzero(wclBssInfo, sizeof(wclBssInfo));
            memcpy(wclBssInfo, metadata, messageSize);
        }
    }
    // Keep associated BSS snapshots above up to date on RX, but defer scan
    // delivery until the native gate is held. finishWCLScan replays the cache.
    if (instance->getWorkQueue()->inGate()) {
        ++wclScanPublishCount;
        wclLastScanPostStatus = instance->postMessage(this, AirportWCL::ScanResult,
                                                    metadata, messageSize, true);
    }
    IOFree(metadata, size);
}

void AirportRTWSkywalkInterface::clearWCLPMKSA()
{
    auto ic = fHalService->get80211Controller();
    ieee80211_pmk *pmk;
    while ((pmk = TAILQ_FIRST(&ic->ic_pmksa))) {
        TAILQ_REMOVE(&ic->ic_pmksa, pmk, pmk_next);
        explicit_bzero(pmk, sizeof(*pmk));
        ::free(pmk);
    }
}

IOReturn AirportRTWSkywalkInterface::setCLEAR_PMKSA_CACHE(void *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(11));
}

IOReturn AirportRTWSkywalkInterface::installWCLKey(apple80211_key *key)
{
    static_assert(sizeof(apple80211_key) == 0x94, "WCL cipher key layout");
    if (!key || !AirportWCL::validCipherKey(key->key_cipher_type, key->key_len,
            key->key_flags, key->key_index, key->key_rsc_len))
        return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    auto ni = ic->ic_bss;
    if (!ic->ic_wcl_enterprise || !ni || ic->ic_state != IEEE80211_S_RUN)
        return kIOReturnNotReady;
    if (key->key_cipher_type == APPLE80211_CIPHER_PMK ||
        key->key_cipher_type == APPLE80211_CIPHER_PMKSA ||
        key->key_cipher_type == APPLE80211_CIPHER_MSK) {
        // WCL's native user-client rejects PTK/GTK, and delivers a PMK/MSK
        // instead. Use the existing net80211 four-way/group-key handshake.
        if (!ieee80211_is_8021x_akm((enum ieee80211_akm)ni->ni_rsnakms))
            return kIOReturnBadArgument;
        uint8_t any = 0;
        for (auto byte : key->key_ea.octet) any |= byte;
        if (any && !IEEE80211_ADDR_EQ(key->key_ea.octet, ni->ni_bssid))
            return kIOReturnBadArgument;
        auto pmk = ieee80211_pmksa_add(ic, (enum ieee80211_akm)ni->ni_rsnakms,
                                     ni->ni_macaddr, key->key, 0);
        IOReturn result = pmk ? kIOReturnSuccess : kIOReturnNoMemory;
        return result;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportRTWSkywalkInterface::accessWCLRSN(apple80211_rsn_ie_data *data, bool write)
{
    if (!data) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    if (write) {
        if (!AirportWCL::validRSNOverride(data->ie, data->len))
            return kIOReturnBadArgument;
        // net80211 constructs negotiated IEs for its own key handshake.
        return kIOReturnUnsupported;

    }
    const uint8_t *ie = ic->ic_bss ? ic->ic_bss->ni_rsnie : nullptr;
    if (!ie) return kIOReturnNotReady;
    size_t length = size_t(ie[1]) + 2;
    if (length > sizeof(data->ie)) return kIOReturnBadArgument;
    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->len = length;
    memcpy(data->ie, ie, length);
    return kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::beginWCLJoin(apple80211AssocCandidates *request)
{
    AirportWCL::JoinRequest join;
    if (!AirportWCL::decodeJoin(request, 0x2cc, join)) {
        return kIOReturnBadArgument;
    }
    return startWCLJoin(join);
}

IOReturn AirportRTWSkywalkInterface::startWCLJoin(AirportWCL::JoinRequest &join)
{
    auto auth = AirportWCL::classifyLegacyAuth(join);
    bool sae = auth == AirportWCL::LegacyAuth::SAE;
    bool passphrase = auth == AirportWCL::LegacyAuth::PersonalPassphrase;
    bool personal = auth == AirportWCL::LegacyAuth::Personal || passphrase;
    bool enterprise = auth == AirportWCL::LegacyAuth::Enterprise;
    bool supported = auth != AirportWCL::LegacyAuth::Invalid;
    ieee80211com *ic = fHalService->get80211Controller();
    // Applying a private MAC restarts firmware asynchronously. WCL can issue
    // the association before that restart has completed; keep one request
    // until the HAL reports READY rather than making the user retry it.
    if (supported && !joinPending && ic->ic_wcl_mac_reconfig &&
        (ic->ic_if.if_flags & IFF_UP)) {
        deferredJoin = join;
        memcpy(joinBSSID, join.bssid, sizeof(joinBSSID));
        explicit_bzero(&join, sizeof(join));
        joinDeferred = joinPending = true;
        joinTimer->setTimeoutMS(30000);
        return kIOReturnSuccess;
    }
    if (!supported || !(ic->ic_if.if_flags & IFF_RUNNING) || joinPending || scanPending) {
        explicit_bzero(&join, sizeof(join));
        return !supported ? kIOReturnUnsupported : kIOReturnBusy;
    }
    if (ic->ic_state == IEEE80211_S_RUN || ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC)
        leaveWCLNetwork();
    ieee80211_sae_clear(ic, true);
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    clearWCLPMKSA();
    ic->ic_flags &= ~(IEEE80211_F_AUTO_JOIN | IEEE80211_F_PSK);
    ic->ic_wcl_enterprise = enterprise;

    if (personal || enterprise || sae) {
        ++ic->ic_join_serial;
        bzero(ic->ic_join_rx_early, sizeof(ic->ic_join_rx_early));
        ic->ic_sae_stage = 1; ic->ic_sae_error = 0;
        ic->ic_sae_rx_data = ic->ic_sae_rx_eapol = ic->ic_sae_eapol_calls = 0;
        bzero(ic->ic_sae_rx_headers, sizeof(ic->ic_sae_rx_headers));
        ieee80211_wpaparams wpa = {};
        wpa.i_enabled = 1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK))
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK |
                              APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X))
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK))
            wpa.i_akms |= IEEE80211_WPA_AKM_PSK;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
            wpa.i_akms |= IEEE80211_WPA_AKM_8021X;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_PSK)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_PSK;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_8021X;
        wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
        if (sae) {
            wpa.i_protos = IEEE80211_WPA_PROTO_WPA2;
            wpa.i_akms = IEEE80211_WPA_AKM_SAE;
            wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP;
            wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        }
        if (!sae && join.rsnLength >= 8 && join.rsn[0] == IEEE80211_ELEMID_RSN &&
            join.rsn[4] == 0 && join.rsn[5] == 0x0f && join.rsn[6] == 0xac) {
            if (join.rsn[7] == 2) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_TKIP;
            if (join.rsn[7] == 4) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        }
        int error = ieee80211_ioctl_setwpaparms(ic, &wpa);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
        if (sae) {
            ic->ic_sae_enabled = true;
            ic->ic_sae_password_len = join.keyLength;
            memcpy(ic->ic_sae_password, join.key, join.keyLength);
            ic->ic_flags |= IEEE80211_F_MFPR | IEEE80211_F_PSK;
#ifdef USE_APPLE_SUPPLICANT
            bzero(ic->ic_rsn_ie_override, sizeof(ic->ic_rsn_ie_override));
#endif
        } else if (personal) {
            if (passphrase) {
                char password[65] = {};
                memcpy(password, join.key, join.keyLength);
                int error = pbkdf2_sha1(password, join.ssid, join.ssidLength, 4096,
                                        ic->ic_psk, sizeof(ic->ic_psk));
                explicit_bzero(password, sizeof(password));
                if (error) { explicit_bzero(&join, sizeof(join)); return kIOReturnError; }
            } else memcpy(ic->ic_psk, join.key, sizeof(ic->ic_psk));
            ic->ic_flags |= IEEE80211_F_PSK;
        } else if (join.keyLength == IEEE80211_PMK_LEN) {
            bool cached = true;
            if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_8021X, join.bssid, join.key, 0) != nullptr;
            if (cached && (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_SHA256_8021X, join.bssid, join.key, 0) != nullptr;
            if (!cached) {
                clearWCLPMKSA();
                explicit_bzero(&join, sizeof(join));
                return kIOReturnNoMemory;
            }
        }
    } else if (auth == AirportWCL::LegacyAuth::Wep) {
        ieee80211_nwkey keys = {};
        keys.i_wepon = IEEE80211_NWKEY_WEP;
        keys.i_defkid = join.keyIndex + 1;
        keys.i_key[join.keyIndex].i_keylen = join.keyLength;
        keys.i_key[join.keyIndex].i_keydat = join.key;
        int error = ieee80211_ioctl_setnwkeys(ic, &keys);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
    }
    ic->ic_des_esslen = join.ssidLength;
    memcpy(ic->ic_des_essid, join.ssid, sizeof(ic->ic_des_essid));
    memcpy(ic->ic_des_bssid, join.bssid, 6);
    memcpy(joinBSSID, join.bssid, 6);
    ic->ic_flags |= IEEE80211_F_DESBSSID;
    ic->ic_wcl_join_requested = true;
    ic->ic_wcl_scan_requested = false;
    current_authtype_lower = join.lowerAuth;
    current_authtype_upper = join.upperAuth;
    explicit_bzero(&join, sizeof(join));
    wclBssValid = false;
    joinPending = true;
    assocNotified = firstBeaconNotified = portAuthorized = false;
    wclAssociatedBeacons = 0;
    bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
    disassocIsVoluntary = false;
    joinTimer->setTimeoutMS(30000);
    if (ic->ic_state != IEEE80211_S_SCAN && ic->ic_newstate(ic, IEEE80211_S_SCAN, -1)) {
        joinPending = false;
        joinTimer->cancelTimeout();
        ic->ic_wcl_join_requested = false;
        ieee80211_sae_clear(ic, true);
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

void AirportRTWSkywalkInterface::resumeWCLJoin()
{
    if (!joinDeferred || wclStopping)
        return;
    AirportWCL::JoinRequest join = deferredJoin;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinDeferred = joinPending = false;
    joinTimer->cancelTimeout();
    IOReturn status = startWCLJoin(join);
    explicit_bzero(&join, sizeof(join));
    if (status != kIOReturnSuccess) {
        joinPending = true;
        finishWCLJoin(1, 0, status);
    }
}

// RX callbacks may hold net80211 locks. Copy into a bounded preallocated
// FIFO instead of synchronously acquiring the native gate from that context.
// Periodic LQM/beacon-health updates need the same gate as join events.
IOReturn AirportRTWSkywalkInterface::postWCLJoinMessage(unsigned message, void *data, size_t size)
{
    if (!wclJoinLock || wclStopping)
        return kIOReturnNotReady;
    if (size > sizeof(wclJoinMessages[0].payload) || (size && !data))
        return kIOReturnBadArgument;
    IOSimpleLockLock(wclJoinLock);
    if (wclJoinCount == 32 || wclStopping || !wclJoinMessageTimer) {
        IOSimpleLockUnlock(wclJoinLock);
        return kIOReturnNoResources;
    }
    auto &entry = wclJoinMessages[(wclJoinHead + wclJoinCount) % 32];
    entry.type = message;
    entry.length = size;
    if (size) memcpy(entry.payload, data, size);
    ++wclJoinCount;
    auto timer = wclJoinMessageTimer;
    timer->retain();
    IOSimpleLockUnlock(wclJoinLock);
    timer->setTimeoutMS(0);
    timer->release();
    return kIOReturnSuccess;
}

void AirportRTWSkywalkInterface::drainWCLJoinMessages(OSObject *owner, IOTimerEventSource *)
{
    auto self = static_cast<AirportRTWSkywalkInterface *>(owner);
    while (!self->wclStopping) {
        JoinMessage entry;
        IOSimpleLockLock(self->wclJoinLock);
        if (!self->wclJoinCount) {
            IOSimpleLockUnlock(self->wclJoinLock);
            break;
        }
        entry = self->wclJoinMessages[self->wclJoinHead];
        self->wclJoinHead = (self->wclJoinHead + 1) % 32;
        --self->wclJoinCount;
        IOSimpleLockUnlock(self->wclJoinLock);
        self->deliverWCLJoinMessage(entry.type, entry.payload, entry.length);
    }
}

IOReturn AirportRTWSkywalkInterface::deliverWCLJoinMessage(unsigned message, void *data, size_t size)
{
    IOReturn status = instance->postMessage(this, message, data, size, true);
    const char *property = nullptr;
    switch (message) {
        case AirportWCL::AssocComplete: property = "RTWWCLAssocPostStatus"; break;
        case AirportWCL::FirstBeacon: property = "RTWWCLFirstBeaconPostStatus"; break;
        case AirportWCL::ConnectComplete: property = "RTWWCLConnectPostStatus"; break;
        case AirportWCL::LinkStatus: property = "RTWWCLLinkPostStatus"; break;
        case AirportWCL::Deauth: property = "RTWWCLDeauthPostStatus"; break;
        case AirportWCL::LqmUpdate:
            property = "RTWWCLLqmPostStatus";
            if (status == kIOReturnSuccess) ++wclLqmPostCount;
            RTW_DIAGNOSTIC(instance->setProperty("RTWWCLLqmPostCount", wclLqmPostCount, 64));
            break;
    }
    if (property) instance->setProperty(property, uint64_t(status), 32);
    RTW_DIAGNOSTIC(instance->setProperty("RTWWCLJoinPostInGate", instance->getWorkQueue()->inGate()));
    return status;
}

void AirportRTWSkywalkInterface::finishWCLJoin(uint16_t status, uint16_t reason, IOReturn driverStatus)
{
    if (!joinPending)
        return;
    AirportWCL::ConnectionEvent event = {};
    event.status = status;
    event.reason = reason;
    memcpy(event.peers[0].bssid, joinBSSID, 6);
    event.peers[0].driverStatus = driverStatus;
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    postWCLJoinMessage(AirportWCL::ConnectComplete, &event, sizeof(event));
    if (status) {
        ieee80211com *ic = fHalService->get80211Controller();
        retainIncompleteJoin(instance, ic, current_authtype_upper);
        ic->ic_wcl_join_requested = false;
        ieee80211_sae_clear(ic, true);
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    }
}

void AirportRTWSkywalkInterface::wclJoinTimeout(OSObject *owner, IOTimerEventSource *)
{
    auto self = OSDynamicCast(AirportRTWSkywalkInterface, owner);
    if (self && !self->wclStopping) {
        self->finishWCLJoin(1, 1004, kIOReturnTimeout);
        self->leaveWCLNetwork();
    }
}

IOReturn AirportRTWSkywalkInterface::leaveWCLNetwork()
{
    ieee80211com *ic = fHalService->get80211Controller();
    if (joinPending) retainIncompleteJoin(instance, ic, current_authtype_upper);
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    ic->ic_wcl_join_requested = false;
    wclAssociatedBeacons = 0;
    wclBssValid = false;
    disassocIsVoluntary = true;
    ic->ic_deauth_reason = IEEE80211_REASON_AUTH_LEAVE;
    if (ic->ic_state > IEEE80211_S_SCAN)
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    ieee80211_sae_clear(ic, true);
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    clearWCLPMKSA();
    ic->ic_wcl_enterprise = false;
    ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_DESBSSID);
    ic->ic_des_esslen = 0;
    bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
    return kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::abortWCLJoin()
{
    leaveWCLNetwork();
    instance->postMessage(this, AirportWCL::JoinAbortComplete, nullptr, 0, true);
    return kIOReturnSuccess;
}

void AirportRTWSkywalkInterface::handleWCLLink(bool up)
{
    if (wclStopping)
        return;
    portAuthorized = up;
    if (!up && wclLinkIndicated) {
        AirportWCL::LinkStatusEvent event = {};
        memcpy(event.bssid, joinBSSID, sizeof(event.bssid));
        event.reason = 255;
        wclLinkIndicated = false;
        wclBssValid = false;
        postWCLJoinMessage(AirportWCL::LinkStatus, &event, sizeof(event));
    }
    if (up && joinPending && firstBeaconNotified)
        finishWCLJoin(0, 0, kIOReturnSuccess);
}

void AirportRTWSkywalkInterface::handleWCLEvent(int code, void *data)
{
    if (wclStopping)
        return;
    // Firmware initialization runs on systq, outside the native PostOffice gate.
    // Serialize only lifecycle notifications; never run synchronous WCL ioctls here.
    if ((code == IEEE80211_EVT_DRIVER_RESET_BEGIN || code == IEEE80211_EVT_DRIVER_READY ||
         code == IEEE80211_EVT_DRIVER_STOPPED) && !instance->getWorkQueue()->inGate()) {
        _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(12),
                                reinterpret_cast<void *>(uintptr_t(code)));
        return;
    }
    ieee80211com *ic = fHalService->get80211Controller();
    switch (code) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            deferWCLCountryUpdate();
            break;
        case IEEE80211_EVT_DRIVER_RESET_BEGIN: {
            if (ic->ic_wcl_mac_reconfig) {
                break;
            }
            uint32_t reset = 0; // Native resetInterfacesBegin.
            instance->postMessage(this, AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            break;
        }
        case IEEE80211_EVT_DRIVER_READY:
        case IEEE80211_EVT_DRIVER_STOPPED: {
            bool ready = code == IEEE80211_EVT_DRIVER_READY;
            if (!ready) {
                finishWCLScan(ic->ic_wcl_mac_reconfig ? kIOReturnAborted : kIOReturnOffline);
                finishWCLJoin(1, 0, kIOReturnOffline);
                portAuthorized = false;
                ic->ic_wcl_join_requested = false;
                clearWCLPMKSA();
                ic->ic_wcl_enterprise = false;
                explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
            }
            // An address application is requested by WCL itself, not a new
            // adapter reset. Replaying firmware-load events here rotates the
            // scan MAC again and recursively restarts the card.
            if (AirportWCL::consumeMacReconfiguration(ic->ic_wcl_mac_reconfig, ready)) {
                if (ready)
                    resumeWCLJoin();
                break;
            }
            if (ready) {
                uint32_t reset = 1; // Native resetInterfacesComplete, only after HAL success.
                instance->postMessage(this, AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            }
            AirportWCL::DriverAvailability event = {};
            event.version = 3;
            event.available = ready;
            event.reason = ready ? 0xe0821803 : 0xe0821804;
            instance->postMessage(this, AirportWCL::DriverAvailable, &event, sizeof(event), true);
            if (ready)
                resumeWCLJoin();
            break;
        }
        case IEEE80211_EVT_BEACON: {
            ++wclBeaconEventCount;
            auto beacon = static_cast<ieee80211_beacon_event *>(data);
            if (!beacon)
                break;
            // Retain the actual associated beacon, including its advancing TSF.
            // WCL polls BEACON_INFO to distinguish fresh reception from a stale BSS.
            if (assocNotified && (joinPending || portAuthorized) &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID) &&
                beacon->frame && beacon->frame_length >= 36 &&
                beacon->frame_length <= 0x800 &&
                (beacon->frame[0] & 0xfc) == IEEE80211_FC0_SUBTYPE_BEACON) {
                uint32_t length = uint32_t(beacon->frame_length);
                bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
                memcpy(wclBeaconInfo, &length, sizeof(length));
                memcpy(wclBeaconInfo + 4, beacon->frame, length);
                ++wclAssociatedBeacons;
                ++wclLqmBeacons;
                // WCL has no legacy LQMData instance at createLQMData().
                // Send the snapshot consumed by WCL instead of legacy 227/229.
                if (portAuthorized && (wclLqmBeacons % 8 == 0)) {
#if __IO80211_TARGET == __MAC_15_2
                    apple80211_rssi_data rssi = {};
                    if (getRSSI(&rssi) == kIOReturnSuccess) {
                        AirportWCL::SequoiaLqmUpdate update = {};
                        update.rssiValid = 1;
                        update.rssi = rssi.aggregate_rssi;
                        postWCLJoinMessage(AirportWCL::LqmUpdate,
                            &update, sizeof(update));
                    }
#else
                    AirportWCL::LqmBeaconUpdate update;
                    if (AirportWCL::makeBeaconUpdate(
                            wclLqmBeacons - wclLqmReportedBeacons, update)) {
                        if (postWCLJoinMessage(AirportWCL::LqmUpdate,
                                &update, sizeof(update)) == kIOReturnSuccess)
                            wclLqmReportedBeacons = wclLqmBeacons;
                    }
#endif
                }
            }
            if (scanPending || joinPending || ic->ic_state == IEEE80211_S_SCAN ||
                (portAuthorized && IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID)))
                publishWCLBeacon(beacon->node, beacon->ies, beacon->length);
            if (joinPending && assocNotified && !firstBeaconNotified &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID)) {
                AirportWCL::FirstBeaconEvent event = {};
                memcpy(event.peer.bssid, joinBSSID, 6);
                if (!wclBssValid)
                    break;
                firstBeaconNotified = true;
                AirportWCL::LinkStatusEvent link = {};
                memcpy(link.bssid, joinBSSID, sizeof(link.bssid));
                link.up = 1;
                link.reason = 255;
                wclLinkIndicated = true;
                postWCLJoinMessage(AirportWCL::LinkStatus, &link, sizeof(link));
                postWCLJoinMessage(AirportWCL::FirstBeacon, &event, sizeof(event));
                if (portAuthorized)
                    finishWCLJoin(0, 0, kIOReturnSuccess);
            }
            break;
        }
        case IEEE80211_EVT_SCAN_DONE:
            if (scanPending) {
                if (scanSkipCompletion)
                    scanSkipCompletion = false;
                else {
                    scanCompleted = true;
                    scanSource->setTimeoutMS(0);
                }
            }
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            if (joinPending && !assocNotified) {
                AirportWCL::AssociationEvent event = {};
                event.status = ic->ic_assoc_status;
                memcpy(event.bssid, joinBSSID, 6);
                event.driverStatus = event.status ? kIOReturnError : kIOReturnSuccess;
                assocNotified = !event.status;
                postWCLJoinMessage(AirportWCL::AssocComplete, &event, sizeof(event));
                if (event.status)
                    finishWCLJoin(event.status, 0, kIOReturnError);
            }
            break;
        case IEEE80211_EVT_STA_DEAUTH: {
            AirportWCL::DeauthEvent event = {};
            event.reason = ic->ic_deauth_reason;
            if (ic->ic_bss)
                memcpy(event.bssid, ic->ic_bss->ni_bssid, 6);
            postWCLJoinMessage(AirportWCL::Deauth, &event, sizeof(event));
            finishWCLJoin(1, event.reason, kIOReturnOffline);
            break;
        }
        default: break;
    }
}

IOReturn AirportRTWSkywalkInterface::getWCL_VALID_CHANNEL_COUNT(unsigned long *count)
{
    if (!count)
        return kIOReturnBadArgument;
    *count = 0;
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i < IEEE80211_CHAN_MAX; ++i)
        if (isset(ic->ic_chan_active, i))
            ++*count;
    return kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *data)
{
    if (!data)
        return kIOReturnBadArgument;
#if __IO80211_TARGET == __MAC_15_2
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[6]) {
        if (bytes[8])
            setCurrentApAddress(reinterpret_cast<ether_addr *>(data));
        if (bytes[7])
            setLinkState(kIO80211NetworkLinkUp, 0, false, 0);
    } else {
        uint32_t debounce = AirportWCL::read32(bytes + 12);
        setCurrentApAddress(nullptr);
        setLinkState(kIO80211NetworkLinkDown, 0, debounce != 0, debounce);
    }
    return kIOReturnSuccess;
#else
    IOReturn status = IO80211InfraInterface::setWCL_LINK_STATE_UPDATE(data);
    return status;
#endif
}

IOReturn AirportRTWSkywalkInterface::getWCL_BSS_INFO(apple80211_beacon_msg *data)
{
    if (!data)
        return kIOReturnBadArgument;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(5), data);
}

IOReturn AirportRTWSkywalkInterface::getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(6), data);
}

IOReturn AirportRTWSkywalkInterface::copyWCLExtendedBss(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    if (!data || !ic->ic_bss || ic->ic_state != IEEE80211_S_RUN)
        return kIOReturnNotReady;
    static_assert(sizeof(apple80211_rate_set_data) == 0xbc, "Extended BSS rates size");
    static_assert(sizeof(apple80211_mcs_index_set_data) == 0x10, "Extended BSS MCS size");
    auto bytes = static_cast<uint8_t *>(data);
#if __IO80211_TARGET == __MAC_15_2
    bzero(bytes, 0x1e0);
#else
    bzero(bytes, 0x214);
#endif
    IOReturn status = getRATE_SET(reinterpret_cast<apple80211_rate_set_data *>(bytes));
    if (status)
        return status;
    status = getMCS_INDEX_SET(reinterpret_cast<apple80211_mcs_index_set_data *>(bytes + 0xbc));
    if (status)
        return status;
    apple80211_vht_mcs_index_set_data vht = {};
    vht.version = APPLE80211_VERSION;
    vht.mcs_map = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_VHT)
        vht.mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    memcpy(bytes + 0xcc, &vht, sizeof(vht));
    // Native updateMCSSet uses version + a 16-bit HE MCS/NSS map (8 bytes).
    uint32_t heVersion = APPLE80211_VERSION;
    uint16_t heMap = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) {
        bool wide = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_160;
        heMap = htole16(AirportWCL::heMcsIntersection(
            le16toh(wide ? ic->ic_he_mcs_nss_supp.rx_mcs_160 : ic->ic_he_mcs_nss_supp.rx_mcs_80),
            le16toh(wide ? ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_160 : ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_80)));
    }
    memcpy(bytes + 0xd4, &heVersion, sizeof(heVersion));
    memcpy(bytes + 0xd8, &heMap, sizeof(heMap));
    if (ic->ic_flags & IEEE80211_F_RSNON)
#if __IO80211_TARGET == __MAC_15_2
        ieee80211_add_rsn(bytes + 0xdd, ic, ic->ic_bss);
#else
        ieee80211_add_rsn(bytes + 0x113, ic, ic->ic_bss);
#endif
    return kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::setWCL_UPDATE_FAST_LANE(apple80211_fastlane *data)
{
    if (!data)
        return kIOReturnBadArgument;
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    return (bytes[0] || bytes[1]) ? kIOReturnUnsupported : kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // No low-latency or P2P session is implemented by this adapter.
    bzero(data, 4);
    return kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::getCHANNELS_INFO(apple80211_channels_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(13), data);
}

IOReturn AirportRTWSkywalkInterface::copyWCLChannels(void *data)
{
    auto info = static_cast<AirportWCL::NativeChannelInfo *>(data);
    bzero(info, sizeof(*info));
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i) {
        const ieee80211_channel *channel = &ic->ic_channels[i];
        if (!isset(ic->ic_chan_active, i) || !channel->ic_freq)
            continue;
        AirportWCL::appendChannel(*info, i, IEEE80211_IS_CHAN_5GHZ(channel),
            channel->ic_flags & IEEE80211_CHAN_DFS,
            channel->ic_flags & IEEE80211_CHAN_PASSIVE,
            IEEE80211_IS_CHAN_HT40(channel) || IEEE80211_IS_CHAN_VHT40(channel),
            IEEE80211_IS_CHAN_VHT80(channel));
    }
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, sizeof(country.cc));
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn AirportRTWSkywalkInterface::getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(14), data);
}

IOReturn AirportRTWSkywalkInterface::copyWCLTrafficCounters(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    uint64_t timestamp;
    absolutetime_to_nanoseconds(mach_absolute_time(), &timestamp);
    const auto counters = AirportWCL::makeTrafficCounters(
        ic->ic_wcl_tx_packets, ic->ic_wcl_rx_packets, timestamp);
    memcpy(data, &counters, sizeof(counters));
    return kIOReturnSuccess;
}

IOReturn AirportRTWSkywalkInterface::getWCL_CHANNELS_INFO(apple80211ChannelInfo *data)
{
    if (!data)
        return kIOReturnBadArgument;
    auto info = reinterpret_cast<AirportWCL::ChannelInfo *>(data);
    bzero(info, sizeof(*info));
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i < IEEE80211_CHAN_MAX && info->count < 400; ++i) {
        if (!isset(ic->ic_chan_active, i))
            continue;
        const ieee80211_channel *channel = &ic->ic_channels[i];
        auto &entry = info->channels[info->count++];
        entry.channel = i;
        entry.channelSpec = uint16_t(i | (IEEE80211_IS_CHAN_5GHZ(channel) ? 0xd000 : 0x1000));
        if (channel->ic_flags & IEEE80211_CHAN_DFS)
            entry.flags |= 2;
        if (channel->ic_flags & IEEE80211_CHAN_PASSIVE)
            entry.flags |= 4;
    }
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, 3);
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}
#endif

#ifdef AIRPORT_WCL
IOReturn AirportRTWSkywalkInterface::getBEACON_INFO(apple80211_beacon_info_t *data)
{
    if (!_fCommandGate || !data)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(7), data);
}
#endif
