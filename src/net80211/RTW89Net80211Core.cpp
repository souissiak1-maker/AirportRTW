/* SPDX-License-Identifier: BSD-3-Clause */
#include "RTW89Net80211Core.hpp"

#include "../kext/RTW88IEEE80211.hpp"
#include "../kext/RTW88PCIDevice.hpp"

#include <libkern/libkern.h>

OSDefineMetaClassAndStructors(RTW89Net80211Core, OSObject)

RTW89Net80211Core *RTW89Net80211Core::create(RTW88PCIDevice *owner)
{
    RTW89Net80211Core *core = new RTW89Net80211Core;
    if (!core)
        return nullptr;
    if (!core->initWithOwner(owner)) {
        core->release();
        return nullptr;
    }
    return core;
}

bool RTW89Net80211Core::initWithOwner(RTW88PCIDevice *owner)
{
    if (!OSObject::init() || !owner)
        return false;
    _owner = owner;
    _lock = IOLockAlloc();
    if (!_lock)
        return false;
    _nodes = (obsd80211::ieee80211_node *)
        IOMallocZero(sizeof(obsd80211::ieee80211_node) * 64);
    if (!_nodes)
        return false;
    reset();
    _owner->setProperty("AirportRTW89Net80211CorePresent", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Net80211Stage", (uint64_t)2, 32);
    _owner->setProperty("AirportRTW89Net80211AuthoritativeAppleScan", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Net80211AuthoritativeState", kOSBooleanTrue);
    /* 0.3.5: net80211 no longer owns Apple GET2/SET2 AUTH_TYPE state. */
    _owner->setProperty("AirportRTW89Net80211AuthoritativeAuth", kOSBooleanFalse);
    _owner->setProperty("AirportRTW89Net80211LegacyAuthMirrorOnly", kOSBooleanFalse);
    _owner->setProperty("AirportRTW89AppleControlIO80211ReferenceParity", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89AppleControlAuthSeparateFromNet80211", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Net80211NoPreSET20TargetInference", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Net80211NodeVerbStorage", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Net80211IntelDriverCodeImported", kOSBooleanFalse);
    return true;
}

void RTW89Net80211Core::free()
{
    if (_nodes) {
        IOFree(_nodes, sizeof(obsd80211::ieee80211_node) * 64);
        _nodes = nullptr;
    }
    if (_lock) {
        IOLockFree(_lock);
        _lock = nullptr;
    }
    _owner = nullptr;
    OSObject::free();
}

void RTW89Net80211Core::reset()
{
    if (_lock)
        IOLockLock(_lock);
    bzero(&_ic, sizeof(_ic));
    if (_nodes)
        bzero(_nodes, sizeof(obsd80211::ieee80211_node) * 64);
    bzero(_visible, sizeof(_visible));
    _visibleCount = 0;
    _ic.ic_state = obsd80211::IEEE80211_S_INIT;
    if (_lock)
        IOLockUnlock(_lock);
    publishTelemetry();
}


void RTW89Net80211Core::clearScanCachePreservingState()
{
    if (!_lock || !_nodes)
        return;
    IOLockLock(_lock);
    int keepSlot = -1;
    if (_ic.ic_bss)
        keepSlot = (int)(_ic.ic_bss - _nodes);
    for (int i = 0; i < 64; ++i) {
        if (i == keepSlot && _nodes[i].valid)
            continue;
        bzero(&_nodes[i], sizeof(_nodes[i]));
    }
    bzero(_visible, sizeof(_visible));
    _visibleCount = 0;
    ++_ic.ic_scan_generation;
    IOLockUnlock(_lock);
    if (_owner)
        _owner->setProperty("AirportRTW89Net80211ScanCacheClearPreservedState",
                            kOSBooleanTrue);
    publishTelemetry();
}

int RTW89Net80211Core::findSlotByBSSID(const uint8_t bssid[6]) const
{
    if (!bssid || !_nodes)
        return -1;
    for (int i = 0; i < 64; ++i) {
        if (_nodes[i].valid && memcmp(_nodes[i].bssid, bssid, 6) == 0)
            return i;
    }
    return -1;
}

int RTW89Net80211Core::allocateSlot()
{
    if (!_nodes)
        return -1;
    for (int i = 0; i < 64; ++i) {
        if (!_nodes[i].valid)
            return i;
    }
    /* Fixed-size Stage-1 node table: replace the oldest generation. */
    uint32_t oldest = 0xffffffffU;
    int oldestSlot = 0;
    for (int i = 0; i < 64; ++i) {
        if (_nodes[i].generation < oldest) {
            oldest = _nodes[i].generation;
            oldestSlot = i;
        }
    }
    return oldestSlot;
}

void RTW89Net80211Core::copyFromRTWBSS(obsd80211::ieee80211_node &dst,
                                       const RTW88BSS &src,
                                       uint32_t generation)
{
    /* The node object lives in a fixed slot, so its address (and therefore
     * &node.verb) remains stable even when the contents are refreshed. */
    bzero(&dst, sizeof(dst));
    dst.valid = true;
    dst.generation = generation;
    memcpy(dst.bssid, src.bssid, sizeof(dst.bssid));
    dst.essid_len = src.ssid_len <= 32 ? src.ssid_len : 32;
    if (dst.essid_len)
        memcpy(dst.essid, src.ssid, dst.essid_len);
    dst.essid[dst.essid_len] = '\0';
    dst.rssi = src.rssi;
    dst.channel = src.channel;
    dst.capinfo = src.capabilities;
    dst.beacon_interval = src.beacon_interval;
    dst.nrates = src.nrates <= sizeof(dst.rates) ? src.nrates : sizeof(dst.rates);
    if (dst.nrates)
        memcpy(dst.rates, src.rates, dst.nrates);
    dst.cipher = src.cipher;
    dst.group_cipher = src.group_cipher;
    dst.akm = src.akm;
    dst.rsn_ie_len = src.rsn_ie_len <= sizeof(dst.rsn_ie) ? src.rsn_ie_len : sizeof(dst.rsn_ie);
    if (dst.rsn_ie_len)
        memcpy(dst.rsn_ie, src.rsn_ie, dst.rsn_ie_len);
    dst.wpa_ie_len = src.wpa_ie_len <= sizeof(dst.wpa_ie) ? src.wpa_ie_len : sizeof(dst.wpa_ie);
    if (dst.wpa_ie_len)
        memcpy(dst.wpa_ie, src.wpa_ie, dst.wpa_ie_len);
    dst.ies_len = src.ies_len <= sizeof(dst.ies) ? src.ies_len : sizeof(dst.ies);
    if (dst.ies_len)
        memcpy(dst.ies, src.ies, dst.ies_len);
    dst.last_seen_ns = src.last_seen_ns;
}

void RTW89Net80211Core::syncFromRTW(const RTW88BSS *source, uint32_t count,
                                    bool scanInProgress, bool connected)
{
    if (!_lock || !_nodes || !source)
        return;
    if (count > 64)
        count = 64;

    IOLockLock(_lock);
    uint32_t generation = ++_ic.ic_scan_generation;
    if (generation == 0)
        generation = ++_ic.ic_scan_generation;

    bool touched[64] = {};
    _visibleCount = 0;
    for (uint32_t i = 0; i < count; ++i) {
        int slot = findSlotByBSSID(source[i].bssid);
        if (slot < 0)
            slot = allocateSlot();
        if (slot < 0 || slot >= 64)
            continue;
        copyFromRTWBSS(_nodes[slot], source[i], generation);
        touched[slot] = true;
        _visible[_visibleCount++] = (uint8_t)slot;
    }

    /* The completed snapshot is authoritative for scan visibility, but the
     * current ic_bss is association state and survives a snapshot that omits
     * it (for example a channel-subset/background scan). */
    for (int i = 0; i < 64; ++i) {
        if (_nodes[i].valid && !touched[i]) {
            if (_ic.ic_bss == &_nodes[i] &&
                _ic.ic_state != obsd80211::IEEE80211_S_INIT)
                continue;
            if (_ic.ic_bss == &_nodes[i]) {
                _ic.ic_bss = nullptr;
                ++_bssChangeCount;
            }
            bzero(&_nodes[i], sizeof(_nodes[i]));
        }
    }

    /* Stage 2: scan refresh owns the node database, not association truth.
     * Only INIT <-> SCAN is derived from scan observation. AUTH/ASSOC/RUN are
     * advanced by explicit desired-state/link events, so a stale RTW snapshot
     * cannot resurrect a just-cleared association after SET22. */
    _lastRTWScanObservation = scanInProgress;
    _lastRTWConnectedObservation = connected;
    if (_ic.ic_state == obsd80211::IEEE80211_S_INIT && scanInProgress)
        recordStateTransitionLocked(obsd80211::IEEE80211_S_SCAN);
    else if (_ic.ic_state == obsd80211::IEEE80211_S_SCAN && !scanInProgress)
        recordStateTransitionLocked(obsd80211::IEEE80211_S_INIT);

    /* A desired/current BSSID may have been selected before the matching node
     * was refreshed. Rebind only in association states; never infer a desired
     * BSS while INIT/SCAN. */
    if (!_ic.ic_bss &&
        (_ic.ic_state == obsd80211::IEEE80211_S_AUTH ||
         _ic.ic_state == obsd80211::IEEE80211_S_ASSOC ||
         _ic.ic_state == obsd80211::IEEE80211_S_RUN)) {
        static const uint8_t zeroBSSID[6] = {};
        if (memcmp(_ic.ic_des_bssid, zeroBSSID, sizeof(zeroBSSID)) != 0)
            bindBSSLocked(_ic.ic_des_bssid);
    }

    ++_syncCount;
    IOLockUnlock(_lock);
    publishTelemetry();
}

uint32_t RTW89Net80211Core::visibleNodeCount() const
{
    if (!_lock || !_nodes)
        return 0;
    IOLockLock(_lock);
    uint32_t count = _visibleCount;
    IOLockUnlock(_lock);
    return count;
}

const obsd80211::ieee80211_node *RTW89Net80211Core::visibleNode(uint32_t ordinal) const
{
    if (!_lock || !_nodes)
        return nullptr;
    IOLockLock(_lock);
    const obsd80211::ieee80211_node *node = nullptr;
    if (ordinal < _visibleCount) {
        uint8_t slot = _visible[ordinal];
        if (slot < 64 && _nodes[slot].valid)
            node = &_nodes[slot];
    }
    IOLockUnlock(_lock);
    return node;
}

obsd80211::ieee80211_node *RTW89Net80211Core::visibleNodeMutable(uint32_t ordinal)
{
    return const_cast<obsd80211::ieee80211_node *>(
        static_cast<const RTW89Net80211Core *>(this)->visibleNode(ordinal));
}

const obsd80211::ieee80211_node *RTW89Net80211Core::findNodeByBSSID(const uint8_t bssid[6]) const
{
    if (!_lock || !_nodes || !bssid)
        return nullptr;
    IOLockLock(_lock);
    int slot = findSlotByBSSID(bssid);
    const obsd80211::ieee80211_node *node = slot >= 0 ? &_nodes[slot] : nullptr;
    IOLockUnlock(_lock);
    return node;
}

void RTW89Net80211Core::recordStateTransitionLocked(
    obsd80211::ieee80211_state next)
{
    const uint32_t oldState = (uint32_t)_ic.ic_state;
    const uint32_t nextState = (uint32_t)next;
    if (oldState == nextState)
        return;
    _stateTransitionHistory[_stateTransitionIndex & 15U] =
        ((oldState & 0xffU) << 8) | (nextState & 0xffU);
    _stateTransitionIndex = (_stateTransitionIndex + 1U) & 15U;
    ++_stateTransitionCount;
    _ic.ic_state = next;
}

void RTW89Net80211Core::bindBSSLocked(const uint8_t *bssid)
{
    obsd80211::ieee80211_node *next = nullptr;
    if (bssid && _nodes) {
        for (int i = 0; i < 64; ++i) {
            if (_nodes[i].valid && memcmp(_nodes[i].bssid, bssid, 6) == 0) {
                next = &_nodes[i];
                break;
            }
        }
    }
    if (_ic.ic_bss != next) {
        _ic.ic_bss = next;
        ++_bssChangeCount;
    }
}

void RTW89Net80211Core::noteDisassociate()
{
    if (!_lock)
        return;

    /* 0.3.5 IO80211Reference parity.  IO80211Reference's setDISASSOCIATE() is a
     * no-op below SCAN, also returns without resetting state while AUTH/ASSOC
     * are in progress, and otherwise deselects the ESS and transitions to
     * SCAN.  Keep Apple current_authtype_* outside this core entirely. */
    IOLockLock(_lock);
    const obsd80211::ieee80211_state state = _ic.ic_state;

    if (state < obsd80211::IEEE80211_S_SCAN ||
        state == obsd80211::IEEE80211_S_AUTH ||
        state == obsd80211::IEEE80211_S_ASSOC) {
        ++_set22ClearCount;
        IOLockUnlock(_lock);
        publishTelemetry();
        if (_owner) {
            _owner->setProperty("AirportRTW89Net80211SET22IO80211ReferenceNoOp",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89Net80211SET22IO80211ReferenceToScan",
                                kOSBooleanFalse);
        }
        return;
    }

    if (_ic.ic_bss) {
        _ic.ic_bss = nullptr;
        ++_bssChangeCount;
    }
    if (_ic.ic_des_esslen != 0)
        ++_desiredChangeCount;
    _ic.ic_des_esslen = 0;
    bzero(_ic.ic_des_essid, sizeof(_ic.ic_des_essid));
    static const uint8_t zeroBSSID[6] = {};
    if (memcmp(_ic.ic_des_bssid, zeroBSSID, sizeof(zeroBSSID)) != 0)
        ++_desiredChangeCount;
    bzero(_ic.ic_des_bssid, sizeof(_ic.ic_des_bssid));

    /* This custom auth tuple belongs to the active net80211 association, not
     * the Apple SET2/GET2 latch.  Clear it when the ESS is actually deselected. */
    if (_ic.ic_auth_valid || _ic.ic_auth_lower != 0 || _ic.ic_auth_upper != 0)
        ++_authChangeCount;
    _ic.ic_auth_valid = false;
    _ic.ic_auth_lower = 0;
    _ic.ic_auth_upper = 0;

    recordStateTransitionLocked(obsd80211::IEEE80211_S_SCAN);
    ++_set22ClearCount;
    IOLockUnlock(_lock);
    publishTelemetry();
    if (_owner) {
        _owner->setProperty("AirportRTW89Net80211SET22IO80211ReferenceNoOp",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Net80211SET22IO80211ReferenceToScan",
                            kOSBooleanTrue);
    }
}

void RTW89Net80211Core::noteDesired(const uint8_t *ssid, uint8_t ssidLen,
                                    const uint8_t *bssid, uint32_t authLower,
                                    uint32_t authUpper, bool authValid)
{
    if (!_lock)
        return;
    if (ssidLen > sizeof(_ic.ic_des_essid))
        ssidLen = sizeof(_ic.ic_des_essid);
    IOLockLock(_lock);

    bool desiredChanged = _ic.ic_des_esslen != ssidLen;
    if (!desiredChanged && ssidLen)
        desiredChanged = !ssid || memcmp(_ic.ic_des_essid, ssid, ssidLen) != 0;
    if (desiredChanged)
        ++_desiredChangeCount;
    bzero(_ic.ic_des_essid, sizeof(_ic.ic_des_essid));
    if (ssid && ssidLen)
        memcpy(_ic.ic_des_essid, ssid, ssidLen);
    _ic.ic_des_esslen = ssidLen;

    uint8_t nextBSSID[6] = {};
    if (bssid)
        memcpy(nextBSSID, bssid, sizeof(nextBSSID));
    if (memcmp(_ic.ic_des_bssid, nextBSSID, sizeof(nextBSSID)) != 0)
        ++_desiredChangeCount;
    memcpy(_ic.ic_des_bssid, nextBSSID, sizeof(_ic.ic_des_bssid));

    if (_ic.ic_auth_lower != authLower || _ic.ic_auth_upper != authUpper ||
        _ic.ic_auth_valid != authValid)
        ++_authChangeCount;
    _ic.ic_auth_lower = authLower;
    _ic.ic_auth_upper = authUpper;
    _ic.ic_auth_valid = authValid;

    /* SET20 supplies association intent. Bind only to that explicit BSSID; do
     * not pick a secured/strongest scan node when the BSSID is absent. */
    if (bssid)
        bindBSSLocked(bssid);
    IOLockUnlock(_lock);
    publishTelemetry();
}

void RTW89Net80211Core::noteAuth(uint32_t authLower, uint32_t authUpper,
                                 bool authValid)
{
    if (!_lock)
        return;
    IOLockLock(_lock);
    if (_ic.ic_auth_lower != authLower || _ic.ic_auth_upper != authUpper ||
        _ic.ic_auth_valid != authValid)
        ++_authChangeCount;
    _ic.ic_auth_lower = authLower;
    _ic.ic_auth_upper = authUpper;
    _ic.ic_auth_valid = authValid;
    IOLockUnlock(_lock);
    publishTelemetry();
}

void RTW89Net80211Core::noteState(obsd80211::ieee80211_state state,
                                  const uint8_t *currentBSSID)
{
    if (!_lock)
        return;
    IOLockLock(_lock);
    recordStateTransitionLocked(state);
    if (state == obsd80211::IEEE80211_S_INIT) {
        if (_ic.ic_bss) {
            _ic.ic_bss = nullptr;
            ++_bssChangeCount;
        }
    } else if (currentBSSID) {
        bindBSSLocked(currentBSSID);
    } else if (!_ic.ic_bss &&
               (state == obsd80211::IEEE80211_S_AUTH ||
                state == obsd80211::IEEE80211_S_ASSOC)) {
        static const uint8_t zeroBSSID[6] = {};
        if (memcmp(_ic.ic_des_bssid, zeroBSSID, sizeof(zeroBSSID)) != 0)
            bindBSSLocked(_ic.ic_des_bssid);
    }
    IOLockUnlock(_lock);
    publishTelemetry();
}

bool RTW89Net80211Core::copyCurrentView(
    obsd80211::ieee80211_current_view &out) const
{
    bzero(&out, sizeof(out));
    if (!_lock || !_nodes)
        return false;
    IOLockLock(_lock);
    out.state = _ic.ic_state;
    out.bss_present = _ic.ic_bss && _ic.ic_bss->valid;
    out.associated = _ic.ic_state == obsd80211::IEEE80211_S_RUN &&
                     out.bss_present;
    if (out.bss_present) {
        memcpy(out.bssid, _ic.ic_bss->bssid, sizeof(out.bssid));
        out.essid_len = _ic.ic_bss->essid_len <= 32 ? _ic.ic_bss->essid_len : 32;
        if (out.essid_len)
            memcpy(out.essid, _ic.ic_bss->essid, out.essid_len);
        out.essid[out.essid_len] = '\0';
        out.channel = _ic.ic_bss->channel;
        out.rssi = _ic.ic_bss->rssi;
        out.capinfo = _ic.ic_bss->capinfo;
        out.beacon_interval = _ic.ic_bss->beacon_interval;
        out.nrates = _ic.ic_bss->nrates < sizeof(out.rates)
                         ? _ic.ic_bss->nrates
                         : (uint8_t)sizeof(out.rates);
        if (out.nrates)
            memcpy(out.rates, _ic.ic_bss->rates, out.nrates);
    }
    out.auth_valid = _ic.ic_auth_valid;
    out.auth_lower = _ic.ic_auth_lower;
    out.auth_upper = _ic.ic_auth_upper;
    out.desired_ssid_present = _ic.ic_des_esslen != 0;
    static const uint8_t zeroBSSID[6] = {};
    out.desired_bssid_present =
        memcmp(_ic.ic_des_bssid, zeroBSSID, sizeof(zeroBSSID)) != 0;
    IOLockUnlock(_lock);
    return true;
}

uint16_t RTW89Net80211Core::copyCurrentSecurityIE(uint8_t *out,
                                                   uint16_t capacity) const
{
    if (!out || capacity == 0 || !_lock || !_nodes)
        return 0;
    uint16_t copied = 0;
    IOLockLock(_lock);
    if (_ic.ic_state == obsd80211::IEEE80211_S_RUN &&
        _ic.ic_bss && _ic.ic_bss->valid) {
        const uint8_t *source = nullptr;
        uint16_t sourceLength = 0;
        if (_ic.ic_bss->rsn_ie_len >= 2) {
            source = _ic.ic_bss->rsn_ie;
            sourceLength = _ic.ic_bss->rsn_ie_len;
        } else if (_ic.ic_bss->wpa_ie_len >= 2) {
            source = _ic.ic_bss->wpa_ie;
            sourceLength = _ic.ic_bss->wpa_ie_len;
        }
        if (source && sourceLength) {
            copied = sourceLength < capacity ? sourceLength : capacity;
            memcpy(out, source, copied);
        }
    }
    IOLockUnlock(_lock);
    return copied;
}

void RTW89Net80211Core::publishTelemetry()
{
    if (!_owner)
        return;

    uint32_t nodeCount = 0, syncCount = 0, generation = 0;
    uint32_t state = 0, transitionCount = 0, transitionIndex = 0;
    uint32_t set22Count = 0, desiredChanges = 0, bssChanges = 0, authChanges = 0;
    uint32_t history[16] = {};
    bool bssPresent = false, desiredPresent = false, authValid = false;
    bool rtwScan = false, rtwConnected = false;
    if (_lock) IOLockLock(_lock);
    nodeCount = _visibleCount;
    syncCount = _syncCount;
    generation = _ic.ic_scan_generation;
    state = (uint32_t)_ic.ic_state;
    bssPresent = _ic.ic_bss != nullptr;
    desiredPresent = _ic.ic_des_esslen != 0;
    authValid = _ic.ic_auth_valid;
    transitionCount = _stateTransitionCount;
    transitionIndex = _stateTransitionIndex;
    set22Count = _set22ClearCount;
    desiredChanges = _desiredChangeCount;
    bssChanges = _bssChangeCount;
    authChanges = _authChangeCount;
    memcpy(history, _stateTransitionHistory, sizeof(history));
    rtwScan = _lastRTWScanObservation;
    rtwConnected = _lastRTWConnectedObservation;
    if (_lock) IOLockUnlock(_lock);

    _owner->setProperty("AirportRTW89Net80211NodeCount", (uint64_t)nodeCount, 32);
    _owner->setProperty("AirportRTW89Net80211SyncCount", (uint64_t)syncCount, 32);
    _owner->setProperty("AirportRTW89Net80211ScanGeneration", (uint64_t)generation, 32);
    _owner->setProperty("AirportRTW89Net80211ICState", (uint64_t)state, 32);
    _owner->setProperty("AirportRTW89Net80211ICBSSPresent",
                        bssPresent ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89Net80211DesiredSSIDPresent",
                        desiredPresent ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89Net80211AuthValid",
                        authValid ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89Net80211StateTransitionCount",
                        (uint64_t)transitionCount, 32);
    _owner->setProperty("AirportRTW89Net80211StateTransitionIndex",
                        (uint64_t)transitionIndex, 32);
    _owner->setProperty("AirportRTW89Net80211SET22ClearCount",
                        (uint64_t)set22Count, 32);
    _owner->setProperty("AirportRTW89Net80211DesiredChangeCount",
                        (uint64_t)desiredChanges, 32);
    _owner->setProperty("AirportRTW89Net80211ICBSSChangeCount",
                        (uint64_t)bssChanges, 32);
    _owner->setProperty("AirportRTW89Net80211AuthChangeCount",
                        (uint64_t)authChanges, 32);
    _owner->setProperty("AirportRTW89Net80211LastRTWScanObservation",
                        rtwScan ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89Net80211LastRTWConnectedObservation",
                        rtwConnected ? kOSBooleanTrue : kOSBooleanFalse);
    const bool authorityConnected =
        state == (uint32_t)obsd80211::IEEE80211_S_RUN && bssPresent;
    _owner->setProperty("AirportRTW89Net80211RTWConnectedAgreement",
                        authorityConnected == rtwConnected ? kOSBooleanTrue
                                                          : kOSBooleanFalse);
    if (OSData *historyData = OSData::withBytes(history, sizeof(history))) {
        _owner->setProperty("AirportRTW89Net80211StateTransitionHistory",
                            historyData);
        historyData->release();
    }
}
