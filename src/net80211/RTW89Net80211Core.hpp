/* SPDX-License-Identifier: BSD-3-Clause
 * RTW89Net80211Core.hpp
 *
 * AirportRTW89 0.3.2 experiment: Stage-2 OpenBSD-net80211 state authority; stack-safety-only repair.
 * This remains a compatibility/adaptation layer rather than Intel driver code.
 * Stage 1 landed persistent ieee80211_node storage for Apple GET11.  Stage 2
 * keeps ieee80211com authoritative for association state (ic_state, ic_bss
 * and desired identity).  As of 0.3.5, Apple AUTH_TYPE configuration is a
 * separate IO80211Reference-style SET2/GET2 latch owned by the controller.
 *
 * Stage 2 scope:
 *   - RTW89 remains the hardware/MLME implementation.
 *   - The existing RTW88 BSS snapshot is imported into persistent nodes.
 *   - Apple GET11 remains backed by node-owned result storage.
 *   - Apple association getters use one net80211 current-state snapshot.
 *   - SET22 follows IO80211Reference-style state-sensitive disassociate semantics.
 *   - SET20 updates net80211 desired/association state; SET2 does not.
 *
 * No iwm/iwx/iwn code is present.  No desired WPA2 target is inferred from
 * nearby scan results before Apple supplies association intent.
 */
#pragma once

#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <libkern/c++/OSObject.h>
#include <sys/types.h>

#ifdef RTW_AIRPORT
#include <IOKit/80211/Apple80211.h>
#endif

struct RTW88BSS;
class RTW88PCIDevice;

namespace obsd80211 {

enum ieee80211_state : uint32_t {
    IEEE80211_S_INIT  = 0,
    IEEE80211_S_SCAN  = 1,
    IEEE80211_S_AUTH  = 2,
    IEEE80211_S_ASSOC = 3,
    IEEE80211_S_RUN   = 4,
};

/* A deliberately narrow node shape for the first porting stage.  Field names
 * mirror the semantic ownership used by OpenBSD net80211, while the payload
 * is limited to what AirportRTW89 already owns and what the legacy Apple scan
 * converter consumes. */
struct ieee80211_node {
    bool valid;
    uint32_t generation;
    uint8_t bssid[6];
    uint8_t essid_len;
    char essid[33];
    int16_t rssi;
    uint8_t channel;
    uint32_t capinfo;
    uint16_t beacon_interval;
    uint8_t nrates;
    uint8_t rates[15];
    uint32_t cipher;
    uint32_t group_cipher;
    uint32_t akm;
    uint8_t rsn_ie[257];
    uint16_t rsn_ie_len;
    uint8_t wpa_ie[257];
    uint16_t wpa_ie_len;
    uint8_t ies[512];
    uint16_t ies_len;
    uint64_t last_seen_ns;
#ifdef RTW_AIRPORT
    /* IO80211Reference's legacy design keeps Apple scan-result storage on the BSS
     * node.  Stage 1 intentionally adopts that ownership model. */
    apple80211_scan_result verb;
#endif
};

struct ieee80211com {
    ieee80211_state ic_state;
    ieee80211_node *ic_bss;
    uint8_t ic_des_bssid[6];
    uint8_t ic_des_essid[32];
    uint8_t ic_des_esslen;
    uint32_t ic_auth_lower;
    uint32_t ic_auth_upper;
    bool ic_auth_valid;
    uint32_t ic_scan_generation;
};

/* Locked, pointer-free Apple-facing projection of ieee80211com.  The node
 * pointer never escapes the core, so callers cannot race a scan refresh. */
struct ieee80211_current_view {
    ieee80211_state state;
    bool associated;
    bool bss_present;
    uint8_t bssid[6];
    uint8_t essid_len;
    char essid[33];
    uint8_t channel;
    int16_t rssi;
    uint32_t capinfo;
    uint16_t beacon_interval;
    uint8_t nrates;
    uint8_t rates[15];
    bool auth_valid;
    uint32_t auth_lower;
    uint32_t auth_upper;
    bool desired_ssid_present;
    bool desired_bssid_present;
};

} // namespace obsd80211

class RTW89Net80211Core : public OSObject {
    OSDeclareDefaultStructors(RTW89Net80211Core)

public:
    static RTW89Net80211Core *create(RTW88PCIDevice *owner);
    bool initWithOwner(RTW88PCIDevice *owner);
    void free() override;

    void reset();
    void clearScanCachePreservingState();
    void syncFromRTW(const RTW88BSS *source, uint32_t count,
                     bool scanInProgress, bool connected);

    uint32_t visibleNodeCount() const;
    const obsd80211::ieee80211_node *visibleNode(uint32_t ordinal) const;
    obsd80211::ieee80211_node *visibleNodeMutable(uint32_t ordinal);
    const obsd80211::ieee80211_node *findNodeByBSSID(const uint8_t bssid[6]) const;

    void noteDisassociate();
    void noteDesired(const uint8_t *ssid, uint8_t ssidLen,
                     const uint8_t *bssid, uint32_t authLower,
                     uint32_t authUpper, bool authValid);
    void noteAuth(uint32_t authLower, uint32_t authUpper, bool authValid);
    void noteState(obsd80211::ieee80211_state state,
                   const uint8_t *currentBSSID = nullptr);
    bool copyCurrentView(obsd80211::ieee80211_current_view &out) const;
    uint16_t copyCurrentSecurityIE(uint8_t *out, uint16_t capacity) const;

    const obsd80211::ieee80211com &com() const { return _ic; }
    uint32_t syncCount() const { return _syncCount; }

private:
    int findSlotByBSSID(const uint8_t bssid[6]) const;
    int allocateSlot();
    void copyFromRTWBSS(obsd80211::ieee80211_node &dst,
                        const RTW88BSS &src, uint32_t generation);
    void recordStateTransitionLocked(obsd80211::ieee80211_state next);
    void bindBSSLocked(const uint8_t *bssid);
    void publishTelemetry();

    RTW88PCIDevice *_owner { nullptr }; // weak; owner outlives core
    IOLock *_lock { nullptr };
    obsd80211::ieee80211com _ic {};
    obsd80211::ieee80211_node *_nodes { nullptr };
    uint8_t _visible[64] {};
    uint32_t _visibleCount { 0 };
    uint32_t _syncCount { 0 };
    uint32_t _stateTransitionCount { 0 };
    uint32_t _stateTransitionIndex { 0 };
    uint32_t _stateTransitionHistory[16] {};
    uint32_t _set22ClearCount { 0 };
    uint32_t _desiredChangeCount { 0 };
    uint32_t _bssChangeCount { 0 };
    uint32_t _authChangeCount { 0 };
    bool _lastRTWScanObservation { false };
    bool _lastRTWConnectedObservation { false };
};
