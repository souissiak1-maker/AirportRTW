/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * RTW88IEEE80211.hpp — 802.11 state machine for rtw88 macOS port.
 *
 * Responsibilities:
 *  - Drives the Linux rtw88 driver (rtw_core_start/stop, rtw_tx, etc.)
 *  - Manages scan, authenticate, associate, 4-way handshake
 *  - Converts between mbuf_t and sk_buff for the driver
 *  - Delivers decrypted data frames as Ethernet to RTW88PCIDevice
 *  - Accepts Ethernet output frames and wraps them as 802.11 data frames
 */
#pragma once

#include <IOKit/IOService.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <sys/mbuf.h>
#include <net/ethernet.h>
#include <kern/thread_call.h>

/* Opaque C driver handle */
struct rtw_dev;
struct pci_dev;
struct ieee80211_hw;
struct ieee80211_vif;
struct ieee80211_sta;
struct ieee80211_channel;
struct sk_buff;

class RTW88PCIDevice;

/* ------------------------------------------------------------------ */
/*  BSS descriptor (scan result)                                        */
/* ------------------------------------------------------------------ */
/* 0.2.181: compact association-time view of a BSS.  Do not place a full
 * RTW88BSS on the Apple80211 request stack: RTW88BSS intentionally owns
 * persistent IE storage and is therefore too large for the small kernel
 * stack. */
struct RTW88ConnectTargetInfo {
    char     ssid[33];
    uint8_t  ssid_len;
    uint8_t  bssid[6];
    int16_t  rssi;
    uint16_t freq;
    uint8_t  channel;
    uint32_t capabilities;
    uint32_t cipher;
    uint32_t group_cipher;
    uint32_t akm;
    uint16_t rsn_ie_len;
    uint16_t wpa_ie_len;
    uint32_t rsn_observation_count;
    uint32_t security_update_count;
    uint32_t security_preserve_count;
    uint32_t security_open_candidate_count;
    uint32_t security_open_clear_count;
    uint32_t last_security_scan_generation;
    uint32_t open_candidate_scan_generation;
};

struct RTW88BSS {
    char   ssid[33];
    uint8_t ssid_len;
    uint8_t bssid[6];
    int16_t rssi;
    uint16_t freq;
    uint8_t  channel;
    uint32_t capabilities;
    uint16_t beacon_interval;
    uint8_t  nrates;
    uint8_t  rates[15];
    uint32_t cipher;       /* selected pairwise WLAN_CIPHER_SUITE_* */
    uint32_t group_cipher; /* selected group WLAN_CIPHER_SUITE_* */
    uint32_t akm;

    /* 0.2.180: IO80211Reference-style persistent security ownership.  Keep the
     * AP security TLVs on the BSS object itself instead of treating the last
     * beacon/probe response as the complete truth.  An incomplete refresh may
     * update RSSI/channel/age without erasing a previously observed RSN/WPA IE.
     * Privacy=0 observations are only downgrade candidates; 0.2.182 commits
     * them at scan completion only when the whole generation saw no RSN/WPA
     * evidence for the same BSSID. */
    uint8_t  rsn_ie[257];
    uint16_t rsn_ie_len;
    uint8_t  wpa_ie[257];
    uint16_t wpa_ie_len;
    uint32_t rsn_observation_count;
    uint32_t security_update_count;
    uint32_t security_preserve_count;
    uint32_t security_open_candidate_count;
    uint32_t security_open_clear_count;
    /* 0.2.182: security downgrades are committed only at scan-generation
     * boundaries.  A Privacy=0 frame is merely an open candidate until a
     * complete scan ends without any security-bearing observation for this
     * BSSID in the same generation. */
    uint32_t last_security_scan_generation;
    uint32_t open_candidate_scan_generation;

    uint32_t last_seen_scan;
    /* Monotonic time (nanoseconds since boot) when this BSS was last observed.
     * Used to populate Apple80211 scan-result cache age instead of always 0. */
    uint64_t last_seen_ns;
    /* 0.2.211: timestamp of the most recent non-sentinel RSSI sample.
     * A real management frame with an unavailable signal reading may still
     * refresh last_seen_ns without erasing a recent valid RSSI. */
    uint64_t last_valid_rssi_ns;
    /* Raw IE data for association */
    uint8_t  ies[512];
    uint16_t ies_len;
    RTW88BSS *next;
};

/* ------------------------------------------------------------------ */
/*  Connection state                                                     */
/* ------------------------------------------------------------------ */
enum RTW88State {
    RTW88_STATE_IDLE = 0,
    RTW88_STATE_SCANNING,
    RTW88_STATE_AUTHENTICATING,
    RTW88_STATE_ASSOCIATING,
    RTW88_STATE_HANDSHAKING,
    RTW88_STATE_CONNECTED,
    RTW88_STATE_DISCONNECTING,
};

/* ------------------------------------------------------------------ */
/*  RTW88IEEE80211                                                       */
/* ------------------------------------------------------------------ */
class RTW88IEEE80211 : public OSObject {
    OSDeclareDefaultStructors(RTW88IEEE80211)

public:
    static RTW88IEEE80211 *create(RTW88PCIDevice *dev, struct pci_dev *pci);

    bool      init(RTW88PCIDevice *dev, struct pci_dev *pci);
    void      free() override;

    /* Called by RTW88PCIDevice */
    IOReturn  start();       /* probe: chip info, efuse, register hw */
    void      stop();        /* full teardown */
    IOReturn  powerOn();     /* enable: rtw_core_start */
    void      powerOff();    /* disable: rtw_core_stop */
    void      handleInterrupt();
    UInt32    outputPacket(mbuf_t m);
    void      getMACAddress(uint8_t *mac);
    bool      assocStageProbe(uint8_t stage); /* 0.2.42 synchronous RA payload audit */
    void      raAuditU32(unsigned int field, uint32_t value);
    void      raAuditU64(unsigned int field, uint64_t value);

    /* Called from compat layer (ieee80211_rx_irqsafe) */
    void      rxFrame(struct sk_buff *skb);
    void      txStatus(struct sk_buff *skb);
    void      scanDone(bool aborted);

    /* Control interface — called from RTW88UserClient */
    /* 0.2.186: Apple-originated scans while associated use a bounded
     * rotating RF slice instead of the old permanent cache-only shortcut.
     * Private/diagnostic callers keep the full-scan default. */
    IOReturn  cmdScan(bool boundedConnectedScan = false);
    IOReturn  cmdConnect(const char *ssid, const char *password,
                          const uint8_t *preferredBSSID = nullptr,
                          bool requireScannedPSK = false);
    IOReturn  cmdConnectWithPMK(const char *ssid, const uint8_t *pmk,
                                uint32_t pmkLen,
                                const uint8_t *preferredBSSID = nullptr,
                                bool requireScannedPSK = false);
    IOReturn  cmdDisconnect();
    /* 0.2.184: Tahoe issues a pre-association DISASSOCIATE even when the
     * station is already idle.  The outer Apple80211 bridge uses this
     * snapshot only for idempotence diagnostics; cmdDisconnect() remains the
     * authoritative state transition. */
    bool      isIdle() const { return _state == RTW88_STATE_IDLE; }
    /* 0.2.165: logical user power transition.  Unlike cmdPowerOff(), OFF
     * aborts scan/association state but deliberately keeps rtw89 firmware and
     * hardware running so the GUI toggle is restart-safe. */
    IOReturn  cmdSetUserPower(bool on);
    /* 0.2.186: explicit logical Wi-Fi OFF invalidates the persistent BSS
     * node cache after scan/association state has quiesced. */
    IOReturn  flushBSSCache();
    IOReturn  cmdPowerOn();
    IOReturn  cmdPowerOff();
    IOReturn  cmdGetState(struct RTW88StateResult *result);
    IOReturn  cmdGetBSSList(uint8_t *buf, uint32_t *len);
    IOReturn  copyBSSSnapshot(RTW88BSS *out, uint32_t capacity,
                              uint32_t *count);
    /* 0.2.179: resolve association security and the eventual connect target
     * from the same live _bssList.  When preferWPA2PSK is true, a matching
     * CCMP+PSK BSS wins over an open/unknown duplicate of the same SSID.
     * The returned snapshot is detached (next == nullptr) and safe to use
     * after the BSS lock is released. */
    bool      copyBestConnectTarget(const char *ssid,
                                    const uint8_t *preferredBSSID,
                                    bool preferWPA2PSK,
                                    RTW88ConnectTargetInfo *out,
                                    uint32_t *matchCount = nullptr,
                                    uint32_t *pskCount = nullptr);
    IOReturn  cmdGetRSSI(int *rssi);

    /* 0.2.156: raw state is SCANNING during an associated background scan,
     * but the station remains logically connected and returns to CONNECTED
     * when the scan completes.  Apple-facing link/status code must use this
     * effective connection state instead of treating the temporary scan state
     * as a disconnect. */
    bool      isConnectedScanInProgress() const;
    /* 0.2.187: raw RTW state alone is not proof of a live infrastructure
     * association.  CoreWiFi must only enter connected-scan/status paths when
     * mac80211 still has an associated vif and a live peer STA. */
    bool      hasActiveAssociation() const;

    /* 0.2.162: publish cold-path RX sanity/PHY telemetry once per Apple poll. */
    void      publishRxSanityTelemetry();

    /* Regulatory bridge used by the native Airport frontend. */
    bool      getRegulatoryCountry(char outAlpha2[3]) const;
    bool      setRegulatoryCountry(const char alpha2[2]);

    /* 0.2.163: Apple RSN supplicant bridge.  IO80211Reference exposes Apple's
     * supplicant on the primary IO80211 interface; keep the Realtek MLME but
     * let Apple own EAPOL and temporal-key installation for secured joins. */
    void      setAppleRSNMode(bool enabled);
    bool      setAppleRSNIE(const uint8_t *ie, uint16_t len);
    bool      copyAppleRSNIE(uint8_t *out, uint32_t capacity,
                             uint32_t *outLen) const;
    IOReturn  installAppleRSNKey(bool pairwise, uint8_t keyidx,
                                 uint32_t cipher, const uint8_t *key,
                                 uint8_t keyLen);
    bool      appleRSNModeEnabled() const { return _appleRSNMode; }
    bool      appleRSNHandshakeComplete() const {
        return _appleRSNPTKInstalled && _appleRSNGTKInstalled;
    }

private:
    /* State machine internals */
    void      processRxMgmt(struct sk_buff *skb);
    void      processRxData(struct sk_buff *skb);
    void      processScanResult(struct sk_buff *skb);
    void      processAssocResponse(struct sk_buff *skb);

    void      doAuthenticate();
    void      doAssociate();
    void      setConnectedChandef(struct ieee80211_channel *chan);
    void      doHandshake(const uint8_t *eapol, uint32_t len);
    void      doDisconnect();
    void      clearKeys();
    void      releaseSta();
    bool      abortActiveScan(bool waitForIdle);
    void      restoreConnectedChannel();
    bool      installKey(struct ieee80211_key_conf **slot, bool pairwise,
                         uint8_t keyidx, uint32_t cipher,
                         const uint8_t *tk, uint8_t tk_len);

    bool      buildAssocReq(uint8_t *buf, uint32_t *len);
    bool      buildAuthReq(uint8_t *buf, uint32_t *len);

    /* WPA2 4-way handshake */
    void      handleEAPOL(const uint8_t *data, uint32_t len);
    void      setHandshakeRxFilter(bool open);
    void      resetHandshakeDiagnostics();
    void      captureHandshakeTxSnapshot(bool atTimeout);
    void      captureHandshakeStationContext();
    bool      deriveKeys(const uint8_t *anonce, const uint8_t *snonce);
    void      sendEAPOLKey(int step, const uint8_t *replay_counter,
                            bool install, bool ack, bool mic);

    /* A-MPDU BlockAck (aggregation) negotiation */
    bool      htAllowed() const;   /* HT/VHT/A-MPDU usable on this link? */
    void      startTxAggregation();
    void      sendAddbaRequest(uint8_t tid);
    void      sendAddbaResponse(uint8_t tid, uint8_t dialog,
                                uint16_t req_param, uint16_t ba_timeout,
                                uint16_t status);
    void      handleBackAction(const uint8_t *b, uint32_t len);

    /* RX A-MPDU reorder + delivery */
    void      deliverDataFrame(struct sk_buff *skb);   /* strip 802.11, inject */
    void      deAmsdu(const uint8_t *data, uint32_t len);
    void      deliverEthernet(const uint8_t *da, const uint8_t *sa,
                              uint16_t ethertype,
                              const uint8_t *payload, uint32_t paylen);
    void      rxBaSetup(uint8_t tid, uint16_t ssn, uint16_t bufsize);
    void      rxBaTeardown(uint8_t tid);
    void      rxBaTeardownAll();
    void      rxReorderInput(uint8_t tid, struct sk_buff *skb, uint16_t sn);
    void      rxReorderArmTimer();
    void      rxReorderFlushStale();
    static void reorderTimerFired(OSObject *owner, IOTimerEventSource *t);

    /* Frame transmission helpers */
    bool      txMgmtFrame(const uint8_t *frame, uint32_t len);
    bool      txNullFunc(bool powerSave);
    bool      txNullDescriptorVariant(uint8_t variant);
    bool      txProbeRequest();
    bool      txDataFrame(mbuf_t m);
    struct sk_buff *mbufToSkb(mbuf_t m);
    mbuf_t    skbToMbuf(struct sk_buff *skb);

    /* Driver callbacks installed in rtw_dev */
    static void compat_rx_frame(void *kext_hw, struct sk_buff *skb);
    static void compat_tx_status(void *kext_hw, struct sk_buff *skb);
    static void compat_scan_done(void *kext_hw, bool aborted);

    /* Timer callback for state machine timeouts */
    static void timerFired(OSObject *owner, IOTimerEventSource *timer);
    void        onTimer();

    /* Connect thread_call — runs doAuthenticate off the IOUserClient thread */
    static void connectTCFn(thread_call_param_t self, thread_call_param_t);
    thread_call_t _connectTC = nullptr;

    /* Manual passive scan fallback for chips/firmware without scan offload */
    static void manualScanTCFn(thread_call_param_t self, thread_call_param_t);
    void        runManualScan();
    thread_call_t _manualScanTC = nullptr;

    /* ---------------------------------------------------------------- */
    RTW88PCIDevice    *_parent        = nullptr;
    struct rtw_dev    *_rtwdev        = nullptr;
    struct ieee80211_hw *_hw          = nullptr;
    struct ieee80211_vif *_vif        = nullptr;
    size_t              _vifAllocSize = 0;
    bool                _ifaceAdded   = false;
    struct ieee80211_sta *_sta        = nullptr;
    size_t              _staAllocSize = 0;
    struct pci_dev     *_pcidev       = nullptr;

    IOWorkLoop         *_wl           = nullptr;
    IOCommandGate      *_gate         = nullptr;
    IOTimerEventSource *_timer        = nullptr;
    IOLock             *_lock         = nullptr;

    RTW88State          _state        = RTW88_STATE_IDLE;
    RTW88State          _scanReturnState = RTW88_STATE_IDLE;
    bool                _powered      = false;
    uint8_t             _macAddr[6]   = {};
    uint32_t            _timeoutMs    = 0;

    /* Scan results */
    RTW88BSS           *_bssList      = nullptr;
    uint32_t            _bssCount     = 0;
    IOLock             *_bssLock      = nullptr;
    uint32_t            _scanGeneration = 0;
    /* 0.2.181: keep scan channel vectors off the kernel stack.  cmdScan()
     * used to allocate 256 pointers (~2 KiB) as a local array, which combined
     * with the Apple80211 call chain was enough to overflow the x86 kernel
     * stack after RTW88BSS grew persistent security storage. */
    struct ieee80211_channel *_scanScratchChannels[256] = {};
    struct ieee80211_channel *_manualScanChannels[256] = {};
    /* 0.2.186: connected Apple scans use a small rotating channel slice.
     * Keep this vector in object storage to preserve 0.2.181 stack safety. */
    struct ieee80211_channel *_connectedScanChannels[8] = {};
    uint32_t            _connectedScanCursor = 0;
    bool                _scanSnapshotUsesRecentWindow = false;
    uint32_t            _manualScanChannelCount = 0;
    /* 0.2.226: known-BSS channel ordering uses object storage rather than a
     * large cmdScan() local vector, preserving the 0.2.181 stack-safety rule. */
    uint16_t            _scanPriorityFrequencies[32] = {};
    uint64_t            _scanPriorityAgesNs[32] = {};
    uint32_t            _scanPriorityFrequencyCount = 0;
    volatile bool       _manualScanAbort = false;
    volatile bool       _manualScanOnHomeChannel = false;
    bool                _manualScanFallbackLogged = false;

    /* 0.2.209: memory-only scan RSSI transition diagnostics.  processScanResult()
     * updates these fields without IORegistry traffic; scanDone() publishes one
     * aggregate snapshot after the RF sweep. */
    uint8_t             _scanRSSILastBSSID[6] = {};
    int16_t             _scanRSSILastPrevious = 0;
    int16_t             _scanRSSILastIncoming = 0;
    int32_t             _scanRSSILastDelta = 0;
    uint32_t            _scanRSSILastAbsDelta = 0;
    uint64_t            _scanRSSILastObservationGapMS = 0;
    uint32_t            _scanRSSILastGeneration = 0;
    uint32_t            _scanRSSILargeJumpCount = 0;
    bool                _scanRSSILastLargeJump = false;
    bool                _scanRSSILastIncomingWasMinus90 = false;
    /* 0.2.211: track the -110 no-signal sentinel separately from real RSSI. */
    bool                _scanRSSILastIncomingWasMinus110 = false;
    bool                _scanRSSILastSentinelRejected = false;
    int16_t             _scanRSSILastApplied = 0;
    uint32_t            _scanRSSISentinelRejectCount = 0;

    /* 0.2.226: one-scan proof that persistent entries are refreshed by real
     * beacon/probe observations rather than by cache enumeration. */
    uint32_t            _scanBSSObservationCount = 0;
    uint32_t            _scanBSSExistingRefreshCount = 0;
    uint32_t            _scanBSSNewCount = 0;
    uint8_t             _scanBSSLastRefreshBSSID[6] = {};
    uint64_t            _scanBSSLastRefreshPreviousAgeMS = 0;
    uint8_t             _scanBSSLastRefreshChannel = 0;
    uint16_t            _scanBSSLastRefreshFrequency = 0;
    uint32_t            _scanBSSLastRefreshGeneration = 0;
    uint8_t             _scanBSSLastRefreshSource = 0; /* 1 beacon, 2 probe */
    uint8_t             _scanBSSLastObservationSource = 0;

    /* Target BSS for connection */
    RTW88BSS            _targetBSS    = {};
    char                _password[64] = {};

    /* WPA2 key material */
    uint8_t  _pmk[32]  = {};
    uint8_t  _ptk[64]  = {};   /* PTK = KCK|KEK|TK */
    uint8_t  _gtk[32]  = {};
    struct ieee80211_key_conf *_ptkConf = nullptr;
    struct ieee80211_key_conf *_gtkConf = nullptr;
    uint8_t  _anonce[32] = {};
    uint8_t  _snonce[32] = {};
    uint8_t  _replayCtr[8] = {};
    uint8_t  _ccmpTxPn[6] = {};
    bool     _rxCcmpIvSkipLogged = false;
    bool     _wpa2     = false;
    bool     _pmkProvided = false;

    /* 0.2.163 Apple RSN state.  The IE is the exact station-selected RSN TLV
     * supplied by IO80211Family and is used in the association request. */
    bool     _appleRSNMode = false;
    bool     _appleRSNPTKInstalled = false;
    bool     _appleRSNGTKInstalled = false;
    uint8_t  _appleRSNIE[257] = {};
    uint16_t _appleRSNIELen = 0;
    uint32_t _appleRSNEAPOLRxCount = 0;
    uint32_t _appleRSNEAPOLTxCount = 0;

    /* WPA2 handshake RX diagnostics.  The 0.2.11 direct-connect path reaches
     * 0.2.12 opened the rtw89 RX filter and proved that M1 reaches the kext
     * and M2 is submitted.  0.2.13 requests a real PCI TX report.  0.2.15
     * additionally records passive cached ring snapshots immediately after M2
     * submission and at timeout, without polling or reclaiming PCI queues. */
    bool     _handshakeRxFilterOpen = false;
    /* 0.2.28 diagnostic only: true while the driver association callbacks
     * are executing, so an EAPOL M1 received in that window is observable. */
    volatile bool _assocNotifyInProgress = false;
    uint32_t _handshakeRxFrames = 0;
    uint32_t _handshakeDataFrames = 0;
    uint32_t _handshakeEapolFrames = 0;
    uint32_t _handshakeM1Count = 0;
    uint32_t _handshakeM3Count = 0;
    uint8_t  _pendingEapolTxStep = 0;
    uint32_t _handshakeM2TxStatusCount = 0;
    uint32_t _handshakeM4TxStatusCount = 0;

    /* 0.2.30 ordinary Ethernet/data-path diagnostics. */
    uint64_t _ordinaryOutputPacketCount = 0;
    uint64_t _ordinaryTxDataFrameCount = 0;
    uint64_t _ordinaryHwSubmitCount = 0;
    uint32_t _ordinaryARPSubmitCount = 0;
    uint32_t _ordinaryDHCPSubmitCount = 0;
    uint32_t _ordinaryTxStatusCount = 0;
    uint32_t _ordinaryTxAckCount = 0;
    uint32_t _ordinaryRxARPCount = 0;
    uint32_t _ordinaryRxDHCPOfferCount = 0;
    uint32_t _nullABSubmitCount[4] = {};
    uint32_t _nullABTxStatusCount[4] = {};
    uint32_t _nullABTxAckCount[4] = {};

    uint32_t _handshakeDisconnectCount = 0;
    uint16_t _handshakeLastDisconnectReason = 0;
    uint8_t  _handshakeLastDisconnectSubtype = 0;

    /* Auth retry budget — bounded so a dead AP returns the state machine
     * to IDLE instead of blocking scan/connect forever. */
    static const uint8_t kMaxAuthRetries = 5;
    uint8_t  _authRetries = 0;

    /* Sequence number for TX frames */
    uint16_t _txSeq    = 0;
    /* Separate SN space for QoS data (TID 0) so the BlockAck window is gap-free */
    uint16_t _dataSeq  = 0;
    uint16_t _assocAID = 0;

    /* A-MPDU aggregation (BlockAck) state */
    bool     _txBaActive = false;  /* uplink TX BlockAck agreement established */
    uint8_t  _baTid      = 0;      /* TID carrying aggregated data (BE)        */
    uint8_t  _connChanWidth = 20;  /* negotiated operating width: 20/40/80 MHz */
    uint8_t  _baDialog   = 0;      /* rolling ADDBA-request dialog token       */
    uint16_t _baBufSize  = 64;     /* advertised BlockAck buffer/window size   */
    uint32_t _rxAddbaRequestCount = 0;
    uint32_t _rxAddbaDeclinedCount = 0;

    /* RX A-MPDU reorder buffer — one per TID with an active downlink BA.
     * Touched from the RX workloop (frame input) and the IEEE80211 workloop
     * (flush timer, disconnect teardown), so guarded by _rxBaLock.  Frames are
     * always delivered with the lock dropped to avoid holding it across the
     * network-stack input path. */
    static const uint16_t kRxBaMaxBuf   = 64;
    static const uint8_t  kRxBaNumTid   = 8;   /* QoS data TIDs 0-7 */
    static const uint32_t kReorderTimeoutMs = 60;
    struct RxReorder {
        bool      active;
        uint16_t  headSn;          /* next expected SN (12-bit, mod 4096) */
        uint16_t  bufSize;         /* reorder window size */
        uint32_t  stored;          /* frames currently buffered */
        struct sk_buff *buf[kRxBaMaxBuf];   /* indexed by SN % bufSize */
    };
    RxReorder *_rxBa[kRxBaNumTid] = {};
    IOLock    *_rxBaLock      = nullptr;
    IOTimerEventSource *_reorderTimer = nullptr;

    /* RSSI tracking */
    int      _rssi     = -100;

    /* Diagnostics: periodic logging of RX activity during scan */
    uint32_t _rxFrameCount = 0;

    /* 0.2.162: mac80211 RX-sanity parity.  The compatibility shim bypasses
     * mac80211 proper, so perform the two correctness checks that matter most
     * for the current non-aggregated station path: reject hardware-reported
     * FCS/PLCP failures and suppress retry duplicates by TID+sequence.  All
     * counters are memory-only on the hot path and published once per poll. */
    uint64_t _rxDataFrameCount = 0;
    uint64_t _rxDataByteCount = 0;
    uint64_t _rxFailedFcsDropCount = 0;
    uint64_t _rxFailedPlcpDropCount = 0;
    uint64_t _rxRetryFrameCount = 0;
    uint64_t _rxRetryDuplicateDropCount = 0;
    uint64_t _rxAmsduFrameCount = 0;
    uint64_t _rxAmsduSubframeCount = 0;
    uint64_t _rxAmsduMalformedCount = 0;
    uint64_t _rxEncodingCount[5] = {};
    uint16_t _rxDuplicateSeq[17] = {};
    uint8_t  _rxDuplicateFrag[17] = {};
    bool     _rxDuplicateValid[17] = {};
    uint32_t _rxLastStatusFlags = 0;
    uint16_t _rxLastEncFlags = 0;
    uint16_t _rxLastFrameLength = 0;
    uint8_t  _rxLastEncoding = 0;
    uint8_t  _rxLastRateIndex = 0;
    uint8_t  _rxLastNSS = 0;
    uint8_t  _rxLastBandwidth = 0;
    int8_t   _rxLastSignal = -100;
};
