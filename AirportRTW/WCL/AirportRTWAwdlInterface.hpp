/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_NATIVE_AWDL_INTERFACE_HPP
#define AIRPORTRTW_NATIVE_AWDL_INTERFACE_HPP
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <Airport/macOS26/IO80211AWDLProtocol.h>
#include "AirportRTWAwdlControl.hpp"
#include "AirportRTWAwdlDatapath.hpp"
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOLocks.h>

struct apple80211_channel;

class AirportRTWAwdlInterface : public IO80211AWDLProtocol {
    OSDeclareDefaultStructors(AirportRTWAwdlInterface)
public:
    static AirportRTWAwdlInterface *withController(IO80211Controller *, AirportRTWAwdl::Control *, const uint8_t mac[6]);
    bool start(IOService *) override;
    void stop(IOService *) override;
    void free() override;
    IOReturn enable(unsigned int) override;
    IOReturn disable(unsigned int) override;
    uintptr_t setMacAddress(ether_addr &) override;
    IOReturn getHardwareAddress(ether_addr *) override;
    const char *getBSDNamePrefix() override { return "awdl"; }
    UInt getMaxTransferUnit() override { return RTWAwdl::DataCodec::mtu; }
    bool isChipInterfaceReady() override;
    void *getTxSubQueue(apple80211_wme_ac) override;
    void *getTxCompQueue() override;
    void *getRxCompQueue() override;
    void *getTxPacketPool() override;
    void *getRxPacketPool() override;
    int getNumTxQueues() override { return 1; }
    int getTxHeadroom() override { return 64; }
    UInt64 getRxQueueCapacity() override { return 128; }
    void enableDatapath() override;
    void disableDatapath() override;
    // Data and TX-ready callbacks are NAPI-safe; provider owns its live reference.
    bool receiveEthernet(const uint8_t *, size_t);
    void resumeTransmit();
    // Action delivery is on nativeWorkLoop(), with verified 72-byte metadata.
    bool receiveAction(const uint8_t *, size_t, const uint8_t *, size_t);
    // NAPI-safe staging of an action with verified native RX metadata.
    // Provider keeps this interface alive and stops producers before shutdown.
    bool queueAction(const uint8_t *, size_t, const uint8_t *, size_t);
    // Source is taken from the frame; provider supplies the actual channel and RSSI.
    bool queueRadioAction(const uint8_t *, size_t, const apple80211_channel &, int32_t,
                          uint32_t wireRxTime = 0, bool wireRxTimeValid = false);
    // Native-workloop only. Returns handoff/arming status, not peer-manager ACK.
    bool postWindowStart(uint16_t counter,uint32_t role,const uint8_t parent[6],
                         const uint8_t root[6],const apple80211_channel &,uint32_t wireTime);
    bool postWindowEnd(uint32_t wireTime);
    bool canPostPeerCacheCompletion() const {
        return enabled_ && !stopping_ && registered_ && baseStarted_;
    }
    bool postPeerCacheCompletion(const uint8_t address[6],bool present);
    bool armWindowTimer(uint64_t deadlineUs,uint64_t nowUs);
    void cancelWindowTimer();
    IOWorkLoop *nativeWorkLoop() const { return loop_; }
    IOReturn getSSID(apple80211_ssid_data *) override;
    IOReturn getCHANNEL(apple80211_channel_data *) override;
    IOReturn getBSSID(apple80211_bssid_data *) override;
    IOReturn getSTATE(apple80211_state_data *) override;
    IOReturn getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) override;
    IOReturn getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) override;
    IOReturn getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *) override;
    IOReturn getAWDL_ELECTION_ID(apple80211_awdl_election_id *) override;
    IOReturn getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) override;
    IOReturn getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *) override;
    IOReturn getPEER_CACHE_MAXIMUM_SIZE(apple80211_peer_cache_maximum_size *) override;
    IOReturn getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) override;
    IOReturn getAWDL_SYNC_STATE(apple80211_awdl_sync_state *) override;
    IOReturn getAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *) override;
    IOReturn getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) override;
    IOReturn getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) override;
    IOReturn getAWDL_DEVICE_CAPABILITIES(apple80211_awdl_device_capabilities *) override;
    IOReturn getAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *) override;
    IOReturn getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) override;
    IOReturn getAWDL_MIN_RATE(apple80211_awdl_min_rate *) override;
    IOReturn getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) override;
    IOReturn getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) override;
    IOReturn getAWDL_DEV_STATS(apple80211_awdl_dev_stats *) override;
    IOReturn getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) override;
    IOReturn getAWDL_CCA(apple80211_awdl_cca *) override;
    IOReturn getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(apple80211_awdl_cap *) override;
    IOReturn getLLW_PARAMS(apple80211_llw_params *) override;
    IOReturn setSSID(apple80211_ssid_data *) override;
    IOReturn setCHANNEL(apple80211_channel_data *) override;
    IOReturn setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) override;
    IOReturn setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) override;
    IOReturn setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *) override;
    IOReturn setAWDL_ELECTION_ID(apple80211_awdl_election_id *) override;
    IOReturn setAWDL_BSSID(apple80211_awdl_bssid *) override;
    IOReturn setAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) override;
    IOReturn setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *) override;
    IOReturn setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) override;
    IOReturn setAWDL_SYNC_STATE(apple80211_awdl_sync_state *) override;
    IOReturn setAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *) override;
    IOReturn setAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) override;
    IOReturn setPEER_CACHE_CONTROL(apple80211_peer_cache_control *) override;
    IOReturn setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *) override;
    IOReturn setAWDL_SYNC_FRAME_TEMPLATE(apple80211_awdl_sync_frame_template *) override;
    IOReturn setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) override;
    IOReturn setAWDL_PEER_TRAFFIC_REGISTRATION(apple80211_awdl_peer_traffic_registration *) override;
    IOReturn setAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *) override;
    IOReturn setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) override;
    IOReturn setAWDL_MIN_RATE(apple80211_awdl_min_rate *) override;
    IOReturn setAWDL_ENCRYPTION_KEYS(apple80211_key *) override;
    IOReturn setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) override;
    IOReturn setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *) override;
    IOReturn setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) override;
    IOReturn setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *) override;
    IOReturn setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) override;
    IOReturn setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *) override;
    IOReturn setCOMPANION_SKYWALK_IF_CREATE(apple80211_companion_skywalk_if_create *) override;
    IOReturn setAWDL_OOB_SEC_PAYLOAD_REQUEST(apple80211_awdl_af_sec_payload_request *) override;
    IOReturn setLLW_PARAMS(apple80211_llw_params *) override;
    IOReturn setTX_RATE(apple80211_tx_rate *) override;
    IOReturn setP2P_COEX_PROTECTION(apple80211_p2p_coex_protection *) override;
    IOReturn setPSF_DWELL(apple80211_awdl_psf_dwell_params *) override;
    IOReturn setAWDL_CONFIG(apple80211_awdl_config_request *) override;
    IOReturn setAWDL_RTG_PEER_STATS_CONFIG(apple80211_rtg_peer_stats_cfg *) override;

private:
    IORecursiveLock *controlLock_ {nullptr};
    using NativeAction=IOReturn (*)(OSObject *,void *,void *,void *,void *);
    struct ControlRequest { AirportRTWAwdl::Request request;bool set;void *payload; };
    struct ToggleRequest { bool enable;unsigned flags; };
    struct AddressRequest { ether_addr *address;uintptr_t result; };
    IOReturn gatedAction(NativeAction,void *);
    static IOReturn dispatchGated(OSObject *,void *,void *,void *,void *);
    static IOReturn toggleGated(OSObject *,void *,void *,void *,void *);
    static IOReturn addressGated(OSObject *,void *,void *,void *,void *);
    IOReturn enableImpl(unsigned int);
    IOReturn disableImpl(unsigned int);
    uintptr_t setMacAddressImpl(ether_addr &);
    bool initialize(IO80211Controller *, AirportRTWAwdl::Control *, const uint8_t *);
    bool publish();
    static IOReturn stopGated(OSObject *, void *, void *, void *, void *);
    void stopImpl(IOService *);
    static void windowTimerFired(OSObject *,IOTimerEventSource *);
    void releaseWindowTimer();
    IOReturn dispatch(AirportRTWAwdl::Request, bool, void *);
    static bool transmit(OSObject *, const uint8_t *, size_t);
    static bool deliverAction(OSObject *, const uint8_t *, size_t, const uint8_t *, size_t);
    IO80211Controller *controller_ {nullptr}; // Held by service attachment.
    AirportRTWAwdl::Control *control_ {nullptr}; // Controller-owned.
    AirportRTWAwdlDatapath *datapath_ {nullptr};
    IOWorkLoop *loop_ {nullptr};
    IOTimerEventSource *windowTimer_ {nullptr};
    bool windowTimerAdded_ {false}, windowOpen_ {false};
    uint8_t mac_[6] {};
    uint8_t registration_[0x130] {};
    bool attached_ {false}, baseStarted_ {false}, prepareAttempted_ {false};
    bool prepared_ {false}, virtualInitAttempted_ {false};
    bool controllerPublished_ {false}, servicePublished_ {false};
    bool registered_ {false}, enabled_ {false}, stopping_ {false};
};
static_assert(!__is_abstract(AirportRTWAwdlInterface), "all native AWDL protocol slots must be implemented");
#endif
#endif
