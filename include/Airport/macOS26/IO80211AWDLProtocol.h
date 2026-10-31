/* SPDX-License-Identifier: GPL-2.0
 * Native Tahoe AWDL ABI declarations, adapted from RTL8814Native
 * Source/AirLayer/AWDLInterface.h, Copyright (c) 2026 DrogaBox.
 * Class/slot boundaries checked against the local Darwin 25.5 family.
 * Opaque return signatures are not callable APIs until individually verified.
 * This declares the family contract only; no support flags or interface creation.
 */
#ifndef RTW_NATIVE_AWDL_PROTOCOL_HPP
#define RTW_NATIVE_AWDL_PROTOCOL_HPP
#if !defined(AIRPORT_WCL) || __IO80211_TARGET != __MAC_26_0
#error "This AWDL declaration is for the native Tahoe frontend only"
#endif
#include <Airport/Apple80211.h>

struct apple80211_ssid_data;
struct apple80211_bssid_data;
struct apple80211_encrypt;
struct apple80211_tx_rate;
struct apple80211_llw_params;
struct apple80211_awdl_sync_params;
struct apple80211_awdl_sync_enabled;
struct apple80211_awdl_extension_state_machine_parameter;
struct apple80211_awdl_election_id;
struct apple80211_awdl_election_metric;
struct apple80211_awdl_sync_channel_sequence;
struct apple80211_peer_cache_maximum_size;
struct apple80211_awdl_master_channel;
struct apple80211_awdl_sync_state;
struct apple80211_awdl_election_rssi_thresholds;
struct apple80211_awdl_presence_mode;
struct apple80211_awdl_election_params;
struct apple80211_awdl_device_capabilities;
struct apple80211_awdl_secondary_master_channel;
struct apple80211_awdl_af_tx_mode;
struct apple80211_awdl_min_rate;
struct apple80211_awdl_txcal_period;
struct apple80211_awdl_dev_stats;
struct apple80211_awdl_dfsp_config;
struct apple80211_awdl_cca;
struct apple80211_awdl_cap;
struct apple80211_awdl_bssid;
struct apple80211_peer_cache_control;
struct apple80211_awdl_oob_request;
struct apple80211_awdl_sync_frame_template;
struct apple80211_awdl_peer_traffic_registration;
struct apple80211_awdl_dfsp_ucsa_config;
struct apple80211_companion_skywalk_if_create;
struct apple80211_awdl_af_sec_payload_request;
struct apple80211_p2p_coex_protection;
struct apple80211_awdl_psf_dwell_params;
struct apple80211_awdl_config_request;
struct apple80211_rtg_peer_stats_cfg;
struct awdl_peer_advert_add;
struct peerSlotDataStats;
struct packetCounters_t;


struct IO80211VirtualInterface : public IO80211SkywalkInterface {
	OSDeclareAbstractStructors(IO80211VirtualInterface)
public:
	/* Overrides of inherited slots: no new vtable entries. */
	virtual void free() override;
	virtual void stop(IOService *) override;
	/* Overrides that IO80211VirtualInterface itself defines (checked against
	 * __ZTV19IO80211AWDLProtocol): without them these cells would resolve to
	 * the IO80211SkywalkInterface or IOService bodies. */
	virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*) override; /* 0x428 */
	virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*) override; /* 0x430 */
	virtual bool start(IOService*) override;                                       /* 0x5C0 */
	virtual bool terminate(IOOptionBits options = 0) override;                                 /* 0x600 */
	virtual bool attach(IOService *) override;                                     /* 0x670 */
	virtual void detach(IOService *) override;                                     /* 0x678 */
	virtual IOReturn newUserClient(task*, void*, unsigned int, OSDictionary*, IOUserClient**) override; /* 0x770 */
	virtual const char * stringFromReturn(int) override;                           /* 0x780 */
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int) override;
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*) override;
    virtual SInt32 setInterfaceEnable(bool) override;
    virtual UInt32 getFeatureFlags() override;
	virtual bool bpfTap(unsigned int, unsigned int) override;                 /* 0x9E0 */
	virtual bool setMulticastAddresses(ether_addr const*, unsigned int) override; /* 0xA88 */
    virtual void * createPeerManager() override;
    virtual void postMessage(unsigned int, void*, unsigned long, bool) override;
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool) override;
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool) override;
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool) override;
    virtual void logSkywalkTxReqPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, bool) override;
    virtual SInt64 pendingPackets(unsigned char) override;
    virtual SInt64 packetSpace(unsigned char) override;
    virtual IO80211LinkState linkState() override;
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int) override;
    virtual void updateLinkParameters(apple80211_interface_availability*) override;
    virtual void updateInterfaceCoexRiskPct(unsigned long long) override;
    virtual void setInterfaceNF(apple80211_channel, long long) override;
    virtual void setDebugFlags(unsigned long long, unsigned int) override;
    virtual SInt64 debugFlags() override;
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*) override;
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*) override;
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*) override;
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*) override;
    virtual SInt64 getWmeTxCounters(unsigned long long*) override;
    virtual void setWoWEnabled(bool) override;
    virtual bool wowEnabled() override;
    virtual void printDataPath(userPrintCtx*) override;
private: virtual void _abi_0c68() override __asm__("__ZN23IO80211VirtualInterface21findOrCreateFlowQueueE20IO80211FlowQueueHash"); public:
private: virtual void _abi_0c70() override __asm__("__ZN23IO80211VirtualInterface30findOrCreateFlowQueueWithCacheE20IO80211FlowQueueHashPb"); public:
private: virtual void _abi_0c78() override __asm__("__ZN23IO80211VirtualInterface21findExistingFlowQueueE20IO80211FlowQueueHash"); public:
private: virtual void _abi_0c80() override __asm__("__ZN23IO80211VirtualInterface17removePacketQueueEPK20IO80211FlowQueueHash"); public:
    virtual void flushPacketQueues() override;
    virtual void cachePeer(ether_addr*, unsigned int*) override;
    virtual bool shouldLog(unsigned long long) override;
    virtual void vlogDebug(unsigned long long, char const*, va_list) override;
    virtual void vlogDebugBPF(unsigned long long, char const*, va_list) override;
    virtual void * getP2PSkywalkPeerMgr() override;
	virtual void _abi_0cd0() override __asm__("__ZN23IO80211VirtualInterface8findPeerER10ether_addr");                              /* 0xCD0 */
    virtual int getEventPipeSize() override;
    virtual UInt64 createEventPipe(IO80211APIUserClient*) override;
	/* Keeps init() and init(IOService*, ether_addr*) visible next to the
	 * overload below. */
	using IO80211SkywalkInterface::init;
	virtual bool init(IO80211Controller *, ether_addr *, uint32_t, const char *); /* 0xE68 */
	virtual uintptr_t setLinkState(IO80211LinkState, unsigned int);                /* 0xE70 */
	virtual uintptr_t forwardPacket(IO80211NetworkPacket *);                       /* 0xE78 */
	virtual uintptr_t handleIoctl(__ifnet *, unsigned long, void *);               /* 0xE80 */
	virtual uintptr_t addPeerToCache(unsigned char *);                             /* 0xE88 */
	virtual uintptr_t deletePeerFromCache(unsigned char *);                        /* 0xE90 */
	virtual uintptr_t handleDebugCmd(apple80211_debug_command *);                  /* 0xE98 */
	virtual uintptr_t getPeerSlotDataStats(ether_addr *, bool,
	                                       peerSlotDataStats *);                   /* 0xEA0 */
	virtual uintptr_t getPeerDataStats(ether_addr *, bool,
	                                   packetCounters_t *);                        /* 0xEA8 */
	virtual uintptr_t clearPeerDataStats(ether_addr *, bool);                      /* 0xEB0 */
	virtual uintptr_t setAwdlCurrentChannelSequenceIndex(unsigned int);            /* 0xEB8 */
	virtual uintptr_t isOutputFlowControlled();                                    /* 0xEC0 */
	virtual uintptr_t setOutputFlowControlled();                                   /* 0xEC8 */
	virtual uintptr_t clearOutputFlowControlled();                                 /* 0xED0 */
	virtual uintptr_t flushFlowQueues(ether_addr *);                               /* 0xED8 */
	virtual uintptr_t configureAQMOutput();                                        /* 0xEE0 */
	virtual uintptr_t attachToBpf();                                               /* 0xEE8 */
	virtual uintptr_t configureIfnet();                                            /* 0xEF0 */
	virtual uintptr_t reset();                                                     /* 0xEF8 */
	virtual uintptr_t dupAndTransmitMcastPacket(IO80211NetworkPacket *,
	                                            unsigned char *,
	                                            unsigned char *);                  /* 0xF00 */
	virtual uintptr_t freeMulticastPacket(IO80211NetworkPacket *);                 /* 0xF08 */
	virtual uintptr_t triggerAWDLMulticastTx(unsigned int, unsigned char);         /* 0xF10 */
	virtual uintptr_t p2pMulticastTx(IO80211NetworkPacket **, unsigned int);       /* 0xF18 */
	virtual uintptr_t p2pMulticastTx(unsigned int, bool);                          /* 0xF20 */
	virtual uintptr_t signalMulticastPackets(unsigned int, unsigned int);          /* 0xF28 */
	virtual uintptr_t sendPendingPacketsToStack(IO80211NetworkPacket **,
	                                            unsigned int);                     /* 0xF30 */
	virtual uintptr_t freePendingPackets(IO80211NetworkPacket **, unsigned int);   /* 0xF38 */
	virtual uintptr_t setMacAddress(ether_addr &) = 0;                             /* 0xF40 pure */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface0();                         /* 0xF48 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface1();                         /* 0xF50 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface2();                         /* 0xF58 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface3();                         /* 0xF60 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface4();                         /* 0xF68 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface5();                         /* 0xF70 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface6();                         /* 0xF78 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface7();                         /* 0xF80 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface8();                         /* 0xF88 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface9();                         /* 0xF90 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface10();                        /* 0xF98 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface11();                        /* 0xFA0 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface12();                        /* 0xFA8 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface13();                        /* 0xFB0 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface14();                        /* 0xFB8 */
	virtual uintptr_t _RESERVEDIO80211VirtualInterface15();                        /* 0xFC0 */
private:
	uint8_t _nativeVirtualStorage[0x8];   /* kernel collection size 0x130: 0x128 + 0x8 */
};

/* 63 AWDL slots, 0xFC8-0x11B8, in vtable order (Docs/AWDL_PURE_SLOTS.md). */
class IO80211AWDLProtocol : public IO80211VirtualInterface {
	OSDeclareAbstractStructors(IO80211AWDLProtocol)
public:
	virtual IOReturn getSSID(apple80211_ssid_data *) = 0;                            /* 0xFC8 */
	virtual IOReturn getCHANNEL(apple80211_channel_data *) = 0;                      /* 0xFD0 */
	virtual IOReturn getBSSID(apple80211_bssid_data *) = 0;                          /* 0xFD8 */
	virtual IOReturn getSTATE(apple80211_state_data *) = 0;                          /* 0xFE0 */
	virtual IOReturn getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) = 0;         /* 0xFE8 */
	virtual IOReturn getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) = 0;       /* 0xFF0 */
	virtual IOReturn getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(
	    apple80211_awdl_extension_state_machine_parameter *) = 0;                    /* 0xFF8 */
	virtual IOReturn getAWDL_ELECTION_ID(apple80211_awdl_election_id *) = 0;         /* 0x1000 */
	virtual IOReturn getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) = 0; /* 0x1008 */
	virtual IOReturn getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
	    apple80211_awdl_sync_channel_sequence *) = 0;                                /* 0x1010 */
	virtual IOReturn getPEER_CACHE_MAXIMUM_SIZE(
	    apple80211_peer_cache_maximum_size *) = 0;                                   /* 0x1018 */
	virtual IOReturn getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) = 0;   /* 0x1020 */
	virtual IOReturn getAWDL_SYNC_STATE(apple80211_awdl_sync_state *) = 0;           /* 0x1028 */
	virtual IOReturn getAWDL_ELECTION_RSSI_THRESHOLDS(
	    apple80211_awdl_election_rssi_thresholds *) = 0;                             /* 0x1030 */
	virtual IOReturn getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) = 0;     /* 0x1038 */
	virtual IOReturn getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) = 0; /* 0x1040 */
	virtual IOReturn getAWDL_DEVICE_CAPABILITIES(
	    apple80211_awdl_device_capabilities *) = 0;                                  /* 0x1048 */
	virtual IOReturn getAWDL_SECONDARY_MASTER_CHANNEL(
	    apple80211_awdl_secondary_master_channel *) = 0;                             /* 0x1050 */
	virtual IOReturn getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) = 0;           /* 0x1058 */
	virtual IOReturn getAWDL_MIN_RATE(apple80211_awdl_min_rate *) = 0;               /* 0x1060 */
	virtual IOReturn getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) = 0;              /* 0x1068 */
	virtual IOReturn getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) = 0;       /* 0x1070 */
	virtual IOReturn getAWDL_DEV_STATS(apple80211_awdl_dev_stats *) = 0;             /* 0x1078 */
	virtual IOReturn getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) = 0;         /* 0x1080 */
	virtual IOReturn getAWDL_CCA(apple80211_awdl_cca *) = 0;                         /* 0x1088 */
	virtual IOReturn getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(
	    apple80211_awdl_cap *) = 0;                                                  /* 0x1090 */
	virtual IOReturn getLLW_PARAMS(apple80211_llw_params *) = 0;                     /* 0x1098 */
	virtual IOReturn setSSID(apple80211_ssid_data *) = 0;                            /* 0x10A0 */
	virtual IOReturn setCHANNEL(apple80211_channel_data *) = 0;                      /* 0x10A8 */
	virtual IOReturn setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) = 0;         /* 0x10B0 */
	virtual IOReturn setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) = 0;       /* 0x10B8 */
	virtual IOReturn setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(
	    apple80211_awdl_extension_state_machine_parameter *) = 0;                    /* 0x10C0 */
	virtual IOReturn setAWDL_ELECTION_ID(apple80211_awdl_election_id *) = 0;         /* 0x10C8 */
	virtual IOReturn setAWDL_BSSID(apple80211_awdl_bssid *) = 0;                     /* 0x10D0 */
	virtual IOReturn setAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) = 0; /* 0x10D8 */
	virtual IOReturn setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
	    apple80211_awdl_sync_channel_sequence *) = 0;                                /* 0x10E0 */
	virtual IOReturn setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) = 0;   /* 0x10E8 */
	virtual IOReturn setAWDL_SYNC_STATE(apple80211_awdl_sync_state *) = 0;           /* 0x10F0 */
	virtual IOReturn setAWDL_ELECTION_RSSI_THRESHOLDS(
	    apple80211_awdl_election_rssi_thresholds *) = 0;                             /* 0x10F8 */
	virtual IOReturn setAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) = 0;     /* 0x1100 */
	virtual IOReturn setPEER_CACHE_CONTROL(apple80211_peer_cache_control *) = 0;     /* 0x1108 */
	virtual IOReturn setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *) = 0;         /* 0x1110 */
	virtual IOReturn setAWDL_SYNC_FRAME_TEMPLATE(
	    apple80211_awdl_sync_frame_template *) = 0;                                  /* 0x1118 */
	virtual IOReturn setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) = 0; /* 0x1120 */
	virtual IOReturn setAWDL_PEER_TRAFFIC_REGISTRATION(
	    apple80211_awdl_peer_traffic_registration *) = 0;                            /* 0x1128 */
	virtual IOReturn setAWDL_SECONDARY_MASTER_CHANNEL(
	    apple80211_awdl_secondary_master_channel *) = 0;                             /* 0x1130 */
	virtual IOReturn setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) = 0;           /* 0x1138 */
	virtual IOReturn setAWDL_MIN_RATE(apple80211_awdl_min_rate *) = 0;               /* 0x1140 */
	virtual IOReturn setAWDL_ENCRYPTION_KEYS(apple80211_key *) = 0;                  /* 0x1148 */
	virtual IOReturn setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) = 0;              /* 0x1150 */
	virtual IOReturn setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *) = 0;    /* 0x1158 */
	virtual IOReturn setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) = 0;       /* 0x1160 */
	virtual IOReturn setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *) = 0;           /* 0x1168 */
	virtual IOReturn setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) = 0;         /* 0x1170 */
	virtual IOReturn setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *) = 0; /* 0x1178 */
	virtual IOReturn setCOMPANION_SKYWALK_IF_CREATE(
	    apple80211_companion_skywalk_if_create *) = 0;                               /* 0x1180 */
	virtual IOReturn setAWDL_OOB_SEC_PAYLOAD_REQUEST(
	    apple80211_awdl_af_sec_payload_request *) = 0;                               /* 0x1188 */
	virtual IOReturn setLLW_PARAMS(apple80211_llw_params *) = 0;                     /* 0x1190 */
	virtual IOReturn setTX_RATE(apple80211_tx_rate *) = 0;                           /* 0x1198 */
	virtual IOReturn setP2P_COEX_PROTECTION(apple80211_p2p_coex_protection *) = 0;   /* 0x11A0 */
	virtual IOReturn setPSF_DWELL(apple80211_awdl_psf_dwell_params *) = 0;           /* 0x11A8 */
	virtual IOReturn setAWDL_CONFIG(apple80211_awdl_config_request *) = 0;           /* 0x11B0 */
	virtual IOReturn setAWDL_RTG_PEER_STATS_CONFIG(
	    apple80211_rtg_peer_stats_cfg *) = 0;                                        /* 0x11B8 */
};

static_assert(sizeof(IO80211SkywalkInterface) == 0x128, "IO80211SkywalkInterface layout");
static_assert(sizeof(IO80211VirtualInterface) == 0x130, "IO80211VirtualInterface layout");
static_assert(sizeof(IO80211AWDLProtocol) == 0x130, "IO80211AWDLProtocol layout");


#endif
