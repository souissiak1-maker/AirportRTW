//
//  IO80211InfraInterface.h
//  itlwm
//
//  Created by qcwap on 2023/6/12.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IO80211InfraInterface_h
#define IO80211InfraInterface_h

struct apple80211_wcl_advisory_info;
struct apple80211_wcl_tx_rx_latency;

class IO80211InfraInterface : public IO80211SkywalkInterface {
    OSDeclareAbstractStructors(IO80211InfraInterface)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *, UInt, void *, void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *, UInt, void *, void *) APPLE_KEXT_OVERRIDE;
    virtual bool start(IOService *) APPLE_KEXT_OVERRIDE;
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams *, sockaddr_dl **) APPLE_KEXT_OVERRIDE;
    virtual IOReturn prepareBSDInterface(ifnet_t, UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn processBSDCommand(ifnet_t, UInt, void *) APPLE_KEXT_OVERRIDE;
    virtual void postMessage(UInt, void *, unsigned long) APPLE_KEXT_OVERRIDE;
    virtual IOReturn reportDataPathEvents(UInt, void *, unsigned long) APPLE_KEXT_OVERRIDE;
    virtual IOReturn recordOutputPacket(mbuf_traffic_class_t, int, int) APPLE_KEXT_OVERRIDE;
    virtual IOReturn recordInputPacket(int, int) APPLE_KEXT_OVERRIDE;
    virtual void logTxPacket(IOSkywalkNetworkPacket *, PacketSkywalkScratch *, mbuf_traffic_class_t, bool) APPLE_KEXT_OVERRIDE;
    virtual void logTxCompletionPacket(IOSkywalkNetworkPacket *, PacketSkywalkScratch *, mbuf_traffic_class_t, int, UInt, bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn inputPacket(IOSkywalkNetworkPacket *, packet_info_tag *, ether_header *) APPLE_KEXT_OVERRIDE;
    virtual SInt64 pendingPackets(unsigned char) APPLE_KEXT_OVERRIDE;
    virtual SInt64 packetSpace(unsigned char) APPLE_KEXT_OVERRIDE;
    virtual bool setLinkState(IO80211LinkState, UInt, bool debounceTimeout = 30, UInt code = 0) APPLE_KEXT_OVERRIDE;
    virtual IO80211LinkState linkState() APPLE_KEXT_OVERRIDE;
    virtual void setScanningState(UInt, bool, apple80211_scan_data *, int) APPLE_KEXT_OVERRIDE;
    virtual void setDataPathState(bool) APPLE_KEXT_OVERRIDE;
    virtual void updateLinkParameters(apple80211_interface_availability *) APPLE_KEXT_OVERRIDE;
    virtual void updateInterfaceCoexRiskPct(unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual void setLQM(unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual void updateLinkStatus() APPLE_KEXT_OVERRIDE;
    virtual void updateLinkStatusGated() APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report *) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceCCA(apple80211_channel, int) APPLE_KEXT_OVERRIDE;
    virtual void removePacketQueue(IO80211FlowQueueHash *) APPLE_KEXT_OVERRIDE;
    virtual void setDebugFlags(unsigned long long, UInt) APPLE_KEXT_OVERRIDE;
    virtual SInt64 debugFlags() APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceChipCounters(apple80211_stat_report *, apple80211_chip_counters_tx *, apple80211_chip_error_counters_tx *, apple80211_chip_counters_rx *) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceMIBdot11(apple80211_stat_report *, apple80211_ManagementInformationBasedot11_counters *) APPLE_KEXT_OVERRIDE;
    virtual void setFrameStats(apple80211_stat_report *, apple80211_frame_counters *) APPLE_KEXT_OVERRIDE;
    virtual SInt64 getWmeTxCounters(unsigned long long *) APPLE_KEXT_OVERRIDE;
    virtual void setEnabledBySystem(bool) APPLE_KEXT_OVERRIDE;
    virtual bool enabledBySystem() APPLE_KEXT_OVERRIDE;
    virtual bool willRoam(ether_addr *, UInt) APPLE_KEXT_OVERRIDE;
    virtual void setPeerManagerLogFlag(UInt, UInt, UInt) APPLE_KEXT_OVERRIDE;
    virtual void setWoWEnabled(bool) APPLE_KEXT_OVERRIDE;
    virtual bool wowEnabled() APPLE_KEXT_OVERRIDE;
    virtual UInt64 createLinkQualityMonitor(IO80211Peer *, IOService *) APPLE_KEXT_OVERRIDE;
    virtual void releaseLinkQualityMonitor(IO80211Peer *) APPLE_KEXT_OVERRIDE;
    virtual void setPoweredOnByUser(bool);
    /* Exact IO80211FamilyLegacy 1200.12.2b1 exports this concrete getter;
     * recovered as a direct, read-only byte access at object +0x3d0. */
    bool poweredOnByUser();
    
public:
    char _data[0x198];
};

#endif /* IO80211InfraInterface_h */
