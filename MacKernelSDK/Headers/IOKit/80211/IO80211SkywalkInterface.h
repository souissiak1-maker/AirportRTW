//
//  IO80211SkywalkInterface.h
//  IO80211Family
//
//  Created by 钟先耀 on 2019/10/18.
//  Copyright © 2019 钟先耀. All rights reserved.
//

#ifndef _IO80211SKYWALK_H
#define _IO80211SKYWALK_H

#include <Availability.h>
#include "IO80211Interface.h"
#include "IOSkywalkEthernetInterface.h"

// This is necessary, because even the latest Xcode does not support properly targeting 11.0.
#ifndef __IO80211_TARGET
#error "Please define __IO80211_TARGET to the requested version"
#endif

class TxSubmissionDequeueStats;
class TxCompletionEnqueueStats;
class IO80211NetworkPacket;
class IOSkywalkNetworkPacket;
class PacketSkywalkScratch;
typedef UInt64 IO80211FlowQueueHash;
class IO80211Peer;
class CCPipe;
class IO80211APIUserClient;
struct apple80211_wme_ac;
struct apple80211_interface_availability;
struct apple80211_cca_report;
struct apple80211_stat_report;
struct apple80211_chip_counters_tx;
struct apple80211_chip_counters_rx;
struct apple80211_chip_error_counters_tx;
struct apple80211_ManagementInformationBasedot11_counters;
struct apple80211_lteCoex_report;
struct apple80211_frame_counters;
struct userPrintCtx;
struct apple80211_lqm_summary;

struct TxPacketRequest {
    uint16_t    unk1;       // 0
    uint16_t    t;       // 2
    uint16_t    mU;       // 4
    uint16_t    mM;       // 6
    uint16_t    pkt_cnt;
    uint16_t    unk2;
    uint16_t    unk3;
    uint16_t    unk4;
    uint32_t    pad;
    mbuf_t      bufs[8];    // 18
    uint32_t    reqTx;
};

static_assert(sizeof(struct TxPacketRequest) == 0x60, "TxPacketRequest size error");

class IO80211SkywalkInterface : public IOSkywalkEthernetInterface {
    OSDeclareAbstractStructors(IO80211SkywalkInterface)

public:
    virtual bool init() APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *, UInt, void *, void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *, UInt, void *, void *) APPLE_KEXT_OVERRIDE;
    virtual bool start(IOService *) APPLE_KEXT_OVERRIDE;
    virtual const char *stringFromReturn(int);
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams *, sockaddr_dl **) APPLE_KEXT_OVERRIDE;
    virtual IOReturn prepareBSDInterface(ifnet_t, UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn processBSDCommand(ifnet_t, UInt, void *) APPLE_KEXT_OVERRIDE;
    virtual SInt32 setRunningState(bool) APPLE_KEXT_OVERRIDE;

    virtual void postMessage(UInt, void *, unsigned long);
    virtual IOReturn reportDataPathEvents(UInt, void *, unsigned long);
    virtual IOReturn recordOutputPacket(mbuf_traffic_class_t, int, int);
    virtual IOReturn recordInputPacket(int, int);
    virtual void logTxPacket(IOSkywalkNetworkPacket *, PacketSkywalkScratch *, mbuf_traffic_class_t, bool);
    virtual void logTxCompletionPacket(IOSkywalkNetworkPacket *, PacketSkywalkScratch *, mbuf_traffic_class_t, int, UInt, bool);
    virtual IOReturn inputPacket(IOSkywalkNetworkPacket *, packet_info_tag *, ether_header *);
    virtual SInt64 pendingPackets(unsigned char);
    virtual SInt64 packetSpace(unsigned char);
    virtual bool setLinkState(IO80211LinkState, UInt, bool debounceTimeout = 30, UInt code = 0);
    virtual IO80211LinkState linkState();
    virtual void setScanningState(UInt, bool, apple80211_scan_data *, int);
    virtual void setDataPathState(bool);
    virtual void updateLinkParameters(apple80211_interface_availability *);
    virtual void updateInterfaceCoexRiskPct(unsigned long long);
    virtual void setLQM(unsigned long long);
    virtual void updateLinkStatus();
    virtual void updateLinkStatusGated();
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report *);
    virtual void setInterfaceCCA(apple80211_channel, int);
    virtual void removePacketQueue(IO80211FlowQueueHash *);
    virtual void setDebugFlags(unsigned long long, UInt);
    virtual SInt64 debugFlags();
    virtual void setInterfaceChipCounters(apple80211_stat_report *, apple80211_chip_counters_tx *, apple80211_chip_error_counters_tx *, apple80211_chip_counters_rx *);
    virtual void setInterfaceMIBdot11(apple80211_stat_report *, apple80211_ManagementInformationBasedot11_counters *);
    virtual void setFrameStats(apple80211_stat_report *, apple80211_frame_counters *);
    virtual SInt64 getWmeTxCounters(unsigned long long *);
    virtual void setEnabledBySystem(bool);
    virtual bool enabledBySystem();
    virtual bool willRoam(ether_addr *, UInt);
    virtual void setPeerManagerLogFlag(UInt, UInt, UInt);
    virtual void setWoWEnabled(bool);
    virtual bool wowEnabled();
    virtual bool shouldLog(unsigned long long);
    virtual void logDebug(char const *, ...);
    virtual void logDebug(unsigned long long, char const *, ...);
    virtual void logDebugHex(void const *, unsigned long, char const *, ...);
    virtual void vlogDebug(unsigned long long, char const *, va_list);
    virtual void vlogDebugBPF(unsigned long long, char const *, va_list);
    virtual UInt64 createLinkQualityMonitor(IO80211Peer *, IOService *);
    virtual void releaseLinkQualityMonitor(IO80211Peer *);
    virtual void setNotificationProperty(OSSymbol const *, OSObject const *);
    virtual void *getWorkerMatchingDict(OSString *);
    virtual bool init(IOService *);
    virtual bool isInterfaceEnabled();
    virtual ether_addr *getSelfMacAddr();
    virtual void setSelfMacAddr(ether_addr *);
    virtual void *getBSSID();
    virtual void *getPacketPool(OSString *);
    virtual void *getLogger();
    virtual IOReturn handleSIOCSIFADDR();
    virtual IOReturn debugHandler(apple80211_debug_command *);
    
public:
    OSString *setInterfaceRole(UInt role);
    void *setInterfaceId(UInt id);
    int getInterfaceRole();
    
public:
    char _data[0x210];
};

#endif /* _IO80211SKYWALK_H */
