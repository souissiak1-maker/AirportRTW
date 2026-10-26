/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef Rtw88LinuxBridge_hpp
#define Rtw88LinuxBridge_hpp

#include <stddef.h>
#include <stdint.h>

class Rtw88PciTransport;

unsigned rtw88LinuxGetNSS(struct Rtw88LinuxContext *context);

struct Rtw88NativeCapabilities {
    uint16_t htCaps;
    uint8_t ampduParams;
    uint8_t htMCS[10];
    uint32_t vhtCaps;
    uint16_t vhtRxMCS;
    uint16_t vhtTxMCS;
    bool ht;
    bool vht;
};

struct Rtw88NativePeer {
    Rtw88NativeCapabilities caps;
    uint16_t widthMHz;
    uint16_t centerFrequency;
};

struct Rtw88LinuxContext {
    typedef void (*ReceiveCallback)(void *, const uint8_t *, size_t,
                                    int32_t, uint16_t, bool, bool);
    typedef void (*TxResumeCallback)(void *);
    void *hardware;
    void *device;
    void *vif;
    void *station;
    size_t vifAllocationSize;
    size_t stationAllocationSize;
    bool stationAdded;
    void *keys[12]; /* group 0..5, pairwise 6..11 */
    uint8_t macAddress[6];
    bool probed;
    bool started;
    bool interfaceAdded;
    bool allMulticast;
    bool scanning;
    uint16_t txAmpduMask;
    volatile uint64_t ampduTxStartCount;
    volatile uint64_t ampduTxStartFailCount;
    volatile uint64_t ampduTxStopCount;
    volatile uint64_t ampduRxStartCount;
    volatile uint64_t ampduRxStartFailCount;
    volatile uint64_t ampduRxStopCount;
    volatile uint32_t assocStageMask;
    volatile uint32_t raAuditU32[50];
    volatile uint64_t raAuditU64[1];
    volatile uint64_t authTxCount;
    volatile uint64_t authTxAckCount;
    volatile uint64_t assocTxCount;
    volatile uint64_t assocTxAckCount;
    volatile uint64_t authRxCount;
    volatile uint64_t assocRxCount;
    volatile uint64_t actionTxCount;
    volatile uint64_t actionTxAckCount;
    volatile uint64_t actionRxCount;
    volatile uint32_t lastActionTxCategory;
    volatile uint32_t lastActionTxCode;
    volatile uint32_t lastActionTxToken;
    volatile uint64_t lastAddbaTxBytes0To7;
    volatile uint32_t lastAddbaTxByte8;
    volatile uint32_t lastAddbaTxParams;
    volatile uint32_t lastAddbaTxTimeout;
    volatile uint32_t lastAddbaTxStartSeqControl;
    volatile uint32_t lastActionRxCategory;
    volatile uint32_t lastActionRxCode;
    volatile uint32_t lastActionRxToken;
    volatile uint32_t lastActionRxStatus;
    volatile uint64_t rxHardwareDecryptedCount;
    volatile uint64_t rxProtectedSoftwareCount;
    volatile uint64_t rxCCMPMICStrippedCount;
    volatile uint64_t rxConnectionProtectedCount;
    volatile uint64_t rxConnectionUndecryptedCount;
    volatile uint64_t rxConnectionInvalidCount;
    volatile uint64_t rxConnectionSNAPCount;
    volatile uint64_t rxConnectionDHCPCount;
    volatile uint64_t txAddressMismatchCount;
    volatile uint64_t dataTxCount;
    volatile uint64_t protectedTxCount;
    volatile uint64_t dhcpTxCount;
    volatile uint64_t dhcpTxAckCount;
    volatile uint64_t arpTxCount;
    volatile uint64_t arpTxAckCount;
    volatile uint32_t lastTxCipher;
    volatile uint32_t lastTxKeyIndex;
    volatile uint32_t lastTxIvLength;
    volatile uint64_t txDescDataCount;
    volatile uint32_t txDescUseRate;
    volatile uint32_t txDescDisableFallback;
    volatile uint32_t txDescHardwareRate;
    volatile uint32_t txDescBandwidth;
    volatile uint32_t txDescAggregationEnabled;
    volatile uint32_t txDescMacId;
    volatile uint32_t txDescQueueSelect;
    volatile uint64_t txReportCount;
    volatile uint32_t txReportStatus;
    volatile uint32_t txReportAttempts;
    void *nativeOwner;
    ReceiveCallback receive;
    TxResumeCallback txResume;
};

bool rtw88LinuxAttach(Rtw88PciTransport *transport,
                      Rtw88LinuxContext *context);
void rtw88LinuxDetach(Rtw88PciTransport *transport,
                      Rtw88LinuxContext *context);
bool rtw88LinuxPowerUp(Rtw88LinuxContext *context);
bool rtw88LinuxSetMacAddress(Rtw88LinuxContext *context, const uint8_t address[6]);
void rtw88LinuxPowerDown(Rtw88LinuxContext *context);

bool rtw88LinuxSetChannel(Rtw88LinuxContext *context, uint16_t channel);
bool rtw88LinuxPrepareConnection(Rtw88LinuxContext *context,
                                 const uint8_t bssid[6], uint16_t channel);
void rtw88LinuxScanBegin(Rtw88LinuxContext *context);
void rtw88LinuxScanEnd(Rtw88LinuxContext *context);
bool rtw88LinuxIsScanning(Rtw88LinuxContext *context);
bool rtw88LinuxGetCapabilities(Rtw88LinuxContext *context, bool fiveGHz,
                               Rtw88NativeCapabilities &caps);
bool rtw88LinuxAssociate(Rtw88LinuxContext *context,
                         const uint8_t bssid[6], uint16_t aid,
                         uint16_t capability, uint16_t channel,
                         uint16_t beaconInterval, uint8_t dtimPeriod,
                         bool qos, bool ht, bool vht, uint8_t rxNss,
                         const Rtw88NativePeer &peer);
void rtw88LinuxDisassociate(Rtw88LinuxContext *context);

enum Rtw88NativeCipher : uint8_t {
    Rtw88CipherWEP40,
    Rtw88CipherTKIP,
    Rtw88CipherCCMP,
    Rtw88CipherWEP104,
};

bool rtw88LinuxSetKey(Rtw88LinuxContext *context, uint8_t keyIndex,
                      Rtw88NativeCipher cipher, bool pairwise,
                      const uint8_t *key, size_t keyLength);
void rtw88LinuxDeleteKey(Rtw88LinuxContext *context, uint8_t keyIndex,
                         bool pairwise);
bool rtw88LinuxTransmit(Rtw88LinuxContext *context, const uint8_t *frame,
                        size_t length, bool management, bool softwareEncrypted = false);
bool rtw88LinuxTxAvailable(Rtw88LinuxContext *context);
unsigned int rtw88LinuxTxAvailableSlots(Rtw88LinuxContext *context);
bool rtw88LinuxAmpduStart(Rtw88LinuxContext *context, uint8_t tid,
                          bool receive, uint16_t sequence, uint16_t window);
void rtw88LinuxAmpduStop(Rtw88LinuxContext *context, uint8_t tid,
                         bool receive);
bool rtw88LinuxConfigureQueue(Rtw88LinuxContext *context, uint8_t accessClass,
                              uint16_t cwMin, uint16_t cwMax, uint8_t aifs,
                              uint16_t txop);
void rtw88LinuxUpdateSlot(Rtw88LinuxContext *context, bool shortSlot);
void rtw88LinuxSetAllMulticast(Rtw88LinuxContext *context, bool enabled);

#endif /* Rtw88LinuxBridge_hpp */
