/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef Rtw89LinuxBridge_hpp
#define Rtw89LinuxBridge_hpp

#include <stddef.h>
#include <stdint.h>

class Rtw89PciTransport;

struct Rtw89LinuxContext {
    typedef void (*ReceiveCallback)(void *, const uint8_t *, size_t,
                                    int32_t, uint16_t, bool, bool);
    typedef void (*TxResumeCallback)(void *);
    void *hardware;
    void *device;
    void *vif;
    void *station;
    size_t vifAllocationSize;
    size_t stationAllocationSize;
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

bool rtw89LinuxAttach(Rtw89PciTransport *transport,
                      Rtw89LinuxContext *context);
void rtw89LinuxDetach(Rtw89PciTransport *transport,
                      Rtw89LinuxContext *context);
bool rtw89LinuxPowerUp(Rtw89LinuxContext *context);
void rtw89LinuxPowerDown(Rtw89LinuxContext *context);

bool rtw89LinuxSetChannel(Rtw89LinuxContext *context, uint16_t channel);
bool rtw89LinuxPrepareConnection(Rtw89LinuxContext *context,
                                 const uint8_t bssid[6], uint16_t channel);
void rtw89LinuxScanBegin(Rtw89LinuxContext *context);
void rtw89LinuxScanEnd(Rtw89LinuxContext *context);
bool rtw89LinuxIsScanning(Rtw89LinuxContext *context);
bool rtw89LinuxAssociate(Rtw89LinuxContext *context,
                         const uint8_t bssid[6], uint16_t aid,
                         uint16_t capability, uint16_t channel,
                         uint16_t beaconInterval, uint8_t dtimPeriod,
                         bool qos, bool ht, bool vht, uint8_t rxNss);
void rtw89LinuxDisassociate(Rtw89LinuxContext *context);

enum Rtw89NativeCipher : uint8_t {
    Rtw89CipherWEP40,
    Rtw89CipherTKIP,
    Rtw89CipherCCMP,
    Rtw89CipherWEP104,
};

bool rtw89LinuxSetKey(Rtw89LinuxContext *context, uint8_t keyIndex,
                      Rtw89NativeCipher cipher, bool pairwise,
                      const uint8_t *key, size_t keyLength);
void rtw89LinuxDeleteKey(Rtw89LinuxContext *context, uint8_t keyIndex,
                         bool pairwise);
bool rtw89LinuxTransmit(Rtw89LinuxContext *context, const uint8_t *frame,
                        size_t length, bool management);
bool rtw89LinuxTxAvailable(Rtw89LinuxContext *context);
unsigned int rtw89LinuxTxAvailableSlots(Rtw89LinuxContext *context);
bool rtw89LinuxAmpduStart(Rtw89LinuxContext *context, uint8_t tid,
                          bool receive, uint16_t sequence, uint16_t window);
void rtw89LinuxAmpduStop(Rtw89LinuxContext *context, uint8_t tid,
                         bool receive);
bool rtw89LinuxConfigureQueue(Rtw89LinuxContext *context, uint8_t accessClass,
                              uint16_t cwMin, uint16_t cwMax, uint8_t aifs,
                              uint16_t txop);
void rtw89LinuxUpdateSlot(Rtw89LinuxContext *context, bool shortSlot);
void rtw89LinuxSetAllMulticast(Rtw89LinuxContext *context, bool enabled);

#endif /* Rtw89LinuxBridge_hpp */
