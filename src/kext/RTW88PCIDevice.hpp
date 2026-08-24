/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * RTW88PCIDevice.hpp — IOEthernetController subclass for PCIe rtw88 chips.
 *
 * Approach mirrors itlwm: present a transparent Ethernet interface to macOS
 * while doing 802.11 management internally.  The 802.11 state machine lives
 * in RTW88IEEE80211; this class handles IOKit life-cycle and the Ethernet
 * framing visible to macOS network stack.
 */
#pragma once

#include <IOKit/IOUserClient.h>
#include <IOKit/IOSharedDataQueue.h>

/* Pull in mbuf_t and related kernel types before any IOKit network headers */
#include <sys/kernel_types.h>

#ifdef RTW_AIRPORT
#include <IOKit/80211/Apple80211.h>
#include <IOKit/80211/IO80211InfraInterface.h>
#define RTW88ControllerBase IO80211Controller
#else
#include <IOKit/network/IOEthernetController.h>
#define RTW88ControllerBase IOEthernetController
#endif
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#ifdef RTW_AIRPORT
#include <kern/thread.h>
#endif

/* Forward declarations */
class RTW88IEEE80211;
class RTW88UserClient;
struct RTW88StateResult;
struct RTW88SyntheticAssociateArgs;
class RTW89Net80211Core;
class RTW88PCIDevice;
class AirportRTW89Interface;

#ifdef RTW_AIRPORT
/* Sonoma and later bind the native Wi-Fi secured-control service to a
 * WiFiDriver whose provider is a PCI wrapper, rather than to a controller
 * matched directly on IOPCIDevice.  Keep the wrapper deliberately small: it
 * owns only the provider relationship and exposes the real PCI nub to the
 * RTW89 controller. */
class AirportRTW89PCIWrapper : public IOService {
    OSDeclareDefaultStructors(AirportRTW89PCIWrapper)

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOPCIDevice *pciDevice() const { return _pciDevice; }

private:
    IOPCIDevice *_pciDevice = nullptr;
};

/* CHANNELS_INFO ABI mirror shared by the virtual/AWDL surface and the 0.3.8
 * Tahoe primary-en2 compatibility bridge.  Keep the mirror local so that the
 * legacy target does not import the IO80211FAMILY_V2 protocol surface. */
struct AirportRTW89ChannelsInfoData {
    UInt32 version;
    UInt32 unknown1;
    UInt16 num_chan_specs;
    UInt16 chan_spec[128];
    UInt8  chan_num[128];
    UInt8  indoor_restric[128];
    UInt8  radar_dfs[128];
    UInt8  passive[128];
    UInt8  support_40Mhz[128];
    UInt8  support_80Mhz[128];
    UInt8  unknown_flags[128];
    UInt8  pad[386];
    UInt32 per_chan[128];
    UInt32 chan_bitmap[128];
} __attribute__((packed));
static_assert(sizeof(AirportRTW89ChannelsInfoData) == 0xA0C,
              "Tahoe CHANNELS_INFO payload size mismatch");
static_assert(offsetof(AirportRTW89ChannelsInfoData, chan_num) == 0x10A,
              "Tahoe CHANNELS_INFO chan_num offset mismatch");
static_assert(offsetof(AirportRTW89ChannelsInfoData, support_40Mhz) == 0x30A,
              "Tahoe CHANNELS_INFO 40MHz offset mismatch");
static_assert(offsetof(AirportRTW89ChannelsInfoData, support_80Mhz) == 0x38A,
              "Tahoe CHANNELS_INFO 80MHz offset mismatch");

/* Concrete controller-attach Skywalk control service.  It owns no BSD/data
 * path.  Any overrides below reuse existing ABI slots and deliberately keep
 * link/peer-monitor state off this object. */
class AirportRTW89SkywalkControlInterface : public IO80211InfraInterface {
    OSDeclareDefaultStructors(AirportRTW89SkywalkControlInterface)

public:
    using RegistrationInfo = IO80211SkywalkInterface::RegistrationInfo;
#ifdef IO80211FAMILY_V2
    bool init(IOService *provider) override;
#endif
    bool initAsControlService(RTW88PCIDevice *controller,
                              AirportRTW89Interface *interface);
    /* 0.2.128: control-only identity bridge.  This object deliberately has
     * no BSD ifnet, so IOSkywalkNetworkInterface's native BSD-name getters
     * cannot resolve a name from an attached interface.  Override only the
     * existing inherited getter slots and answer from the enX identity that
     * the deferred probe already published as registry properties. */
    const char *getBSDName(void) const override;
    const char *getBSDNamePrefix(void) override;
    UInt getBSDUnitNumber(void) override;
    /* 0.2.158: this object is control-only.  A Skywalk link transition/LQM
     * update can arm IO80211PeerManager monitoring, but this non-BSD object
     * never owns the peer/data-path objects that monitor expects.  Acknowledge
     * link-state writes and ignore LQM without entering Apple's peer machinery. */
    bool setLinkState(IO80211LinkState state, UInt reason,
                      bool debounceTimeout = 30, UInt code = 0) override;
    void setLQM(unsigned long long lqm) override;
    /* 0.2.137-0.2.139: trace/directly serve native Skywalk user-client opens through
     * Apple's inherited Skywalk user-client slot.  This overrides an
     * inherited slot only; it adds no vtable entry and does not start or
     * activate the Skywalk data path. */
    IOReturn newUserClient(task_t owningTask, void *securityID, UInt32 type,
                           OSDictionary *properties,
                           IOUserClient **handler) override;
    /* Version-pinned ABI for the restored IOSkywalkFamily image used by the
     * target system (UUID 035A9AD9-6CDE-362F-8DEC-B664BC6431EC).  The outer
     * expansion offsets were verified from that exact binary; do not replace
     * these with the recovered C++ members unless that binary changes. */
    static constexpr size_t kNetworkExpansionOffset = 0xc0;
    static constexpr size_t kEthernetExpansionOffset = 0x108;
    static constexpr size_t kExpansionRegistrationOffset = 0x0;
    /* Exact IOSkywalkFamily 035A9AD9... disassembly:
     *   IOSkywalkNetworkInterface::prepareBSDInterface +0x0c:
     *       expansion = *(this + 0xc0)
     *       expansion->+0x08 = ifnet
     *       registration = expansion->+0x00
     *       mtu = *(registration + 0x4c)
     * The Ethernet expansion at +0x108 also has its RegistrationInfo at +0,
     * but +0x08 is NOT a second BSD-ifnet slot. */
    static constexpr size_t kExpansionBSDInterfaceOffset = 0x8;
    static constexpr size_t kNetworkRegistrationCopySize = 0x108;
    static constexpr size_t kRegistrationInfoSize = 0x130;
    /* Exact IO80211FamilyLegacy 1200.12.2b1 IO80211SkywalkInterface::start:
     * successful Infrastructure-role start stores a non-null postMessage
     * context at object +0x110 and the controller-side request object at
     * +0x118. These are READ-ONLY diagnostics; never write through them. */
    static constexpr size_t kPostMessageContextOffset = 0x110;
    static constexpr size_t kControllerRequestObjectOffset = 0x118;
    /* Exact IO80211FamilyLegacy 1200.12.2b1:
     * IO80211SkywalkInterface::setRunningState(bool) writes its boolean state
     * directly at object +0x1d8 and returns 0.  Read-only diagnostics may
     * inspect this byte; never write it directly. */
    static constexpr size_t kSkywalkRunningStateOffset = 0x1d8;
    /* Exact IO80211FamilyLegacy 1200.12.2b1:
     * IO80211SkywalkInterface::setLinkState(...) stores the IO80211LinkState
     * value at object +0x1dc after issuing an ifnet_event. This field is
     * read-only diagnostic state; never write it directly. */
    static constexpr size_t kSkywalkLinkStateOffset = 0x1dc;
    /* Exact IOSkywalkFamily reportLinkStatus(status, media) reads/writes these
     * fields in the network expansion at object+0xc0. +0x18 is the internal
     * synchronization/event context used by the method; +0x38 caches the
     * active media type and +0x40 caches link status. Read-only diagnostics
     * only; never write these fields directly. */
    static constexpr size_t kNetworkExpansionReportContextOffset = 0x18;
    static constexpr size_t kNetworkExpansionMediaTypeOffset = 0x38;
    static constexpr size_t kNetworkExpansionReportedLinkStatusOffset = 0x40;

    void *rawNetworkExpansion() const {
        return *(void * const *)((const UInt8 *)this + kNetworkExpansionOffset);
    }
    void *rawEthernetExpansion() const {
        return *(void * const *)((const UInt8 *)this + kEthernetExpansionOffset);
    }
    void **rawNetworkRegistrationSlot() const {
        void *expansion = rawNetworkExpansion();
        return expansion ? (void **)((UInt8 *)expansion + kExpansionRegistrationOffset)
                         : nullptr;
    }
    void **rawEthernetRegistrationSlot() const {
        void *expansion = rawEthernetExpansion();
        return expansion ? (void **)((UInt8 *)expansion + kExpansionRegistrationOffset)
                         : nullptr;
    }
    ifnet_t *rawNetworkBSDInterfaceSlot() const {
        void *expansion = rawNetworkExpansion();
        return expansion ? (ifnet_t *)((UInt8 *)expansion + kExpansionBSDInterfaceOffset)
                         : nullptr;
    }
    void *rawPostMessageContext() const {
        return *(void * const *)((const UInt8 *)this + kPostMessageContextOffset);
    }
    void *rawControllerRequestObject() const {
        return *(void * const *)((const UInt8 *)this + kControllerRequestObjectOffset);
    }
    bool rawSkywalkRunningState() const {
        return *(const UInt8 *)((const UInt8 *)this + kSkywalkRunningStateOffset) != 0;
    }
    UInt32 rawSkywalkLinkState() const {
        return *(const UInt32 *)((const UInt8 *)this + kSkywalkLinkStateOffset);
    }
    void *rawNetworkReportContext() const {
        void *expansion = rawNetworkExpansion();
        return expansion ? *(void **)((UInt8 *)expansion + kNetworkExpansionReportContextOffset)
                         : nullptr;
    }
    UInt32 rawNetworkReportedMediaType() const {
        void *expansion = rawNetworkExpansion();
        return expansion ? *(const UInt32 *)((const UInt8 *)expansion + kNetworkExpansionMediaTypeOffset)
                         : 0;
    }
    UInt32 rawNetworkReportedLinkStatus() const {
        void *expansion = rawNetworkExpansion();
        return expansion ? *(const UInt32 *)((const UInt8 *)expansion + kNetworkExpansionReportedLinkStatusOffset)
                         : 0;
    }

    /* Retained only as a diagnostic comparison with the known-bad recovered
     * header layout.  No 0.2.73 write is allowed through these members. */
    void *typedNetworkExpansion() const { return mExpansionData; }
    void *typedEthernetExpansion() const { return mExpansionData2; }
};

/* BSD companion required by the modern IO80211/Skywalk control topology.
 * The proven AirportRTW89Interface remains the Realtek data-path owner; this
 * companion exists so IOSkywalkFamily can bind a real ifnet to the primary
 * IO80211InfraInterface and construct IO80211APIUserClient. */
class AirportRTW89SkywalkBSDInterface : public IO80211Interface {
    OSDeclareDefaultStructors(AirportRTW89SkywalkBSDInterface)

public:
    bool initWithSkywalkInterfaceAndProvider(
        IONetworkController *controller,
        IO80211SkywalkInterface *interface);
    IOReturn attachToDataLinkLayer(IOOptionBits options,
                                   void *parameter) override;
    void detachFromDataLinkLayer(IOOptionBits options,
                                 void *parameter) override;
    SInt32 performCommand(IONetworkController *controller, unsigned long command,
                          void *arg0, void *arg1) override;
    IOReturn newUserClient(task_t owningTask, void *securityID, UInt32 type,
                           OSDictionary *properties,
                           IOUserClient **handler) override;
    IOService *getProvider(void) const override;

private:
    IO80211SkywalkInterface *_skywalk = nullptr;
    bool _dataLinkAttached = false;
    bool _nativeType0FactoryUseBaseProvider = false;
    UInt32 _nativeUserClientHistorySequence = 0;
};

#endif

/* Non-BSD endpoint for IO80211Old's type-0 service open.  It attaches to the
 * existing legacy interface as an IOService child only; it never creates or
 * registers an IONetworkInterface and therefore cannot claim another enX. */
/* Tahoe's IO80211Old path still resolves this historical metaclass by its
 * exact name even though IO80211Family no longer publishes it.  Supplying the
 * compatibility endpoint under that identity lets the inherited type-0 open
 * complete instead of falling through solely because the class is absent. */
class AirportRTW89APIUserClient : public IOUserClient {
    OSDeclareDefaultStructors(AirportRTW89APIUserClient)

public:
    bool initWithTaskAndOwner(task_t owningTask, void *securityID, UInt32 type,
                              OSDictionary *properties,
                              RTW88PCIDevice *owner);
    void free() override;
    IOReturn clientClose() override;
    IOReturn registerNotificationPort(mach_port_t port, UInt32 type,
                                      io_user_reference_t refCon) override;
    IOReturn clientMemoryForType(UInt32 type, IOOptionBits *options,
                                 IOMemoryDescriptor **memory) override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args,
                            IOExternalMethodDispatch *dispatch,
                            OSObject *target, void *reference) override;

private:
    RTW88PCIDevice *_owner = nullptr;
    IOSharedDataQueue *_eventQueue = nullptr;
    IOBufferMemoryDescriptor *_eventRingState = nullptr;
};

/* Tahoe airportd's sandbox accepts the Apple API-client identity used by
 * IO80211Old, but rejects a functionally equivalent custom class after the
 * provider factory returns it. The restored Ventura legacy image does not
 * publish this metaclass, so supply a thin identity alias over our endpoint. */
class IO80211APIUserClient : public AirportRTW89APIUserClient {
    OSDeclareDefaultStructors(IO80211APIUserClient)
};

/* Match IO80211Reference 2.3.0's Ventura legacy interface layout.  The
 * two-argument initializer is a driver helper, not an override of
 * IO80211Interface::init.  Tahoe with the restored Ventura family rejects the
 * inherited Type-0 factory, so newUserClient preserves the inherited result
 * first and supplies the Apple-named compatibility endpoint only for that
 * exact unsupported Type-0 case. */
class AirportRTW89Interface : public IO80211Interface {
    OSDeclareDefaultStructors(AirportRTW89Interface)

public:
    IOReturn newUserClient(task_t owningTask, void *securityID, UInt32 type,
                           OSDictionary *properties,
                           IOUserClient **handler) override;
    /* Ventura IO80211Reference parity: this is the controller's sole BSD
     * infrastructure interface.  Tahoe otherwise classifies en2 as
     * non-primary even though no second AirportRTW BSD interface exists,
     * which prevents the inherited native type-0 path from treating it as
     * the station control endpoint. */
    bool isPrimaryInterface(void) const override;

    SInt32 performCommand(IONetworkController *controller,
                          unsigned long command, void *arg0,
                          void *arg1) override;
    /* 0.2.197 diagnostic: observe the inherited return-to-errno mapping at
     * the interface boundary without changing the mapping itself. */
    int errnoFromReturn(int rtn) override;
    UInt32 inputPacket(mbuf_t packet, UInt32 length = 0,
                       IOOptionBits options = 0,
                       void *parameter = nullptr) override;
    /* 0.2.171 diagnostic: observe framework user-power writes before the
     * inherited IO80211Interface setter applies them.  Driver-owned transport
     * pins bypass this override through pinAirportTransportUserPowerOn(). */
    void setPoweredOnByUser(bool value) override;
    /* 0.2.172 diagnostic: independently observe framework system-enable
     * writes. Driver-owned transport pins bypass this override through
     * pinAirportTransportSystemEnableOn(). */
    void setEnabledBySystem(bool value) override;
    bool init(IO80211Controller *controller, RTW88PCIDevice *owner);

private:
    friend class RTW88PCIDevice;

    /* 0.2.246: non-virtual compatibility body.  Lifecycle SET22/SET20 are
     * handled by the thin public performCommand() wrapper so deep association
     * work never runs underneath this historically large Tahoe shim frame. */
    SInt32 performCommandCompatBody(IONetworkController *controller,
                                    unsigned long command, void *arg0,
                                    void *arg1);
    /* 0.2.253: prepare the proven outer POWER/19 state in a separate
     * non-virtual helper.  The helper returns before Apple's inherited
     * performCommand() is entered, so the POWER callback cannot run beneath
     * the historical ~9.5 KiB compatibility frame. */
    bool prepareStackSafeOuterPowerSet(SInt32 reqVal, UInt32 reqLen,
                                       user_addr_t reqData,
                                       bool *requestedOn, bool *changed,
                                       IOReturn *applyResult);

    RTW88PCIDevice *_owner = nullptr;

    /* 0.2.217 IO80211Reference/Tahoe routing-parity probe.
     *
     * IO80211Interface::performCommand() is synchronous for the legacy
     * Apple80211 marshaller, but Tahoe also drives unrelated GET traffic on
     * several threads.  Keep a tiny request-scoped table keyed by thread so
     * the controller-side apple80211Request() callback can acknowledge the
     * exact outer request without relying on a racy global "last request".
     * This is diagnostic state only; it is not exposed to Apple and does not
     * alter the vtable or any request return value. */
    struct IO80211ReferenceParityScope {
        thread_t thread = THREAD_NULL;
        UInt32 sequence = 0;
        SInt32 outerRequestType = -1;
        bool outerIsSet = false;
        bool active = false;
        bool dispatcherEntered = false;
        unsigned int dispatcherRawRequestType = 0;
        int dispatcherRawRequestNumber = 0;
        UInt32 dispatcherNormalizedRequest = 0;
        bool dispatcherIsGet = false;
        SInt32 dispatcherReturn = kIOReturnNotReady;
    };
    IO80211ReferenceParityScope _io80211ReferenceParityScopes[16] = {};
    volatile UInt32 _io80211ReferenceParitySequence = 0;

    /* 0.2.198 request-scoped native GET11 marshaller probe state.
     * 0.2.199 leaves these fields dormant: Tahoe returned 16 before entering
     * the controller, so the native GET11 probe is no longer armed. */
    volatile bool _get11NativeProbeActive = false;
    thread_t _get11NativeProbeThread = THREAD_NULL;
    volatile bool _get11NativeProbeEnteredInner = false;
    volatile SInt32 _get11NativeProbeInnerReturn = kIOReturnNotReady;
    apple80211_scan_result *_get11NativeProbeResult = nullptr;
    SInt16 _get11NativeProbeOriginalRSSI = 0;
    UInt32 _get11NativeProbeOriginalAge = 0;
    volatile bool _get11NativeProbeMarkerApplied = false;

};

/* RTW88PCIDevice --------------------------------------------------------- */
class RTW88PCIDevice : public RTW88ControllerBase {
    OSDeclareDefaultStructors(RTW88PCIDevice)

    friend class RTW88UserClient;
    friend class RTW88IEEE80211;
#ifdef RTW_AIRPORT
    friend class AirportRTW89SkywalkControlInterface;
    friend class AirportRTW89SkywalkBSDInterface;
    friend class AirportRTW89Interface;
    friend class AirportRTW89APIUserClient;
#endif

public:
    /* IOService */
    bool     init(OSDictionary *props) override;
    bool     start(IOService *provider) override;
    void     stop(IOService *provider) override;
    void     free() override;
    void     systemWillShutdown(IOOptionBits specifier) override;
    IOReturn powerStateWillChangeTo(IOPMPowerFlags flags, unsigned long state,
                                     IOService *actor) override;
#ifdef RTW_AIRPORT
    /* 0.2.51: IOKit PM registration/state probe. */
    IOReturn registerWithPolicyMaker(IOService *policyMaker) override;
    IOReturn setPowerState(unsigned long powerStateOrdinal,
                           IOService *whatDevice) override;
#endif

    /* IONetworkController */
    const OSString *newVendorString() const override;
    const OSString *newModelString() const override;
    IOReturn enable(IONetworkInterface *iface) override;
    IOReturn disable(IONetworkInterface *iface) override;
    IOReturn setMaxPacketSize(UInt32 maxSize) override;
    IOReturn getMaxPacketSize(UInt32 *maxSize) const override;
    IOReturn selectMedium(const IONetworkMedium *medium) override;
    bool     configureInterface(IONetworkInterface *iface) override;
    UInt32   outputPacket(mbuf_t m, void *param) override;
    /* Provide a gated output queue so outputPacket() is serialized through the
     * work loop.  Without this the stack calls outputPacket() concurrently,
     * racing rtw_pci_tx_write_data's BD fill (which reads ring->r.wp before the
     * irq_lock) and leaving a zeroed descriptor that stalls the TX DMA engine. */
    IOOutputQueue *createOutputQueue() override;

    /* IOEthernetController */
    IOReturn getHardwareAddress(IOEthernetAddress *addr) override;
    IOReturn setHardwareAddress(const IOEthernetAddress *addr) override;
    IOReturn setMulticastMode(bool active) override;
    IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count) override;
    IOReturn setPromiscuousMode(bool active) override;
    IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    /* Match IO80211Reference's controller feature advertisement. */
    UInt32 getFeatures() const override;

#ifdef RTW_AIRPORT
    /* IO80211Controller — native AirPort frontend.  AirportRTW89Interface is
     * the one and only BSD/ifnet frontend.  The Skywalk control interface is
     * non-BSD and is never returned from createInterface(). */
    IONetworkInterface *createInterface(void) override;
    IOReturn enable(IO80211SkywalkInterface *interface) override;
    IOReturn disable(IO80211SkywalkInterface *interface) override;
    SInt32 apple80211Request(unsigned int requestType, int requestNumber,
                             IO80211Interface *interface, void *data);
    /* 0.2.208: narrow primary-STA GET11 controller marshaller hook. */
    SInt32 apple80211_ioctl_get(IO80211Interface *interface,
                                IO80211VirtualInterface *virtualInterface,
                                ifnet_t net, void *data) override;
    /* Sonoma/Skywalk surface used by IO80211Reference: observe/delegate the
     * framework ioctl and keep SkywalkRequest unsupported exactly as upstream. */
    SInt32 apple80211_ioctl(IO80211SkywalkInterface *interface,
                            unsigned long command, void *data) override;
    SInt32 apple80211SkywalkRequest(UInt requestType, int requestNumber,
                                    IO80211SkywalkInterface *interface,
                                    void *data) override;
#ifdef IO80211FAMILY_V2
    SInt32 apple80211SkywalkRequest(UInt requestType, int requestNumber,
                                    IO80211SkywalkInterface *interface,
                                    void *data, void *context) override;
    bool isCommandProhibited(int command) override { (void)command; return false; }
    SInt32 handleCardSpecific(IO80211SkywalkInterface *interface,
                              unsigned long command, void *data,
                              bool isGet) override;
    IOReturn getDRIVER_VERSION(IO80211SkywalkInterface *,
                               apple80211_version_data *) override;
    IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface *,
                                 apple80211_version_data *) override;
    IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *,
                                  apple80211_capability_data *) override;
    IOReturn getPOWER(IO80211SkywalkInterface *, apple80211_power_data *) override;
    IOReturn setPOWER(IO80211SkywalkInterface *, apple80211_power_data *) override;
    IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface *,
                             apple80211_country_code_data *) override;
    IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface *,
                             apple80211_country_code_data *) override;
    IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface *,
                               apple80211_debug_command *) override;
#endif
    bool requiresExplicitMBufRelease() override { return false; }
    bool flowIdSupported() override { return false; }
    /* 0.2.103: expose the same virtual-interface entry points used by
     * IO80211Reference.  The RTW89 port currently emulates the Apple80211/AWDL
     * control contract; hardware-backed AWDL data path work remains separate. */
    SInt32 enableVirtualInterface(IO80211VirtualInterface *interface) override;
    SInt32 disableVirtualInterface(IO80211VirtualInterface *interface) override;
    IO80211VirtualInterface *createVirtualInterface(ether_addr *address,
                                                     UInt role) override;
    SInt32 apple80211VirtualRequest(UInt requestType, int requestNumber,
                                    IO80211VirtualInterface *interface,
                                    void *data) override;
    /* 0.2.55: observe the legacy IO80211 frontend's final data-link attach
     * callback and re-notify power only after Apple's base implementation has
     * finished initializing the interface/scan-manager side. */
    void dataLinkLayerAttachComplete(IO80211Interface *interface);
#ifdef IO80211FAMILY_V2
    void dataLinkLayerAttachComplete() override;
#endif
    IOWorkLoop *getWorkLoop() const override { return _workLoop; }
    IOService *getProvider() const override { return _pciDev; }
    IOOutputQueue *getOutputQueue() const override;
    bool createWorkLoop() override;
    SInt32 stopDMA();
    UInt32 hardwareOutputQueueDepth(IO80211Interface *interface);
#ifdef IO80211FAMILY_V2
    UInt32 hardwareOutputQueueDepth() override;
#endif
    /* 0.2.30: observe the IO80211-family transmit request path. */
    void requestPacketTx(void *request, UInt count) override;
    UInt32 getDataQueueDepth(OSObject *object) override;
    SInt32 performCountryCodeOperation(IO80211Interface *interface,
                                        IO80211CountryCodeOp operation);
#ifdef IO80211FAMILY_V2
    SInt32 performCountryCodeOperation(IO80211CountryCodeOp operation) override;
#endif
    SInt32 enableFeature(IO80211FeatureCode feature, void *data) override;
    bool useAppleRSNSupplicant(IO80211Interface *interface) override;
    bool useAppleRSNSupplicant(IO80211VirtualInterface *interface) override;
    IOReturn getHardwareAddressForInterface(IO80211Interface *interface,
                                             IOEthernetAddress *address);
#ifdef IO80211FAMILY_V2
    IOReturn getHardwareAddressForInterface(IOEthernetAddress *address) override;
#endif
    void inputMonitorPacket(mbuf_t packet, UInt32 channel, void *metadata,
                            unsigned long metadataLength);
    SInt32 monitorModeSetEnabled(IO80211Interface *interface, bool enabled,
                                 UInt flags);
#ifdef IO80211FAMILY_V2
    SInt32 monitorModeSetEnabled(bool enabled, UInt flags) override;
#endif
    IO80211Interface *getNetworkInterface() override;

    /* 0.2.84: explicit userspace-triggered prepareBSDInterface() probe after
     * exact-binary-guided pre-seeding of both RegistrationInfo pointers. */
    IOReturn runSkywalkManualPrepareProbe();
    IOReturn runSkywalkManualDeferProbe();
    IOReturn runSkywalkManualStartProbe();
    IOReturn runSkywalkManualEnableProbe();
    IOReturn runSkywalkManualUserPowerProbe();
    IOReturn runSkywalkManualPowerNotifyProbe();
    IOReturn runSkywalkManualBSDLinkProbe();
    IOReturn runSkywalkManualRunningProbe();
    IOReturn runSkywalkManualPrivateLinkProbe();
    IOReturn runSkywalkManualReportLinkProbe();
    IOReturn runSkywalkManualControllerPowerProbe();
#endif

    /* IOUserClient creation */
    IOReturn newUserClient(task_t owningTask, void *securityID,
                           UInt32 type, OSDictionary *properties,
                           IOUserClient **handler) override;

    /* Called from interrupt handler */
    void handleInterrupt(IOInterruptEventSource *src, int count);

    /* Resume a flow-control-stalled output queue once the IRQ bottom-half has
     * freed BE ring slots.  Called via a C trampoline from the compat layer. */
    void resumeTxIfStalled();

    /* Called from RTW88IEEE80211 to deliver RX frames to macOS */
    void injectRxFrame(mbuf_t m);
    /* The workloop the RX/interrupt path runs on. RTW88IEEE80211 attaches its
     * RX reorder flush timer here so all frame delivery is serialized on one
     * thread (injectRxFrame's queue+flush is not safe against concurrent
     * callers). */
    IOWorkLoop *getRxWorkLoop() const { return _workLoop; }
    /* Allocate an input mbuf via the IONetworkController allocator (sets
     * m_len and pkthdr.len consistently — required for inputPacket). */
    mbuf_t allocateInputPacket(uint32_t len);

    /* DMA helpers — used by Linux compat dma_alloc_coherent */
    void *allocCoherent(size_t size, IOPhysicalAddress *phys);
    void  freeCoherent(size_t size, void *virt, IOPhysicalAddress phys);
    void  freeCoherentByPhys(IOPhysicalAddress phys);
    /* Bounce buffer helpers for dma_map_single / dma_sync_single_for_cpu */
    void  setBounceOrigVA(IOPhysicalAddress phys, void *orig_va);
    void  syncBounceForCpu(IOPhysicalAddress dma, size_t size);

    /* PCI config space — used by Linux compat pci_read/write_config_* */
    UInt8  pciReadByte(int offset);
    UInt16 pciReadWord(int offset);
    UInt32 pciReadDword(int offset);
    void   pciWriteByte(int offset, UInt8 val);
    void   pciWriteWord(int offset, UInt16 val);
    void   pciWriteDword(int offset, UInt32 val);
    int    pciFindCapability(int cap);

    /* 802.11 state machine accessors */
    RTW88IEEE80211 *get80211() { return _ieee80211; }
    RTW89Net80211Core *getNet80211() { return _net80211; }
#ifdef RTW_AIRPORT
    /* 0.3.8: shared canonical CHANNELS_INFO builder is intentionally public
     * to the legacy interface marshaller; it is read-only capability
     * publication and does not mutate radio/association state. */
    void airportFillChannelsInfo(AirportRTW89ChannelsInfoData *data) const;
    /* 0.3.11: private rtw88ctl-only diagnostic.  This does not forge an outer
     * Apple ioctl; it invokes the same airportSet(ASSOCIATE) implementation
     * with an explicitly supplied SSID/BSSID and no credential bytes. */
    IOReturn airportSyntheticAssociateDiagnostic(
        const RTW88SyntheticAssociateArgs &args);
#endif

    /* MMIO base — used by compat ioremap shim */
    volatile void *mmioBase() const { return _mmioBase; }

    /* Persist the startup stage on the PCI provider.  The provider remains in
     * IORegistry even when start() fails and the controller child detaches, so
     * this survives failures that happen before registerService(). */
    void setBringupStage(const char *stage, SInt32 code = 0);

private:
    bool     attachDevice();
    void     recoverPCIForBoot(IOPCIDevice *pciDev);
    bool     setupInterrupt();
    bool     setupDMA();
    void     teardown();
    const char *chipDisplayName() const;
    void     publishHardwareIdentity();

    bool     setupMediumDict();
    void     addMedium(OSDictionary *mediums, IOMediumType type, UInt64 speed);

    static void interruptOccurred(OSObject *owner,
                                   IOInterruptEventSource *src, int count);

    void debugTimerFired(IOTimerEventSource *src);

#ifdef RTW_AIRPORT
    void publishSkywalkExpansionCheckpoint(
        AirportRTW89SkywalkControlInterface *interface,
        const char *networkKey, const char *ethernetKey,
        const char *agreementKey);
    bool createAndAttachSkywalkPrimaryInterface();
    bool preseedSkywalkRegistrationCopies(
        const AirportRTW89SkywalkControlInterface::RegistrationInfo &registrationInfo);
    void publishSkywalkPowerState(const char *stage);
    void synchronizeAirportPowerState(IONetworkInterface *iface);
    void pinAirportTransportUserPowerOn(IO80211Interface *interface);
    void pinAirportTransportSystemEnableOn(IO80211Interface *interface);
    enum AirportLogicalPowerSource : UInt32 {
        kAirportLogicalPowerApple80211 = 1,
        kAirportLogicalPowerControllerEnable = 2,
        kAirportLogicalPowerControllerDisable = 3,
        kAirportLogicalPowerOuterApple80211 = 4,
        kAirportLogicalPowerFrameworkUserLatch = 5,
    };
    /* Persistent IO80211Reference-style user-visible Wi-Fi power state.
     * Only valid Apple80211 POWER SET radio data changes it; controller
     * lifecycle callbacks and the always-live IO80211 transport do not. */
    bool setAirportLogicalPowerState(bool on, AirportLogicalPowerSource source);
    IOReturn applyAirportUserPowerState(bool on, AirportLogicalPowerSource source);
    /* 0.2.52 diagnostic: reassert only IO80211 power bits after the
     * Apple80211 POWER SET wrapper has returned.  Deliberately does not
     * touch link state so an established association cannot be torn down. */
    void relatchAirportPowerStatePostReturn();
    /* 0.2.29: publish IO80211 carrier state directly from association and
     * disconnect paths.  Polling remains a fallback, not the sole edge source. */
    void airportPublishLinkState(bool up, SInt32 rssi, bool rsnComplete);
    bool airportRefreshCountryCode(const char *reason, bool notifyChange);
    void airportPublishOutputQueueDiagnostics(const char *stage);
    void airportRepairOutputQueue(const char *stage);
    void airportPollState();
    void airportScanDoneTimerFired(IOTimerEventSource *src);
    void airportResetScanCache();
    IOReturn airportRefreshScanCache();
    SInt32 airportGet(unsigned int requestNumber, void *data);
    /* 0.3.5: AUTH_TYPE is a pure IO80211Reference-style Apple control-state
     * latch.  It deliberately bypasses RTW/net80211 state acquisition. */
    SInt32 airportGetAuthTypeAppleControl(void *data);
    /* 0.3.10: stack-guard-sensitive status GETs bypass airportGetBody and its
     * diagnostic IORegistry work.  This is also the authoritative small-path
     * implementation of the optional pre-RUN GET4 target-channel experiment. */
    SInt32 airportGetStackSafeHotStatus(unsigned int requestNumber, void *data);
    /* 0.3.2: stack-split body.  airportGet() gathers RTW state first so
     * cmdGetState cannot execute beneath this large getter frame. */
    SInt32 airportGetBody(unsigned int requestNumber, void *data,
                          const RTW88StateResult &state);
    SInt32 airportSet(unsigned int requestNumber, void *data,
                      IO80211Interface *interface);
    UInt32 airportChannelFlags(UInt32 channel) const;
    UInt32 airportStateFromRTW(UInt32 state) const;
#endif

    IOPCIDevice            *_pciDev       = nullptr;
    IOMemoryMap            *_mmioMap      = nullptr;
    volatile void          *_mmioBase     = nullptr;
    IOWorkLoop             *_workLoop     = nullptr;
    IOCommandGate          *_cmdGate      = nullptr;
    IOInterruptEventSource *_intrSrc      = nullptr;
    IOTimerEventSource     *_debugTimer   = nullptr;
#ifdef RTW_AIRPORT
    IOTimerEventSource     *_airportScanDoneTimer = nullptr;
    IO80211Interface       *_iface        = nullptr;
    AirportRTW89SkywalkControlInterface *_skywalkInterface = nullptr;
    AirportRTW89SkywalkBSDInterface *_skywalkBSDCompanion = nullptr;
    bool                    _creatingSkywalkBSDCompanion = false;
    bool                    _skywalkStarted = false;
    bool                    _skywalkOwnsBSDQueue = false;
    bool                    _skywalkRegisterOnlyProbe = false;
    bool                    _skywalkLegacyBindPending = false;
    bool                    _skywalkLegacyBindRetried = false;
    void                   *_skywalkNetworkRegistrationCopy = nullptr;
    void                   *_skywalkEthernetRegistrationCopy = nullptr;
#else
    IOEthernetInterface    *_iface        = nullptr;
#endif
    IOGatedOutputQueue     *_txQueue      = nullptr;

#ifdef RTW_AIRPORT
    IOLock                 *_airportLock  = nullptr;
    struct RTW88BSS        *_airportBSSCache = nullptr;
    UInt32                  _airportBSSCount = 0;
    UInt32                  _airportBSSIndex = 0;
    UInt32                  _airportScanCacheRefreshSerial = 0;
    /* GET SCAN_RESULT is an iterator protocol. CoreWLAN can enumerate the
     * same snapshot concurrently from several threads, so one controller-wide
     * cursor lets one caller consume another caller's results. Keep a small
     * cursor per calling thread and invalidate all cursors whenever a scan is
     * requested or a completed snapshot replaces the cache. */
    struct AirportScanIterator {
        thread_t thread;
        UInt32 index;
        UInt32 serial;
        UInt32 lastUse;
    };
    AirportScanIterator     _airportScanIterators[16] = {};
    UInt32                  _airportScanIterationSerial = 1;
    UInt32                  _airportScanIteratorUseSerial = 0;
    /* 0.2.211: when a new disconnected scan has not heard its first BSS yet,
     * keep serving the last valid Apple snapshot while SCAN_DONE remains
     * deferred. This flag lets the early timer distinguish held visibility
     * from genuinely fresh current-generation results. */
    bool                    _airportScanCacheHeldPrevious = false;
    UInt32                  _airportScanCacheHeldPreviousCount = 0;
    UInt32                  _airportScanCacheHeldPreviousEventCount = 0;
    struct apple80211_scan_result *_airportScanResults = nullptr;
    UInt32                  _airportScanResultGetCount = 0;
    UInt32                  _airportScanResultSuccessCount = 0;
    UInt32                  _airportScanResultEndCount = 0;
    /* 0.2.208 first-real-result controller ioctl_get GET11 ownership probe.
     * SET22 arms one probe for the first result of the next refreshed snapshot. */
    volatile bool           _airportGet11ControllerIoctlGetProbeActive = false;
    thread_t                _airportGet11ControllerIoctlGetProbeThread = THREAD_NULL;
    volatile UInt32         _airportGet11ControllerIoctlGetEntryCount = 0;
    bool                    _airportGet11ControllerFirstResultJoinArmed = false;
    UInt32                  _airportGet11ControllerFirstResultArmSnapshotSerial = 0;
    UInt32                  _airportGet11ControllerFirstResultAttemptCount = 0;
    /* 0.2.199: absolute monotonic checkpoints for the real scan-completion
     * edge and any subsequent SCAN_CACHE_UPDATED publication.  0.2.227
     * suppresses that second edge for disconnected Apple-owned scans to avoid
     * a duplicate GET11 enumeration.  These values remain diagnostic only. */
    UInt64                  _airportLastRealScanCompletionMonotonicMS = 0;
    UInt64                  _airportLastScanCacheUpdatedPostMonotonicMS = 0;
    UInt32                  _airportLastState = 0;
    bool                    _airportScanObserved = false;
    /* 0.2.227: disconnected Apple scans have one completion owner: the
     * genuine RTW89 RF-completion edge.  The historical 100 ms fake
     * SCAN_DONE timer remains available only for associated scans. */
    bool                    _airportDisconnectedScanCompletionPending = false;
    UInt32                  _airportDisconnectedRealCompletionPostCount = 0;
    bool                    _airportScanDoneTimerPending = false;
    UInt32                  _airportScanDoneTimerFireCount = 0;
    UInt32                  _airportScanDonePostCount = 0;
    bool                    _airportAssocPending = false;
    UInt32                  _airportAssocResult = 0;
    /* 0.5.26: Tahoe 26.5 no longer supplies a directional radio state during
     * the initial legacy POWER transaction: both outer and hidden inner SETs
     * are version-only/zero-radio payloads and the inherited user-power latch
     * remains false.  Start logically ON alongside the already-enabled RTW89
     * controller.  A later framework-confirmed OFF edge still updates this
     * state through the zero-radio OFF path in airportSet(). */
    bool                    _airportLogicalPowerOn = true;
    /* 0.2.169: shared ordering telemetry across controller enable/disable and
     * inner Apple80211 POWER callbacks. */
    UInt32                  _airportPowerEventSequence = 0;
    UInt32                  _airportControllerEnableCount = 0;
    UInt32                  _airportControllerDisableCount = 0;
    /* 0.2.171: distinguish real framework setPoweredOnByUser(bool) calls from
     * our own always-on transport pins. */
    UInt32                  _airportFrameworkUserPowerSetCount = 0;
    UInt32                  _airportFrameworkUserPowerLastSequence = 0;
    /* 0.2.172: framework setEnabledBySystem(bool) telemetry, kept separate
     * from driver-owned always-on transport pins. */
    UInt32                  _airportFrameworkSystemEnableSetCount = 0;
    UInt32                  _airportFrameworkSystemEnableLastSequence = 0;
    UInt32                  _airportInternalTransportPinCount = 0;
    UInt32                  _airportInternalSystemEnablePinCount = 0;
    UInt32                  _airportLogicalPowerTransitionCount = 0;
    UInt32                  _airportLinkPublishUpCount = 0;
    UInt32                  _airportLinkPublishDownCount = 0;
    UInt64                  _airportOutputPacketCount = 0;
    UInt64                  _airportOutputPacketBytes = 0;
    UInt32                  _airportOutputARPCount = 0;
    UInt32                  _airportOutputIPv4Count = 0;
    UInt32                  _airportOutputDHCPCount = 0;
    UInt32                  _airportOutputQueueWakeCount = 0;
    UInt32                  _airportRequestPacketTxCount = 0;
    UInt32                  _airportGetDataQueueDepthCount = 0;
    UInt32                  _airportOutputQueueRepairCount = 0;
    bool                    _airportPowerRelatchPending = false;
    /* 0.2.188: Tahoe can cache the pre-superclass POWER_CHANGED edge even
     * though 0.2.175 re-pins the transport only after the hidden marshaller
     * returns.  Publish exactly one deferred ON edge from the controller
     * timer after the outer POWER SET has fully unwound. */
    bool                    _airportPostSuperPowerOnNotifyPending = false;
    UInt32                  _airportPostSuperPowerOnNotifyCount = 0;
    /* 0.3.26: exclusive-native post-registration power synchronization.
     * Stage 1 pins system-enable, stage 2 pins user-power, stage 3 posts the
     * power-change notification.  Each stage runs on a separate controller
     * timer tick and aborts if the BSD ifnet disappears. */
    UInt32                  _nativeCompanionPostRegisterPowerStage = 0;
    bool                    _nativeCompanionPostRegisterPowerPending = false;
    bool                    _nativeCompanionPostRegisterPowerCompleted = false;
    /* The first RF scan after a hard OFF -> ON cache flush must not publish
     * the normal 100 ms partial SCAN_DONE.  Hold that one completion until
     * the full scan has rebuilt the Apple snapshot.  In 0.2.227 disconnected
     * Apple-owned scans publish only that real-completion SCAN_DONE edge. */
    bool                    _airportPowerOnFullScanNotifyPending = false;
    UInt32                  _airportPowerOnFullScanNotifyCount = 0;
    bool                    _airportScanNotifyConsumptionProbePending = false;
    UInt32                  _airportScanNotifyConsumptionProbeDelayTicks = 0;
    UInt32                  _airportScanNotifyGetCountAtPost = 0;
    UInt32                  _airportScanNotifyProbeCount = 0;
    /* 0.2.111: defer userspace-facing availability/power notifications until
     * after IO80211Old has completed its legacy endpoint handshake. */
    bool                    _airportPostBindNotificationsPending = false;
    bool                    _airportPostBindNotificationsPosted = false;
    /* 0.2.112 diagnostic: after the post-bind notification probe has run,
     * launch exactly one native RTW89 scan from the controller timer.  This
     * bypasses airportd/CoreWLAN dispatch only for the purpose of proving the
     * hardware/manual-scan + BSS-cache path; it does not create a user client
     * and does not alter Apple80211 request routing. */
    bool                    _airportOneShotHardwareScanPending = false;
    bool                    _airportOneShotHardwareScanAttempted = false;
    UInt32                  _airportOneShotHardwareScanDelayTicks = 0;
    UInt32                  _airportPowerRelatchCount = 0;
    /* 0.2.53 diagnostic: prove whether Tahoe/CoreWLAN is actually calling
     * the driver's POWER GET/SET paths when the public Wi-Fi switch says Off. */
    UInt32                  _airportPowerGetCount = 0;
    UInt32                  _airportPowerSetCount = 0;
    /* 0.2.57: retain the first eight POWER SET payloads instead of only the
     * final call.  Words 0..5 are the incoming buffer, word 6 is the decoded
     * request.  Word 7 is a flag field: bit 0 scalar layout, bit 1 interface
     * poweredOnByUser, bit 2 interface enabledBySystem, bit 3 controller
     * enabled. */
    UInt32                  _airportPowerSetHistory[8][8] = {};
    /* 0.2.55 frontend diagnostics. */
    UInt32                  _airportDataLinkAttachCompleteCount = 0;
    UInt32                  _airportStateGetCount = 0;
    UInt32                  _airportScanSetCount = 0;
    /* Circular trace of the last 64 normalized Apple80211 requests.  Each
     * word stores the request number in bits 0..30 and GET in bit 31. */
    UInt32                  _airportRequestHistory[64] = {};
    UInt32                  _airportRequestHistoryIndex = 0;
    UInt32                  _airportRequestHistoryCount = 0;

    /* 0.2.217 monotonic controller-dispatch counter used by the outer
     * marshaller trace.  Unlike the 64-entry history count, this never
     * saturates after the first 64 requests. */
    volatile UInt32         _io80211ReferenceParityDispatcherSequence = 0;

    /* 0.3.5 IO80211Reference-style Apple control-state block.
     *
     * Keep Apple-facing configuration ownership separate from net80211/RTW
     * association state.  This mirrors IO80211Reference's current_authtype_*
     * latch: SET2 writes these fields and GET2 returns only these fields.
     * SET22 never clears them. */
    struct IO80211ReferenceAppleControlState {
        UInt32 current_authtype_lower = 0;
        UInt32 current_authtype_upper = 0;
    };
    IO80211ReferenceAppleControlState _airportAppleControl = {};
    /* Diagnostic only: IO80211Reference's GET2 does not gate on validity. */
    bool                    _airportAppleControlAuthConfigured = false;
    /* 0.2.177: preserve security-sensitive outer Apple80211 SET payloads only
     * long enough for IO80211Interface's synchronous inner callback to consume
     * them.  Tahoe has already proven it can lose fields while marshalling
     * POWER; use the same boundary for WPA2 AUTH/ASSOCIATE/RSN/CIPHER data.
     * These buffers are kernel-private and are never published to IORegistry. */
    UInt32                  _airportOuterSecuritySequence = 0;
    apple80211_authtype_data _airportOuterAuthCache = {};
    bool                    _airportOuterAuthCacheValid = false;
    UInt32                  _airportOuterAuthCacheSequence = 0;
    apple80211_assoc_data   _airportOuterAssocCache = {};
    bool                    _airportOuterAssocCacheValid = false;
    /* 0.3.11: exact-thread origin tag so a concurrent real SET20 cannot be
     * misclassified as the private synthetic diagnostic. */
    thread_t                _airportSyntheticAssociateThread = THREAD_NULL;
    volatile UInt32         _airportSyntheticAssociateCount = 0;
    volatile UInt32         _airportRealAssociateCount = 0;
    /* Metadata-only IOUC trace arm set by the confirmed controller SET22
     * ingress and consumed by the custom type-0 request marshaller. */
    volatile UInt32         _airportIOUCAssociationCaptureSequence = 0;
    volatile UInt64         _airportIOUCAssociationCaptureStartMS = 0;
    UInt32                  _airportOuterAssocCacheSequence = 0;
    apple80211_rsn_ie_data  _airportOuterRSNIECache = {};
    bool                    _airportOuterRSNIECacheValid = false;
    UInt32                  _airportOuterRSNIECacheSequence = 0;
    apple80211_key          _airportOuterCipherKeyCache = {};
    bool                    _airportOuterCipherKeyCacheValid = false;
    UInt32                  _airportOuterCipherKeyCacheSequence = 0;
    char                    _airportCountryCode[3] = {'Z', 'Z', '\0'};
    UInt32                  _airportBtcMode = 0;
    UInt32                  _airportBtcOptions = 0;
    UInt32                  _airportBtcConfigWords[5] = {};
    UInt32                  _airportAwdlElectionMetric = 0;
    UInt32                  _airportAwdlElectionId = 0;
    UInt32                  _airportAwdlPresenceMode = 0;
    UInt32                  _airportAwdlSyncState = 0;
    UInt32                  _airportAwdlMasterChannel = 0;
    UInt32                  _airportAwdlSecondaryMasterChannel = 0;
    UInt32                  _airportAwdlMinRate = 0;
    UInt32                  _airportAwdlPeerCacheMaximum = 0;
    UInt32                  _airportAwdlAfTxMode = 0;
    bool                    _airportAwdlSyncEnabled = false;
    UInt8                   _airportAwdlBSSID[6] = {};
    UInt32                  _airportVirtualRequestCount = 0;
#endif

    RTW88IEEE80211         *_ieee80211    = nullptr;
    RTW89Net80211Core      *_net80211     = nullptr;
    RTW88UserClient        *_userClient   = nullptr;

    IOEthernetAddress       _macAddr;
    bool                    _enabled      = false;
    bool                    _systemShutdownQuiesced = false;
    bool                    _initialized  = false;

    /* TX flow control: set when outputPacket() stalls the gated queue because
     * the BE ring is nearly full; cleared when the IRQ completion path frees
     * slots and resumes the queue.  See createOutputQueue()/outputPacket(). */
    volatile bool           _txStalled    = false;

    /* Linked-list of allocated DMA buffers for cleanup */
    struct DMAEntry {
        IOBufferMemoryDescriptor *desc;
        void    *virt;        /* kernel VA of the bounce/coherent buffer */
        IOPhysicalAddress phys;
        size_t   size;
        void    *orig_va;     /* original CPU VA for bounce mappings (NULL=coherent) */
        DMAEntry *next;
    };
    DMAEntry *_dmaList        = nullptr;
    IOSimpleLock *_dmaLock    = nullptr;

    /* Entries whose desc->complete()/release() was deferred because
     * preemption was disabled at free time (TX-completion interrupt path).
     * Drained by drainPendingFree() from preemption-enabled contexts. */
    DMAEntry     *_dmaPendingFree    = nullptr;
    IOSimpleLock *_pendingFreeLock   = nullptr;
    void          drainPendingFree();

    /* Back-pointer passed to compat layer */
    struct pci_dev *_compatPciDev = nullptr;
};
