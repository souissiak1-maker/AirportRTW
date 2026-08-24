/* 0.2.256: primary-decision / controller-ownership audit.
 *
 * 0.2.255 proved moving initial LINK VALID until after attachInterface() does
 * not make Tahoe emit APPLE80211_IOC_ASSOCIATE/20.  The next live-registry
 * clue was IOPrimaryInterface becoming false after our earlier cosmetic true
 * publication.  Do not add another post-registration force.  Instead, record the
 * framework's real isPrimaryInterface() decision, BSD unit, provider built-in
 * state, and controller/provider identity across attach/register/data-link
 * completion.  No request return, topology, or association behavior changes.
 */
/* 0.2.250: legacy-only association topology experiment.
 *
 * 0.2.249 proved across repeated real WPA2 attempts that Tahoe emits a
 * payload-less DISASSOCIATE/22 immediately before "Will associate", but no
 * ASSOCIATE/20 exists in either the outer SET-only ring or controller history.
 * Keep all working marshalling/scan/IE/lifecycle behavior intact and suppress
 * only the extra control-only Skywalk primary so the live topology matches the
 * single legacy IO80211Interface ownership model during association.
 */
/* 0.2.249: SET-only outer sequence diagnostic on the stack-safe Tahoe marshaller.
 * Preserve the 0.2.245 typed marshaller, but route lifecycle SET22/SET20
 * through a tiny outer wrapper so the deep disconnect/associate backend does
 * not execute underneath the very large legacy compatibility stack frame. */
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// RTW88PCIDevice.cpp — IOEthernetController for PCIe rtw88 adapters

#include "RTW88PCIDevice.hpp"
/* 0.5.26 rebuild marker: initial logical power now follows controller ON. */
#include "../net80211/RTW89Net80211Core.hpp"

/* 0.2.159: keep IORegistry writes off the TX/RX packet hot path. */
#define RTW89_PER_PACKET_IOREG_DIAGNOSTICS 0
#include "RTW88IEEE80211.hpp"
#include "RTW88UserClient.hpp"

#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkMedium.h>
#ifdef RTW_AIRPORT
#include <libkern/copyio.h>
#include <net/kpi_interface.h>
#include <net/if.h>
#include <pexpert/pexpert.h>
#include <sys/proc.h>
#endif

/* The Linux-compat pci_ops that route through this class */
extern "C" {
#include "../compat/rtw88_compat.h"
}

extern "C" void rtw88_trigger_interrupt(void);
extern "C" boolean_t preemption_enabled(void);

/* Driver family name shown in ioreg properties */
#ifdef RTW89_MACOS
#define RTW_DRV_NAME "rtw89"
#else
#define RTW_DRV_NAME "rtw88"
#endif

#ifdef RTW_AIRPORT
#define super IO80211Controller
#else
#define super IOEthernetController
#endif
#ifdef RTW_AIRPORT
/* 0.5.37: file-local timing state deliberately lives outside the controller
 * object.  AirportRTW's IO80211 subclasses have ABI-sensitive layouts; adding
 * a controller member in 0.5.36 broke the first DRIVER_VERSION transaction. */
static volatile UInt64 gAirportRTW89Type0StartupStartMS = 0;
/* Set by the controller's association-truth poll on a real connected ->
 * disconnected edge.  This is file-external state rather than an object
 * member so the legacy IO80211 subclass layout remains unchanged. */
volatile UInt64 gAirportRTW89LinkLossTransitionStartMS = 0;

/* 0.3.7 native secured-control parity.
 *
 * IO80211Reference's modern network-controller personality is explicitly a
 * Wi-Fi root service (IOMatchCategory=WiFiDriver, IONetworkRootType=airport).
 * AirportRTW89 still owns the PCI device directly, so we must not pretend to
 * have IO80211Reference's IOPCIEDeviceWrapper provider topology.  Publish the
 * equivalent runtime service identity only, and keep a truthful RSN-done bit
 * that remains false until our existing real key-install/handshake-done edge.
 *
 * A secondary boot arg, rtw89_native_iouc_strict=1, suppresses the custom
 * type-0 fallback after the inherited IO80211Interface route fails.  It is
 * diagnostic-only and disabled by default because 0.2.259 proved the custom
 * legacy selector path is needed for the current OPEN post-bind lifecycle. */
static bool airportNativeIOUCStrictMode(void)
{
    /* 0.4.3 Ventura reference topology: IO80211Reference-Ventura uses the
     * inherited IO80211Interface user-client factory on its single BSD
     * IO80211Interface.  Native Type-0 is therefore mandatory in this branch;
     * never manufacture AirportRTW89APIUserClient when Apple's factory fails. */
    return true;
}

/* 0.5.0: exact Ventura IO80211Reference interface-dispatch experiment.
 *
 * IO80211ReferenceInterface overrides only inputPacket(); Apple80211 command
 * marshalling and type-0 user-client creation remain owned by the restored
 * IO80211Interface superclass.  Keep this opt-in until it has been verified
 * on the user's Tahoe/IO80211FamilyLegacy combination, so the known-good
 * legacy scanning/open-network path remains recoverable without replacing
 * the kext. */
static bool airportVenturaInterfaceParity(void)
{
    int value = 0;
    return PE_parse_boot_argn("rtw89_ventura_parity", &value,
                              sizeof(value)) && value != 0;
}

/* 0.3.19: opt-in IO80211Reference-style Skywalk/BSD companion topology.
 *
 * This remains disabled unless rtw89_native_topology=1 is present so a
 * failed experiment cannot remove the known-good 0.3.16 open-network path.
 * The experiment uses the already-existing AirportRTW89SkywalkBSDInterface
 * createInterface() branch and the base IONetworkController attach path,
 * matching IO80211Reference's modern sequence more closely than the previous
 * control-only/shared-ifnet approximation. */
static bool airportNativeTopologyExperiment(void)
{
    int value = 0;
    return PE_parse_boot_argn("rtw89_native_topology", &value, sizeof(value)) &&
           value != 0;
}

/* 0.3.20: exclusive native-owner experiment.
 *
 * When enabled together with rtw89_native_topology=1, temporarily remove the
 * already-attached legacy AirportRTW89Interface before IO80211 configures the
 * Skywalk BSD companion.  0.3.18/0.3.19 proved the companion itself is valid
 * and that IO80211Controller rejects it only while the legacy interface is
 * already present.  If companion attachment fails, recreate the legacy
 * interface in the same boot. */
static bool airportExclusiveNativeTopology(void)
{
    int value = 0;
    return PE_parse_boot_argn("rtw89_exclusive_native", &value, sizeof(value)) &&
           value != 0;
}

/* 0.3.36: make the controller's primary-interface identity agree with the
 * exclusive-native BSD companion.  Earlier exclusive-native builds detached
 * the legacy _iface after successfully attaching AirportRTW89SkywalkBSDInterface,
 * leaving IO80211Controller::getNetworkInterface() effectively NULL even while
 * that companion owned the live enX ifnet.  Some Apple Wi-Fi state decisions
 * consult the controller's network interface independently of Apple80211 POWER.
 *
 * Preserve legacy behavior outside the exclusive-native experiment. */
IO80211Interface *AirportRTW89::getNetworkInterface()
{
    static UInt32 queryCount = 0;
    ++queryCount;

    const bool exclusiveNative =
        airportNativeTopologyExperiment() && airportExclusiveNativeTopology();
    IO80211Interface *returned = _iface;
    if (exclusiveNative && _skywalkBSDCompanion)
        returned = _skywalkBSDCompanion;

    setProperty("AirportRTW89GetNetworkInterfaceSeen", kOSBooleanTrue);
    setProperty("AirportRTW89GetNetworkInterfaceCount", (uint64_t)queryCount, 32);
    setProperty("AirportRTW89GetNetworkInterfaceExclusiveNative",
                exclusiveNative ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89GetNetworkInterfaceLegacyPresent",
                _iface ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89GetNetworkInterfaceLegacyPointer",
                (uint64_t)(uintptr_t)_iface, 64);
    setProperty("AirportRTW89GetNetworkInterfaceCompanionPresent",
                _skywalkBSDCompanion ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89GetNetworkInterfaceCompanionPointer",
                (uint64_t)(uintptr_t)_skywalkBSDCompanion, 64);
    setProperty("AirportRTW89GetNetworkInterfaceCompanionIfnetPresent",
                (_skywalkBSDCompanion && _skywalkBSDCompanion->getIfnet())
                    ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89GetNetworkInterfaceReturnedPresent",
                returned ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89GetNetworkInterfaceReturnedPointer",
                (uint64_t)(uintptr_t)returned, 64);
    setProperty("AirportRTW89GetNetworkInterfaceReturnedIsCompanion",
                (returned && returned == _skywalkBSDCompanion)
                    ? kOSBooleanTrue : kOSBooleanFalse);
    if (returned && returned->getMetaClass())
        setProperty("AirportRTW89GetNetworkInterfaceReturnedClass",
                    returned->getMetaClass()->getClassName());

    return returned;
}

/* 0.3.19: diagnostic companion configuration probe.
 *
 * IO80211Reference asks IO80211Controller::configureInterface() to configure its
 * sole BSD companion.  AirportRTW currently reaches the same method only
 * after a legacy IO80211Interface has already been attached.  If the IO80211
 * superclass rejects a second controller-owned BSD interface, the companion
 * dies before attachToDataLinkLayer().
 *
 * rtw89_native_companion_base_config=1 is intentionally diagnostic-only.
 * It bypasses IO80211Controller::configureInterface() for the Skywalk BSD
 * companion and invokes IOEthernetController::configureInterface() instead.
 * This does NOT represent the final native architecture; it isolates whether
 * the rejection is specifically in the IO80211 layer.
 */
static bool airportNativeCompanionBaseConfigProbe(void)
{
    int value = 0;
    return PE_parse_boot_argn("rtw89_native_companion_base_config",
                              &value, sizeof(value)) &&
           value != 0;
}

static bool airportMetaClassPresent(const char *className)
{
    if (!className)
        return false;
    const OSSymbol *symbol = OSSymbol::withCString(className);
    const OSMetaClass *meta = symbol
        ? OSMetaClass::getMetaClassWithName(symbol) : nullptr;
    OSSafeReleaseNULL(symbol);
    return meta != nullptr;
}
#endif
/* One extra macro-expansion level so a -DRTW88Foo=RTW89Foo class rename
 * (rtw89 kext build) also renames the OSMetaClass name string:
 * arguments used plainly in a macro body are expanded before being
 * passed to OSDefineMetaClassAndStructors' internal stringify. */
#define RTW_DEFINE_METACLASS(cls, super) OSDefineMetaClassAndStructors(cls, super)
#ifdef RTW_AIRPORT
RTW_DEFINE_METACLASS(RTW88PCIDevice, IO80211Controller)
OSDefineMetaClassAndStructors(AirportRTW89Interface, IO80211Interface)
OSDefineMetaClassAndStructors(AirportRTW89APIUserClient, IOUserClient)
OSDefineMetaClassAndStructors(IO80211APIUserClient,
                              AirportRTW89APIUserClient)
OSDefineMetaClassAndStructors(AirportRTW89PCIWrapper, IOService)

bool AirportRTW89PCIWrapper::start(IOService *provider)
{
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci || !IOService::start(provider))
        return false;

    _pciDevice = pci;
    _pciDevice->retain();
    const UInt8 builtIn = 0;
    if (OSData *value = OSData::withBytes(&builtIn, sizeof(builtIn))) {
        setProperty("built-in", value);
        value->release();
    }
    setProperty("AirportRTW89PCIWrapperActive", kOSBooleanTrue);
    registerService();
    return true;
}

void AirportRTW89PCIWrapper::stop(IOService *provider)
{
    if (_pciDevice) {
        _pciDevice->release();
        _pciDevice = nullptr;
    }
    IOService::stop(provider);
}
#else
RTW_DEFINE_METACLASS(RTW88PCIDevice, IOEthernetController)
#endif

#ifdef RTW_AIRPORT
static void airportPrimaryAuditSetBool(RTW88PCIDevice *owner,
                                       const char *stage,
                                       const char *field,
                                       bool value)
{
    if (!owner || !stage || !field)
        return;
    char key[160] = {};
    snprintf(key, sizeof(key), "AirportRTW89PrimaryAudit%s%s", stage, field);
    owner->setProperty(key, value ? kOSBooleanTrue : kOSBooleanFalse);
}

static void airportPrimaryAuditSetUInt(RTW88PCIDevice *owner,
                                       const char *stage,
                                       const char *field,
                                       uint64_t value,
                                       unsigned int bits = 32)
{
    if (!owner || !stage || !field)
        return;
    char key[160] = {};
    snprintf(key, sizeof(key), "AirportRTW89PrimaryAudit%s%s", stage, field);
    owner->setProperty(key, value, bits);
}

static void airportPrimaryAuditSetString(RTW88PCIDevice *owner,
                                         const char *stage,
                                         const char *field,
                                         const char *value)
{
    if (!owner || !stage || !field || !value || !value[0])
        return;
    char key[160] = {};
    snprintf(key, sizeof(key), "AirportRTW89PrimaryAudit%s%s", stage, field);
    owner->setProperty(key, value);
}

static void airportPublishPrimaryDecisionSnapshot(
    RTW88PCIDevice *owner,
    IO80211Interface *interface,
    const char *stage)
{
    if (!owner || !stage)
        return;

    airportPrimaryAuditSetBool(owner, stage, "InterfacePresent",
                               interface != nullptr);
    if (!interface)
        return;

    /* Read-only audit.  The virtual method is the framework's actual primary
     * decision; the registry property can be rewritten later when the BSD unit
     * is assigned, so record both independently. */
    airportPrimaryAuditSetBool(owner, stage, "VirtualIsPrimary",
                               interface->isPrimaryInterface());

    OSObject *primary = interface->getProperty(kIOPrimaryInterface);
    airportPrimaryAuditSetBool(owner, stage, "PropertyPresent",
                               primary != nullptr);
    airportPrimaryAuditSetBool(owner, stage, "PropertyIsBoolean",
                               OSDynamicCast(OSBoolean, primary) != nullptr);
    airportPrimaryAuditSetBool(owner, stage, "PropertyTrue",
                               primary == kOSBooleanTrue);

    OSNumber *unit = OSDynamicCast(
        OSNumber, interface->getProperty(kIOInterfaceUnit));
    airportPrimaryAuditSetBool(owner, stage, "UnitPropertyPresent",
                               unit != nullptr);
    if (unit)
        airportPrimaryAuditSetUInt(owner, stage, "UnitProperty",
                                   unit->unsigned32BitValue());
    airportPrimaryAuditSetUInt(owner, stage, "UnitMethod",
                               interface->getUnitNumber());

    OSString *bsdName = OSDynamicCast(
        OSString, interface->getProperty(kIOBSDNameKey));
    airportPrimaryAuditSetBool(owner, stage, "BSDNamePresent",
                               bsdName != nullptr);
    if (bsdName)
        airportPrimaryAuditSetString(owner, stage, "BSDName",
                                     bsdName->getCStringNoCopy());

    IONetworkController *controller = interface->getController();
    IOService *interfaceProvider = interface->getProvider();
    airportPrimaryAuditSetBool(owner, stage, "ControllerPresent",
                               controller != nullptr);
    airportPrimaryAuditSetBool(owner, stage, "ControllerMatchesOwner",
                               controller == owner);
    airportPrimaryAuditSetBool(owner, stage, "InterfaceProviderPresent",
                               interfaceProvider != nullptr);
    airportPrimaryAuditSetBool(owner, stage, "InterfaceProviderIsController",
                               interfaceProvider == controller);
    if (controller)
        airportPrimaryAuditSetUInt(owner, stage, "ControllerRegistryEntryID",
                                   controller->getRegistryEntryID(), 64);
    if (interfaceProvider)
        airportPrimaryAuditSetUInt(owner, stage,
                                   "InterfaceProviderRegistryEntryID",
                                   interfaceProvider->getRegistryEntryID(), 64);

    IOService *controllerProvider = controller ? controller->getProvider()
                                               : nullptr;
    airportPrimaryAuditSetBool(owner, stage, "ControllerProviderPresent",
                               controllerProvider != nullptr);
    if (controllerProvider) {
        airportPrimaryAuditSetUInt(owner, stage,
                                   "ControllerProviderRegistryEntryID",
                                   controllerProvider->getRegistryEntryID(), 64);
        const OSMetaClass *meta = controllerProvider->getMetaClass();
        if (meta)
            airportPrimaryAuditSetString(owner, stage,
                                         "ControllerProviderClass",
                                         meta->getClassName());

        OSObject *builtIn = controllerProvider->getProperty("built-in");
        airportPrimaryAuditSetBool(owner, stage,
                                   "ControllerProviderBuiltinPresent",
                                   builtIn != nullptr);
        airportPrimaryAuditSetBool(owner, stage,
                                   "ControllerProviderBuiltinIsBoolean",
                                   OSDynamicCast(OSBoolean, builtIn) != nullptr);
        airportPrimaryAuditSetBool(owner, stage,
                                   "ControllerProviderBuiltinBooleanTrue",
                                   builtIn == kOSBooleanTrue);
        airportPrimaryAuditSetBool(owner, stage,
                                   "ControllerProviderBuiltinIsData",
                                   OSDynamicCast(OSData, builtIn) != nullptr);
    }
}
#endif

static constexpr unsigned int kRTW88TxStallAvail = 96;
static constexpr unsigned int kRTW88TxResumeAvail = 160;

#ifdef RTW_AIRPORT
/* 0.2.51 diagnostic PM participation. Hardware transitions remain suppressed. */
static IOPMPowerState kRTW89AirportPowerStates[2] = {
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMPowerOn | kIOPMDeviceUsable,
        kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};
static UInt32 gRTW89AirportPMState = 1;
static UInt32 gRTW89AirportPMSetPowerStateCount = 0;

/* 0.2.176 status/association diagnostic hash.  Used only for SSID/BSSID
 * correlation so the IORegistry probe never publishes network identity. */
/* 0.2.245: explicit legacy Apple80211 payload marshalling.
 *
 * IO80211Reference relies on IO80211Interface to translate the outer apple80211req
 * userspace envelope into a kernel-resident typed payload before invoking the
 * controller's apple80211Request(SIOCGA80211/SIOCSA80211, request, ...).  On
 * Tahoe's restored IO80211FamilyLegacy that inherited marshaller is not
 * equivalent for AirportRTW89: some requests reach the controller without
 * user-buffer copyout, while others are swallowed before the controller.
 *
 * Keep the already-proven raw-layout compatibility bridges (POWER, GET11,
 * GET27, COUNTRY, ASSOCIATE, etc.) in performCommand().  For otherwise
 * unhandled requests whose public fixed-size payload type is known, this table
 * lets AirportRTW89 perform the remaining copyin -> controller dispatch ->
 * copyout operation itself. Unknown/private layouts still fall back to Apple's
 * inherited marshaller.
 */
struct AirportLegacyMarshalSpec {
    size_t size;
    bool allowGet;
    bool allowSet;
};

static bool airportLegacyMarshalSpecForRequest(UInt32 request,
                                                AirportLegacyMarshalSpec *out)
{
    if (!out)
        return false;

    AirportLegacyMarshalSpec spec = {};
    switch (request) {
    case APPLE80211_IOC_SSID:
        spec = { sizeof(apple80211_ssid_data), true, false };
        break;
    case APPLE80211_IOC_AUTH_TYPE:
        spec = { sizeof(apple80211_authtype_data), true, true };
        break;
    case APPLE80211_IOC_CHANNEL:
        spec = { sizeof(apple80211_channel_data), true, true };
        break;
    case APPLE80211_IOC_PROTMODE:
        spec = { sizeof(apple80211_protmode_data), true, true };
        break;
    case APPLE80211_IOC_TXPOWER:
        spec = { sizeof(apple80211_txpower_data), true, false };
        break;
    case APPLE80211_IOC_RATE:
        spec = { sizeof(apple80211_rate_data), true, false };
        break;
    case APPLE80211_IOC_SCAN_REQ:
        spec = { sizeof(apple80211_scan_data), false, true };
        break;
    case APPLE80211_IOC_SCAN_REQ_MULTIPLE:
        spec = { sizeof(apple80211_scan_multiple_data), false, true };
        break;
    case APPLE80211_IOC_CARD_CAPABILITIES:
        spec = { sizeof(apple80211_capability_data), true, false };
        break;
    case APPLE80211_IOC_STATE:
        spec = { sizeof(apple80211_state_data), true, false };
        break;
    case APPLE80211_IOC_BSSID:
        spec = { sizeof(apple80211_bssid_data), true, false };
        break;
    case APPLE80211_IOC_PHY_MODE:
        spec = { sizeof(apple80211_phymode_data), true, false };
        break;
    case APPLE80211_IOC_OP_MODE:
        spec = { sizeof(apple80211_opmode_data), true, false };
        break;
    case APPLE80211_IOC_RSSI:
        spec = { sizeof(apple80211_rssi_data), true, false };
        break;
    case APPLE80211_IOC_NOISE:
        spec = { sizeof(apple80211_noise_data), true, false };
        break;
    case APPLE80211_IOC_INT_MIT:
        spec = { sizeof(apple80211_intmit_data), true, false };
        break;
    case APPLE80211_IOC_POWER:
        spec = { sizeof(apple80211_power_data), true, false };
        break;
    case APPLE80211_IOC_ASSOCIATE_RESULT:
        spec = { sizeof(apple80211_assoc_result_data), true, false };
        break;
    case APPLE80211_IOC_RATE_SET:
        spec = { sizeof(apple80211_rate_set_data), true, false };
        break;
    case APPLE80211_IOC_MCS_INDEX_SET:
        spec = { sizeof(apple80211_mcs_index_set_data), true, false };
        break;
    case APPLE80211_IOC_LOCALE:
        spec = { sizeof(apple80211_locale_data), true, false };
        break;
    case APPLE80211_IOC_DEAUTH:
        spec = { sizeof(apple80211_deauth_data), true, true };
        break;
    case APPLE80211_IOC_TX_ANTENNA:
    case APPLE80211_IOC_ANTENNA_DIVERSITY:
        spec = { sizeof(apple80211_antenna_data), true, false };
        break;
    case APPLE80211_IOC_DRIVER_VERSION:
    case APPLE80211_IOC_HARDWARE_VERSION:
        spec = { sizeof(apple80211_version_data), true, false };
        break;
    case APPLE80211_IOC_RSN_IE:
        spec = { sizeof(apple80211_rsn_ie_data), true, true };
        break;
    case APPLE80211_IOC_ASSOCIATION_STATUS:
        spec = { sizeof(apple80211_assoc_status_data), true, false };
        break;
    case APPLE80211_IOC_COUNTRY_CODE:
        spec = { sizeof(apple80211_country_code_data), true, true };
        break;
    case APPLE80211_IOC_RADIO_INFO:
        spec = { sizeof(apple80211_radio_info_data), true, false };
        break;
    case APPLE80211_IOC_MCS:
        spec = { sizeof(apple80211_mcs_data), true, false };
        break;
    case APPLE80211_IOC_ROAM_THRESH:
        spec = { sizeof(apple80211_roam_threshold_data), true, false };
        break;
    case APPLE80211_IOC_POWERSAVE:
        spec = { sizeof(apple80211_powersave_data), true, false };
        break;
    case APPLE80211_IOC_CIPHER_KEY:
        spec = { sizeof(apple80211_key), false, true };
        break;
    case APPLE80211_IOC_TX_NSS:
        spec = { sizeof(apple80211_tx_nss_data), true, true };
        break;
    case APPLE80211_IOC_NSS:
        spec = { sizeof(apple80211_nss_data), true, false };
        break;
    case APPLE80211_IOC_CURRENT_NETWORK:
        spec = { sizeof(apple80211_scan_result), true, false };
        break;
    case APPLE80211_IOC_SUPPORTED_CHANNELS:
    case APPLE80211_IOC_HW_SUPPORTED_CHANNELS:
        spec = { sizeof(apple80211_sup_channel_data), true, false };
        break;
    case APPLE80211_IOC_CHANNELS_INFO:
        spec = { sizeof(AirportRTW89ChannelsInfoData), true, false };
        break;
    default:
        return false;
    }

    *out = spec;
    return true;
}

/* 0.3.8: stack-safe primary GET207/CHANNELS_INFO bridge.  Tahoe routes this
 * request through the real legacy en2 performCommand path, while 0.3.7 only
 * exposed the already-correct payload builder on the virtual/AWDL surface.
 * Build the 0xA0C payload on the heap so frequent menu/background scan queries
 * never re-enter the historical ~9.5 KiB compatibility frame. */
static SInt32 airportDirectGetChannelsInfo(RTW88PCIDevice *owner,
                                           UInt32 requestLength,
                                           user_addr_t requestData)
{
    if (!owner || requestData == 0)
        return kIOReturnBadArgument;

    static volatile UInt32 requestCount = 0;
    static volatile UInt32 successCount = 0;
    const UInt32 sequence = __sync_add_and_fetch(&requestCount, 1U);
    const size_t structSize = sizeof(AirportRTW89ChannelsInfoData);
    const size_t minimumUseful =
        offsetof(AirportRTW89ChannelsInfoData, chan_num) + 22U;

    SInt32 result = kIOReturnBadArgument;
    int copyoutResult = -1;
    size_t copyLength = 0;
    UInt16 numChannels = 0;

    if (requestLength >= minimumUseful) {
        AirportRTW89ChannelsInfoData *value =
            static_cast<AirportRTW89ChannelsInfoData *>(IOMallocZero(structSize));
        if (!value) {
            result = kIOReturnNoMemory;
        } else {
            owner->airportFillChannelsInfo(value);
            numChannels = value->num_chan_specs;
            copyLength = requestLength < structSize ? requestLength : structSize;
            copyoutResult = copyout(value, requestData, copyLength);
            result = copyoutResult == 0 ? kIOReturnSuccess
                                        : (SInt32)copyoutResult;
            IOFree(value, structSize);
            if (result == kIOReturnSuccess)
                __sync_add_and_fetch(&successCount, 1U);
        }
    }

    owner->setProperty("AirportRTW89DirectGet207BridgeSeen", kOSBooleanTrue);
    owner->setProperty("AirportRTW89DirectGet207BridgeCount",
                       (uint64_t)sequence, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeSuccessCount",
                       (uint64_t)successCount, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeReqLen",
                       (uint64_t)requestLength, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeStructSize",
                       (uint64_t)structSize, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeMinimumUsefulSize",
                       (uint64_t)minimumUseful, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeCopyLength",
                       (uint64_t)copyLength, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeCopyoutReturn",
                       (uint64_t)(uint32_t)copyoutResult, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeNumChannels",
                       (uint64_t)numChannels, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeReturn",
                       (uint64_t)(uint32_t)result, 32);
    owner->setProperty("AirportRTW89DirectGet207BridgeCompatBodyBypassed",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89ChannelsInfoScanStabilityEnabled",
                       kOSBooleanTrue);
    return result;
}

static bool airportExplicitLegacyMarshal(RTW88PCIDevice *owner,
                                         AirportRTW89Interface *interface,
                                         bool isSet, UInt32 request,
                                         UInt32 requestLength,
                                         user_addr_t requestData,
                                         SInt32 *outResult)
{
    if (!owner || !interface || !outResult)
        return false;

    /* 0.5.45: GET11 is the one legacy GET whose controller ABI returns a
     * pointer to an apple80211_scan_result rather than filling the typed
     * object supplied by the caller.  The 0.5.24 all-GET stack-safety gate
     * made the older direct GET11 bridge in performCommandCompatBody
     * unreachable and delegated this pointer-shaped request to Tahoe's
     * inherited marshaller.  That path consumes/builds results without
     * reliably copying the 1164-byte object to req_data.
     *
     * Handle it in this small, stack-safe marshaller before the fixed-size
     * table lookup.  The persistent result remains controller-owned and is
     * copied immediately; no pointer escapes this synchronous request. */
    if (!isSet && request == APPLE80211_IOC_SCAN_RESULT) {
        if (!requestData ||
            requestLength < sizeof(apple80211_scan_result))
            return false;

        apple80211_scan_result *scanResult = nullptr;
        const SInt32 innerResult = owner->apple80211Request(
            (unsigned int)SIOCGA80211, (int)request, interface, &scanResult);
        SInt32 finalResult = innerResult;
        int copyoutResult = -1;
        if (innerResult == kIOReturnSuccess) {
            if (!scanResult) {
                finalResult = kIOReturnNotReady;
            } else {
                copyoutResult = copyout(
                    scanResult, requestData, sizeof(apple80211_scan_result));
                if (copyoutResult != 0)
                    finalResult = (SInt32)copyoutResult;
            }
        }

        static volatile UInt32 directGet11Count = 0;
        static volatile UInt32 directGet11SuccessCount = 0;
        const UInt32 count =
            __sync_add_and_fetch(&directGet11Count, 1U);
        const UInt32 successCount =
            finalResult == kIOReturnSuccess
                ? __sync_add_and_fetch(&directGet11SuccessCount, 1U)
                : directGet11SuccessCount;
        owner->setProperty("AirportRTW89StackSafeDirectGet11Seen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89StackSafeDirectGet11Count",
                           (uint64_t)count, 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11SuccessCount",
                           (uint64_t)successCount, 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11ReqLen",
                           (uint64_t)requestLength, 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11StructSize",
                           (uint64_t)sizeof(apple80211_scan_result), 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11PointerPresent",
                           scanResult ? kOSBooleanTrue : kOSBooleanFalse);
        owner->setProperty("AirportRTW89StackSafeDirectGet11InnerReturn",
                           (uint64_t)(uint32_t)innerResult, 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11CopyoutReturn",
                           (uint64_t)(uint32_t)copyoutResult, 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11FinalReturn",
                           (uint64_t)(uint32_t)finalResult, 32);
        owner->setProperty("AirportRTW89StackSafeDirectGet11CompatBodyBypassed",
                           kOSBooleanTrue);
        *outResult = finalResult;
        return true;
    }

    AirportLegacyMarshalSpec spec = {};
    if (!airportLegacyMarshalSpecForRequest(request, &spec))
        return false;
    if ((isSet && !spec.allowSet) || (!isSet && !spec.allowGet))
        return false;

    /* Tahoe's legacy GET1/GET9 wire ABI omits the public structure header:
     * GET1 is exactly 32 SSID bytes and GET9 is exactly 6 BSSID bytes.
     * Route those raw forms through the typed controller getter, then copy
     * only the raw payload back.  Before RUN the typed getter still returns
     * IO80211Reference's failure code, so this cannot recreate the old
     * pre-SET20 empty-success normalization. */
    if (!isSet && requestData &&
        request == APPLE80211_IOC_SSID &&
        requestLength == APPLE80211_MAX_SSID_LEN) {
        apple80211_ssid_data value = {};
        const SInt32 innerResult = owner->apple80211Request(
            (unsigned int)SIOCGA80211, (int)request, interface, &value);
        SInt32 finalResult = innerResult;
        if (innerResult == kIOReturnSuccess) {
            UInt8 rawSSID[APPLE80211_MAX_SSID_LEN] = {};
            UInt32 length = value.ssid_len;
            if (length > APPLE80211_MAX_SSID_LEN)
                length = APPLE80211_MAX_SSID_LEN;
            if (length)
                memcpy(rawSSID, value.ssid_bytes, length);
            const int copyoutResult = copyout(
                rawSSID, requestData, sizeof(rawSSID));
            if (copyoutResult != 0)
                finalResult = (SInt32)copyoutResult;
            else {
                owner->setProperty(
                    "AirportRTW89PostRUNRawSSIDMarshallerSucceeded",
                    kOSBooleanTrue);
                owner->setProperty(
                    "AirportRTW89PostRUNSSIDPublicationSucceeded",
                    kOSBooleanTrue);
            }
        }
        owner->setProperty("AirportRTW89PostRUNRawSSIDMarshallerSeen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89PostRUNRawSSIDMarshallerInnerReturn",
                           (uint64_t)(uint32_t)innerResult, 32);
        owner->setProperty("AirportRTW89PostRUNRawSSIDMarshallerFinalReturn",
                           (uint64_t)(uint32_t)finalResult, 32);
        *outResult = finalResult;
        return true;
    }

    if (!isSet && requestData &&
        request == APPLE80211_IOC_BSSID &&
        requestLength == APPLE80211_ADDR_LEN) {
        apple80211_bssid_data value = {};
        const SInt32 innerResult = owner->apple80211Request(
            (unsigned int)SIOCGA80211, (int)request, interface, &value);
        SInt32 finalResult = innerResult;
        if (innerResult == kIOReturnSuccess) {
            const int copyoutResult = copyout(
                value.bssid.octet, requestData, APPLE80211_ADDR_LEN);
            if (copyoutResult != 0)
                finalResult = (SInt32)copyoutResult;
            else {
                owner->setProperty(
                    "AirportRTW89PostRUNRawBSSIDMarshallerSucceeded",
                    kOSBooleanTrue);
                owner->setProperty(
                    "AirportRTW89PostRUNBSSIDPublicationSucceeded",
                    kOSBooleanTrue);
            }
        }
        owner->setProperty("AirportRTW89PostRUNRawBSSIDMarshallerSeen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89PostRUNRawBSSIDMarshallerInnerReturn",
                           (uint64_t)(uint32_t)innerResult, 32);
        owner->setProperty("AirportRTW89PostRUNRawBSSIDMarshallerFinalReturn",
                           (uint64_t)(uint32_t)finalResult, 32);
        *outResult = finalResult;
        return true;
    }

    if (!requestData || requestLength < spec.size || spec.size == 0 ||
        spec.size > 16384U)
        return false;

    void *payload = IOMalloc(spec.size);
    if (!payload) {
        *outResult = kIOReturnNoMemory;
        return true;
    }
    bzero(payload, spec.size);

    /* Copy the public prefix for both GET and SET.  Apple callers seed GET
     * structures with version/input fields, so preserving that seed matches
     * IO80211Interface's typed marshalling contract more closely than handing
     * the controller an all-zero object. */
    const int copyinResult = copyin(requestData, payload, spec.size);
    SInt32 innerResult = copyinResult == 0
        ? owner->apple80211Request(
              isSet ? (unsigned int)SIOCSA80211
                    : (unsigned int)SIOCGA80211,
              (int)request, interface, payload)
        : (SInt32)copyinResult;

    int copyoutResult = 0;
    size_t copyoutLength = 0;
    SInt32 finalResult = innerResult;
    if (!isSet && innerResult == kIOReturnSuccess) {
        copyoutLength = spec.size;
        /* Tahoe supplies a 4824-byte private capacity for GET27 while the
         * public object is 776 bytes.  Copy only the populated version/count
         * and channel entries, matching the already-proven direct bridge and
         * leaving the unknown private tail untouched. */
        if (request == APPLE80211_IOC_SUPPORTED_CHANNELS ||
            request == APPLE80211_IOC_HW_SUPPORTED_CHANNELS) {
            const apple80211_sup_channel_data *channels =
                static_cast<const apple80211_sup_channel_data *>(payload);
            UInt32 channelCount = channels->num_channels;
            if (channelCount > APPLE80211_MAX_CHANNELS)
                channelCount = APPLE80211_MAX_CHANNELS;
            const size_t usedLength =
                offsetof(apple80211_sup_channel_data, supported_channels) +
                (size_t)channelCount * sizeof(apple80211_channel);
            if (usedLength <= spec.size)
                copyoutLength = usedLength;
        }
        copyoutResult = copyout(payload, requestData, copyoutLength);
        if (copyoutResult != 0)
            finalResult = (SInt32)copyoutResult;
    }

    /* 0.3.6: SSID/BSSID/CURRENT_NETWORK now use the same explicit fixed-size
     * marshalling path as the other public Apple80211 structures.  The inner
     * handlers retain IO80211Reference's pre-RUN failures, so a successful copyout
     * here is necessarily publication of real associated state, not a
     * pre-SET20 empty-success invention. */
    if (!isSet && finalResult == kIOReturnSuccess) {
        if (request == APPLE80211_IOC_SSID)
            owner->setProperty("AirportRTW89PostRUNSSIDPublicationSucceeded",
                               kOSBooleanTrue);
        else if (request == APPLE80211_IOC_BSSID)
            owner->setProperty("AirportRTW89PostRUNBSSIDPublicationSucceeded",
                               kOSBooleanTrue);
        else if (request == APPLE80211_IOC_CHANNEL)
            owner->setProperty("AirportRTW89PostRUNChannelPublicationSucceeded",
                               kOSBooleanTrue);
        else if (request == APPLE80211_IOC_CURRENT_NETWORK)
            owner->setProperty("AirportRTW89PostRUNCurrentNetworkPublicationSucceeded",
                               kOSBooleanTrue);
    }

    static volatile UInt32 marshalCount = 0;
    const UInt32 count = __sync_add_and_fetch(&marshalCount, 1U);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerSeen",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerCount",
                       (uint64_t)count, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerRequest",
                       (uint64_t)request, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerIsSet",
                       isSet ? kOSBooleanTrue : kOSBooleanFalse);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerReqLen",
                       (uint64_t)requestLength, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerCanonicalSize",
                       (uint64_t)spec.size, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerCopyinReturn",
                       (uint64_t)(uint32_t)copyinResult, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerInnerReturn",
                       (uint64_t)(uint32_t)innerResult, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerCopyoutReturn",
                       (uint64_t)(uint32_t)copyoutResult, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerCopyoutLength",
                       (uint64_t)copyoutLength, 32);
    owner->setProperty(
        "AirportRTW89ExplicitLegacyMarshallerSupportedChannelsUsedPrefix",
        (!isSet && finalResult == kIOReturnSuccess &&
         (request == APPLE80211_IOC_SUPPORTED_CHANNELS ||
          request == APPLE80211_IOC_HW_SUPPORTED_CHANNELS))
            ? kOSBooleanTrue : kOSBooleanFalse);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerFinalReturn",
                       (uint64_t)(uint32_t)finalResult, 32);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerIO80211ReferenceABI",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89ExplicitLegacyMarshallerReturnNormalized",
                       kOSBooleanFalse);

    /* The payload can contain authentication/key material on SET. Never leave
     * a copied userspace payload in freed kernel memory. */
    bzero(payload, spec.size);
    IOFree(payload, spec.size);

    *outResult = finalResult;
    return true;
}

static UInt64 airportOuterStatusDiagHash(const UInt8 *bytes, size_t length)
{
    UInt64 hash = 1469598103934665603ULL;
    if (!bytes)
        return hash;
    for (size_t i = 0; i < length; ++i) {
        hash ^= (UInt64)bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* 0.2.217 privacy-safe user-buffer metadata for the Tahoe GET103 probe.
 * Never retain payload bytes.  A bounded chunked copyin records only the
 * number/location/value of the first non-zero byte plus an FNV-1a hash.  This
 * is sufficient to distinguish a caller-seeded version byte from data written
 * by IO80211Interface::performCommand() without publishing SSID/BSSID or other
 * CURRENT_NETWORK contents. */
struct AirportUserBufferMetadata {
    int copyinResult;
    UInt32 bytesChecked;
    UInt32 nonZeroBytes;
    UInt32 firstNonZeroOffset;
    UInt32 firstNonZeroValue;
    UInt32 hash;
};

static AirportUserBufferMetadata airportInspectUserBuffer(
    user_addr_t address, UInt32 length)
{
    AirportUserBufferMetadata meta = {};
    meta.copyinResult = 0;
    meta.firstNonZeroOffset = 0xffffffffU;
    meta.hash = 2166136261U;
    if (!address || length == 0)
        return meta;

    UInt8 chunk[64] = {};
    for (UInt32 offset = 0; offset < length; offset += sizeof(chunk)) {
        UInt32 copyLength = length - offset;
        if (copyLength > sizeof(chunk))
            copyLength = sizeof(chunk);
        bzero(chunk, sizeof(chunk));
        meta.copyinResult = copyin(address + offset, chunk, copyLength);
        if (meta.copyinResult != 0)
            break;
        meta.bytesChecked += copyLength;
        for (UInt32 i = 0; i < copyLength; ++i) {
            const UInt8 value = chunk[i];
            meta.hash ^= (UInt32)value;
            meta.hash *= 16777619U;
            if (value != 0) {
                if (meta.nonZeroBytes == 0) {
                    meta.firstNonZeroOffset = offset + i;
                    meta.firstNonZeroValue = value;
                }
                ++meta.nonZeroBytes;
            }
        }
    }
    return meta;
}

/* 0.2.217 IO80211Reference parity trace for requests that actually traverse
 * IO80211Interface::performCommand().  The existing 0.2.214 WPA2 ring remains
 * the authoritative outer ordering trace and also covers direct bridges.  This
 * companion ring answers a narrower question: for each inherited call, did
 * Apple's superclass synchronously enter our controller dispatcher, on the
 * same interface/thread, and what state/buffer metadata surrounded that hop?
 *
 * No Apple80211 payload bytes are stored. */
struct IO80211ReferenceParityTraceEntry {
    UInt64 enterMonotonicMS;
    UInt64 exitMonotonicMS;
    UInt32 sequence;
    UInt32 windowSequence;
    SInt32 requestType;
    SInt32 requestValue;
    UInt32 requestLength;
    UInt32 flags;
    SInt32 superclassReturn;
    SInt32 finalReturn;
    UInt32 dispatcherRawRequestType;
    SInt32 dispatcherRawRequestNumber;
    UInt32 dispatcherNormalizedRequest;
    SInt32 dispatcherReturn;
    UInt32 rawStateBefore;
    UInt32 rawStateAfter;
    UInt32 bssCountBefore;
    UInt32 bssCountAfter;
    UInt32 scanSerialBefore;
    UInt32 scanSerialAfter;
    UInt32 preNonZeroBytes;
    UInt32 preFirstNonZeroOffset;
    UInt32 preFirstNonZeroValue;
    UInt32 preHash;
    UInt32 postNonZeroBytes;
    UInt32 postFirstNonZeroOffset;
    UInt32 postFirstNonZeroValue;
    UInt32 postHash;
};
static_assert(sizeof(IO80211ReferenceParityTraceEntry) == 120,
              "IO80211Reference parity trace entry size mismatch");

enum : UInt32 {
    kParityTraceSet = 1U << 0,
    kParityTraceEnvelope40 = 1U << 1,
    kParityTraceDataPresent = 1U << 2,
    kParityTraceScopeAllocated = 1U << 3,
    kParityTraceDispatcherEntered = 1U << 4,
    kParityTraceDispatcherDirectionMatch = 1U << 5,
    kParityTraceDispatcherRequestMatch = 1U << 6,
    kParityTraceDispatcherInterfaceMatch = 1U << 7,
    kParityTraceControllerMatchesOwner = 1U << 8,
    kParityTraceConnectedBefore = 1U << 9,
    kParityTraceConnectedAfter = 1U << 10,
    kParityTraceLogicalPowerBefore = 1U << 11,
    kParityTraceUserPowerBefore = 1U << 12,
    kParityTraceSystemEnabledBefore = 1U << 13,
    kParityTraceAssocPendingBefore = 1U << 14,
    kParityTraceCurrentNetworkScanned = 1U << 15,
    kParityTraceCurrentNetworkChanged = 1U << 16,
    kParityTraceGET1WouldNormalize = 1U << 17,
    kParityTraceGET103WouldNormalize = 1U << 18,
    kParityTraceSET22 = 1U << 19,
    kParityTraceSET20 = 1U << 20,
    kParityTraceScopeCollision = 1U << 21,
    kParityTraceGET9WouldNormalize = 1U << 22,
    kParityTraceGET16WouldNormalize = 1U << 23,
    kParityTraceComplete = 1U << 31,
};

static IO80211ReferenceParityTraceEntry gIO80211ReferenceParityTraceRing[256] = {};
static volatile UInt32 gIO80211ReferenceParityTraceOrdinal = 0;

/* 0.2.214: bounded, metadata-only native WPA2 pre-SET20 trace.
 *
 * This deliberately lives outside performCommand() so the 64-entry ring and
 * trace bookkeeping do not consume kernel stack in the already-large Apple
 * ioctl marshaller. The ring starts at SET22/DISASSOCIATE and records at most
 * the next eight seconds of outer Apple80211 traffic. No request payload bytes
 * are captured, so SSIDs/passwords/keys are not retained here. */
struct AirportWPA2PreflightTraceEntry {
    UInt64 enterMonotonicMS;
    UInt64 exitMonotonicMS;
    UInt32 windowSequence;
    UInt32 ordinal;
    SInt32 requestType;
    SInt32 requestValue;
    UInt32 requestLength;
    UInt32 flags;
    SInt32 result;
    UInt32 reserved;
};
static_assert(sizeof(AirportWPA2PreflightTraceEntry) == 48,
              "WPA2 preflight trace entry size mismatch");

struct AirportWPA2PreflightTraceCookie {
    UInt32 slot;
    UInt32 ordinal;
    UInt32 windowSequence;
    UInt8 prefixSlot;
    bool active;
    bool prefixActive;
};

enum : UInt32 {
    kWPA2TraceSet = 1U << 0,
    kWPA2TraceEnvelope40 = 1U << 1,
    kWPA2TraceDataPresent = 1U << 2,
    kWPA2TraceWindow = 1U << 3,
    kWPA2TraceSuperclass = 1U << 4,
    kWPA2TraceDirectBridge = 1U << 5,
    kWPA2TraceDirectGet11 = 1U << 6,
    kWPA2TraceDIS22 = 1U << 7,
    kWPA2TraceSET20 = 1U << 8,
    kWPA2TraceComplete = 1U << 31,
};

static AirportWPA2PreflightTraceEntry gAirportWPA2PreflightTraceRing[256] = {};
static volatile UInt32 gAirportWPA2PreflightTraceWindowSequence = 0;
static volatile UInt32 gAirportWPA2PreflightTraceOrdinal = 0;
static volatile UInt32 gAirportWPA2PreflightTraceWindowActive = 0;
static volatile UInt64 gAirportWPA2PreflightTraceWindowStartMS = 0;

/* 0.2.260: non-wrapping first-prefix recorder for the security preflight.
 *
 * The 0.2.259 WPA2 run proved the legacy bind is healthy but the existing
 * 64-entry circular preflight trace wrapped before the decisive SET22 ->
 * missing-SET20 prefix could be inspected.  Preserve the first 64 metadata
 * entries of each newly-started SET22 window and then freeze them permanently
 * until the next window starts.  This is observation-only: no payload bytes,
 * SSIDs, BSSIDs, credentials, RSN IE bytes, or key bytes are retained. */
struct AirportWPA2SecurityPrefixTraceEntry {
    UInt64 enterMonotonicMS;
    UInt64 exitMonotonicMS;
    UInt32 windowSequence;
    UInt32 ordinal;
    SInt32 requestType;
    SInt32 requestValue;
    UInt32 requestLength;
    UInt32 flags;
    SInt32 result;
    UInt32 reserved;
};
static_assert(sizeof(AirportWPA2SecurityPrefixTraceEntry) == 48,
              "WPA2 security prefix trace entry size mismatch");

static AirportWPA2SecurityPrefixTraceEntry
    gAirportWPA2SecurityPrefixTrace[64] = {};
static volatile UInt32 gAirportWPA2SecurityPrefixCount = 0;
static volatile UInt32 gAirportWPA2SecurityPrefixFrozen = 0;
static volatile UInt32 gAirportWPA2SecurityPrefixWindowSequence = 0;
static volatile UInt64 gAirportWPA2SecurityPrefixStartMS = 0;

static UInt64 airportWPA2PreflightMonotonicMS()
{
    uint64_t nowNs = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
    return nowNs / 1000000ULL;
}

/* 0.3.6: timestamp every controller/interface/Skywalk user-client open stage.
 * The WPA2 capture showed CWEAPOLClient::eapolClientControlMode activity that
 * was not synchronous with the old type-0 counters.  Preserve only endpoint
 * metadata -- no task identity, payload, entitlement, refCon, or key bytes. */
struct AirportUserClientOpenTraceEntry {
    UInt64 monotonicMS;
    UInt32 sequence;
    UInt32 endpoint; /* 1=controller, 2=legacy interface, 3=Skywalk */
    UInt32 stage;    /* 0=enter, 1=native IO80211, 2=native Skywalk,
                      * 3=custom fallback, 4=final */
    UInt32 type;
    SInt32 result;
    UInt32 flags;    /* bit0 task, bit1 securityID, bit2 properties,
                      * bit3 handler pointer, bit4 handler object */
};
static_assert(sizeof(AirportUserClientOpenTraceEntry) == 32,
              "user-client open trace entry size mismatch");

static AirportUserClientOpenTraceEntry gAirportUserClientOpenTrace[64] = {};
static volatile UInt32 gAirportUserClientOpenTraceSequence = 0;

/* 0.3.33: human-readable caller histories for the native services.  The
 * existing binary trace remains intact; these properties add process identity
 * so a secured-association attempt can be correlated with the exact service
 * that received each IOServiceOpen. */
static volatile UInt32 gAirportControllerUserClientHistorySequence = 0;
static volatile UInt32 gAirportInterfaceUserClientHistorySequence = 0;
static volatile UInt32 gAirportSkywalkUserClientHistorySequence = 0;
static volatile UInt32 gAirportAPIClientMethodHistorySequence = 0;

static void airportRecordAPIClientMethodHistory(
    RTW88PCIDevice *owner, const char *operation, UInt32 selector)
{
    if (!owner || !operation)
        return;
    const UInt32 sequence = __sync_add_and_fetch(
        &gAirportAPIClientMethodHistorySequence, 1U) - 1U;
    const UInt32 slot = sequence & 0x1fU;
    const int callerPid = proc_selfpid();
    char callerName[64] = {};
    proc_selfname(callerName, (int)sizeof(callerName));
    char key[96] = {};
    char value[192] = {};
    snprintf(key, sizeof(key),
             "AirportRTW89APIClientMethodHistory%02u", slot);
    snprintf(value, sizeof(value),
             "seq=%u ms=%llu pid=%d name=%s op=%s selector=%u",
             sequence, airportWPA2PreflightMonotonicMS(), callerPid,
             callerName[0] ? callerName : "-", operation, selector);
    owner->setProperty(key, value);
    owner->setProperty("AirportRTW89APIClientMethodHistorySequence",
                       (uint64_t)sequence, 32);
    owner->setProperty("AirportRTW89APIClientMethodHistorySlot",
                       (uint64_t)slot, 32);
}

static void airportRecordNamedUserClientHistory(
    RTW88PCIDevice *owner, const char *prefix, volatile UInt32 *sequencePtr,
    UInt32 type, IOReturn result, IOUserClient **handler)
{
    if (!owner || !prefix || !sequencePtr)
        return;
    const UInt32 sequence = __sync_add_and_fetch(sequencePtr, 1U) - 1U;
    const UInt32 slot = sequence & 0x0fU;
    const int callerPid = proc_selfpid();
    char callerName[64] = {};
    proc_selfname(callerName, (int)sizeof(callerName));
    const bool created = handler && *handler;
    const char *createdClass = "-";
    if (created) {
        const OSMetaClass *meta = (*handler)->getMetaClass();
        if (meta && meta->getClassName())
            createdClass = meta->getClassName();
    }
    char key[128] = {};
    char value[256] = {};
    snprintf(key, sizeof(key), "%sHistory%02u", prefix, slot);
    snprintf(value, sizeof(value),
             "seq=%u pid=%d name=%s type=%u ret=0x%08x created=%u class=%s",
             sequence, callerPid, callerName[0] ? callerName : "-", type,
             (uint32_t)result, created ? 1U : 0U, createdClass);
    owner->setProperty(key, value);
    snprintf(key, sizeof(key), "%sHistorySequence", prefix);
    owner->setProperty(key, (uint64_t)sequence, 32);
    snprintf(key, sizeof(key), "%sHistorySlot", prefix);
    owner->setProperty(key, (uint64_t)slot, 32);
}

static void airportRecordUserClientOpen(
    RTW88PCIDevice *owner, UInt32 endpoint, UInt32 stage, UInt32 type,
    SInt32 result, task_t owningTask, void *securityID,
    OSDictionary *properties, IOUserClient **handler)
{
    if (!owner)
        return;
    const UInt32 sequence = __sync_add_and_fetch(
        &gAirportUserClientOpenTraceSequence, 1U);
    AirportUserClientOpenTraceEntry &entry =
        gAirportUserClientOpenTrace[(sequence - 1U) & 63U];
    bzero(&entry, sizeof(entry));
    entry.monotonicMS = airportWPA2PreflightMonotonicMS();
    entry.sequence = sequence;
    entry.endpoint = endpoint;
    entry.stage = stage;
    entry.type = type;
    entry.result = result;
    if (owningTask) entry.flags |= 1U << 0;
    if (securityID) entry.flags |= 1U << 1;
    if (properties) entry.flags |= 1U << 2;
    if (handler) entry.flags |= 1U << 3;
    if (handler && *handler) entry.flags |= 1U << 4;

    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceSeen",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceSequence",
                       (uint64_t)sequence, 32);
    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceLastMS",
                       (uint64_t)entry.monotonicMS, 64);
    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceLastEndpoint",
                       (uint64_t)endpoint, 32);
    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceLastStage",
                       (uint64_t)stage, 32);
    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceLastType",
                       (uint64_t)type, 32);
    owner->setProperty("AirportRTW89EAPOLControlUserClientTraceLastReturn",
                       (uint64_t)(uint32_t)result, 32);
    if (OSData *traceData = OSData::withBytes(
            gAirportUserClientOpenTrace, sizeof(gAirportUserClientOpenTrace))) {
        owner->setProperty("AirportRTW89EAPOLControlUserClientTrace", traceData);
        traceData->release();
    }
}

static AirportWPA2PreflightTraceCookie airportWPA2PreflightTraceBegin(
    RTW88PCIDevice *owner, bool isSet, bool is40, SInt32 reqType,
    SInt32 reqVal, UInt32 reqLen, user_addr_t reqData)
{
    AirportWPA2PreflightTraceCookie cookie = {};
    if (!owner)
        return cookie;

    const UInt64 nowMS = airportWPA2PreflightMonotonicMS();
    const bool startsWindow =
        isSet && reqType == APPLE80211_IOC_DISASSOCIATE;

    UInt32 windowSequence = gAirportWPA2PreflightTraceWindowSequence;
    UInt32 activeValue = __sync_add_and_fetch(
        &gAirportWPA2PreflightTraceWindowActive, 0U);
    if (activeValue != 0U) {
        const UInt32 observedSequence =
            gAirportWPA2PreflightTraceWindowSequence;
        const UInt64 observedStart = gAirportWPA2PreflightTraceWindowStartMS;
        if (nowMS >= observedStart + 8000ULL &&
            observedSequence == gAirportWPA2PreflightTraceWindowSequence &&
            observedStart == gAirportWPA2PreflightTraceWindowStartMS) {
            __sync_bool_compare_and_swap(
                &gAirportWPA2PreflightTraceWindowActive, 1U, 0U);
        }
    }

    bool startedNewWindow = false;
    activeValue = __sync_add_and_fetch(
        &gAirportWPA2PreflightTraceWindowActive, 0U);
    if (startsWindow && activeValue == 0U) {
        windowSequence = __sync_add_and_fetch(
            &gAirportWPA2PreflightTraceWindowSequence, 1U);
        gAirportWPA2PreflightTraceWindowStartMS = nowMS;
        __sync_synchronize();
        __sync_lock_test_and_set(&gAirportWPA2PreflightTraceWindowActive, 1U);
        startedNewWindow = true;
    } else {
        windowSequence = gAirportWPA2PreflightTraceWindowSequence;
    }

    if (startedNewWindow) {
        bzero(gAirportWPA2SecurityPrefixTrace,
              sizeof(gAirportWPA2SecurityPrefixTrace));
        __sync_lock_test_and_set(&gAirportWPA2SecurityPrefixCount, 0U);
        __sync_lock_test_and_set(&gAirportWPA2SecurityPrefixFrozen, 0U);
        __sync_lock_test_and_set(&gAirportWPA2SecurityPrefixWindowSequence,
                                 windowSequence);
        gAirportWPA2SecurityPrefixStartMS = nowMS;
        __sync_synchronize();

        owner->setProperty("AirportRTW89WPA2SecurityPrefixEnabled",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixDiagnosticOnly",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixPayloadCaptured",
                           kOSBooleanFalse);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixStartedBySET22",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixWindowSequence",
                           (uint64_t)windowSequence, 32);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixStartMS",
                           (uint64_t)nowMS, 64);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixCount",
                           (uint64_t)0, 32);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixFrozen",
                           kOSBooleanFalse);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixSET20Seen",
                           kOSBooleanFalse);
        owner->setProperty("AirportRTW89WPA2SecurityPrefixEntrySize",
                           (uint64_t)sizeof(AirportWPA2SecurityPrefixTraceEntry),
                           32);
    }

    const bool active = __sync_add_and_fetch(
                            &gAirportWPA2PreflightTraceWindowActive, 0U) != 0U;
    if (!active) {
        owner->setProperty("AirportRTW89WPA2PreflightTraceEnabled",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89WPA2PreflightTraceWindowActive",
                           kOSBooleanFalse);
        return cookie;
    }

    windowSequence = gAirportWPA2PreflightTraceWindowSequence;
    const UInt32 ordinal = __sync_add_and_fetch(
        &gAirportWPA2PreflightTraceOrdinal, 1U);
    const UInt32 slot = (ordinal - 1U) & 255U;
    AirportWPA2PreflightTraceEntry &entry =
        gAirportWPA2PreflightTraceRing[slot];

    bzero(&entry, sizeof(entry));
    entry.enterMonotonicMS = nowMS;
    entry.exitMonotonicMS = 0;
    entry.windowSequence = windowSequence;
    entry.requestType = reqType;
    entry.requestValue = reqVal;
    entry.requestLength = reqLen;
    entry.flags = (isSet ? kWPA2TraceSet : 0U) |
                  (is40 ? kWPA2TraceEnvelope40 : 0U) |
                  (reqData != 0 ? kWPA2TraceDataPresent : 0U) |
                  kWPA2TraceWindow |
                  (startsWindow ? kWPA2TraceDIS22 : 0U) |
                  (isSet && reqType == APPLE80211_IOC_ASSOCIATE
                       ? kWPA2TraceSET20 : 0U);
    entry.result = (SInt32)0x7fffffff;
    __sync_synchronize();
    entry.ordinal = ordinal;

    cookie.slot = slot;
    cookie.ordinal = ordinal;
    cookie.windowSequence = windowSequence;
    cookie.active = true;

    if (gAirportWPA2SecurityPrefixWindowSequence == windowSequence &&
        __sync_add_and_fetch(&gAirportWPA2SecurityPrefixFrozen, 0U) == 0U) {
        UInt32 prefixSlot = 64U;
        while (true) {
            const UInt32 observed = __sync_add_and_fetch(
                &gAirportWPA2SecurityPrefixCount, 0U);
            if (observed >= 64U) {
                __sync_lock_test_and_set(&gAirportWPA2SecurityPrefixFrozen,
                                         1U);
                break;
            }
            if (__sync_bool_compare_and_swap(&gAirportWPA2SecurityPrefixCount,
                                             observed, observed + 1U)) {
                prefixSlot = observed;
                break;
            }
        }

        if (prefixSlot < 64U) {
            AirportWPA2SecurityPrefixTraceEntry &prefixEntry =
                gAirportWPA2SecurityPrefixTrace[prefixSlot];
            bzero(&prefixEntry, sizeof(prefixEntry));
            prefixEntry.enterMonotonicMS = nowMS;
            prefixEntry.windowSequence = windowSequence;
            prefixEntry.ordinal = prefixSlot + 1U;
            prefixEntry.requestType = reqType;
            prefixEntry.requestValue = reqVal;
            prefixEntry.requestLength = reqLen;
            prefixEntry.flags = (isSet ? kWPA2TraceSet : 0U) |
                                (is40 ? kWPA2TraceEnvelope40 : 0U) |
                                (reqData != 0 ? kWPA2TraceDataPresent : 0U) |
                                kWPA2TraceWindow |
                                (startsWindow ? kWPA2TraceDIS22 : 0U) |
                                (isSet && reqType == APPLE80211_IOC_ASSOCIATE
                                     ? kWPA2TraceSET20 : 0U);
            prefixEntry.result = (SInt32)0x7fffffff;
            __sync_synchronize();

            cookie.prefixSlot = (UInt8)prefixSlot;
            cookie.prefixActive = true;

            if (prefixSlot + 1U >= 64U)
                __sync_lock_test_and_set(&gAirportWPA2SecurityPrefixFrozen,
                                         1U);

            const UInt32 prefixCount = __sync_add_and_fetch(
                &gAirportWPA2SecurityPrefixCount, 0U);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixCount",
                               (uint64_t)(prefixCount > 64U ? 64U
                                                           : prefixCount),
                               32);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixFrozen",
                               __sync_add_and_fetch(
                                   &gAirportWPA2SecurityPrefixFrozen, 0U) != 0U
                                   ? kOSBooleanTrue : kOSBooleanFalse);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastReqType",
                               (uint64_t)(UInt32)reqType, 32);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastReqVal",
                               (uint64_t)(UInt32)reqVal, 32);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastReqLen",
                               (uint64_t)reqLen, 32);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastIsSet",
                               isSet ? kOSBooleanTrue : kOSBooleanFalse);
        }
    }

    const UInt32 ringCount = ordinal < 256U ? ordinal : 256U;
    owner->setProperty("AirportRTW89WPA2PreflightTraceEnabled",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89WPA2PreflightTracePayloadCaptured",
                       kOSBooleanFalse);
    owner->setProperty("AirportRTW89WPA2PreflightTraceWindowMS",
                       (uint64_t)8000, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceWindowSequence",
                       (uint64_t)windowSequence, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceWindowStartMS",
                       (uint64_t)gAirportWPA2PreflightTraceWindowStartMS, 64);
    owner->setProperty("AirportRTW89WPA2PreflightTraceWindowActive",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89WPA2PreflightTraceRingIndex",
                       (uint64_t)(ordinal & 255U), 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceRingCount",
                       (uint64_t)ringCount, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceEntrySize",
                       (uint64_t)sizeof(AirportWPA2PreflightTraceEntry), 32);
    if (startsWindow) {
        owner->setProperty("AirportRTW89WPA2PreflightTraceStartedBySET22",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89WPA2PreflightTraceSET22LastMS",
                           (uint64_t)nowMS, 64);
    }
    if (startedNewWindow) {
        owner->setProperty("AirportRTW89WPA2PreflightTraceSET22StartMS",
                           (uint64_t)nowMS, 64);
        owner->setProperty("AirportRTW89WPA2PreflightTraceSET20Seen",
                           kOSBooleanFalse);
    }
    return cookie;
}

static SInt32 airportWPA2PreflightTraceFinish(
    RTW88PCIDevice *owner, const AirportWPA2PreflightTraceCookie &cookie,
    SInt32 returnValue, UInt32 pathFlags)
{
    if (!owner || !cookie.active)
        return returnValue;

    const UInt64 exitMS = airportWPA2PreflightMonotonicMS();
    AirportWPA2PreflightTraceEntry &entry =
        gAirportWPA2PreflightTraceRing[cookie.slot & 255U];
    bool entryStillOwned = false;

    if (entry.ordinal == cookie.ordinal &&
        entry.windowSequence == cookie.windowSequence) {
        entry.exitMonotonicMS = exitMS;
        entry.flags |= pathFlags | kWPA2TraceComplete;
        entry.result = returnValue;
        __sync_synchronize();
        entryStillOwned = true;
    }

    bool prefixEntryStillOwned = false;
    if (cookie.prefixActive && cookie.prefixSlot < 64U) {
        AirportWPA2SecurityPrefixTraceEntry &prefixEntry =
            gAirportWPA2SecurityPrefixTrace[cookie.prefixSlot];
        if (prefixEntry.ordinal == cookie.prefixSlot + 1U &&
            prefixEntry.windowSequence == cookie.windowSequence) {
            prefixEntry.exitMonotonicMS = exitMS;
            prefixEntry.flags |= pathFlags | kWPA2TraceComplete;
            prefixEntry.result = returnValue;
            __sync_synchronize();
            prefixEntryStillOwned = true;

            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastReturn",
                               (uint64_t)(uint32_t)returnValue, 32);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastExitMS",
                               (uint64_t)exitMS, 64);
            owner->setProperty("AirportRTW89WPA2SecurityPrefixLastOrdinal",
                               (uint64_t)(cookie.prefixSlot + 1U), 32);
            owner->setProperty(
                "AirportRTW89WPA2SecurityPrefixEntryStillOwned",
                kOSBooleanTrue);

            if ((prefixEntry.flags & kWPA2TraceSET20) != 0U)
                owner->setProperty(
                    "AirportRTW89WPA2SecurityPrefixSET20Seen",
                    kOSBooleanTrue);

            if (OSData *prefixData = OSData::withBytes(
                    gAirportWPA2SecurityPrefixTrace,
                    sizeof(gAirportWPA2SecurityPrefixTrace))) {
                owner->setProperty("AirportRTW89WPA2SecurityPrefixTrace",
                                   prefixData);
                prefixData->release();
            }
        }
    }
    if (cookie.prefixActive && !prefixEntryStillOwned)
        owner->setProperty("AirportRTW89WPA2SecurityPrefixEntryStillOwned",
                           kOSBooleanFalse);

    const bool isSET20 = entryStillOwned &&
                         (entry.flags & kWPA2TraceSET20) != 0U;
    if (isSET20 &&
        cookie.windowSequence == gAirportWPA2PreflightTraceWindowSequence) {
        __sync_lock_test_and_set(&gAirportWPA2PreflightTraceWindowActive, 0U);
    }

    owner->setProperty("AirportRTW89WPA2PreflightTraceLastReqType",
                       (uint64_t)(uint32_t)entry.requestType, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceLastReqVal",
                       (uint64_t)(uint32_t)entry.requestValue, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceLastReqLen",
                       (uint64_t)entry.requestLength, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceLastIsSet",
                       (entry.flags & kWPA2TraceSet) != 0U
                           ? kOSBooleanTrue : kOSBooleanFalse);
    owner->setProperty("AirportRTW89WPA2PreflightTraceLastReturn",
                       (uint64_t)(uint32_t)returnValue, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceLastExitMS",
                       (uint64_t)exitMS, 64);
    owner->setProperty("AirportRTW89WPA2PreflightTraceLastOrdinal",
                       (uint64_t)cookie.ordinal, 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceEntryStillOwned",
                       entryStillOwned ? kOSBooleanTrue : kOSBooleanFalse);
    owner->setProperty("AirportRTW89WPA2PreflightTraceWindowActive",
                       __sync_add_and_fetch(
                           &gAirportWPA2PreflightTraceWindowActive, 0U) != 0U
                           ? kOSBooleanTrue : kOSBooleanFalse);

    if (returnValue != kIOReturnSuccess) {
        owner->setProperty(
            "AirportRTW89WPA2PreflightTraceLastNonSuccessReqType",
            (uint64_t)(uint32_t)entry.requestType, 32);
        owner->setProperty(
            "AirportRTW89WPA2PreflightTraceLastNonSuccessReturn",
            (uint64_t)(uint32_t)returnValue, 32);
        owner->setProperty(
            "AirportRTW89WPA2PreflightTraceLastNonSuccessExitMS",
            (uint64_t)exitMS, 64);
    }
    if (isSET20) {
        owner->setProperty("AirportRTW89WPA2PreflightTraceSET20Seen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89WPA2PreflightTraceSET20Return",
                           (uint64_t)(uint32_t)returnValue, 32);
    }

    const UInt32 ordinal = gAirportWPA2PreflightTraceOrdinal;
    const UInt32 ringCount = ordinal < 256U ? ordinal : 256U;
    owner->setProperty("AirportRTW89WPA2PreflightTraceRingIndex",
                       (uint64_t)(ordinal & 255U), 32);
    owner->setProperty("AirportRTW89WPA2PreflightTraceRingCount",
                       (uint64_t)ringCount, 32);
    if (OSData *traceData = OSData::withBytes(
            gAirportWPA2PreflightTraceRing,
            sizeof(gAirportWPA2PreflightTraceRing))) {
        owner->setProperty("AirportRTW89WPA2PreflightTraceRing", traceData);
        traceData->release();
    }
    return returnValue;
}
#endif


/* ------------------------------------------------------------------ */
/*  PCI ops shim (C linkage, called from driver C code)                */
/* ------------------------------------------------------------------ */

static RTW88PCIDevice *g_pci_dev_instance = nullptr;

static int compat_pci_read_config_byte(struct pci_dev *dev, int where, u8 *val)
{
    if (!g_pci_dev_instance) { *val = 0xff; return -1; }
    *val = g_pci_dev_instance->pciReadByte(where);
    return 0;
}
static int compat_pci_read_config_word(struct pci_dev *dev, int where, u16 *val)
{
    if (!g_pci_dev_instance) { *val = 0xffff; return -1; }
    *val = g_pci_dev_instance->pciReadWord(where);
    return 0;
}
static int compat_pci_read_config_dword(struct pci_dev *dev, int where, u32 *val)
{
    if (!g_pci_dev_instance) { *val = 0xffffffff; return -1; }
    *val = g_pci_dev_instance->pciReadDword(where);
    return 0;
}
static int compat_pci_write_config_byte(struct pci_dev *dev, int where, u8 val)
{
    if (!g_pci_dev_instance) return -1;
    g_pci_dev_instance->pciWriteByte(where, val);
    return 0;
}
static int compat_pci_write_config_word(struct pci_dev *dev, int where, u16 val)
{
    if (!g_pci_dev_instance) return -1;
    g_pci_dev_instance->pciWriteWord(where, val);
    return 0;
}
static int compat_pci_write_config_dword(struct pci_dev *dev, int where, u32 val)
{
    if (!g_pci_dev_instance) return -1;
    g_pci_dev_instance->pciWriteDword(where, val);
    return 0;
}
static void *compat_ioremap(struct pci_dev *dev, int bar, size_t len)
{
    /* Already mapped at start; just return the cached base */
    return (void *)g_pci_dev_instance->mmioBase();
}
static void compat_iounmap(struct pci_dev *dev, void *addr) {}

static int compat_enable_msi(struct pci_dev *dev)
{
    /* Handled by IOInterruptEventSource in setupInterrupt() */
    return 0;
}
static void compat_disable_msi(struct pci_dev *dev) {}

static int compat_pci_find_capability(struct pci_dev *dev, int cap)
{
    if (!g_pci_dev_instance) return 0;
    return g_pci_dev_instance->pciFindCapability(cap);
}

static struct pci_ops_rtw88 _pci_io_ops = {
    .read_config_byte   = compat_pci_read_config_byte,
    .read_config_word   = compat_pci_read_config_word,
    .read_config_dword  = compat_pci_read_config_dword,
    .write_config_byte  = compat_pci_write_config_byte,
    .write_config_word  = compat_pci_write_config_word,
    .write_config_dword = compat_pci_write_config_dword,
    .ioremap            = compat_ioremap,
    .iounmap            = compat_iounmap,
    .enable_msi         = compat_enable_msi,
    .disable_msi        = compat_disable_msi,
    .pci_find_capability = compat_pci_find_capability,
};



/* DMA ops shim */
static void *compat_dma_alloc(struct device *dev, size_t size,
                               dma_addr_t *dma_handle, gfp_t flag)
{
    if (!g_pci_dev_instance) return nullptr;
    IOPhysicalAddress phys = 0;
    void *virt = g_pci_dev_instance->allocCoherent(size, &phys);
    if (dma_handle) *dma_handle = (dma_addr_t)phys;
    return virt;
}
static void compat_dma_free(struct device *dev, size_t size,
                             void *cpu_addr, dma_addr_t dma_handle)
{
    if (g_pci_dev_instance)
        g_pci_dev_instance->freeCoherent(size, cpu_addr,
                                          (IOPhysicalAddress)dma_handle);
}
static dma_addr_t compat_dma_map(struct device *dev, void *ptr,
                                   size_t size, int dir)
{
    /*
     * Always bounce: allocate a physically-contiguous <4GB buffer, record the
     * original CPU VA in orig_va, and hand the chip the bounce PA.
     *
     * DMA_TO_DEVICE (1): copy ptr→bounce now; chip reads from bounce.
     * DMA_FROM_DEVICE (0): don't copy now; chip writes to bounce.
     *   dma_sync_single_for_cpu() will copy bounce→ptr after chip is done.
     *
     * This is the standard software bounce-buffer strategy.  It costs a memcpy
     * per RX packet but is always correct regardless of where IOMalloc places
     * the skb data pages.
     */
    if (!g_pci_dev_instance || !ptr) return 0;

    IOPhysicalAddress phys = 0;
    void *bounce = g_pci_dev_instance->allocCoherent(size, &phys);
    if (!bounce) return 0;

    /* Store the original VA so sync_for_cpu can copy the received data back */
    g_pci_dev_instance->setBounceOrigVA((IOPhysicalAddress)phys, ptr);

    /* TX: feed the chip data now */
    if (dir == 1 /* DMA_TO_DEVICE */ || dir == 2 /* DMA_BIDIRECTIONAL */)
        memcpy(bounce, ptr, size);

    return (dma_addr_t)phys;
}
static void compat_dma_unmap(struct device *dev, dma_addr_t addr,
                               size_t size, int dir)
{
    /* Free the bounce buffer; freeCoherentByPhys is a no-op if not found */
    if (g_pci_dev_instance)
        g_pci_dev_instance->freeCoherentByPhys((IOPhysicalAddress)addr);
}
static void compat_dma_sync_cpu(struct device *dev, dma_addr_t addr,
                                  size_t size, int dir)
{
    /*
     * RX: chip finished writing to the bounce buffer.  Copy it into the
     * original skb->data buffer so the driver can read it from there.
     */
    if (dir == 0 /* DMA_FROM_DEVICE */ && g_pci_dev_instance)
        g_pci_dev_instance->syncBounceForCpu((IOPhysicalAddress)addr, size);
}
static void compat_dma_sync_dev(struct device *dev, dma_addr_t addr,
                                  size_t size, int dir)
{
    /* Re-arm for next DMA: bounce is already in place, nothing to do */
}

static struct rtw88_dma_alloc_ops _dma_ops = {
    .alloc_coherent         = compat_dma_alloc,
    .free_coherent          = compat_dma_free,
    .map_single             = compat_dma_map,
    .unmap_single           = compat_dma_unmap,
    .sync_single_for_cpu    = compat_dma_sync_cpu,
    .sync_single_for_device = compat_dma_sync_dev,
};

const char *RTW88PCIDevice::chipDisplayName() const
{
    if (!_compatPciDev)
        return "Realtek Wireless";

    switch (_compatPciDev->device) {
    case 0xB822:
        return "RTL8822BE";
    case 0xC822:
    case 0xC82F:
        return "RTL8822CE";
    case 0xC821:
    case 0xB821:
        return "RTL8821CE";
    case 0x8821:
        return "RTL8821AE";
    case 0x8812:
        return "RTL8812AE";
    case 0x8813:
        return "RTL8814AE";
    default:
        return "Realtek Wireless";
    }
}

const OSString *RTW88PCIDevice::newVendorString() const
{
    /* Ventura IO80211Reference identifies its IONetworkController vendor as
     * Apple even though the underlying PCI device remains Intel.  Match that
     * restored-framework contract without changing RTW89 PCI matching. */
    return OSString::withCString("Apple");
}

const OSString *RTW88PCIDevice::newModelString() const
{
    return OSString::withCString(chipDisplayName());
}

void RTW88PCIDevice::publishHardwareIdentity()
{
    const char *chip = chipDisplayName();

    if (_ieee80211)
        _ieee80211->getMACAddress(_macAddr.bytes);

    setName(chip);
    /* IO80211Reference presents the controller to IO80211Family as Apple while
     * retaining the actual chipset in its model/firmware strings. */
    setProperty(kIOVendor, "Apple");
    setProperty(kIOModel, chip);
    setProperty(kIORevision, RTW_DRV_NAME);
    setProperty(kIOBuiltin, kOSBooleanTrue);
    setProperty(kIOLocation, "Internal");
    setProperty("IOUserVisibleName", chip);
    setProperty("Product Name", chip);
    setProperty("Device Name", chip);
    setProperty("Model", chip);
    setProperty("Vendor", "Apple");

    if (_macAddr.bytes[0] || _macAddr.bytes[1] || _macAddr.bytes[2] ||
        _macAddr.bytes[3] || _macAddr.bytes[4] || _macAddr.bytes[5]) {
        OSData *mac = OSData::withBytes(_macAddr.bytes, sizeof(_macAddr.bytes));
        if (mac) {
            setProperty(kIOMACAddress, mac);
            mac->release();
        }
    }

    if (_iface) {
        _iface->setName(chip);
        _iface->setProperty(kIOVendor, "Apple");
        _iface->setProperty(kIOModel, chip);
        _iface->setProperty(kIORevision, RTW_DRV_NAME);
        _iface->setProperty(kIOBuiltin, kOSBooleanTrue);
        _iface->setProperty(kIOPrimaryInterface, kOSBooleanTrue);
        _iface->setProperty(kIOLocation, "Internal");
        _iface->setProperty("IOUserVisibleName", chip);
        _iface->setProperty("Product Name", chip);
        _iface->setProperty("Device Name", chip);
        _iface->setProperty("Model", chip);
        _iface->setProperty("Vendor", "Apple");

        if (_macAddr.bytes[0] || _macAddr.bytes[1] || _macAddr.bytes[2] ||
            _macAddr.bytes[3] || _macAddr.bytes[4] || _macAddr.bytes[5]) {
            OSData *mac = OSData::withBytes(_macAddr.bytes, sizeof(_macAddr.bytes));
            if (mac) {
                _iface->setProperty(kIOMACAddress, mac);
                mac->release();
            }
        }
    }
}

/* C-linkage trampoline registered with the compat layer; the IRQ bottom-half
 * calls it after tx_isr to resume a flow-control-stalled output queue. */
extern "C" void rtw88_tx_resume_trampoline(void)
{
    if (g_pci_dev_instance)
        g_pci_dev_instance->resumeTxIfStalled();
}

/* rtw89 PCI-core diagnostic bridge.  The Linux driver can report its exact
 * probe substage and errno onto the persistent IOPCIDevice provider. */
extern "C" void rtw89_macos_set_probe_stage(const char *stage, int code)
{
    if (g_pci_dev_instance)
        g_pci_dev_instance->setBringupStage(stage, (SInt32)code);
}

/* 0.2.34 persistent descriptor/CAM bridge.  The rtw89 C core reports only
 * numeric fields; this C++ boundary converts them into stable IORegistry keys
 * on the AirportRTW89 controller, avoiding dependence on transient dmesg. */
extern "C" void rtw89_macos_set_null_ab_variant_u32(unsigned int variant,
                                                     unsigned int field,
                                                     uint32_t value)
{
    static const char *const variantName[] = {"A", "B", "C", "D"};
    static const char *const fieldName[] = {
        nullptr,
        "TxType", "MacId", "QSel", "ChDMA", "Port", "HdrLLC",
        "UseRate", "Rate", "FallbackOff", "BK", "HWSSN", "HWSeq",
        "SWMLD", "StaPresent", "VifPresent", "TxFlags", "CtrlFlags",
        "FrameControl", "Sequence", "LowRate", "STBC", "LDPC",
        "TIDIndicate", "PacketSize", "Addr1Lo", "Addr1Hi", "Addr2Lo",
        "Addr2Hi", "Addr3Lo", "Addr3Hi", "WDLen", "WPLen", "AddrLen",
        "TxRaw", "TxDone", "TxRetryLimit", "TxLifetime", "TxMacIdDrop",
        "RingTx", "RingAck",
        "TXWD00", "TXWD01", "TXWD02", "TXWD03", "TXWD04", "TXWD05",
        "TXWD06", "TXWD07", "TXWD08", "TXWD09", "TXWD10", "TXWD11",
        "TXWD12", "TXWD13", "TXWD14", "TXWD15"
    };
    if (!g_pci_dev_instance || variant < 1 || variant > 4 ||
        field == 0 || field >= (sizeof(fieldName) / sizeof(fieldName[0])))
        return;
    char key[128];
    snprintf(key, sizeof(key), "AirportRTW89NullAB_%s_%s",
             variantName[variant - 1], fieldName[field]);
    g_pci_dev_instance->setProperty(key, (uint64_t)value, 32);
}

extern "C" void rtw89_macos_set_null_ab_global_u32(unsigned int group,
                                                    unsigned int index,
                                                    uint32_t value)
{
    if (!g_pci_dev_instance)
        return;
    char key[128];
    switch (group) {
    case 1: {
        static const char *const name[] = {
            nullptr, "UpdateMode", "Version", "Length", "VifMacId",
            "StaMacId", "Port", "NetType", "AID", "AddrValid",
            "AddrIndex", "AddrBSSIDIndex", "BSSIDValid", "BSSIDIndex",
            "BSSIDPhy", "Result"
        };
        if (index == 0 || index >= sizeof(name) / sizeof(name[0])) return;
        snprintf(key, sizeof(key), "AirportRTW89NullAB_CAM_%s", name[index]);
        break;
    }
    case 2:
        snprintf(key, sizeof(key), "AirportRTW89NullAB_CAM_DW%02u", index);
        break;
    case 3: {
        static const char *const name[] = {
            nullptr, "Length", "MacId", "StaPresent", "Port", "NetType",
            "Band", "LowestRate", "Function", "Result"
        };
        if (index == 0 || index >= sizeof(name) / sizeof(name[0])) return;
        snprintf(key, sizeof(key), "AirportRTW89NullAB_CCTL_%s", name[index]);
        break;
    }
    case 4:
        snprintf(key, sizeof(key), "AirportRTW89NullAB_CCTL_DW%02u", index);
        break;
    default:
        return;
    }
    g_pci_dev_instance->setProperty(key, (uint64_t)value, 32);
}

/* ------------------------------------------------------------------ */
/*  Persistent bring-up diagnostics                                     */
/* ------------------------------------------------------------------ */

void RTW88PCIDevice::setBringupStage(const char *stage, SInt32 code)
{
    const char *text = stage ? stage : "unknown";
    OSString *value = OSString::withCString(text);
    if (value) {
        setProperty("AirportRTW89BringupStage", value);
        if (_pciDev)
            _pciDev->setProperty("AirportRTW89BringupStage", value);
        value->release();
    }

    setProperty("AirportRTW89BringupCode", (uint64_t)(uint32_t)code, 32);
    if (_pciDev)
        _pciDev->setProperty("AirportRTW89BringupCode",
                             (uint64_t)(uint32_t)code, 32);

    /* IOReturn and Linux errno values are often displayed sign-extended by
     * ioreg.  Publish a positive errno as a separate field for unambiguous
     * diagnosis. */
    const uint32_t errorNumber = code < 0 ? (uint32_t)(-(int64_t)code) : 0;
    setProperty("AirportRTW89BringupErrno", (uint64_t)errorNumber, 32);
    if (_pciDev)
        _pciDev->setProperty("AirportRTW89BringupErrno",
                             (uint64_t)errorNumber, 32);
}

/* ------------------------------------------------------------------ */
/*  IOService lifecycle                                                 */
/* ------------------------------------------------------------------ */

/* 0.2.204: warm-restart PCI recovery.
 *
 * 0.2.203 proved that terminal RTW89 core_stop + IRQ quiesce + clearing Bus
 * Master is not sufficient on this machine: after Apple-menu Restart the kext
 * binary is loaded, but the AirportRTW89 child never survives start() and en2
 * does not exist.  Cold power removal still recovers the device.
 *
 * Recover at the earliest point where our matched IOPCIDevice provider is
 * available, before IO80211Controller::start() can touch the function.  This
 * is intentionally limited to standard PCI configuration state: request D0,
 * verify/fallback the PMCSR state bits, allow the D3hot->D0 settle interval,
 * then enable Memory Space and Bus Master.  No vendor MMIO reset is issued
 * before BAR mapping and no saved PCI configuration from a previous boot is
 * assumed to exist.
 *
 * Every diagnostic is also written to the provider.  The provider normally
 * outlives a failed controller child, so a start failure can still be audited
 * from IORegistry on the same boot.
 */
void RTW88PCIDevice::recoverPCIForBoot(IOPCIDevice *pciDev)
{
    if (!pciDev)
        return;

    auto publishBool = [&](const char *key, bool value) {
        setProperty(key, value ? kOSBooleanTrue : kOSBooleanFalse);
        pciDev->setProperty(key, value ? kOSBooleanTrue : kOSBooleanFalse);
    };
    auto publish32 = [&](const char *key, UInt32 value) {
        setProperty(key, (uint64_t)value, 32);
        pciDev->setProperty(key, (uint64_t)value, 32);
    };

    publishBool("AirportRTW89BootPCIRecoveryAttempted", true);

    const UInt16 vendorBefore = pciDev->configRead16(kIOPCIConfigVendorID);
    const UInt16 deviceBefore = pciDev->configRead16(kIOPCIConfigDeviceID);
    const UInt16 commandBefore = pciDev->configRead16(kIOPCIConfigCommand);
    const UInt32 bar2Before = pciDev->configRead32(kIOPCIConfigBaseAddress2);
    publish32("AirportRTW89BootPCIVendorBefore", vendorBefore);
    publish32("AirportRTW89BootPCIDeviceBefore", deviceBefore);
    publish32("AirportRTW89BootPCICommandBefore", commandBefore);
    publish32("AirportRTW89BootPCIBAR2Before", bar2Before);

    UInt8 pmCapOffset = 0;
    const UInt32 pmCapability =
        pciDev->findPCICapability(kIOPCIPowerManagementCapability,
                                  &pmCapOffset);
    publishBool("AirportRTW89BootPCIPMCapabilityPresent",
                pmCapability != 0 && pmCapOffset != 0);
    publish32("AirportRTW89BootPCIPMCapabilityOffset", pmCapOffset);

    UInt16 pmcsrBefore = 0;
    UInt16 pmcsrAfterFramework = 0;
    UInt16 pmcsrAfter = 0;
    if (pmCapability != 0 && pmCapOffset != 0) {
        pmcsrBefore = pciDev->configRead16((IOByteCount)pmCapOffset + 4);
        publish32("AirportRTW89BootPCIPMCSRBefore", pmcsrBefore);
        publish32("AirportRTW89BootPCIPowerStateBefore",
                  pmcsrBefore & kPCIPMCSPowerStateMask);
    }

    /* Public IOPCIDevice contract: state D0 requests the function in D0 and
     * disables PCI PM policy for the device.  On an ordinary cold boot this is
     * idempotent; on the failing warm-boot path it repairs a function left in
     * D3 before the controller superclass runs. */
    const IOReturn pmRet =
        pciDev->enablePCIPowerManagement(kPCIPMCSPowerStateD0);
    publish32("AirportRTW89BootPCID0RequestReturn", (UInt32)pmRet);
    publishBool("AirportRTW89BootPCID0RequestSucceeded",
                pmRet == kIOReturnSuccess);

    if (pmCapability != 0 && pmCapOffset != 0) {
        pmcsrAfterFramework =
            pciDev->configRead16((IOByteCount)pmCapOffset + 4);
        publish32("AirportRTW89BootPCIPMCSRAfterFramework",
                  pmcsrAfterFramework);

        /* Some restored/legacy IOPCIFamily combinations accept the framework
         * PM request without changing PMCSR.  Use the standard PM capability
         * itself as a narrowly-scoped fallback: change only bits 1:0. */
        if ((pmcsrAfterFramework & kPCIPMCSPowerStateMask) !=
            kPCIPMCSPowerStateD0) {
            const UInt16 forcedD0 =
                (UInt16)(pmcsrAfterFramework & ~kPCIPMCSPowerStateMask);
            pciDev->configWrite16((IOByteCount)pmCapOffset + 4, forcedD0);
            publishBool("AirportRTW89BootPCID0FallbackWrite", true);
        } else {
            publishBool("AirportRTW89BootPCID0FallbackWrite", false);
        }

        /* PCI D3hot -> D0 requires a settling interval before normal function
         * access.  20 ms is deliberately conservative while still negligible
         * at boot. */
        IOSleep(20);
        pmcsrAfter = pciDev->configRead16((IOByteCount)pmCapOffset + 4);
        publish32("AirportRTW89BootPCIPMCSRAfter", pmcsrAfter);
        publish32("AirportRTW89BootPCIPowerStateAfter",
                  pmcsrAfter & kPCIPMCSPowerStateMask);
        publishBool("AirportRTW89BootPCID0Verified",
                    (pmcsrAfter & kPCIPMCSPowerStateMask) ==
                        kPCIPMCSPowerStateD0);
    } else {
        /* No PM capability means there is no standard D-state register to
         * repair; continue with command-register recovery. */
        publishBool("AirportRTW89BootPCID0FallbackWrite", false);
        publishBool("AirportRTW89BootPCID0Verified", true);
    }

    const bool memoryWasEnabled = pciDev->setMemoryEnable(true);
    const bool busMasterWasEnabled = pciDev->setBusMasterEnable(true);
    publishBool("AirportRTW89BootPCIMemoryWasEnabled", memoryWasEnabled);
    publishBool("AirportRTW89BootPCIBusMasterWasEnabled", busMasterWasEnabled);

    const UInt16 commandAfter = pciDev->configRead16(kIOPCIConfigCommand);
    const UInt16 vendorAfter = pciDev->configRead16(kIOPCIConfigVendorID);
    const UInt16 deviceAfter = pciDev->configRead16(kIOPCIConfigDeviceID);
    publish32("AirportRTW89BootPCICommandAfter", commandAfter);
    publish32("AirportRTW89BootPCIVendorAfter", vendorAfter);
    publish32("AirportRTW89BootPCIDeviceAfter", deviceAfter);
    publishBool("AirportRTW89BootPCIMemoryEnabledAfter",
                (commandAfter & kIOPCICommandMemorySpace) != 0);
    publishBool("AirportRTW89BootPCIBusMasterEnabledAfter",
                (commandAfter & kIOPCICommandBusMaster) != 0);
    publishBool("AirportRTW89BootPCIConfigResponsive",
                vendorAfter != 0xffff && vendorAfter != 0x0000 &&
                deviceAfter != 0xffff && deviceAfter != 0x0000);

    IOLog("rtw88: boot PCI recovery vendor=%04x device=%04x cmd=%04x->%04x pmcap=0x%02x pmcsr=%04x->%04x pmret=0x%08x\n",
          vendorBefore, deviceBefore, commandBefore, commandAfter,
          pmCapOffset, pmcsrBefore, pmcsrAfter, pmRet);
}

bool RTW88PCIDevice::init(OSDictionary *props)
{
    IOLog("rtw88: RTW88PCIDevice::init\n");
    if (!super::init(props)) return false;
    _dmaLock        = IOSimpleLockAlloc();
    _pendingFreeLock = IOSimpleLockAlloc();
#ifdef RTW_AIRPORT
    _airportLock = IOLockAlloc();
    _airportBSSCache = (RTW88BSS *)IOMallocZero(sizeof(RTW88BSS) * 64);
    _airportScanResults = (apple80211_scan_result *)IOMallocZero(sizeof(apple80211_scan_result) * 64);
    _airportLastState = RTW88_STATE_IDLE;
    _airportAssocResult = APPLE80211_RESULT_UNAVAILABLE;
    return _dmaLock != nullptr && _pendingFreeLock != nullptr &&
           _airportLock != nullptr && _airportBSSCache != nullptr &&
           _airportScanResults != nullptr;
#else
    return _dmaLock != nullptr && _pendingFreeLock != nullptr;
#endif
}

bool RTW88PCIDevice::start(IOService *provider)
{
    IOLog("rtw88: RTW88PCIDevice::start\n");
    setBringupStage("start-enter");

    /* 0.2.204: recover standard PCI power/command state before the IO80211
     * superclass touches a function that may have survived a warm restart in
     * D3.  Retain the matched provider now (rather than after super::start())
     * so BringupStage also survives a superclass-start failure on the PCI nub. */
    IOPCIDevice *bootPciDev = OSDynamicCast(IOPCIDevice, provider);
#ifdef RTW_AIRPORT
    if (!bootPciDev) {
        AirportRTW89PCIWrapper *wrapper =
            OSDynamicCast(AirportRTW89PCIWrapper, provider);
        if (wrapper)
            bootPciDev = wrapper->pciDevice();
    }
#endif
    if (bootPciDev) {
        _pciDev = bootPciDev;
        _pciDev->retain();
        setBringupStage("pre-super-pci-provider");
        recoverPCIForBoot(bootPciDev);
        setBringupStage("pre-super-pci-recovered");
    }

    if (!super::start(provider)) {
        setBringupStage("super-start-failed", kIOReturnError);
        return false;
    }

#ifdef RTW_AIRPORT
    /* 0.4.4 Ventura IO80211Reference parity: the controller is matched directly
     * on IOPCIDevice under IODefaultMatchCategory. Do not rewrite the live
     * controller into the Sonoma/Tahoe WiFiDriver/IONetworkRootType identity;
     * IO80211Reference Ventura does not do that before attaching IO80211Interface. */
    setProperty("AirportRTW89VenturaDirectPCIProviderParity", kOSBooleanTrue);
    setProperty("AirportRTW89VenturaDefaultMatchCategoryParity", kOSBooleanTrue);
    /* 0.5.41: IO80211Reference Ventura does not publish IO80211RSNDone during
     * controller initialization.  Leave the property absent until a real
     * association/disassociation or key-install transition owns its value. */
    setProperty("AirportRTW89InitialControllerRSNDonePublicationSuppressed",
                kOSBooleanTrue);
    const bool nativeStrict = airportNativeIOUCStrictMode();
    setProperty("AirportRTW89NativeIOUCStrictModeAvailable", kOSBooleanTrue);
    setProperty("AirportRTW89NativeIOUCStrictModeEnabled",
                nativeStrict ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89VenturaInterfaceParityEnabled",
                airportVenturaInterfaceParity() ? kOSBooleanTrue
                                                 : kOSBooleanFalse);

    setProperty("AirportRTW89SecurityControlObservability", kOSBooleanTrue);
    setProperty("AirportRTW89SecurityControlObservabilityVersion",
                (uint64_t)303, 32);
    setProperty("AirportRTW89SecurityControlBehaviorModified", kOSBooleanFalse);

    /* 0.3.12: IO80211APIUserClient ingress-only telemetry.  This build does
     * not add another CHANNELS_INFO bridge or change selector dispatch.  The
     * marker is intentionally boot-persistent in IORegistry so a post-reboot
     * capture can prove the intended binary is active before a join test. */
    setProperty("AirportRTW89Build0312IOUCIngressTelemetry", kOSBooleanTrue);
    setProperty("AirportRTW89IOUCIngressTelemetryBuild", (uint64_t)312, 32);
    setProperty("AirportRTW89Build0313PreDispatchTelemetry", kOSBooleanTrue);
    setProperty("AirportRTW89PreDispatchTelemetryBuild", (uint64_t)313, 32);
    setProperty("AirportRTW89PreDispatchTelemetryBehaviorModified", kOSBooleanFalse);
    setProperty("AirportRTW89IOUCIngressTelemetryBehaviorModified",
                kOSBooleanFalse);
    setProperty("AirportRTW89IOUCGet207Seen", kOSBooleanFalse);
    setProperty("AirportRTW89IOUCGet207Count", (uint64_t)0, 32);
    setProperty("AirportRTW89ApplePerformGet207Seen", kOSBooleanFalse);

    /* 0.2.217: publish compile-time Apple80211/private-class ABI landmarks so
     * one Tahoe IORegistry capture can be compared directly with the
     * IO80211Reference Sequoia/Tahoe headers/binary.  Sizes only; no payloads. */
    setProperty("AirportRTW89IO80211ReferenceParityBuild", kOSBooleanTrue);
    setProperty("AirportRTW89IO80211ReferenceParityDiagnosticOnly",
                kOSBooleanTrue);
    setProperty("AirportRTW89ParityABIInterfaceCompileSize",
                (uint64_t)sizeof(AirportRTW89Interface), 32);
    setProperty("AirportRTW89ParityABIControllerCompileSize",
                (uint64_t)sizeof(RTW88PCIDevice), 32);
    setProperty("AirportRTW89ParityABISSIDStructSize",
                (uint64_t)sizeof(apple80211_ssid_data), 32);
    setProperty("AirportRTW89ParityABIChannelStructSize",
                (uint64_t)sizeof(apple80211_channel_data), 32);
    setProperty("AirportRTW89ParityABIScanResultStructSize",
                (uint64_t)sizeof(apple80211_scan_result), 32);
    setProperty("AirportRTW89ParityABIAssociateStructSize",
                (uint64_t)sizeof(apple80211_assoc_data), 32);
    setProperty("AirportRTW89ParityABIAuthTypeStructSize",
                (uint64_t)sizeof(apple80211_authtype_data), 32);
    setProperty("AirportRTW89ParityABIRSNIEStructSize",
                (uint64_t)sizeof(apple80211_rsn_ie_data), 32);
    setProperty("AirportRTW89ParityABICipherKeyStructSize",
                (uint64_t)sizeof(apple80211_key), 32);
    setProperty("AirportRTW89ParityABIPowerStructSize",
                (uint64_t)sizeof(apple80211_power_data), 32);
    setProperty("AirportRTW89ParityABICapabilityStructSize",
                (uint64_t)sizeof(apple80211_capability_data), 32);
    setProperty("AirportRTW89ParityABIApple80211Version",
                (uint64_t)APPLE80211_VERSION, 32);
    if (provider && provider->getMetaClass() &&
        provider->getMetaClass()->getClassName()) {
        setProperty("AirportRTW89ParityProviderClass",
                    provider->getMetaClass()->getClassName());
    }

    /* 0.2.147: Before attempting any further Skywalk lifecycle
     * transition, inspect the exact classes exported by this restored IO80211
     * framework.  IO80211InfraInterface is abstract, so a failed allocation is
     * expected and is not sufficient to distinguish a missing class from an
     * abstract one.  Record metaclass presence and live object sizes as an ABI
     * gate for the concrete subclass added by the next stage. */
    struct SkywalkMetaProbe {
        const char *className;
        const char *presentKey;
        const char *sizeKey;
    };
    static const SkywalkMetaProbe metaProbes[] = {
        { "IOSkywalkInterface", "AirportRTW89MetaIOSkywalkInterfacePresent",
          "AirportRTW89MetaIOSkywalkInterfaceSize" },
        { "IOSkywalkNetworkInterface", "AirportRTW89MetaIOSkywalkNetworkPresent",
          "AirportRTW89MetaIOSkywalkNetworkSize" },
        { "IOSkywalkEthernetInterface", "AirportRTW89MetaIOSkywalkEthernetPresent",
          "AirportRTW89MetaIOSkywalkEthernetSize" },
        { "IO80211SkywalkInterface", "AirportRTW89Meta80211SkywalkPresent",
          "AirportRTW89Meta80211SkywalkSize" },
        { "IO80211InfraInterface", "AirportRTW89Meta80211InfraPresent",
          "AirportRTW89Meta80211InfraSize" },
        /* 0.2.147: read-only native-control class availability probes.  These
         * are string-based metaclass lookups only: they add no link-time
         * dependency on the named Apple classes. */
        { "IO80211APIUserClient", "AirportRTW89Meta80211APIUserClientPresent",
          "AirportRTW89Meta80211APIUserClientSize" },
        { "IO80211AsyncEventUserClient", "AirportRTW89Meta80211AsyncEventUserClientPresent",
          "AirportRTW89Meta80211AsyncEventUserClientSize" },
        { "IOSkywalkNetworkBSDClient", "AirportRTW89MetaSkywalkNetworkBSDClientPresent",
          "AirportRTW89MetaSkywalkNetworkBSDClientSize" },
        { "IOUserNetworkWLAN", "AirportRTW89MetaIOUserNetworkWLANPresent",
          "AirportRTW89MetaIOUserNetworkWLANSize" },
        { "IO80211ControllerV2", "AirportRTW89Meta80211ControllerV2Present",
          "AirportRTW89Meta80211ControllerV2Size" },
        { "IO80211InfraProtocol", "AirportRTW89Meta80211InfraProtocolPresent",
          "AirportRTW89Meta80211InfraProtocolSize" },
        { "IOUserUserClient", "AirportRTW89MetaIOUserUserClientPresent",
          "AirportRTW89MetaIOUserUserClientSize" },
    };
    for (const SkywalkMetaProbe &probe : metaProbes) {
        const OSSymbol *name = OSSymbol::withCString(probe.className);
        const OSMetaClass *meta = name
            ? OSMetaClass::getMetaClassWithName(name) : nullptr;
        setProperty(probe.presentKey,
                    meta ? kOSBooleanTrue : kOSBooleanFalse);
        if (meta)
            setProperty(probe.sizeKey, (uint64_t)meta->getClassSize(), 32);
        OSSafeReleaseNULL(name);
    }

    OSObject *infraProbe = OSMetaClass::allocClassWithName("IO80211InfraInterface");
    setProperty("AirportRTW89SkywalkInfraClassAllocatable",
                infraProbe ? kOSBooleanTrue : kOSBooleanFalse);
    if (infraProbe) {
        const OSMetaClass *meta = infraProbe->getMetaClass();
        if (meta && meta->getClassName())
            setProperty("AirportRTW89SkywalkInfraAllocatedClass",
                        meta->getClassName());
        setProperty("AirportRTW89SkywalkInfraIsIOService",
                    OSDynamicCast(IOService, infraProbe)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkInfraIs80211Skywalk",
                    OSDynamicCast(IO80211SkywalkInterface, infraProbe)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        infraProbe->release();
    }

    AirportRTW89SkywalkControlInterface *concreteProbe =
        new AirportRTW89SkywalkControlInterface;
    setProperty("AirportRTW89ConcreteSkywalkAllocatable",
                concreteProbe ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ConcreteSkywalkCompileSize",
                (uint64_t)sizeof(AirportRTW89SkywalkControlInterface), 32);
    if (concreteProbe) {
        setProperty("AirportRTW89ConcreteSkywalkIs80211Skywalk",
                    OSDynamicCast(IO80211SkywalkInterface, concreteProbe)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConcreteSkywalkIs80211Infra",
                    OSDynamicCast(IO80211InfraInterface, concreteProbe)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        bool concreteInit = concreteProbe->init(this);
        setProperty("AirportRTW89ConcreteSkywalkInitAttempted",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ConcreteSkywalkInitRawResult",
                    (uint64_t)(concreteInit ? 1 : 0), 8);
        setProperty("AirportRTW89ConcreteSkywalkInitSucceeded",
                    concreteInit ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConcreteSkywalkPostInitIs80211Skywalk",
                    OSDynamicCast(IO80211SkywalkInterface, concreteProbe)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConcreteSkywalkPostInitIs80211Infra",
                    OSDynamicCast(IO80211InfraInterface, concreteProbe)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConcreteSkywalkReleasedAfterInitAttempt",
                    kOSBooleanTrue);
        concreteProbe->release();
    }

    /* 0.2.73: permanent Skywalk creation is deferred until the PCI provider,
     * hardware backend and working legacy IO80211Interface are established.
     * The class/ABI probes above remain read-only diagnostics. */
#endif

    if (!_pciDev) {
        IOLog("rtw88: provider is not IOPCIDevice\n");
        return false;
    }
    setBringupStage("provider-ready");

    /* Enable bus mastering & memory space */
    _pciDev->setBusMasterEnable(true);
    _pciDev->setMemoryEnable(true);

    /* Map BAR2 — rtw88 driver hardcodes bar_id=2 in pci.c */
    _mmioMap = _pciDev->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    if (!_mmioMap) {
        IOLog("rtw88: failed to map BAR2\n");
        setBringupStage("bar2-map-failed", kIOReturnNoMemory);
        return false;
    }
    setBringupStage("bar2-mapped");
    _mmioBase = (volatile void *)_mmioMap->getVirtualAddress();
    IOLog("rtw88: BAR2 mapped at %p, size 0x%llx\n",
          (void *)_mmioBase, (unsigned long long)_mmioMap->getLength());

    /* Install global compat ops */
    g_pci_dev_instance = this;
    rtw88_pci_io_ops   = &_pci_io_ops;
    rtw88_dma_ops      = &_dma_ops;

    /* Initialise compat runtime (workqueues, timers) */
    rtw88_compat_init();

    /* Build the pci_dev struct for the Linux driver */
    _compatPciDev = (struct pci_dev *)IOMallocZero(sizeof(struct pci_dev));
    if (!_compatPciDev) {
        setBringupStage("compat-pci-allocation-failed", kIOReturnNoMemory);
        return false;
    }

    _compatPciDev->vendor  = _pciDev->configRead16(0x00);
    _compatPciDev->device  = _pciDev->configRead16(0x02);
    _compatPciDev->kext_dev = this;
    _compatPciDev->resource[2]     = (resource_size_t)_mmioBase;
    _compatPciDev->resource_len[2] = (resource_size_t)_mmioMap->getLength();

    IOLog("rtw88: PCI device %04x:%04x\n",
          _compatPciDev->vendor, _compatPciDev->device);

    /* IO80211Controller::start() calls our createWorkLoop() override.  Keep
     * a fallback for unusual framework builds that skip that call. */
    if (!_workLoop)
        _workLoop = IOWorkLoop::workLoop();
    if (!_workLoop) {
        setBringupStage("workloop-failed", kIOReturnNoMemory);
        return false;
    }

    _cmdGate = IOCommandGate::commandGate(this);
    if (!_cmdGate) {
        setBringupStage("command-gate-failed", kIOReturnNoMemory);
        return false;
    }
    _workLoop->addEventSource(_cmdGate);

    /* Set up interrupt */
    if (!setupInterrupt()) {
        IOLog("rtw88: setupInterrupt failed\n");
        setBringupStage("interrupt-setup-failed", kIOReturnError);
        return false;
    }
    setBringupStage("interrupt-ready");

    /* Locate firmware Resources/ and set fw dir */
    rtw88_find_fw_dir();

    /* Create 802.11 state machine */
    _ieee80211 = RTW88IEEE80211::create(this, _compatPciDev);
    if (!_ieee80211) {
        IOLog("rtw88: failed to create RTW88IEEE80211\n");
        setBringupStage("ieee80211-create-failed", kIOReturnNoMemory);
        return false;
    }
    setBringupStage("ieee80211-created");

    /* Force-disable BT coexistence.  rtw_pci_probe (inside create()) has
     * already run rtw_core_init which filled rtwdev->efuse.btcoex from
     * the chip's eFuse — but the actual coex setup happens later in
     * rtw_power_on (via _ieee80211->start() below).  Override now so the
     * coex driver initialises with wifi_only=true and never enables the
     * BT-side H2C/C2H exchange that appears to be wedging BE TX. */
    rtw88_force_wifi_only();

    /* Run the full probe now so the MAC address is populated before
     * the Ethernet interface is attached.  enable() will call
     * rtw_core_start() to power on the hardware for TX/RX. */
    setBringupStage("ieee80211-starting");
    IOReturn probeRet = _ieee80211->start();
    if (probeRet != kIOReturnSuccess) {
        IOLog("rtw88: probe failed (0x%08x)\n", probeRet);

        /* RTW88IEEE80211::start() has already published the precise inner
         * failure (for example probe-core-init-failed with Linux errno).
         * Do not overwrite it with the generic kIOReturnError wrapper. */
        setProperty("AirportRTW89IEEE80211StartReturn",
                    (uint64_t)(uint32_t)probeRet, 32);
        if (_pciDev)
            _pciDev->setProperty("AirportRTW89IEEE80211StartReturn",
                                 (uint64_t)(uint32_t)probeRet, 32);
        return false;
    }
    setBringupStage("ieee80211-started");

#ifdef RTW_AIRPORT
    /* 0.3.0 Stage 1: land the OpenBSD-net80211 state-universe boundary
     * without replacing the proven RTW89 hardware/MLME path yet.  The
     * object becomes authoritative for Apple scan-node storage immediately;
     * later 0.3.x stages can move MLME/security ownership behind the same
     * boundary. */
    _net80211 = RTW89Net80211Core::create(this);
    if (!_net80211) {
        IOLog("rtw88: failed to create RTW89Net80211Core\n");
        setBringupStage("net80211-core-create-failed", kIOReturnNoMemory);
        return false;
    }
    setBringupStage("net80211-core-created");
#endif

    /* Attach the selected macOS frontend — Ethernet or native IO80211. */
    setBringupStage("interface-attaching");
    if (!attachDevice()) {
        setBringupStage("interface-attach-failed", kIOReturnError);
        return false;
    }
    setBringupStage("interface-attached");
#ifdef RTW_AIRPORT
    /* 0.2.131: Tahoe may satisfy CWInterface.countryCode() from the
     * interface registry without issuing legacy Apple80211 GET 51.  Publish
     * EFUSE/active regulatory state (or rtw89_cc=XX) before registration. */
    airportRefreshCountryCode("post-interface-attach", false);
#endif

#if defined(RTW_AIRPORT) && __IO80211_TARGET >= __MAC_13_0
    /* 0.2.250 single-variable topology experiment.  0.2.249 proved the
     * request marshaller itself is no longer hiding ASSOCIATE/20: across
     * repeated password-backed joins Tahoe sends DISASSOCIATE/22, logs
     * "Will associate", and then fails without ever emitting SET20.
     *
     * The remaining structural difference in this branch is the second,
     * control-only IO80211Infra/Skywalk service promoted as controller-primary.
     * Keep its implementation compiled, but do not instantiate/register/start
     * it in this build.  The genuine AirportRTW89Interface remains the only
     * live 802.11 interface.  No getter, SET return, scan bridge, or Realtek
     * association backend behavior changes here. */
    /* 0.4.3: match the actual IO80211Reference-Ventura target, not the Sonoma
     * V2 target.  Ventura compiles IO80211Reference.cpp + IO80211ReferenceInterface
     * and attaches one IO80211Interface through IO80211Controller::attachInterface().
     * It does NOT compile IO80211ReferenceV2/SkywalkInterface/EthernetInterface.
     * Keep the experimental Skywalk classes in the source for later Sonoma
     * work, but do not instantiate them in this Ventura-native branch. */
    /* 0.4.19: keep the proven legacy topology as the unconditional default,
     * but make the already-implemented full Skywalk companion experiment
     * reachable again when rtw89_native_topology=1 is explicitly supplied.
     * The exclusive-owner form additionally requires
     * rtw89_exclusive_native=1 and is the closest existing match for
     * IO80211Reference V2's single primary Skywalk/BSD ownership model. */
    const bool legacyOnlyAssociationTopology =
        !airportNativeTopologyExperiment();
    setProperty("AirportRTW89VenturaIO80211ReferenceTopology",
                legacyOnlyAssociationTopology ? kOSBooleanTrue
                                              : kOSBooleanFalse);
    setProperty("AirportRTW89LegacyOnlyTopology",
                legacyOnlyAssociationTopology ? kOSBooleanTrue
                                              : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkControlServiceSuppressedForLegacyParity",
                legacyOnlyAssociationTopology ? kOSBooleanTrue
                                              : kOSBooleanFalse);
    setProperty("AirportRTW89LegacyOnlyInterfacePresentAtTopologySelection",
                _iface ? kOSBooleanTrue : kOSBooleanFalse);
    _skywalkInterface = nullptr;
    _skywalkLegacyBindPending = false;
    _skywalkLegacyBindRetried = false;

    if (!legacyOnlyAssociationTopology) {
    const bool exclusiveNative =
        airportNativeTopologyExperiment() && airportExclusiveNativeTopology();
    setProperty("AirportRTW89ExclusiveNativeExperimentEnabled",
                exclusiveNative ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ExclusiveNativeLegacyDetachAttempted",
                kOSBooleanFalse);
    setProperty("AirportRTW89ExclusiveNativeLegacyDetached",
                kOSBooleanFalse);
    setProperty("AirportRTW89ExclusiveNativeLegacyFallbackAttempted",
                kOSBooleanFalse);
    setProperty("AirportRTW89ExclusiveNativeLegacyFallbackSucceeded",
                kOSBooleanFalse);

    if (exclusiveNative && _iface) {
        setProperty("AirportRTW89ExclusiveNativeLegacyDetachAttempted",
                    kOSBooleanTrue);
        if (_txQueue) {
            _txQueue->release();
            _txQueue = nullptr;
        }
        detachInterface(_iface);
        _iface->release();
        _iface = nullptr;
        setProperty("AirportRTW89ExclusiveNativeLegacyDetached",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SingleBSDOwnerTopology",
                    kOSBooleanTrue);
    }

    /* Publish the Skywalk interface.  In exclusive-native mode there is no
     * legacy AirportRTW89Interface at this point; the BSD companion will
     * provide the interface identity after data-link attachment. */
    AirportRTW89SkywalkControlInterface *controlService =
        new AirportRTW89SkywalkControlInterface;
    setProperty("AirportRTW89NonBSDSkywalkServiceCreateAttempted",
                kOSBooleanTrue);
    if (controlService &&
        controlService->initAsControlService(
            this, OSDynamicCast(AirportRTW89Interface, _iface)) &&
        controlService->attach(this)) {
        _skywalkInterface = controlService;
        setProperty("AirportRTW89NonBSDSkywalkServiceAttached",
                    kOSBooleanTrue);
        setProperty("AirportRTW89NonBSDSkywalkServiceHasBSDInterface",
                    kOSBooleanFalse);

        /* 0.2.139: first IO80211Reference-style native-lifecycle step.
         *
         * IO80211Reference does not leave its Skywalk interface as an ordinary
         * IOService child only: the IO80211Controller also attaches it through
         * the IOSkywalkInterface-specific attachInterface() path, making it the
         * controller's primary Skywalk interface before later BSD/registration
         * work.  0.2.136 proved registry-plane visibility alone is insufficient
         * and 0.2.137 proved IO80211SkywalkInterface::newUserClient(type 0)
         * returns kIOReturnNotFound on the passive object.
         *
         * Promote this already-safe control-only object through that controller
         * attach stage, but DO NOT create IO80211Reference's second BSD companion,
         * initialize RegistrationInfo, defer BSD attach, start/enable Skywalk,
         * or change ownership of the working legacy en2.  This isolates whether
         * the missing controller-primary relationship is what native user-client
         * creation is looking for. */
        controlService->setInterfaceRole(1);
        setProperty("AirportRTW89IO80211ReferencePrimaryAttachAttempted",
                    kOSBooleanTrue);
        const bool primaryAttached =
            attachInterface((IOSkywalkInterface *)controlService,
                            (IOService *)this);
        setProperty("AirportRTW89IO80211ReferencePrimaryAttachResult",
                    primaryAttached ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89IO80211ReferencePrimaryMatches",
                    getPrimarySkywalkInterface() == controlService
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89IO80211ReferencePrimaryProviderIsController",
                    controlService->getProvider() == (IOService *)this
                        ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.3.19: optionally reproduce IO80211Reference's real modern topology.
         * IO80211Reference attaches an IO80211InfraInterface first and then asks
         * IONetworkController to construct a BSD companion whose provider is
         * that Skywalk interface.  Previous AirportRTW experiments stopped
         * before this step because a second attach could disturb the working
         * legacy queue.  Keep the experiment behind rtw89_native_topology=1
         * and preserve 0.3.16 behavior otherwise. */
        const bool nativeTopology = airportNativeTopologyExperiment();
        setProperty("AirportRTW89NativeTopologyExperimentEnabled",
                    nativeTopology ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89NativeTopologyFallbackAvailable",
                    kOSBooleanTrue);

        bool companionAttached = false;
        if (nativeTopology && primaryAttached &&
            getPrimarySkywalkInterface() == controlService) {
            setProperty("AirportRTW89SkywalkBSDCompanionAttachAttempted",
                        kOSBooleanTrue);
            _creatingSkywalkBSDCompanion = true;
            setProperty("AirportRTW89SkywalkBSDCompanionAttachEntered",
                        kOSBooleanTrue);
            IONetworkInterface *bsdInterface = nullptr;
            companionAttached =
                IONetworkController::attachInterface(&bsdInterface, true);
            _creatingSkywalkBSDCompanion = false;
            setProperty("AirportRTW89SkywalkBSDCompanionAttachReturned",
                        kOSBooleanTrue);
            setProperty("AirportRTW89SkywalkBSDCompanionAttachReturnedInterface",
                        bsdInterface ? kOSBooleanTrue : kOSBooleanFalse);

            _skywalkBSDCompanion =
                OSDynamicCast(AirportRTW89SkywalkBSDInterface, bsdInterface);
            setProperty("AirportRTW89SkywalkBSDCompanionAttachSucceeded",
                        companionAttached ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkBSDCompanionPresent",
                        _skywalkBSDCompanion ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkBSDCompanionClassMatched",
                        _skywalkBSDCompanion ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89SingleBSDOwnerTopology",
                        kOSBooleanFalse);

            if (_skywalkBSDCompanion && _skywalkBSDCompanion->getIfnet()) {
                const char *prefix = ifnet_name(_skywalkBSDCompanion->getIfnet());
                const UInt32 unit = ifnet_unit(_skywalkBSDCompanion->getIfnet());
                if (prefix)
                    setProperty("AirportRTW89SkywalkBSDCompanionNamePrefix",
                                prefix);
                setProperty("AirportRTW89SkywalkBSDCompanionUnit",
                            (uint64_t)unit, 32);
            }

            if (exclusiveNative) {
                setProperty("AirportRTW89ExclusiveNativeIO80211ConfigureSucceeded",
                            companionAttached ? kOSBooleanTrue : kOSBooleanFalse);
                setProperty("AirportRTW89ExclusiveNativeLegacyInterfaceAbsentAfterCompanion",
                            _iface ? kOSBooleanFalse : kOSBooleanTrue);

                /* 0.3.26: 0.3.25 proved that mutating the companion's
                 * IO80211 transport latches during the controller enable edge
                 * can prevent BSD registration entirely.  Arm a staged power
                 * synchronization only after attachInterface(..., true) has
                 * returned a live companion with an ifnet.  The existing
                 * controller timer executes each Apple power operation on a
                 * separate tick and aborts if the ifnet disappears. */
                const bool bsdReady = companionAttached &&
                    _skywalkBSDCompanion && _skywalkBSDCompanion->getIfnet();
                _nativeCompanionPostRegisterPowerPending = bsdReady;
                _nativeCompanionPostRegisterPowerStage = bsdReady ? 1 : 0;
                _nativeCompanionPostRegisterPowerCompleted = false;
                setProperty("AirportRTW89NativeCompanionBSDRegistered",
                            bsdReady ? kOSBooleanTrue : kOSBooleanFalse);
                setProperty("AirportRTW89NativeCompanionPostRegisterPowerArmed",
                            bsdReady ? kOSBooleanTrue : kOSBooleanFalse);
            }
        } else {
            setProperty("AirportRTW89SkywalkBSDCompanionAttachAttempted",
                        kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkBSDCompanionAttachSucceeded",
                        kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkBSDCompanionPresent",
                        kOSBooleanFalse);
            setProperty("AirportRTW89SingleBSDOwnerTopology",
                        kOSBooleanTrue);
        }

        if (exclusiveNative && !companionAttached && !_iface) {
            setProperty("AirportRTW89ExclusiveNativeLegacyFallbackAttempted",
                        kOSBooleanTrue);
            const bool fallbackAttached =
                attachInterface((IONetworkInterface **)&_iface, true);
            setProperty("AirportRTW89ExclusiveNativeLegacyFallbackSucceeded",
                        fallbackAttached ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ExclusiveNativeLegacyFallbackInterfacePresent",
                        _iface ? kOSBooleanTrue : kOSBooleanFalse);
            if (fallbackAttached) {
                _txQueue = OSDynamicCast(IOGatedOutputQueue, getOutputQueue());
                if (_txQueue) _txQueue->retain();
            }
        }

        /* 0.2.142: keep the legacy AirportRTW89Interface as the one and only
         * BSD/ifnet owner, but give the non-BSD Skywalk primary the
         * RegistrationInfo state IO80211Reference establishes before its later
         * BSD/data-path stages.  This is intentionally a control-plane-only
         * experiment: no second BSD/ifnet companion exists, and we do
         * not call prepareBSDInterface(), deferBSDAttach(), start(), enable(),
         * registerNetworkInterface(), or create logical links/queues.
         *
         * 0.2.139 proved controller-primary ownership alone does not change
         * native newUserClient(type 0): it still returns kIOReturnNotFound.
         * This isolates whether the missing prerequisite is the initialized
         * RegistrationInfo stored on the modern Skywalk object itself. */
        setProperty("AirportRTW89NonBSDRegistrationInitAttempted",
                    kOSBooleanTrue);
        AirportRTW89SkywalkControlInterface::RegistrationInfo registrationInfo = {};
        const bool registrationInitialized =
            primaryAttached && getPrimarySkywalkInterface() == controlService &&
            controlService->initRegistrationInfo(
                &registrationInfo, 1, sizeof(registrationInfo));
        setProperty("AirportRTW89NonBSDRegistrationInitSucceeded",
                    registrationInitialized ? kOSBooleanTrue : kOSBooleanFalse);

        bool registrationPreseeded = false;
        if (registrationInitialized)
            registrationPreseeded =
                preseedSkywalkRegistrationCopies(registrationInfo);
        setProperty("AirportRTW89NonBSDRegistrationPreseedSucceeded",
                    registrationPreseeded ? kOSBooleanTrue : kOSBooleanFalse);
        bool sharedIfnetPrepared = false;
        if (!nativeTopology && registrationPreseeded && _iface && _iface->getIfnet()) {
            /* prepareBSDInterface transfers scheduling ownership away from
             * the legacy IONetworkController queue.  Drop our retained
             * reference before Apple retires that queue; its allocation can
             * immediately be reused for RegistrationInfo storage. */
            if (_txQueue) {
                _txQueue->release();
                _txQueue = nullptr;
            }
            _skywalkOwnsBSDQueue = true;
            setProperty("AirportRTW89LegacyOutputQueueReleasedBeforeSkywalkPrepare",
                        kOSBooleanTrue);
            controlService->prepareBSDInterface(_iface->getIfnet(), 0);
            sharedIfnetPrepared =
                controlService->rawNetworkBSDInterfaceSlot() &&
                *controlService->rawNetworkBSDInterfaceSlot() ==
                    _iface->getIfnet();
        }
        setProperty("AirportRTW89SkywalkSharedIfnetPrepareAttempted",
                    (!nativeTopology && registrationPreseeded && _iface &&
                     _iface->getIfnet())
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkSharedIfnetPrepared",
                    sharedIfnetPrepared ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89NonBSDPrepareBSDSuppressed",
                    nativeTopology ? kOSBooleanFalse : kOSBooleanTrue);
        setProperty("AirportRTW89NonBSDSecondIfnetSuppressed",
                    nativeTopology ? kOSBooleanFalse : kOSBooleanTrue);
        setProperty("AirportRTW89IO80211ReferenceBSDCompanionSuppressed",
                    nativeTopology ? kOSBooleanFalse : kOSBooleanTrue);
        setProperty("AirportRTW89IO80211ReferenceFullActivationSuppressed",
                    nativeTopology ? kOSBooleanFalse : kOSBooleanTrue);

        /* 0.2.127: arm the existing deferred identity-only probe.  The
         * 0.2.124-0.2.126 code was unreachable because this latch remained
         * false for the entire boot.  The timer still waits until Apple's
         * dataLinkLayerAttachComplete() callback has fired before it reads
         * any BSD identity.  The deferred block only mirrors name/prefix/unit
         * onto the passive control-only service; it never starts, enables,
         * powers, re-registers, or creates a Skywalk/BSD interface. */
        _skywalkLegacyBindRetried = false;
        _skywalkLegacyBindPending = true;
        setProperty("AirportRTW89SkywalkDeferredIdentityArmed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkDeferredLegacyBindPending",
                    kOSBooleanTrue);
    } else {
        setProperty("AirportRTW89NonBSDSkywalkServiceAttached",
                    kOSBooleanFalse);
        if (controlService)
            controlService->release();
    }
    } else {
        setProperty("AirportRTW89NonBSDSkywalkServiceCreateAttempted",
                    kOSBooleanFalse);
        setProperty("AirportRTW89NonBSDSkywalkServiceAttached",
                    kOSBooleanFalse);
        setProperty("AirportRTW89NonBSDSkywalkServiceRegistered",
                    kOSBooleanFalse);
        setProperty("AirportRTW89IO80211ReferencePrimaryAttachAttempted",
                    kOSBooleanFalse);
        setProperty("AirportRTW89AutomaticControlLifecycleAttempted",
                    kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkDeferredIdentityArmed",
                    kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkDeferredLegacyBindPending",
                    kOSBooleanFalse);
    }
#endif

    _initialized = true;
    /* Wire TX flow-control resume: fired from the IRQ bottom-half after tx_isr
     * frees BE ring slots, so a stalled output queue gets re-serviced. */
    rtw88_set_tx_resume_cb(rtw88_tx_resume_trampoline);
    if (_intrSrc) _intrSrc->enable();

    /* Debug: poll BE ring + HISR/HIMR every second. Logs distinguish chip
     * stop vs interrupt loss vs IMR masking when TX appears stuck. */
    _debugTimer = IOTimerEventSource::timerEventSource(
        this, OSMemberFunctionCast(IOTimerEventSource::Action,
                                   this, &RTW88PCIDevice::debugTimerFired));
    if (_debugTimer) {
        _workLoop->addEventSource(_debugTimer);
        _debugTimer->setTimeoutMS(1000);
    }
#ifdef RTW_AIRPORT
    /* 0.2.119: IO80211Reference arms a dedicated 100 ms timer for every
     * Apple80211 SCAN_REQ and posts APPLE80211_M_SCAN_DONE from that timer,
     * independently of when the underlying radio scan finishes.  Keep this
     * timer separate from the 1 s debug/poll timer so the userspace handoff
     * matches that contract closely. */
    _airportScanDoneTimer = IOTimerEventSource::timerEventSource(
        this, OSMemberFunctionCast(IOTimerEventSource::Action,
                                   this, &RTW88PCIDevice::airportScanDoneTimerFired));
    if (_airportScanDoneTimer) {
        _workLoop->addEventSource(_airportScanDoneTimer);
        setProperty("AirportRTW89IntelScanDoneTimerCreated", kOSBooleanTrue);
        setProperty("AirportRTW89IntelScanDoneTimerDelayMS", (uint64_t)100, 32);
    } else {
        setProperty("AirportRTW89IntelScanDoneTimerCreated", kOSBooleanFalse);
    }
#endif

    IOLog("rtw88: device started successfully\n");
#ifdef RTW_AIRPORT
    airportPublishPrimaryDecisionSnapshot(
        this, _iface, "PreControllerRegister");
#endif
    registerService();   /* IO80211Reference legacy order: controller, then netif. */
#ifdef RTW_AIRPORT
    airportPublishPrimaryDecisionSnapshot(
        this, _iface, "PostControllerRegister");
    if (_iface) {
        _iface->registerService();
        /* 0.5.21: registerService() changes this property to false on the
         * restored Ventura framework. AirportRTW's default topology has one
         * and only one BSD IO80211Interface, so restore the public identity
         * after Apple's registration pass. */
        _iface->setProperty(kIOPrimaryInterface, kOSBooleanTrue);
        setProperty("AirportRTW89LegacyPrimaryRepublishedAfterRegister",
                    kOSBooleanTrue);
        setProperty("AirportRTW89LegacyPrimaryAfterRegister",
                    _iface->getProperty(kIOPrimaryInterface) == kOSBooleanTrue
                        ? kOSBooleanTrue : kOSBooleanFalse);
        airportPublishPrimaryDecisionSnapshot(
            this, _iface, "PostInterfaceRegister");
#if __IO80211_TARGET >= __MAC_13_0
        if (getProperty("AirportRTW89LegacyOnlyTopology") == kOSBooleanTrue)
            setProperty("AirportRTW89LegacyPrimaryOnlyInterfaceRegistered",
                        kOSBooleanTrue);
#endif
    }
#if __IO80211_TARGET >= __MAC_13_0
    if (_skywalkInterface) {
        /* 0.2.136: diagnostic-only IO80211Plane publication probe.
         *
         * Keep the already-stable control-only IO80211InfraInterface object.
         * This intentionally does NOT call start(), prepareBSDInterface(),
         * attachToDataLinkLayer(), enable(), create another ifnet, or build
         * Skywalk queues/logical links.  The only new operation is adding the
         * existing registry entry as a child of this controller in
         * IO80211Plane, then recording the result for the next boot. */
        const IORegistryPlane *io80211Plane =
            IORegistryEntry::getPlane("IO80211Plane");

        setProperty("AirportRTW89IO80211PlaneFound",
                    io80211Plane ? kOSBooleanTrue : kOSBooleanFalse);

        if (io80211Plane) {
            const bool controllerInPlane = inPlane(io80211Plane);
            setProperty("AirportRTW89ControllerInIO80211Plane",
                        controllerInPlane ? kOSBooleanTrue
                                          : kOSBooleanFalse);

            const bool attached =
                _skywalkInterface->attachToParent(this, io80211Plane);
            setProperty("AirportRTW89SkywalkIO80211PlaneAttachResult",
                        attached ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkInIO80211Plane",
                        _skywalkInterface->inPlane(io80211Plane)
                            ? kOSBooleanTrue
                            : kOSBooleanFalse);
        }

        _skywalkInterface->registerService();
        setProperty("AirportRTW89NonBSDSkywalkServiceRegistered",
                    kOSBooleanTrue);

        /* 0.2.149: make the now-proven control-only lifecycle part of normal
         * bring-up.  0.2.148 demonstrated that Tahoe receives and caches
         * valid scan results while the non-BSD Skywalk primary remains
         * classified Off; manually applying start(controller),
         * setEnabledBySystem(true), and setPoweredOnByUser(true), followed by
         * a userspace rebind, immediately restores the visible Wi-Fi list.
         *
         * Keep the exact order and safety boundaries already proven by the
         * manual probes.  This runs only after the control service has been
         * registered, matching the state in which the manual sequence was
         * validated.  It still creates no BSD interface, performs no BSD
         * preparation/defer, never calls the controller Skywalk enable path,
         * and never explicitly changes RTW89 hardware power. */
        /* The legacy ifnet does not exist yet.  Starting this object here and
         * binding it later makes Tahoe's type-0 open return Unsupported even
         * though prepareBSDInterface succeeds.  Defer the whole lifecycle to
         * dataLinkLayerAttachComplete(), where it can follow the native order:
         * prepare -> start -> system-enable -> user-power. */
        setProperty("AirportRTW89AutomaticControlLifecycleAttempted",
                    kOSBooleanFalse);
        setProperty("AirportRTW89AutomaticControlLifecycleDeferredForIfnet",
                    kOSBooleanTrue);
        setProperty("AirportRTW89AutomaticControlLifecycleSucceeded",
                    kOSBooleanFalse);
        setProperty("AirportRTW89AutomaticControlNoSecondIfnet",
                    kOSBooleanTrue);
        setProperty("AirportRTW89AutomaticControlNoBSDPreparation",
                    kOSBooleanTrue);
        setProperty("AirportRTW89AutomaticControlNoBSDDefer",
                    kOSBooleanTrue);
        setProperty("AirportRTW89AutomaticControlNoControllerEnable",
                    kOSBooleanTrue);
    }
#endif
#endif
    setBringupStage("controller-registered");
    return true;
}

void RTW88PCIDevice::debugTimerFired(IOTimerEventSource *src)
{
#ifdef RTW_AIRPORT
    /* 0.3.26b: Tahoe may publish the companion BSD ifnet only after
     * attachInterface(..., true) returns.  If the initial attach-time probe
     * saw no ifnet, arm the staged power sequence on the first later timer
     * tick where the accepted companion has a live ifnet.  Complete only once
     * per controller start so the periodic timer cannot re-run the sequence. */
    if (!_nativeCompanionPostRegisterPowerPending &&
        !_nativeCompanionPostRegisterPowerCompleted &&
        airportNativeTopologyExperiment() &&
        airportExclusiveNativeTopology() &&
        _skywalkBSDCompanion && _skywalkBSDCompanion->getIfnet()) {
        _nativeCompanionPostRegisterPowerPending = true;
        _nativeCompanionPostRegisterPowerStage = 1;
        setProperty("AirportRTW89NativeCompanionBSDRegistered", kOSBooleanTrue);
        setProperty("AirportRTW89NativeCompanionPostRegisterPowerLateArmed", kOSBooleanTrue);
        setProperty("AirportRTW89NativeCompanionPostRegisterPowerArmed", kOSBooleanTrue);
    }

    /* 0.3.26: post-registration native companion power staging.  Never run
     * these calls during attach/enable.  A full timer tick separates system
     * enable, user power, and POWER_CHANGED, and progression stops immediately
     * if the BSD ifnet disappears after either Apple lifecycle call. */
    if (_nativeCompanionPostRegisterPowerPending &&
        airportNativeTopologyExperiment() &&
        airportExclusiveNativeTopology() &&
        _skywalkBSDCompanion) {
        const bool ifnetBefore = _skywalkBSDCompanion->getIfnet() != nullptr;
        setProperty("AirportRTW89NativeCompanionPostRegisterIfnetBefore",
                    ifnetBefore ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89NativeCompanionPostRegisterPowerStage",
                    (uint64_t)_nativeCompanionPostRegisterPowerStage, 32);

        if (!ifnetBefore) {
            _nativeCompanionPostRegisterPowerPending = false;
            setProperty("AirportRTW89NativeCompanionPostRegisterAbortedNoIfnet",
                        kOSBooleanTrue);
        } else if (_nativeCompanionPostRegisterPowerStage == 1) {
            setProperty("AirportRTW89NativeCompanionSystemEnableAttempted",
                        kOSBooleanTrue);
            const bool before = _skywalkBSDCompanion->enabledBySystem();
            _skywalkBSDCompanion->IO80211Interface::setEnabledBySystem(true);
            const bool after = _skywalkBSDCompanion->enabledBySystem();
            const bool survived = _skywalkBSDCompanion->getIfnet() != nullptr;
            setProperty("AirportRTW89NativeCompanionSystemEnableBefore",
                        before ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89NativeCompanionSystemEnableAfter",
                        after ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89NativeCompanionPresentAfterSystemEnable",
                        survived ? kOSBooleanTrue : kOSBooleanFalse);
            if (survived)
                _nativeCompanionPostRegisterPowerStage = 2;
            else {
                _nativeCompanionPostRegisterPowerPending = false;
                setProperty("AirportRTW89NativeCompanionPostRegisterStoppedAfterSystemEnable",
                            kOSBooleanTrue);
            }
        } else if (_nativeCompanionPostRegisterPowerStage == 2) {
            setProperty("AirportRTW89NativeCompanionUserPowerAttempted",
                        kOSBooleanTrue);
            const bool before = _skywalkBSDCompanion->poweredOnByUser();
            _skywalkBSDCompanion->IO80211Interface::setPoweredOnByUser(true);
            const bool after = _skywalkBSDCompanion->poweredOnByUser();
            const bool survived = _skywalkBSDCompanion->getIfnet() != nullptr;
            setProperty("AirportRTW89NativeCompanionUserPowerBefore",
                        before ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89NativeCompanionUserPowerAfter",
                        after ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89NativeCompanionPresentAfterUserPower",
                        survived ? kOSBooleanTrue : kOSBooleanFalse);
            if (survived)
                _nativeCompanionPostRegisterPowerStage = 3;
            else {
                _nativeCompanionPostRegisterPowerPending = false;
                setProperty("AirportRTW89NativeCompanionPostRegisterStoppedAfterUserPower",
                            kOSBooleanTrue);
            }
        } else if (_nativeCompanionPostRegisterPowerStage == 3) {
            /* 0.3.37: the exclusive-native BSD companion is now the
             * controller's primary IO80211Interface.  Publish the same
             * completion edge native AirPort drivers use once the interface
             * exists, system-enable is asserted, and user power is ON.
             * CoreWiFi can otherwise accept GET POWER=ON while retaining its
             * separate driver-availability latch as unavailable/off. */
            _skywalkBSDCompanion->postMessage(APPLE80211_M_DRIVER_AVAILABLE,
                                               nullptr, 0);
            setProperty("AirportRTW89NativeCompanionDriverAvailablePosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89NativeCompanionDriverAvailableMS",
                        (uint64_t)airportWPA2PreflightMonotonicMS(), 64);
            _skywalkBSDCompanion->postMessage(APPLE80211_M_POWER_CHANGED,
                                               nullptr, 0);
            const bool survived = _skywalkBSDCompanion->getIfnet() != nullptr;
            setProperty("AirportRTW89NativeCompanionPowerChangedPosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89NativeCompanionPresentAfterPowerChanged",
                        survived ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89NativeCompanionPostRegisterPowerComplete",
                        survived ? kOSBooleanTrue : kOSBooleanFalse);
            _nativeCompanionPostRegisterPowerPending = false;
            _nativeCompanionPostRegisterPowerStage = 0;
            _nativeCompanionPostRegisterPowerCompleted = true;
        } else {
            _nativeCompanionPostRegisterPowerPending = false;
        }
    }
    /* 0.2.188: publish the ON power edge only after the outer Apple80211 SET
     * stack has completely unwound.  This keeps the 0.2.175 authoritative
     * SET semantics and avoids the direct-SET recursion that broke 0.2.108,
     * while giving CoreWiFi a cache-invalidating POWER_CHANGED edge that is
     * ordered after Tahoe's hidden superclass cleanup and our transport re-pin. */
    if (_airportPostSuperPowerOnNotifyPending) {
        _airportPostSuperPowerOnNotifyPending = false;
        setProperty("AirportRTW89PostSuperPowerOnNotifyPending",
                    kOSBooleanFalse);

        /* 0.3.37: honor the controller's native primary-interface identity. */
        IO80211Interface *powerWifi = getNetworkInterface();
        const bool canNotify = _airportLogicalPowerOn && powerWifi;
        setProperty("AirportRTW89PostSuperPowerOnNotifyInterfacePresent",
                    powerWifi ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89PostSuperPowerOnNotifyLogicalOn",
                    _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);

        if (canNotify) {
            pinAirportTransportUserPowerOn(powerWifi);
            pinAirportTransportSystemEnableOn(powerWifi);
            powerWifi->postMessage(APPLE80211_M_POWER_CHANGED, nullptr, 0);
            ++_airportPostSuperPowerOnNotifyCount;
            setProperty("AirportRTW89PostSuperPowerOnNotifyCount",
                        (uint64_t)_airportPostSuperPowerOnNotifyCount, 32);
            setProperty("AirportRTW89PostSuperPowerOnNotifyPosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89PostSuperPowerOnNotifyUserPower",
                        powerWifi->poweredOnByUser() ? kOSBooleanTrue
                                                     : kOSBooleanFalse);
            setProperty("AirportRTW89PostSuperPowerOnNotifySystemEnable",
                        powerWifi->enabledBySystem() ? kOSBooleanTrue
                                                     : kOSBooleanFalse);
        } else {
            setProperty("AirportRTW89PostSuperPowerOnNotifyPosted",
                        kOSBooleanFalse);
        }
    }

    airportPollState();

    if (_airportScanNotifyConsumptionProbePending) {
        if (_airportScanNotifyConsumptionProbeDelayTicks > 0) {
            --_airportScanNotifyConsumptionProbeDelayTicks;
            setProperty("AirportRTW89PostScanNotifyProbeDelayTicks",
                        (uint64_t)_airportScanNotifyConsumptionProbeDelayTicks,
                        32);
        } else {
            _airportScanNotifyConsumptionProbePending = false;
            ++_airportScanNotifyProbeCount;
            const UInt32 getCountNow = _airportScanResultGetCount;
            const UInt32 getDelta =
                getCountNow - _airportScanNotifyGetCountAtPost;
            setProperty("AirportRTW89PostScanNotifyConsumptionProbePending",
                        kOSBooleanFalse);
            setProperty("AirportRTW89PostScanNotifyProbeCount",
                        (uint64_t)_airportScanNotifyProbeCount, 32);
            setProperty("AirportRTW89PostScanNotifyGetCountAfterOneSecond",
                        (uint64_t)getCountNow, 32);
            setProperty("AirportRTW89PostScanNotifyGetCountDelta",
                        (uint64_t)getDelta, 32);
            setProperty("AirportRTW89PostScanNotifyConsumedByGET11",
                        getDelta != 0 ? kOSBooleanTrue : kOSBooleanFalse);
        }
    }

    /* 0.2.78 safety rollback/probe.  0.2.77 proved that executing the private
     * Skywalk bind sequence after the legacy data-link callback can stall the
     * Tahoe boot before userspace becomes usable.  Keep the timing probe, but
     * do NOT call registerService(), prepareBSDInterface(),
     * initRegistrationInfo(), or start() from this deferred path.  Record the
     * first real legacy ifnet and stop.  This distinguishes "ifnet timing is
     * now correct" from "the private bind sequence is safe" without risking
     * another boot hang. */
    if (_skywalkLegacyBindPending && !_skywalkLegacyBindRetried &&
        !_skywalkStarted && _skywalkInterface && _iface &&
        _airportDataLinkAttachCompleteCount > 0) {
        ifnet_t legacyIfp = _iface->getIfnet();
        setProperty("AirportRTW89SkywalkDeferredLegacyIfnetPresent",
                    legacyIfp ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.2.125: on the restored Ventura IO80211 stack, the genuine
         * AirportRTW89Interface can already be registered as BSD enX while
         * getIfnet() still returns NULL through this subclass.  IONetworkInterface
         * publishes kIOBSDNameKey once BSD registration completes, so use the
         * interface registry identity as the safe fallback.  This reads only
         * registry properties from the sole BSD/data owner; it does not create,
         * attach, start, enable, re-register, or power any Skywalk interface. */
        char interfaceName[IFNAMSIZ] = {};
        char prefixBuffer[IFNAMSIZ] = {};
        UInt32 unit = 0;
        bool identityFromIfnet = false;
        bool identityFromBSDRegistry = false;
        bool identityFromIfnetList = false;

        if (legacyIfp) {
            const char *prefix = ifnet_name(legacyIfp);
            unit = ifnet_unit(legacyIfp);
            if (prefix && prefix[0]) {
                snprintf(prefixBuffer, sizeof(prefixBuffer), "%s", prefix);
                snprintf(interfaceName, sizeof(interfaceName), "%s%u", prefix, unit);
                identityFromIfnet = interfaceName[0] != 0;
            }
        } else {
            OSString *bsdNameString = OSDynamicCast(
                OSString, _iface->getProperty(kIOBSDNameKey));
            OSString *prefixString = OSDynamicCast(
                OSString, _iface->getProperty(kIOInterfaceNamePrefix));
            OSNumber *unitNumber = OSDynamicCast(
                OSNumber, _iface->getProperty(kIOInterfaceUnit));

            setProperty("AirportRTW89ControlOnlySkywalkLegacyBSDNamePresent",
                        bsdNameString ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ControlOnlySkywalkLegacyPrefixPresent",
                        prefixString ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ControlOnlySkywalkLegacyUnitPresent",
                        unitNumber ? kOSBooleanTrue : kOSBooleanFalse);

            const char *bsdName = bsdNameString
                ? bsdNameString->getCStringNoCopy() : nullptr;
            const char *registryPrefix = prefixString
                ? prefixString->getCStringNoCopy() : nullptr;

            if (bsdName && bsdName[0])
                snprintf(interfaceName, sizeof(interfaceName), "%s", bsdName);
            if (registryPrefix && registryPrefix[0])
                snprintf(prefixBuffer, sizeof(prefixBuffer), "%s", registryPrefix);
            if (unitNumber)
                unit = unitNumber->unsigned32BitValue();

            /* Be tolerant if IOInterfaceNamePrefix/Unit have not been mirrored
             * yet: derive both from a conventional BSD name such as en2. */
            if (interfaceName[0] && (!prefixBuffer[0] || !unitNumber)) {
                size_t split = 0;
                while (interfaceName[split] &&
                       !(interfaceName[split] >= '0' && interfaceName[split] <= '9') &&
                       split + 1 < sizeof(prefixBuffer)) {
                    prefixBuffer[split] = interfaceName[split];
                    split++;
                }
                prefixBuffer[split] = '\0';

                if (!unitNumber && interfaceName[split]) {
                    UInt32 parsedUnit = 0;
                    bool haveDigit = false;
                    for (size_t i = split; interfaceName[i]; i++) {
                        if (interfaceName[i] < '0' || interfaceName[i] > '9') {
                            haveDigit = false;
                            break;
                        }
                        haveDigit = true;
                        parsedUnit = parsedUnit * 10 +
                                     (UInt32)(interfaceName[i] - '0');
                    }
                    if (haveDigit)
                        unit = parsedUnit;
                }
            }

            identityFromBSDRegistry = interfaceName[0] && prefixBuffer[0];
        }

        /* 0.2.126: the restored IO80211Interface wrapper does not expose the
         * live ifnet through getIfnet(), and its registry plane does not carry
         * BSD Name even though the networking stack has already attached enX.
         * As a final read-only fallback, enumerate attached ifnets and select
         * the unique enX whose link-layer address matches this controller's
         * hardware address.  This only borrows references returned by
         * ifnet_list_get() and releases them with ifnet_list_free(); it does
         * not create, attach, enable, retain, or alter any interface. */
        if (!identityFromIfnet && !identityFromBSDRegistry) {
            ifnet_t *interfaces = nullptr;
            u_int32_t interfaceCount = 0;
            errno_t listResult = ifnet_list_get(IFNET_FAMILY_ANY,
                                                &interfaces,
                                                &interfaceCount);
            setProperty("AirportRTW89ControlOnlySkywalkIfnetListGetReturn",
                        (uint64_t)(uint32_t)listResult, 32);
            setProperty("AirportRTW89ControlOnlySkywalkIfnetListCount",
                        (uint64_t)interfaceCount, 32);

            UInt32 macMatchCount = 0;
            char matchedName[IFNAMSIZ] = {};
            char matchedPrefix[IFNAMSIZ] = {};
            UInt32 matchedUnit = 0;

            if (listResult == 0 && interfaces) {
                for (u_int32_t i = 0; i < interfaceCount; ++i) {
                    ifnet_t candidate = interfaces[i];
                    if (!candidate)
                        continue;

                    const char *candidatePrefix = ifnet_name(candidate);
                    if (!candidatePrefix || candidatePrefix[0] != 'e' ||
                        candidatePrefix[1] != 'n' || candidatePrefix[2] != '\0')
                        continue;

                    UInt8 candidateMAC[kIOEthernetAddressSize] = {};
                    errno_t addrResult = ifnet_lladdr_copy_bytes(
                        candidate, candidateMAC, sizeof(candidateMAC));
                    if (addrResult != 0 ||
                        memcmp(candidateMAC, _macAddr.bytes,
                               sizeof(candidateMAC)) != 0)
                        continue;

                    ++macMatchCount;
                    const UInt32 candidateUnit = ifnet_unit(candidate);
                    if (macMatchCount == 1) {
                        snprintf(matchedPrefix, sizeof(matchedPrefix), "%s",
                                 candidatePrefix);
                        snprintf(matchedName, sizeof(matchedName), "%s%u",
                                 candidatePrefix, candidateUnit);
                        matchedUnit = candidateUnit;
                    }
                }
                ifnet_list_free(interfaces);
            }

            setProperty("AirportRTW89ControlOnlySkywalkIfnetMACMatchCount",
                        (uint64_t)macMatchCount, 32);

            if (macMatchCount == 1 && matchedName[0] && matchedPrefix[0]) {
                snprintf(interfaceName, sizeof(interfaceName), "%s",
                         matchedName);
                snprintf(prefixBuffer, sizeof(prefixBuffer), "%s",
                         matchedPrefix);
                unit = matchedUnit;
                identityFromIfnetList = true;
                setProperty("AirportRTW89ControlOnlySkywalkIfnetListMatchedName",
                            matchedName);
                setProperty("AirportRTW89ControlOnlySkywalkIfnetListMatchedUnit",
                            (uint64_t)matchedUnit, 32);
            }
        }

        bool haveIdentity = identityFromIfnet || identityFromBSDRegistry ||
                            identityFromIfnetList;
        setProperty("AirportRTW89ControlOnlySkywalkIdentityFromIfnet",
                    identityFromIfnet ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControlOnlySkywalkIdentityFromBSDRegistry",
                    identityFromBSDRegistry ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControlOnlySkywalkIdentityFromIfnetList",
                    identityFromIfnetList ? kOSBooleanTrue : kOSBooleanFalse);

        if (haveIdentity) {
            _skywalkLegacyBindRetried = true;
            _skywalkLegacyBindPending = false;
            setProperty("AirportRTW89SkywalkDeferredLegacyBindPending",
                        kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkDeferredLegacyBindAttempted",
                        kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkDeferredLegacyBindSuppressedForSafety",
                        kOSBooleanTrue);
            setProperty("AirportRTW89SkywalkDeferredLegacyBSDName", interfaceName);
            setProperty("AirportRTW89SkywalkDeferredLegacyBSDUnit",
                        (uint64_t)unit, 32);

            _skywalkInterface->setProperty("IOInterfaceName", interfaceName);
            _skywalkInterface->setProperty(kIOInterfaceNamePrefix, prefixBuffer);
            _skywalkInterface->setProperty(kIOInterfaceUnit,
                                           (uint64_t)unit, 32);

            setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceName",
                        interfaceName);
            setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceNamePrefix",
                        prefixBuffer);
            setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceUnit",
                        (uint64_t)unit, 32);
            setProperty("AirportRTW89ControlOnlySkywalkLegacyIfnetPresent",
                        legacyIfp ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ControlOnlySkywalkIdentityPublished",
                        kOSBooleanTrue);
            setProperty("AirportRTW89ControlOnlySkywalkDeferredIdentityPublished",
                        kOSBooleanTrue);
            setProperty("AirportRTW89ControlOnlySkywalkDeferredIdentityNoReregister",
                        kOSBooleanTrue);
            setProperty("AirportRTW89SkywalkActivationGatePassed",
                        kOSBooleanFalse);

            const char *identitySource = identityFromIfnet
                ? "direct ifnet"
                : (identityFromBSDRegistry
                    ? "BSD Name registry"
                    : "MAC-matched ifnet list");
            IOLog("AirportRTW89 0.2.127: deferred control-only Skywalk identity %s "
                  "published from %s; private bind suppressed\n",
                  interfaceName, identitySource);
        }
    }

    /* 0.2.52: run after the Apple80211 ioctl stack has unwound.  If the
     * framework overwrites setPoweredOnByUser(true) after airportSet()
     * returns, this one-shot relatch should make CoreWLAN observe ON. */
    if (_airportPowerRelatchPending) {
        _airportPowerRelatchPending = false;
        relatchAirportPowerStatePostReturn();
    }

    /* 0.2.259: restore the missing legacy post-bind completion edge while
     * keeping 0.2.258's useIOUCWhenPossible=false route selection.
     *
     * 0.2.137 armed this deferred block when selector 1 selected the legacy
     * ioctl path.  0.2.138 removed that arm when it switched to the IOUC=true
     * discovery experiment, and 0.2.258 restored selector 1=false without
     * restoring the arm.  Publish exactly DRIVER_AVAILABLE then POWER_CHANGED
     * on the genuine BSD IO80211Interface after the user-client callback has
     * unwound.  The historical 0.2.112 one-shot hardware scan is deliberately
     * NOT scheduled in this build so this experiment isolates only the two
     * post-bind framework notifications. */
    if (_airportPostBindNotificationsPending &&
        !_airportPostBindNotificationsPosted) {
        _airportPostBindNotificationsPending = false;
        const UInt64 postBindBeginMS = airportWPA2PreflightMonotonicMS();
        setProperty("AirportRTW89PostBindNotifyBeginMS",
                    (uint64_t)postBindBeginMS, 64);
        IO80211Interface *wifi = getNetworkInterface();
        setProperty("AirportRTW89PostBindNotifyInterfacePresent",
                    wifi ? kOSBooleanTrue : kOSBooleanFalse);
        if (wifi) {
            wifi->postMessage(APPLE80211_M_DRIVER_AVAILABLE, nullptr, 0);
            setProperty("AirportRTW89PostBindDriverAvailablePosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89PostBindDriverAvailableMS",
                        (uint64_t)airportWPA2PreflightMonotonicMS(), 64);
            wifi->postMessage(APPLE80211_M_POWER_CHANGED, nullptr, 0);
            setProperty("AirportRTW89PostBindPowerChangedPosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89PostBindPowerChangedMS",
                        (uint64_t)airportWPA2PreflightMonotonicMS(), 64);
            setProperty("AirportRTW89PostBindUserPower",
                        wifi->poweredOnByUser() ? kOSBooleanTrue
                                                : kOSBooleanFalse);
            setProperty("AirportRTW89PostBindSystemEnable",
                        wifi->enabledBySystem() ? kOSBooleanTrue
                                                : kOSBooleanFalse);
            _airportPostBindNotificationsPosted = true;
            setProperty("AirportRTW89PostBindNotificationsPosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89PostBindNotificationOnly259",
                        kOSBooleanTrue);
            setProperty("AirportRTW89PostBindOneShotHardwareScanSuppressed259",
                        kOSBooleanTrue);
        }
    }

    if (_airportOneShotHardwareScanPending &&
        !_airportOneShotHardwareScanAttempted) {
        if (_airportOneShotHardwareScanDelayTicks > 0) {
            --_airportOneShotHardwareScanDelayTicks;
            setProperty("AirportRTW89OneShotHardwareScanDelayTicks",
                        (uint64_t)_airportOneShotHardwareScanDelayTicks, 32);
        } else {
            IO80211Interface *wifi = getNetworkInterface();
            const bool ready = _ieee80211 && _enabled && wifi &&
                               wifi->poweredOnByUser() &&
                               wifi->enabledBySystem();
            setProperty("AirportRTW89OneShotHardwareScanReady",
                        ready ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89OneShotHardwareScanControllerEnabled",
                        _enabled ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89OneShotHardwareScanUserPower",
                        (wifi && wifi->poweredOnByUser())
                            ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89OneShotHardwareScanSystemEnable",
                        (wifi && wifi->enabledBySystem())
                            ? kOSBooleanTrue : kOSBooleanFalse);

            if (ready) {
                _airportOneShotHardwareScanPending = false;
                _airportOneShotHardwareScanAttempted = true;
                setProperty("AirportRTW89OneShotHardwareScanAttempted",
                            kOSBooleanTrue);

                /* 0.2.189: Tahoe commonly submits its own SCAN request during
                 * the same post-ON window as this historical one-shot scan.
                 * Do not reset the Apple cache or start a second scan if the
                 * backend is already scanning.  Adopt the in-flight scan and
                 * keep the OFF->ON full-completion notification pending so its
                 * real completion publishes CACHE_UPDATED -> SCAN_DONE. */
                RTW88StateResult oneShotState = {};
                const bool haveOneShotState =
                    _ieee80211->cmdGetState(&oneShotState) == kIOReturnSuccess;
                bool coalesced = haveOneShotState &&
                    oneShotState.state == RTW88_STATE_SCANNING;
                IOReturn scanResult = kIOReturnSuccess;

                setProperty("AirportRTW89PowerOnOneShotStateBefore",
                            (uint64_t)(haveOneShotState
                                ? oneShotState.state : 0xff), 32);

                if (coalesced) {
                    _airportScanObserved = true;
                    setProperty("AirportRTW89PowerOnOneShotCoalesced",
                                kOSBooleanTrue);
                    setProperty("AirportRTW89PowerOnOneShotCacheResetSkipped",
                                kOSBooleanTrue);
                    setProperty("AirportRTW89PowerOnFullScanStartFailed",
                                kOSBooleanFalse);
                } else {
                    airportResetScanCache();
                    _airportScanObserved = true;
                    scanResult = _ieee80211->cmdScan();

                    /* Close the small check/start race: if Tahoe began a scan
                     * after cmdGetState() but before cmdScan(), Busy means we
                     * should join that scan rather than destroy completion
                     * tracking. */
                    if (scanResult == kIOReturnBusy) {
                        memset(&oneShotState, 0, sizeof(oneShotState));
                        const bool haveRacedState =
                            _ieee80211->cmdGetState(&oneShotState) ==
                                kIOReturnSuccess;
                        if (haveRacedState &&
                            oneShotState.state == RTW88_STATE_SCANNING) {
                            coalesced = true;
                            scanResult = kIOReturnSuccess;
                            _airportScanObserved = true;
                            setProperty("AirportRTW89PowerOnOneShotCoalesced",
                                        kOSBooleanTrue);
                            setProperty("AirportRTW89PowerOnOneShotRaceBusyCoalesced",
                                        kOSBooleanTrue);
                            setProperty("AirportRTW89PowerOnFullScanStartFailed",
                                        kOSBooleanFalse);
                        }
                    }

                    if (scanResult != kIOReturnSuccess) {
                        _airportScanObserved = false;
                        if (_airportPowerOnFullScanNotifyPending) {
                            _airportPowerOnFullScanNotifyPending = false;
                            setProperty("AirportRTW89PowerOnFullScanNotifyPending",
                                        kOSBooleanFalse);
                            setProperty("AirportRTW89PowerOnFullScanStartFailed",
                                        kOSBooleanTrue);
                        }
                    }
                }

                setProperty("AirportRTW89PowerOnOneShotCoalesced",
                            coalesced ? kOSBooleanTrue : kOSBooleanFalse);
                setProperty("AirportRTW89OneShotHardwareScanReturn",
                            (uint64_t)(uint32_t)scanResult, 32);
                setProperty("AirportRTW89OneShotHardwareScanStarted",
                            scanResult == kIOReturnSuccess
                                ? kOSBooleanTrue : kOSBooleanFalse);
                IOLog("AirportRTW89 0.2.189: post-ON native scan returned "
                      "0x%x (coalesced=%d)\n", scanResult,
                      coalesced ? 1 : 0);
            } else {
                /* Keep the probe bounded to the normal timer cadence and retry
                 * only after another second if bring-up is not fully ready yet. */
                _airportOneShotHardwareScanDelayTicks = 1;
                setProperty("AirportRTW89OneShotHardwareScanDeferredNotReady",
                            kOSBooleanTrue);
            }
        }
    }
#endif
    unsigned int avail = rtw88_be_tx_avail();
    if (_txStalled && avail >= kRTW88TxResumeAvail)
        resumeTxIfStalled();
    if (_txStalled || avail < kRTW88TxStallAvail)
        rtw88_debug_dump_tx_state();
    src->setTimeoutMS(1000);   /* re-arm */
}

void RTW88PCIDevice::stop(IOService *provider)
{
    IOLog("rtw88: RTW88PCIDevice::stop\n");
    teardown();
    super::stop(provider);
}

void RTW88PCIDevice::systemWillShutdown(IOOptionBits specifier)
{
    const bool isRestart = specifier == kIOMessageSystemWillRestart;
    const bool isPowerOff = specifier == kIOMessageSystemWillPowerOff;
    const bool finalPowerTransition = isRestart || isPowerOff;

    IOLog("rtw88: systemWillShutdown specifier=0x%llx restart=%d poweroff=%d\n",
          (unsigned long long)specifier, isRestart ? 1 : 0,
          isPowerOff ? 1 : 0);

#ifdef RTW_AIRPORT
    setProperty("AirportRTW89SystemWillShutdownSeen", kOSBooleanTrue);
    setProperty("AirportRTW89SystemWillShutdownSpecifier",
                (uint64_t)specifier, 64);
    setProperty("AirportRTW89SystemWillShutdownRestart",
                isRestart ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SystemWillShutdownPowerOff",
                isPowerOff ? kOSBooleanTrue : kOSBooleanFalse);
#endif

    /* 0.2.203: macOS Restart does not guarantee that the ordinary controller
     * disable()/stop() path runs before the platform performs a warm reset.
     * AirportRTW89 intentionally keeps the RTW89 backend powered across
     * routine IO80211 lifecycle disables so Wi-Fi OFF/ON is restart-safe.
     * That policy is correct for a live system but wrong at the final system
     * restart boundary: firmware/HCI/DMA can otherwise survive long enough to
     * leave the PCI function in a state that only a cold power cut clears.
     *
     * Quiesce only for the terminal power-off/restart callback.  Keep normal
     * Wi-Fi toggle semantics untouched.  Stop new TX first, then let the RTW89
     * core perform its normal remove-interface -> core_stop sequence while
     * interrupts are still available for any final firmware/HCI completion.
     * Disable the interrupt event source and PCI bus mastering only after the
     * core has stopped, preventing any DMA from crossing the warm reboot.
     */
    if (finalPowerTransition && !_systemShutdownQuiesced) {
        _systemShutdownQuiesced = true;

#ifdef RTW_AIRPORT
        setProperty("AirportRTW89SystemShutdownQuiesceStarted",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SystemShutdownQuiesceWasEnabled",
                    _enabled ? kOSBooleanTrue : kOSBooleanFalse);
#endif

        rtw88_set_tx_resume_cb(nullptr);

        if (_debugTimer)
            _debugTimer->cancelTimeout();
#ifdef RTW_AIRPORT
        if (_airportScanDoneTimer) {
            _airportScanDoneTimer->cancelTimeout();
            _airportScanDoneTimerPending = false;
        }
#endif

        if (_txQueue) {
            _txQueue->stop();
            _txQueue->flush();
        }

        if (_ieee80211) {
            IOLog("rtw88: system shutdown quiesce: RTW89 core powerOff begin\n");
            _ieee80211->powerOff();
            IOLog("rtw88: system shutdown quiesce: RTW89 core powerOff complete\n");
#ifdef RTW_AIRPORT
            setProperty("AirportRTW89SystemShutdownCorePowerOffCalled",
                        kOSBooleanTrue);
#endif
        }

        if (_intrSrc)
            _intrSrc->disable();

        if (_pciDev) {
            _pciDev->setBusMasterEnable(false);
#ifdef RTW_AIRPORT
            setProperty("AirportRTW89SystemShutdownPCIBusMasterDisabled",
                        kOSBooleanTrue);
#endif
        }

        _enabled = false;
        drainPendingFree();

#ifdef RTW_AIRPORT
        setProperty("AirportRTW89ControllerEnabled", kOSBooleanFalse);
        setProperty("AirportRTW89SystemShutdownQuiesceCompleted",
                    kOSBooleanTrue);
#endif
        IOLog("rtw88: system shutdown quiesce complete\n");
    }

    super::systemWillShutdown(specifier);
}

void RTW88PCIDevice::free()
{
    if (_compatPciDev) { IOFree(_compatPciDev, sizeof(*_compatPciDev)); _compatPciDev = nullptr; }
    if (_pendingFreeLock) { drainPendingFree(); IOSimpleLockFree(_pendingFreeLock); _pendingFreeLock = nullptr; }
    if (_dmaLock)         { IOSimpleLockFree(_dmaLock);        _dmaLock        = nullptr; }
#ifdef RTW_AIRPORT
    if (_airportScanResults) { IOFree(_airportScanResults, sizeof(apple80211_scan_result) * 64); _airportScanResults = nullptr; }
    if (_airportBSSCache) { IOFree(_airportBSSCache, sizeof(RTW88BSS) * 64); _airportBSSCache = nullptr; }
    if (_airportLock) { IOLockFree(_airportLock); _airportLock = nullptr; }
#endif
    super::free();
}

void RTW88PCIDevice::teardown()
{
    /* Stop the IRQ bottom-half from calling back into us before we tear down
     * the output queue it services. */
    rtw88_set_tx_resume_cb(nullptr);

    if (_debugTimer)
        _debugTimer->cancelTimeout();
#ifdef RTW_AIRPORT
    if (_airportScanDoneTimer)
        _airportScanDoneTimer->cancelTimeout();
#endif
    if (_intrSrc)
        _intrSrc->disable();
    if (_txQueue) {
        _txQueue->stop();
        _txQueue->flush();
    }

    if (_enabled) disable(_iface);
    drainPendingFree();   /* release any bounce bufs deferred during TX ISR */

#if defined(RTW_AIRPORT) && __IO80211_TARGET >= __MAC_13_0
    if (_skywalkBSDCompanion) {
        detachInterface(_skywalkBSDCompanion);
        _skywalkBSDCompanion->release();
        _skywalkBSDCompanion = nullptr;
    }
    if (_skywalkInterface) {
        /* 0.2.136: undo the diagnostic-only IO80211Plane relationship before
         * tearing down the normal IOService attachment.  detachFromParent()
         * is a no-op if the plane was unavailable or the attach failed. */
        const IORegistryPlane *io80211Plane =
            IORegistryEntry::getPlane("IO80211Plane");
        if (io80211Plane)
            _skywalkInterface->detachFromParent(this, io80211Plane);

        _skywalkInterface->terminate(kIOServiceSynchronous);
        _skywalkInterface->detach(this);
        _skywalkInterface->release();
        _skywalkInterface = nullptr;
    }
#endif

#ifdef RTW_AIRPORT
    if (_net80211) { _net80211->release(); _net80211 = nullptr; }
#endif
    if (_ieee80211)  { _ieee80211->stop(); _ieee80211->release(); _ieee80211 = nullptr; }

    rtw88_compat_exit();

#ifdef RTW_AIRPORT
    if (_airportScanDoneTimer) { _airportScanDoneTimer->cancelTimeout(); _workLoop->removeEventSource(_airportScanDoneTimer); _airportScanDoneTimer->release(); _airportScanDoneTimer = nullptr; }
#endif
    if (_debugTimer) { _debugTimer->cancelTimeout(); _workLoop->removeEventSource(_debugTimer); _debugTimer->release(); _debugTimer = nullptr; }
    if (_intrSrc)  { _workLoop->removeEventSource(_intrSrc); _intrSrc->release();  _intrSrc = nullptr; }
    if (_cmdGate)  { _workLoop->removeEventSource(_cmdGate); _cmdGate->release();  _cmdGate = nullptr; }
    if (_txQueue)  { _txQueue->release();   _txQueue = nullptr; }
#ifndef IO80211FAMILY_V2
    if (_iface)    { detachInterface(_iface); _iface->release(); _iface = nullptr; }
#else
    _iface = nullptr;
#endif
    if (_workLoop) { _workLoop->release();   _workLoop = nullptr; }
    if (_mmioMap)  { _mmioMap->release();    _mmioMap = nullptr; _mmioBase = nullptr; }
    if (_pciDev)   { _pciDev->release();     _pciDev = nullptr; }

    g_pci_dev_instance = nullptr;
    rtw88_pci_io_ops   = nullptr;
    rtw88_dma_ops      = nullptr;
}

/* ------------------------------------------------------------------ */
/*  Interrupt                                                           */
/* ------------------------------------------------------------------ */

bool RTW88PCIDevice::setupInterrupt()
{
    _intrSrc = IOInterruptEventSource::interruptEventSource(
        this,
        OSMemberFunctionCast(IOInterruptEventSource::Action,
                             this, &RTW88PCIDevice::handleInterrupt),
        _pciDev, 0);

    if (!_intrSrc) {
        IOLog("rtw88: failed to create interrupt event source\n");
        return false;
    }
    _workLoop->addEventSource(_intrSrc);

    return true;
}

void RTW88PCIDevice::handleInterrupt(IOInterruptEventSource *src, int count)
{
    if (_ieee80211)
        rtw88_trigger_interrupt();
}

/* ------------------------------------------------------------------ */
/*  IOEthernetController / IONetworkController                          */
/* ------------------------------------------------------------------ */

#ifdef RTW_AIRPORT
void RTW88PCIDevice::dataLinkLayerAttachComplete(IO80211Interface *interface)
{
    ++_airportDataLinkAttachCompleteCount;
    setProperty("AirportRTW89DataLinkAttachCompleteSeen", kOSBooleanTrue);
    setProperty("AirportRTW89DataLinkAttachCompleteCount",
                (uint64_t)_airportDataLinkAttachCompleteCount, 32);
    setProperty("AirportRTW89DataLinkAttachInterfacePresent",
                interface ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89DataLinkAttachControllerEnabledBeforeSuper",
                _enabled ? kOSBooleanTrue : kOSBooleanFalse);

    airportPublishPrimaryDecisionSnapshot(
        this, interface, "DataLinkBeforeSuper");

    if (interface) {
        setProperty("AirportRTW89DataLinkAttachUserPowerBeforeSuper",
                    interface->poweredOnByUser() ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        setProperty("AirportRTW89DataLinkAttachSystemEnableBeforeSuper",
                    interface->enabledBySystem() ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
    }

    /* Preserve IO80211FamilyLegacy's normal attach completion.  Historical
     * IO80211 logs show this base callback leading into
     * finishAttachToDataLinkLayer()/Scan Manager initialization. */
    RTW88ControllerBase::dataLinkLayerAttachComplete(interface);
    setProperty("AirportRTW89DataLinkAttachSuperReturned", kOSBooleanTrue);
    airportPublishPrimaryDecisionSnapshot(
        this, interface, "DataLinkAfterSuper");

    if (!interface)
        return;

    setProperty("AirportRTW89DataLinkAttachUserPowerAfterSuper",
                interface->poweredOnByUser() ? kOSBooleanTrue
                                             : kOSBooleanFalse);
    setProperty("AirportRTW89DataLinkAttachSystemEnableAfterSuper",
                interface->enabledBySystem() ? kOSBooleanTrue
                                             : kOSBooleanFalse);

    /* 0.2.78 timing diagnostic: this is the earliest framework callback in
     * our legacy path where the BSD ifnet is expected to be materialized.
     * The actual Skywalk bind is still deferred to the controller timer. */
    ifnet_t completedIfp = interface->getIfnet();
    setProperty("AirportRTW89DataLinkAttachIfnetPresentAfterSuper",
                completedIfp ? kOSBooleanTrue : kOSBooleanFalse);

#if __IO80211_TARGET >= __MAC_13_0
    /* The controller start path runs before IO80211Family has materialized
     * en2, so shared-ifnet preparation must occur here, after the superclass
     * data-link callback.  Transfer queue ownership first: Apple's
     * prepareBSDInterface() retires the legacy IONetworkController queue. */
    if (completedIfp && _skywalkInterface && !_skywalkOwnsBSDQueue) {
        void **networkRegistration =
            _skywalkInterface->rawNetworkRegistrationSlot();
        void **ethernetRegistration =
            _skywalkInterface->rawEthernetRegistrationSlot();
        const bool registrationReady =
            networkRegistration && ethernetRegistration &&
            _skywalkNetworkRegistrationCopy &&
            _skywalkEthernetRegistrationCopy &&
            *networkRegistration == _skywalkNetworkRegistrationCopy &&
            *ethernetRegistration == _skywalkEthernetRegistrationCopy;
        setProperty("AirportRTW89DataLinkSkywalkRegistrationReady",
                    registrationReady ? kOSBooleanTrue : kOSBooleanFalse);

        if (registrationReady) {
            /* Publish the sole BSD owner's identity before Skywalk consumes
             * the shared ifnet.  The old timer required !_skywalkStarted and
             * therefore could never run after the ordered lifecycle began. */
            const char *completedPrefix = ifnet_name(completedIfp);
            const UInt32 completedUnit = ifnet_unit(completedIfp);
            char completedName[IFNAMSIZ] = {};
            if (completedPrefix && completedPrefix[0])
                snprintf(completedName, sizeof(completedName), "%s%u",
                         completedPrefix, completedUnit);
            if (completedName[0]) {
                _skywalkInterface->setProperty("IOInterfaceName",
                                               completedName);
                _skywalkInterface->setProperty(kIOInterfaceNamePrefix,
                                               completedPrefix);
                _skywalkInterface->setProperty(kIOInterfaceUnit,
                                               (uint64_t)completedUnit, 32);
                setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceName",
                            completedName);
                setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceNamePrefix",
                            completedPrefix);
                setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceUnit",
                            (uint64_t)completedUnit, 32);
                setProperty("AirportRTW89ControlOnlySkywalkIdentityPublished",
                            kOSBooleanTrue);
                setProperty("AirportRTW89DataLinkSkywalkIdentityBeforePrepare",
                            kOSBooleanTrue);
                _skywalkLegacyBindRetried = true;
                _skywalkLegacyBindPending = false;
                setProperty("AirportRTW89SkywalkDeferredLegacyBindPending",
                            kOSBooleanFalse);
            }

            /* 0.3.14: this Skywalk service is control-only: it has no TX
             * submission queues and cannot own en2's data path.  Retiring the
             * legacy IOGatedOutputQueue here leaves carrier active but gives
             * the BSD stack nowhere to submit DHCP/ARP (capacity/state both
             * remain zero).  Keep our retained legacy queue and ownership
             * while still preparing the shared ifnet for the control-plane
             * lifecycle below. */
            _skywalkOwnsBSDQueue = false;
            setProperty("AirportRTW89DataLinkLegacyQueueReleased",
                        kOSBooleanFalse);
            setProperty("AirportRTW89DataLinkLegacyQueueRetainedForTX",
                        kOSBooleanTrue);
            setProperty("AirportRTW89DataLinkSkywalkPrepareAttempted",
                        kOSBooleanTrue);
            _skywalkInterface->prepareBSDInterface(completedIfp, 0);
            const bool prepared =
                _skywalkInterface->rawNetworkBSDInterfaceSlot() &&
                *_skywalkInterface->rawNetworkBSDInterfaceSlot() == completedIfp;
            setProperty("AirportRTW89DataLinkSkywalkPrepared",
                        prepared ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89SkywalkSharedIfnetPrepared",
                        prepared ? kOSBooleanTrue : kOSBooleanFalse);

            if (prepared) {
                setProperty("AirportRTW89AutomaticControlLifecycleAttempted",
                            kOSBooleanTrue);
                setProperty("AirportRTW89AutomaticControlLifecycleAfterPrepare",
                            kOSBooleanTrue);

                const IOReturn automaticStart = runSkywalkManualStartProbe();
                setProperty("AirportRTW89AutomaticControlStartReturn",
                            (uint64_t)(uint32_t)automaticStart, 32);

                IOReturn automaticSystemEnable = kIOReturnNotReady;
                IOReturn automaticUserPower = kIOReturnNotReady;
                if (automaticStart == kIOReturnSuccess) {
                    automaticSystemEnable = runSkywalkManualEnableProbe();
                    setProperty("AirportRTW89AutomaticControlSystemEnableReturn",
                                (uint64_t)(uint32_t)automaticSystemEnable, 32);
                }
                if (automaticSystemEnable == kIOReturnSuccess) {
                    automaticUserPower = runSkywalkManualUserPowerProbe();
                    setProperty("AirportRTW89AutomaticControlUserPowerReturn",
                                (uint64_t)(uint32_t)automaticUserPower, 32);
                }

                const bool lifecycleReady =
                    automaticStart == kIOReturnSuccess &&
                    automaticSystemEnable == kIOReturnSuccess &&
                    automaticUserPower == kIOReturnSuccess;
                setProperty("AirportRTW89AutomaticControlLifecycleSucceeded",
                            lifecycleReady ? kOSBooleanTrue
                                           : kOSBooleanFalse);
            }

            /* prepareBSDInterface() may stop or zero the legacy queue while
             * binding the shared ifnet.  Restore it only after that operation
             * and the control lifecycle have returned. */
            airportRepairOutputQueue("post-skywalk-prepare-legacy-tx");
        }
    }
#endif
    setProperty("AirportRTW89SkywalkDeferredLegacyBindReadyAfterDataLink",
                (_skywalkLegacyBindPending && completedIfp)
                    ? kOSBooleanTrue : kOSBooleanFalse);

    /* 0.2.168: 0.2.167 separated the user-visible logical power state from
     * IO80211Interface::poweredOnByUser(), but this late attach callback still
     * carried the old 0.2.165 behavior and could silently write the logical
     * OFF state back into the primary transport latch after the post-return
     * re-pin.  That recreated the one-way OFF condition during boot/attach.
     * Keep the primary Apple transport live here too; GET POWER remains the
     * authoritative user-visible state through _airportLogicalPowerOn. */
    pinAirportTransportUserPowerOn(interface);
    pinAirportTransportSystemEnableOn(interface);
    setProperty("AirportRTW89DataLinkAttachPrimaryTransportPinnedOn",
                kOSBooleanTrue);
    setProperty("AirportRTW89DataLinkAttachLogicalPowerAtPin",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);
    interface->postMessage(APPLE80211_M_POWER_CHANGED);

    setProperty("AirportRTW89DataLinkAttachPowerNotifyPosted",
                kOSBooleanTrue);
    setProperty("AirportRTW89DataLinkAttachUserPowerAfterNotify",
                interface->poweredOnByUser() ? kOSBooleanTrue
                                             : kOSBooleanFalse);
    setProperty("AirportRTW89DataLinkAttachSystemEnableAfterNotify",
                interface->enabledBySystem() ? kOSBooleanTrue
                                             : kOSBooleanFalse);
}

#ifdef IO80211FAMILY_V2
void RTW88PCIDevice::dataLinkLayerAttachComplete()
{
    setProperty("AirportRTW89V2DataLinkAttachCompleteSeen", kOSBooleanTrue);
    RTW88ControllerBase::dataLinkLayerAttachComplete();
}
#endif
#endif

bool RTW88PCIDevice::attachDevice()
{
    /* IO80211Reference 2.3.0 establishes the controller's 802.11 medium table
     * before attachInterface().  IO80211Family consumes controller state
     * while constructing/configuring IO80211Interface, so preserve that
     * ordering instead of publishing the medium after the interface exists. */
    if (!setupMediumDict()) {
        setBringupStage("medium-dictionary-failed", kIOReturnError);
        return false;
    }
    setBringupStage("medium-dictionary-ready");

    setBringupStage("attachInterface-call");
    if (!attachInterface((IONetworkInterface **)&_iface, true)) {
        IOLog("rtw88: attachInterface failed\n");
        setBringupStage("attachInterface-returned-false", kIOReturnError);
        return false;
    }
    setBringupStage("attachInterface-returned-true");

#ifdef RTW_AIRPORT
    /* 0.2.255: match IO80211Reference's legacy ordering: medium selection is
     * already complete, attachInterface(..., true) has returned successfully,
     * and only now do we publish the initial VALID-only link state.  Preserve
     * the exact previous link bits and current-medium argument. */
    setProperty("AirportRTW89InitialLinkValidPostAttachAttempted",
                kOSBooleanTrue);
    setProperty("AirportRTW89InitialLinkValidPostAttachInterfacePresent",
                _iface ? kOSBooleanTrue : kOSBooleanFalse);
    const IONetworkMedium *postAttachMedium = getCurrentMedium();
    setProperty("AirportRTW89InitialLinkValidPostAttachCurrentMediumPresent",
                postAttachMedium ? kOSBooleanTrue : kOSBooleanFalse);
    const bool postAttachLinkValid =
        setLinkStatus(kIONetworkLinkValid, postAttachMedium);
    setProperty("AirportRTW89InitialLinkValidPostAttachPublished",
                postAttachLinkValid ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89InitialLinkValidPostAttachStatus",
                (uint64_t)kIONetworkLinkValid, 32);
    if (postAttachMedium)
        setProperty("AirportRTW89InitialLinkValidPostAttachMediumType",
                    (uint64_t)postAttachMedium->getType(), 32);

    setProperty("AirportRTW89LegacyInterfaceAttachedUnregistered",
                kOSBooleanTrue);
    setProperty("AirportRTW89LegacyBSDRegistrationSuppressed",
                kOSBooleanFalse);
#endif

    publishHardwareIdentity();
#ifdef RTW_AIRPORT
    airportPublishPrimaryDecisionSnapshot(
        this, _iface, "PostAttachIdentity");
#endif

    _txQueue = OSDynamicCast(IOGatedOutputQueue, getOutputQueue());
    if (_txQueue) _txQueue->retain();
#ifdef RTW_AIRPORT
    airportPublishOutputQueueDiagnostics("attach-after-getOutputQueue");
#endif
    setBringupStage("interface-attached-unregistered");
    return true;
}

#ifdef RTW_AIRPORT
bool RTW88PCIDevice::createWorkLoop()
{
    if (_workLoop)
        return true;
    _workLoop = IOWorkLoop::workLoop();
    return _workLoop != nullptr;
}

IOOutputQueue *RTW88PCIDevice::getOutputQueue() const
{
    return super::getOutputQueue();
}
#endif

bool RTW88PCIDevice::setupMediumDict()
{
#ifdef RTW_AIRPORT
    OSDictionary *mediums = OSDictionary::withCapacity(2);
    if (!mediums) return false;

    /* Match the attachment path proven by the Senmiko native build. */
    addMedium(mediums, kIOMediumIEEE80211, 54);
    addMedium(mediums, kIOMediumIEEE80211None, 0);

    bool published = publishMediumDictionary(mediums);
    mediums->release();
    if (!published) return false;

    IONetworkMedium *primary = IONetworkMedium::getMediumWithType(
        OSDynamicCast(OSDictionary, getProperty(kIOMediumDictionary)),
        kIOMediumIEEE80211);
    if (!primary || !setCurrentMedium(primary) || !setSelectedMedium(primary))
        return false;

#ifdef RTW_AIRPORT
    /* 0.2.255: IO80211Reference legacy parity.  Publish the medium before
     * attachInterface(), but defer the initial VALID-only link publication
     * until the IO80211Interface has actually been attached.  Publishing the
     * initial link state here meant no legacy interface existed to observe
     * that transition.  Do not change the medium itself or the link bits. */
    setProperty("AirportRTW89InitialLinkValidDeferredUntilAfterAttach",
                kOSBooleanTrue);
    setProperty("AirportRTW89InitialLinkValidPublishedBeforeAttach",
                kOSBooleanFalse);
#endif
    return true;
#else
    OSDictionary *mediums = OSDictionary::withCapacity(4);
    if (!mediums) return false;

    addMedium(mediums, kIOMediumEthernetAuto, 0);
    addMedium(mediums, kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex,  10);
    addMedium(mediums, kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex, 100);
    addMedium(mediums, kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex, 1000);

    setProperty(kIOMediumDictionary, mediums);
    mediums->release();

    IONetworkMedium *autoMedium = IONetworkMedium::getMediumWithType(
        OSDynamicCast(OSDictionary, getProperty(kIOMediumDictionary)),
        kIOMediumEthernetAuto);
    setCurrentMedium(autoMedium);
    setLinkStatus(kIONetworkLinkActive | kIONetworkLinkValid,
                  IONetworkMedium::getMediumWithType(
                      OSDynamicCast(OSDictionary, getProperty(kIOMediumDictionary)),
                      kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex));
    return true;
#endif
}

void RTW88PCIDevice::addMedium(OSDictionary *mediums, IOMediumType type, UInt64 speed)
{
    IONetworkMedium *m = IONetworkMedium::medium(type, speed * 1000000ULL);
    if (m) {
        IONetworkMedium::addMedium(mediums, m);
        m->release();
    }
}

#ifdef RTW_AIRPORT
bool RTW88PCIDevice::setAirportLogicalPowerState(
    bool on, AirportLogicalPowerSource source)
{
    const bool changed = (_airportLogicalPowerOn != on);
    _airportLogicalPowerOn = on;

    setProperty("AirportRTW89LogicalPowerOn",
                on ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89LogicalPowerCurrent",
                on ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89LogicalPowerLastSource",
                (uint64_t)source, 32);
    setProperty("AirportRTW89LogicalPowerLastChanged",
                changed ? kOSBooleanTrue : kOSBooleanFalse);
    if (changed) {
        ++_airportLogicalPowerTransitionCount;
        setProperty("AirportRTW89LogicalPowerTransitionCount",
                    (uint64_t)_airportLogicalPowerTransitionCount, 32);
    }
    return changed;
}

IOReturn RTW88PCIDevice::applyAirportUserPowerState(
    bool on, AirportLogicalPowerSource source)
{
    const bool logicalPowerBefore = _airportLogicalPowerOn;
    const bool changed = setAirportLogicalPowerState(on, source);

    setProperty("AirportRTW89PowerStateStored",
                on ? (uint64_t)APPLE80211_POWER_ON
                   : (uint64_t)APPLE80211_POWER_OFF,
                8);
    setProperty("AirportRTW89UserPowerTransitionIdempotent",
                changed ? kOSBooleanFalse : kOSBooleanTrue);

    /* 0.2.175: redundant state-bearing requests acknowledge the already
     * stored IO80211Reference-style state but do not retrigger firmware power
     * commands, scan cancellation, or a fresh hardware scan. */
    if (!changed) {
        setProperty("AirportRTW89UserPowerTransitionHardwareCommandSkipped",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }

    setProperty("AirportRTW89UserPowerTransitionHardwareCommandSkipped",
                kOSBooleanFalse);

    if (!on) {
        _airportScanObserved = false;
        _airportOneShotHardwareScanPending = false;
        _airportPostSuperPowerOnNotifyPending = false;
        _airportPowerOnFullScanNotifyPending = false;
        setProperty("AirportRTW89PostSuperPowerOnNotifyPending",
                    kOSBooleanFalse);
        setProperty("AirportRTW89PowerOnFullScanNotifyPending",
                    kOSBooleanFalse);
        if (_airportScanDoneTimer) {
            _airportScanDoneTimer->cancelTimeout();
            _airportScanDoneTimerPending = false;
        }

        /* 0.2.186: logical OFF is a hard visibility boundary.  Empty the
         * Apple-facing snapshot immediately so Control Center cannot continue
         * displaying the pre-OFF network list while the backend quiesces. */
        airportResetScanCache();
        setProperty("AirportRTW89PowerOffAppleScanCacheCleared",
                    kOSBooleanTrue);

        const IOReturn logicalResult = _ieee80211
            ? _ieee80211->cmdSetUserPower(false)
            : kIOReturnNotReady;
        const IOReturn bssFlushResult =
            (_ieee80211 && logicalResult == kIOReturnSuccess)
                ? _ieee80211->flushBSSCache()
                : logicalResult;
        setProperty("AirportRTW89PowerOffPersistentBSSFlushReturn",
                    (uint64_t)(uint32_t)bssFlushResult, 32);
        setProperty("AirportRTW89PowerOffPersistentBSSFlushed",
                    bssFlushResult == kIOReturnSuccess ?
                        kOSBooleanTrue : kOSBooleanFalse);

        /* Tahoe restart-safety adaptation: user-visible OFF must not tear
         * down the IO80211 transport needed to receive a later ON request. */
        if (_iface) {
            pinAirportTransportUserPowerOn(_iface);
            pinAirportTransportSystemEnableOn(_iface);
            setProperty("AirportRTW89PrimaryTransportPowerPinnedOn",
                        kOSBooleanTrue);
        }
#if __IO80211_TARGET >= __MAC_13_0
        if (_skywalkInterface)
            _skywalkInterface->IO80211InfraInterface::setPoweredOnByUser(true);
#endif
        _airportPowerRelatchPending = true;
        setProperty("AirportRTW89HardwarePowerOffSuppressedForRestartSafety",
                    kOSBooleanTrue);
        setProperty("AirportRTW89UserPowerToggleAuthoritative",
                    kOSBooleanTrue);
        setProperty("AirportRTW89UserPowerOffLogicalResult",
                    (uint64_t)(uint32_t)logicalResult, 32);
        return kIOReturnSuccess;
    }

    const IOReturn result = _ieee80211
        ? _ieee80211->cmdSetUserPower(true)
        : kIOReturnNotReady;
    if (_iface) {
        pinAirportTransportUserPowerOn(_iface);
        pinAirportTransportSystemEnableOn(_iface);
        _iface->postMessage(APPLE80211_M_POWER_CHANGED, nullptr, 0);
    }
#if __IO80211_TARGET >= __MAC_13_0
    if (_skywalkInterface)
        _skywalkInterface->IO80211InfraInterface::setPoweredOnByUser(true);
#endif
    _airportPowerRelatchPending = false;
    if (result == kIOReturnSuccess && !logicalPowerBefore) {
        _airportOneShotHardwareScanPending = true;
        _airportOneShotHardwareScanAttempted = false;
        _airportOneShotHardwareScanDelayTicks = 0;
        _airportPowerOnFullScanNotifyPending = true;
        setProperty("AirportRTW89UserPowerOnFreshScanScheduled",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PowerOnFullScanNotifyPending",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PowerOnFullScanEarlyDoneSuppressed",
                    kOSBooleanFalse);
        setProperty("AirportRTW89PowerOnFullScanStartFailed",
                    kOSBooleanFalse);
        setProperty("AirportRTW89PowerOnOneShotCoalesced",
                    kOSBooleanFalse);
        setProperty("AirportRTW89PowerOnOneShotRaceBusyCoalesced",
                    kOSBooleanFalse);
        setProperty("AirportRTW89PowerOnOneShotCacheResetSkipped",
                    kOSBooleanFalse);
    }
    setProperty("AirportRTW89UserPowerToggleAuthoritative",
                kOSBooleanTrue);
    return result;
}

void RTW88PCIDevice::pinAirportTransportUserPowerOn(
    IO80211Interface *interface)
{
    if (!interface)
        return;

    ++_airportInternalTransportPinCount;
    setProperty("AirportRTW89InternalTransportPinActive", kOSBooleanTrue);
    setProperty("AirportRTW89InternalTransportPinCount",
                (uint64_t)_airportInternalTransportPinCount, 32);
    setProperty("AirportRTW89InternalTransportPinBaseBefore",
                interface->poweredOnByUser()
                    ? kOSBooleanTrue : kOSBooleanFalse);

    /* Explicit qualification is intentional: driver-owned transport liveness
     * must not be mistaken for a Tahoe/framework user-power request. */
    interface->IO80211Interface::setPoweredOnByUser(true);

    setProperty("AirportRTW89InternalTransportPinBaseAfter",
                interface->poweredOnByUser()
                    ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89InternalTransportPinActive", kOSBooleanFalse);
}

void RTW88PCIDevice::pinAirportTransportSystemEnableOn(
    IO80211Interface *interface)
{
    if (!interface)
        return;

    ++_airportInternalSystemEnablePinCount;
    setProperty("AirportRTW89InternalSystemEnablePinActive", kOSBooleanTrue);
    setProperty("AirportRTW89InternalSystemEnablePinCount",
                (uint64_t)_airportInternalSystemEnablePinCount, 32);
    setProperty("AirportRTW89InternalSystemEnablePinBaseBefore",
                interface->enabledBySystem()
                    ? kOSBooleanTrue : kOSBooleanFalse);

    /* Explicit qualification intentionally bypasses the 0.2.172 diagnostic
     * override so driver-owned transport liveness cannot masquerade as a
     * Tahoe/framework system-enable request. */
    interface->IO80211Interface::setEnabledBySystem(true);

    setProperty("AirportRTW89InternalSystemEnablePinBaseAfter",
                interface->enabledBySystem()
                    ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89InternalSystemEnablePinActive", kOSBooleanFalse);
}

void RTW88PCIDevice::synchronizeAirportPowerState(IONetworkInterface *iface)
{
    IO80211Interface *wifi = OSDynamicCast(
        IO80211Interface, iface ? iface : _iface);
    if (!wifi) {
        setProperty("AirportRTW89PowerStateSyncInterfaceMissing",
                    kOSBooleanTrue);
        return;
    }

    /* 0.2.167: separate the Apple transport latch from the user-visible
     * logical radio state.  The primary IO80211Interface must stay internally
     * powered so Tahoe can deliver a later ON request after OFF.  GET POWER
     * still reports _airportLogicalPowerOn, so this does not restore the old
     * forced-ON user-visible behavior. */
    pinAirportTransportUserPowerOn(wifi);
    pinAirportTransportSystemEnableOn(wifi);
    wifi->setLinkState(kIO80211NetworkLinkDown, 0);
    wifi->postMessage(APPLE80211_M_POWER_CHANGED);

    setProperty("AirportRTW89PowerStateSynchronized", kOSBooleanTrue);
    setProperty("AirportRTW89PoweredOnByUserForced", kOSBooleanFalse);
    setProperty("AirportRTW89PrimaryTransportPowerPinnedOn",
                kOSBooleanTrue);
    setProperty("AirportRTW89UserPowerToggleAuthoritative", kOSBooleanTrue);
    setProperty("AirportRTW89LogicalPowerOn",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);
}

void RTW88PCIDevice::relatchAirportPowerStatePostReturn()
{
    IO80211Interface *wifi = getNetworkInterface();
    if (!wifi) {
        setProperty("AirportRTW89PostReturnPowerRelatchInterfaceMissing",
                    kOSBooleanTrue);
        return;
    }

    /* 0.2.54: read the framework latches around the existing relatch.
     * Current Tahoe reverse-engineered headers expose these as non-virtual
     * methods, so this probe does not alter IO80211Interface's vtable. */
    const bool userBefore = wifi->poweredOnByUser();
    const bool systemBefore = wifi->enabledBySystem();
    setProperty("AirportRTW89InterfaceUserPowerBeforeRelatch",
                userBefore ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89InterfaceSystemEnableBeforeRelatch",
                systemBefore ? kOSBooleanTrue : kOSBooleanFalse);

    /* 0.2.167: this latch is transport availability, not the user-visible
     * logical radio state.  Keep it ON even while GET POWER reports OFF. */
    pinAirportTransportUserPowerOn(wifi);
    pinAirportTransportSystemEnableOn(wifi);

    const bool userAfter = wifi->poweredOnByUser();
    const bool systemAfter = wifi->enabledBySystem();
    setProperty("AirportRTW89InterfaceUserPowerAfterRelatch",
                userAfter ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89InterfaceSystemEnableAfterRelatch",
                systemAfter ? kOSBooleanTrue : kOSBooleanFalse);
    /* While logically OFF, do not publish a second POWER_CHANGED after the
     * hidden transport re-pin; that notification could make the UI re-query
     * the framework latch instead of our logical GET POWER result. */
    if (_airportLogicalPowerOn)
        wifi->postMessage(APPLE80211_M_POWER_CHANGED);
    else
        setProperty("AirportRTW89PrimaryTransportRelatchSilent",
                    kOSBooleanTrue);

    ++_airportPowerRelatchCount;
    setProperty("AirportRTW89PostReturnPowerRelatchSeen", kOSBooleanTrue);
    setProperty("AirportRTW89PostReturnPowerRelatchCount",
                (uint64_t)_airportPowerRelatchCount, 32);
    setProperty("AirportRTW89PostReturnPowerRelatchForcedOn",
                kOSBooleanFalse);
}
#endif

#ifdef RTW_AIRPORT
bool AirportRTW89APIUserClient::initWithTaskAndOwner(
    task_t owningTask, void *securityID, UInt32 type,
    OSDictionary *properties, RTW88PCIDevice *owner)
{
    if (!owner ||
        !IOUserClient::initWithTask(owningTask, securityID, type, properties))
        return false;
    _owner = owner;
    /* 0.5.14: IO80211Old maps memory type 1 immediately after selector 3
     * initializes event monitoring.  Its consumer uses the standard
     * IODataQueue ABI, so allocate the shared ring before publishing this
     * user client.  Events can be added incrementally without changing the
     * mapping contract. */
    _eventQueue = IOSharedDataQueue::withCapacity(64U * 1024U);
    /* IO80211Old maps a second region as the ring-state block.  Keep this
     * separate from the ring data mapping: user space writes its read cursor
     * here while the producer owns the data-region write cursor.  One page is
     * deliberately used because IOConnectMapMemory maps page granularity and
     * Tahoe validates that the state address is independently mapped. */
    _eventRingState = IOBufferMemoryDescriptor::withOptions(
        kIOMemoryKernelUserShared | kIODirectionInOut,
        PAGE_SIZE, PAGE_SIZE);
    if (_eventRingState && _eventRingState->getBytesNoCopy())
        bzero(_eventRingState->getBytesNoCopy(), PAGE_SIZE);
    if (_owner) {
        const UInt64 nowMS = airportWPA2PreflightMonotonicMS();
        _owner->setProperty("AirportRTW89SecurityControlCustomClientInitSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89SecurityControlCustomClientInitMS",
                            (uint64_t)nowMS, 64);
        _owner->setProperty("AirportRTW89SecurityControlCustomClientType",
                            (uint64_t)type, 32);
        _owner->setProperty("AirportRTW89SecurityControlOwningTaskPresent",
                            owningTask ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SecurityControlSecurityIDPresent",
                            securityID ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SecurityControlPropertiesPresent",
                            properties ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SecurityControlPropertiesCount",
                            (uint64_t)(properties ? properties->getCount() : 0),
                            32);
        _owner->setProperty("AirportRTW89IOUCEventQueueAllocated",
                            _eventQueue ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCEventQueueCapacity",
                            (uint64_t)(64U * 1024U), 32);
        _owner->setProperty("AirportRTW89IOUCEventRingStateAllocated",
                            _eventRingState ? kOSBooleanTrue
                                            : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCEventRingStateSize",
                            (uint64_t)PAGE_SIZE, 32);
    }
    return _eventQueue != nullptr && _eventRingState != nullptr;
}

void AirportRTW89APIUserClient::free()
{
    if (_eventQueue) {
        _eventQueue->setNotificationPort(MACH_PORT_NULL);
        _eventQueue->release();
        _eventQueue = nullptr;
    }
    OSSafeReleaseNULL(_eventRingState);
    IOUserClient::free();
}

IOReturn AirportRTW89APIUserClient::clientClose()
{
    if (_owner) {
        airportRecordAPIClientMethodHistory(_owner, "close", UINT32_MAX);
        _owner->setProperty("AirportRTW89AppleEndpointClosed", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89SecurityControlCustomClientCloseMS",
                            (uint64_t)airportWPA2PreflightMonotonicMS(), 64);
    }
    terminate();
    return kIOReturnSuccess;
}

IOReturn AirportRTW89APIUserClient::registerNotificationPort(
    mach_port_t port, UInt32 type, io_user_reference_t refCon)
{
    airportRecordAPIClientMethodHistory(_owner, "notify", type);
    static volatile UInt32 callCount = 0;
    const UInt32 sequence = __sync_add_and_fetch(&callCount, 1U);
    if (_owner) {
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortSeen",
            kOSBooleanTrue);
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortCount",
            (uint64_t)sequence, 32);
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortType",
            (uint64_t)type, 32);
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortPortPresent",
            port != MACH_PORT_NULL ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortRefConNonZero",
            refCon != 0 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortMS",
            (uint64_t)airportWPA2PreflightMonotonicMS(), 64);
    }
    IOReturn result = kIOReturnUnsupported;
    /* IO80211Old registers the event-queue wake port with notification type
     * zero.  Accept type one as well for compatibility with legacy clients;
     * both refer to the sole Type-0 event pipe exposed by this endpoint. */
    if (_eventQueue && (type == 0U || type == 1U)) {
        _eventQueue->setNotificationPort(port);
        result = kIOReturnSuccess;
    }
    if (_owner)
        _owner->setProperty(
            "AirportRTW89SecurityControlRegisterNotificationPortReturn",
            (uint64_t)(uint32_t)result, 32);
    if (_owner && result == kIOReturnSuccess)
        _owner->setProperty("AirportRTW89IOUCEventQueueNotificationPortSet",
                            port != MACH_PORT_NULL ? kOSBooleanTrue
                                                   : kOSBooleanFalse);
    return result;
}

IOReturn AirportRTW89APIUserClient::clientMemoryForType(
    UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory)
{
    airportRecordAPIClientMethodHistory(_owner, "memory", type);
    static volatile UInt32 callCount = 0;
    const UInt32 sequence = __sync_add_and_fetch(&callCount, 1U);
    if (_owner) {
        _owner->setProperty("AirportRTW89SecurityControlClientMemorySeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89SecurityControlClientMemoryCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89SecurityControlClientMemoryType",
                            (uint64_t)type, 32);
        _owner->setProperty("AirportRTW89SecurityControlClientMemoryMS",
                            (uint64_t)airportWPA2PreflightMonotonicMS(), 64);
    }
    IOReturn result = kIOReturnUnsupported;
    if (type == 1U && options && memory && _eventQueue) {
        *options = 0;
        *memory = _eventQueue->getMemoryDescriptor();
        result = *memory ? kIOReturnSuccess : kIOReturnNoMemory;
    } else if (type == 2U && options && memory && _eventRingState) {
        *options = 0;
        _eventRingState->retain();
        *memory = _eventRingState;
        result = kIOReturnSuccess;
    }
    if (_owner) {
        _owner->setProperty("AirportRTW89SecurityControlClientMemoryReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89SecurityControlClientMemoryDescriptorReturned",
            (memory && *memory) ? kOSBooleanTrue : kOSBooleanFalse);
        if (type == 1U)
            _owner->setProperty("AirportRTW89IOUCEventRingBufferMapped",
                                result == kIOReturnSuccess ? kOSBooleanTrue
                                                           : kOSBooleanFalse);
        else if (type == 2U)
            _owner->setProperty("AirportRTW89IOUCEventRingStateMapped",
                                result == kIOReturnSuccess ? kOSBooleanTrue
                                                           : kOSBooleanFalse);
    }
    return result;
}

IOReturn AirportRTW89APIUserClient::externalMethod(
    uint32_t selector, IOExternalMethodArguments *args,
    IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)
{
    airportRecordAPIClientMethodHistory(_owner, "external", selector);
    struct EndpointCallTrace {
        UInt64 monotonicMS;
        UInt32 sequence;
        UInt32 selector;
        UInt32 argumentsVersion;
        UInt32 asyncReferenceCount;
        UInt32 scalarInputCount;
        UInt32 scalarOutputCount;
        UInt32 structureInputSize;
        UInt32 structureOutputSize;
        UInt32 structureOutputDescriptorSize;
        UInt8 asyncWakePortPresent;
        UInt8 asyncReferencePresent;
        UInt8 structureInputPresent;
        UInt8 structureInputDescriptorPresent;
        UInt8 structureOutputPresent;
        UInt8 structureOutputDescriptorPresent;
        UInt8 structureVariableOutputPresent;
        UInt8 reserved;
        UInt64 structureInputDescriptorLength;
        UInt64 structureOutputDescriptorLength;
        UInt32 ingressFlags;
        UInt32 envelopeShape;
        SInt32 decodedRequest;
        UInt32 decodedDeclaredLength;
        UInt8 decodedRequestValid;
        UInt8 decodedIsGet;
        UInt8 decodedIsSet;
        UInt8 decodedDirectionKnown;
        UInt32 decodedEffectiveLength;
    };
    static_assert(sizeof(EndpointCallTrace) == 96,
                  "IOUC ingress trace entry size mismatch");
    enum : UInt32 {
        kIOUCIngressArgumentsPresent = 1U << 0,
        kIOUCIngressDirectStructureInput = 1U << 1,
        kIOUCIngressInputDescriptor = 1U << 2,
        kIOUCIngressDirectStructureOutput = 1U << 3,
        kIOUCIngressOutputDescriptor = 1U << 4,
        kIOUCIngressScalarInput = 1U << 5,
        kIOUCIngressScalarOutput = 1U << 6,
        kIOUCIngressSelector0 = 1U << 7,
        kIOUCIngressInputDescriptorMapped = 1U << 8,
        kIOUCIngressOutputDescriptorMapped = 1U << 9,
        kIOUCIngressSelector0MetadataDecoded = 1U << 10,
        kIOUCIngressGet207 = 1U << 11,
    };
    static EndpointCallTrace trace[32] = {};
    static volatile UInt32 callCount = 0;
    struct IOUCRequestTrace {
        UInt64 monotonicMS;
        UInt32 sequence;
        UInt32 command;
        SInt32 request;
        UInt32 payloadLength;
        SInt32 result;
        UInt8 isGet;
        UInt8 isSet;
        UInt8 completed;
        UInt8 reserved;
    };
    static IOUCRequestTrace requestTrace[32] = {};
    static UInt32 requestTraceCount = 0;
    static IOUCRequestTrace associationRequestTrace[512] = {};
    static volatile UInt32 associationRequestTraceCount = 0;
    static volatile UInt32 associationRequestTraceWindow = 0;
    static volatile UInt32 selector0Count = 0;
    static volatile UInt32 get207Count = 0;
    const UInt32 callSequence = __sync_add_and_fetch(&callCount, 1U);
    const UInt64 callMS = airportWPA2PreflightMonotonicMS();

    EndpointCallTrace &entry = trace[(callSequence - 1U) % 32U];
    bzero(&entry, sizeof(entry));
    entry.monotonicMS = callMS;
    entry.sequence = callSequence;
    entry.selector = selector;
    if (args) {
        entry.ingressFlags |= kIOUCIngressArgumentsPresent;
        entry.argumentsVersion = args->version;
        entry.asyncReferenceCount = args->asyncReferenceCount;
        entry.scalarInputCount = args->scalarInputCount;
        entry.scalarOutputCount = args->scalarOutputCount;
        entry.structureInputSize = args->structureInputSize;
        entry.structureOutputSize = args->structureOutputSize;
        entry.structureOutputDescriptorSize =
            args->structureOutputDescriptorSize;
        entry.asyncWakePortPresent = args->asyncWakePort != MACH_PORT_NULL;
        entry.asyncReferencePresent = args->asyncReference != nullptr;
        entry.structureInputPresent = args->structureInput != nullptr;
        entry.structureInputDescriptorPresent =
            args->structureInputDescriptor != nullptr;
        entry.structureOutputPresent = args->structureOutput != nullptr;
        entry.structureOutputDescriptorPresent =
            args->structureOutputDescriptor != nullptr;
        entry.structureVariableOutputPresent =
            args->structureVariableOutputData != nullptr;
        if (args->structureInput)
            entry.ingressFlags |= kIOUCIngressDirectStructureInput;
        if (args->structureInputDescriptor) {
            entry.ingressFlags |= kIOUCIngressInputDescriptor;
            entry.structureInputDescriptorLength =
                args->structureInputDescriptor->getLength();
        }
        if (args->structureOutput)
            entry.ingressFlags |= kIOUCIngressDirectStructureOutput;
        if (args->structureOutputDescriptor) {
            entry.ingressFlags |= kIOUCIngressOutputDescriptor;
            entry.structureOutputDescriptorLength =
                args->structureOutputDescriptor->getLength();
        }
        if (args->scalarInputCount)
            entry.ingressFlags |= kIOUCIngressScalarInput;
        if (args->scalarOutputCount)
            entry.ingressFlags |= kIOUCIngressScalarOutput;
        if (args->structureInputSize == 32U ||
            args->structureInputSize == 40U ||
            args->structureInputSize == 48U)
            entry.envelopeShape = args->structureInputSize;
    }
    if (selector == 0) {
        entry.ingressFlags |= kIOUCIngressSelector0;
        __sync_add_and_fetch(&selector0Count, 1U);
    }
    if (_owner) {
        _owner->setProperty("AirportRTW89AppleEndpointExternalMethodSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89AppleEndpointExternalMethodCount",
                            (uint64_t)callSequence, 32);
        _owner->setProperty("AirportRTW89AppleEndpointLastSelector",
                            (uint64_t)selector, 32);
        _owner->setProperty("AirportRTW89AppleEndpointScalarInputCount",
                            (uint64_t)(args ? args->scalarInputCount : 0), 32);
        _owner->setProperty("AirportRTW89AppleEndpointStructureInputSize",
                            (uint64_t)(args ? args->structureInputSize : 0), 64);
        _owner->setProperty("AirportRTW89AppleEndpointScalarOutputCount",
                            (uint64_t)(args ? args->scalarOutputCount : 0), 32);
        _owner->setProperty("AirportRTW89AppleEndpointStructureOutputSize",
                            (uint64_t)(args ? args->structureOutputSize : 0), 64);
        _owner->setProperty(
            "AirportRTW89AppleEndpointStructureOutputDescriptorSize",
            (uint64_t)(args ? args->structureOutputDescriptorSize : 0), 64);
        _owner->setProperty("AirportRTW89AppleEndpointAsyncReferenceCount",
                            (uint64_t)(args ? args->asyncReferenceCount : 0), 32);
        _owner->setProperty("AirportRTW89AppleEndpointArgumentsVersion",
                            (uint64_t)(args ? args->version : 0), 32);
        _owner->setProperty("AirportRTW89SecurityControlExternalMethodLastMS",
                            (uint64_t)callMS, 64);
        _owner->setProperty("AirportRTW89IOUCIngressTelemetrySeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89IOUCIngressTraceVersion",
                            (uint64_t)313, 32);
        _owner->setProperty("AirportRTW89IOUCIngressTraceEntrySize",
                            (uint64_t)sizeof(EndpointCallTrace), 32);
        _owner->setProperty("AirportRTW89IOUCIngressTraceCapacity",
                            (uint64_t)32, 32);
        _owner->setProperty("AirportRTW89IOUCIngressLastSequence",
                            (uint64_t)callSequence, 32);
        _owner->setProperty("AirportRTW89IOUCIngressLastSelector",
                            (uint64_t)selector, 32);
        _owner->setProperty("AirportRTW89IOUCIngressLastMS",
                            (uint64_t)callMS, 64);
        _owner->setProperty("AirportRTW89IOUCIngressArgumentsPresent",
                            args ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCIngressDirectStructureInputPresent",
                            (args && args->structureInput)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCIngressInputDescriptorPresent",
                            (args && args->structureInputDescriptor)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCIngressDirectStructureOutputPresent",
                            (args && args->structureOutput)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCIngressOutputDescriptorPresent",
                            (args && args->structureOutputDescriptor)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89IOUCIngressScalarInputCount",
                            (uint64_t)(args ? args->scalarInputCount : 0), 32);
        _owner->setProperty("AirportRTW89IOUCIngressStructureInputSize",
                            (uint64_t)(args ? args->structureInputSize : 0), 64);
        _owner->setProperty("AirportRTW89IOUCIngressScalarOutputCount",
                            (uint64_t)(args ? args->scalarOutputCount : 0), 32);
        _owner->setProperty("AirportRTW89IOUCIngressStructureOutputCapacity",
                            (uint64_t)(args ? args->structureOutputSize : 0), 64);
        _owner->setProperty(
            "AirportRTW89IOUCIngressStructureOutputDescriptorCapacity",
            (uint64_t)(args ? args->structureOutputDescriptorSize : 0), 64);
        _owner->setProperty("AirportRTW89IOUCIngressInputDescriptorLength",
                            (uint64_t)entry.structureInputDescriptorLength, 64);
        _owner->setProperty("AirportRTW89IOUCIngressOutputDescriptorLength",
                            (uint64_t)entry.structureOutputDescriptorLength, 64);
        _owner->setProperty("AirportRTW89IOUCIngressLastFlags",
                            (uint64_t)entry.ingressFlags, 32);
        _owner->setProperty("AirportRTW89IOUCSelector0Count",
                            (uint64_t)selector0Count, 32);
        if (selector == 0) {
            _owner->setProperty("AirportRTW89IOUCSelector0Seen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89IOUCSelector0MetadataDecoded",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0RequestValid",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0IsGet",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0IsSet",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0DirectionKnown",
                                kOSBooleanFalse);
            _owner->setProperty(
                "AirportRTW89IOUCSelector0DeclaredPayloadLength",
                (uint64_t)0, 32);
            _owner->setProperty(
                "AirportRTW89IOUCSelector0EffectivePayloadLength",
                (uint64_t)0, 32);
            _owner->setProperty("AirportRTW89IOUCSelector0PayloadPresent",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0OutputCapacity",
                                (uint64_t)(args ? args->structureOutputSize : 0),
                                64);
            _owner->setProperty("AirportRTW89IOUCSelector0InputDescriptorMapped",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0DispatcherCalled",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0DispatcherReturn",
                                (uint64_t)(uint32_t)kIOReturnNotReady, 32);
            _owner->setProperty("AirportRTW89IOUCSelector0Return",
                                (uint64_t)(uint32_t)kIOReturnNotReady, 32);
            _owner->setProperty("AirportRTW89IOUCSelector0EnvelopeShape",
                                (uint64_t)entry.envelopeShape, 32);
        }
        if (__sync_add_and_fetch(&get207Count, 0U) == 0U) {
            _owner->setProperty("AirportRTW89IOUCPreGet207LastSequence",
                                (uint64_t)callSequence, 32);
            _owner->setProperty("AirportRTW89IOUCPreGet207LastSelector",
                                (uint64_t)selector, 32);
            _owner->setProperty("AirportRTW89IOUCPreGet207LastMS",
                                (uint64_t)callMS, 64);
        }
        OSData *traceData = OSData::withBytes(trace, sizeof(trace));
        if (traceData) {
            _owner->setProperty("AirportRTW89AppleEndpointCallTrace", traceData);
            traceData->release();
        }

    }

    /* 0.2.258: Ventura/OCLP legacy-control-path parity.
     *
     * This custom type-0 endpoint was introduced as an ABI discovery fallback.
     * 0.2.138 deliberately returned useIOUCWhenPossible=true even though the
     * endpoint did not implement the operational Apple80211 IOUC transport.
     * The 0.2.257 runtime still selects that experimental path: native
     * IO80211Interface::newUserClient(type 0) fails, the custom fallback opens,
     * and userspace sends many selector-0 calls with ordinary Apple80211-sized
     * outputs.  Keep tracing selector 0 unchanged, but return false for the
     * one-byte selector-1 preference so the restored Ventura IO80211Old stack
     * is asked to use its legacy ioctl/performCommand transport instead.
     *
     * This does not synthesize ASSOCIATE/20 and does not change GET, POWER,
     * LINK VALID, interface ownership, registration, or hardware behavior. */
    if (selector == 0 && args && args->structureInputDescriptor) {
        static constexpr IOByteCount kIOUCEnvelopeSize = 0x3c30;
        static constexpr IOByteCount kIOUCMaximumSize = 0x10000;
        static constexpr UInt32 kIOUCPayloadCapacity = 0x3c00;
        static constexpr IOByteCount kIOUCRequestOffset = 0x3c18;
        static constexpr IOByteCount kIOUCRequestLengthOffset = 0x3c20;
        static constexpr IOByteCount kIOUCPayloadOffset = 0x8;
        static constexpr UInt32 kIOUCWireSet32 = 0x802069c8U;
        static constexpr UInt32 kIOUCWireGet32 = 0xc02069c9U;
        static constexpr UInt32 kIOUCWireSet40 = 0x802869c8U;
        static constexpr UInt32 kIOUCWireGet40 = 0xc02869c9U;
        static constexpr UInt32 kIOUCWireSet48 = 0x803069c8U;
        static constexpr UInt32 kIOUCWireGet48 = 0xc03069c9U;

        IOMemoryDescriptor *input = args->structureInputDescriptor;
        IOMemoryDescriptor *output = args->structureOutputDescriptor;
        IOMemoryMap *inputMap = nullptr;
        IOMemoryMap *outputMap = nullptr;
        bool inputPrepared = false;
        bool outputPrepared = false;
        IOReturn result = kIOReturnBadArgument;
        IOReturn dispatcherResult = kIOReturnNotReady;
        IOReturn copyoutResult = kIOReturnNotReady;
        bool dispatcherCalled = false;
        bool copyoutAttempted = false;
        bool decodedIsGet = false;
        bool decodedIsSet = false;
        bool decodedPayloadPresent = false;
        bool get207Decoded = false;
        bool modernGet27Handled = false;
        UInt32 decodedDeclaredPayloadLength = 0;
        UInt32 decodedEffectivePayloadLength = 0;
        UInt32 decodedEnvelopeShape = 0;
        UInt64 decodedOutputCapacity = output
            ? (args->structureOutputDescriptorSize
                   ? (UInt64)args->structureOutputDescriptorSize
                   : (UInt64)output->getLength())
            : (UInt64)args->structureOutputSize;
        IOUCRequestTrace *requestTraceEntry = nullptr;
        IOUCRequestTrace *associationRequestTraceEntry = nullptr;

        const IOByteCount inputLength = input->getLength();
        if (_owner)
            _owner->setProperty("AirportRTW89IOUCMarshallerInputLength",
                                (uint64_t)inputLength, 64);
        if (inputLength < kIOUCEnvelopeSize ||
            inputLength > kIOUCMaximumSize)
            goto iouc_cleanup;

        result = input->prepare(kIODirectionNone);
        if (_owner)
            _owner->setProperty("AirportRTW89IOUCMarshallerInputPrepareReturn",
                                (uint64_t)(uint32_t)result, 32);
        if (result == kIOReturnSuccess) {
            inputPrepared = true;
        } else if (result == kIOReturnNotFound) {
            /* IOUserClient may hand a compatibility endpoint a descriptor
             * which its trap path has already prepared.  A second prepare()
             * then returns kIOReturnNotFound.  Do not claim ownership of that
             * preparation (and therefore do not complete it below), but keep
             * every mapping and bounds check in force. */
            if (_owner)
                _owner->setProperty(
                    "AirportRTW89IOUCMarshallerInputAlreadyPrepared",
                    kOSBooleanTrue);
        } else {
            goto iouc_cleanup;
        }

        inputMap = input->map(kIOMapAnywhere);
        if (!inputMap || inputMap->getLength() < kIOUCEnvelopeSize ||
            inputMap->getLength() > kIOUCMaximumSize ||
            inputMap->getVirtualAddress() == 0) {
            result = kIOReturnVMError;
            goto iouc_cleanup;
        }
        entry.ingressFlags |= kIOUCIngressInputDescriptorMapped;
        if (_owner)
            _owner->setProperty("AirportRTW89IOUCSelector0InputDescriptorMapped",
                                kOSBooleanTrue);

        {
            UInt8 *envelope = reinterpret_cast<UInt8 *>(
                inputMap->getVirtualAddress());
            const UInt32 command = *reinterpret_cast<const UInt32 *>(envelope);
            const SInt32 request = *reinterpret_cast<const SInt32 *>(
                envelope + kIOUCRequestOffset);
            const UInt32 rawPayloadLength =
                *reinterpret_cast<const UInt32 *>(
                    envelope + kIOUCRequestLengthOffset);
            const UInt32 setPayloadLength =
                *reinterpret_cast<const UInt32 *>(
                    envelope + sizeof(UInt32));
            const bool wireIsGet =
                command == kIOUCWireGet32 || command == kIOUCWireGet40 ||
                command == kIOUCWireGet48;
            const bool wireIsSet =
                command == kIOUCWireSet32 || command == kIOUCWireSet40 ||
                command == kIOUCWireSet48;
            const UInt32 envelopeShape =
                (command == kIOUCWireGet32 || command == kIOUCWireSet32)
                    ? 32U
                    : ((command == kIOUCWireGet40 || command == kIOUCWireSet40)
                           ? 40U
                           : ((command == kIOUCWireGet48 ||
                               command == kIOUCWireSet48)
                                  ? 48U : 0U));
            const bool isGet = command == kIOUCWireGet40;
            const bool isSet = command == kIOUCWireSet40;
            UInt32 payloadLength = rawPayloadLength;

            decodedIsGet = wireIsGet;
            decodedIsSet = wireIsSet;
            decodedEnvelopeShape = envelopeShape;
            decodedDeclaredPayloadLength = wireIsSet
                ? setPayloadLength : rawPayloadLength;
            decodedPayloadPresent = wireIsSet
                ? setPayloadLength != 0U
                : (rawPayloadLength != 0U || decodedOutputCapacity != 0U);
            entry.ingressFlags |= kIOUCIngressSelector0MetadataDecoded;
            entry.envelopeShape = envelopeShape;
            entry.decodedRequest = request;
            entry.decodedDeclaredLength = decodedDeclaredPayloadLength;
            entry.decodedRequestValid = 1U;
            entry.decodedIsGet = wireIsGet ? 1U : 0U;
            entry.decodedIsSet = wireIsSet ? 1U : 0U;
            entry.decodedDirectionKnown = (wireIsGet || wireIsSet) ? 1U : 0U;

            if (request == APPLE80211_IOC_CHANNELS_INFO) {
                get207Decoded = true;
                entry.ingressFlags |= kIOUCIngressGet207;
                const UInt32 seen = __sync_add_and_fetch(&get207Count, 1U);
                if (_owner) {
                    _owner->setProperty("AirportRTW89IOUCGet207Seen",
                                        kOSBooleanTrue);
                    _owner->setProperty("AirportRTW89IOUCGet207Count",
                                        (uint64_t)seen, 32);
                    _owner->setProperty("AirportRTW89IOUCGet207Selector",
                                        (uint64_t)selector, 32);
                    _owner->setProperty("AirportRTW89IOUCGet207RequestLength",
                                        (uint64_t)decodedDeclaredPayloadLength,
                                        32);
                    _owner->setProperty("AirportRTW89IOUCGet207OutputCapacity",
                                        (uint64_t)decodedOutputCapacity, 64);
                    _owner->setProperty(
                        "AirportRTW89IOUCGet207OutputDescriptorLength",
                        (uint64_t)(output ? output->getLength() : 0), 64);
                    _owner->setProperty("AirportRTW89IOUCGet207EnvelopeShape",
                                        (uint64_t)decodedEnvelopeShape, 32);
                }
            }

            /* Tahoe's 40-byte IOUC envelope is populated the same way as
             * IO80211APIUserClient::_runDriverCommandHelper(): SET carries
             * its input size in the word at +4, while GET derives its size
             * from the external-method output argument.  The field at
             * 0x3c20 is scratch written by the helper, not trusted input. */
            if (isSet) {
                payloadLength = setPayloadLength;
            } else if (isGet) {
                payloadLength = output
                    ? (UInt32)output->getLength()
                    : args->structureOutputSize;
            }
            decodedEffectivePayloadLength = payloadLength;
            entry.decodedEffectiveLength = payloadLength;

            if (_owner) {
                _owner->setProperty("AirportRTW89IOUCMarshallerMappedLength",
                                    (uint64_t)inputMap->getLength(), 64);
                _owner->setProperty("AirportRTW89IOUCMarshallerRawCommand",
                                    (uint64_t)command, 32);
                _owner->setProperty("AirportRTW89IOUCMarshallerRawRequest",
                                    (uint64_t)(uint32_t)request, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCMarshallerRawPayloadLength",
                    (uint64_t)rawPayloadLength, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCMarshallerEffectivePayloadLength",
                    (uint64_t)payloadLength, 32);
                _owner->setProperty("AirportRTW89IOUCSelector0MetadataDecoded",
                                    kOSBooleanTrue);
                _owner->setProperty("AirportRTW89IOUCSelector0RequestValid",
                                    kOSBooleanTrue);
                _owner->setProperty("AirportRTW89IOUCSelector0Request",
                                    (uint64_t)(uint32_t)request, 32);
                _owner->setProperty("AirportRTW89IOUCSelector0IsGet",
                                    wireIsGet ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89IOUCSelector0IsSet",
                                    wireIsSet ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89IOUCSelector0DirectionKnown",
                                    (wireIsGet || wireIsSet)
                                        ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCSelector0DeclaredPayloadLength",
                    (uint64_t)decodedDeclaredPayloadLength, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCSelector0EffectivePayloadLength",
                    (uint64_t)payloadLength, 32);
                _owner->setProperty("AirportRTW89IOUCSelector0PayloadPresent",
                                    decodedPayloadPresent
                                        ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89IOUCSelector0EnvelopeShape",
                                    (uint64_t)envelopeShape, 32);
                _owner->setProperty("AirportRTW89IOUCSelector0OutputCapacity",
                                    (uint64_t)decodedOutputCapacity, 64);
            }

            if ((!isGet && !isSet) || request < -1 || request > 0x24a ||
                payloadLength > kIOUCPayloadCapacity ||
                kIOUCPayloadOffset + payloadLength > kIOUCRequestOffset) {
                result = kIOReturnBadArgument;
                goto iouc_cleanup;
            }

            {
                const UInt32 traceSequence = __sync_add_and_fetch(
                    &requestTraceCount, 1U);
                requestTraceEntry =
                    &requestTrace[(traceSequence - 1U) % 32U];
                bzero(requestTraceEntry, sizeof(*requestTraceEntry));
                requestTraceEntry->monotonicMS = callMS;
                requestTraceEntry->sequence = traceSequence;
                requestTraceEntry->command = command;
                requestTraceEntry->request = request;
                requestTraceEntry->payloadLength = payloadLength;
                requestTraceEntry->isGet = isGet ? 1U : 0U;
                requestTraceEntry->isSet = isSet ? 1U : 0U;

                const UInt32 windowSequence = _owner
                    ? __sync_add_and_fetch(
                          &_owner->_airportIOUCAssociationCaptureSequence, 0U)
                    : 0U;
                const UInt64 windowStartMS = _owner
                    ? _owner->_airportIOUCAssociationCaptureStartMS : 0U;
                const bool activeWindow = windowSequence != 0U &&
                    callMS >= windowStartMS &&
                    callMS < windowStartMS + 8000ULL;
                if (activeWindow) {
                    if (associationRequestTraceWindow != windowSequence) {
                        bzero(associationRequestTrace,
                              sizeof(associationRequestTrace));
                        __sync_lock_test_and_set(
                            &associationRequestTraceCount, 0U);
                        __sync_lock_test_and_set(
                            &associationRequestTraceWindow, windowSequence);
                    }
                    const UInt32 associationOrdinal =
                        __sync_fetch_and_add(
                            &associationRequestTraceCount, 1U);
                    if (associationOrdinal < 512U) {
                        associationRequestTraceEntry =
                            &associationRequestTrace[associationOrdinal];
                        *associationRequestTraceEntry = *requestTraceEntry;
                    }
                }
            }

            if (_owner) {
                _owner->setProperty("AirportRTW89IOUCMarshallerSeen",
                                    kOSBooleanTrue);
                _owner->setProperty("AirportRTW89IOUCMarshallerCommand",
                                    (uint64_t)command, 32);
                _owner->setProperty("AirportRTW89IOUCMarshallerRequest",
                                    (uint64_t)(uint32_t)request, 32);
                _owner->setProperty("AirportRTW89IOUCMarshallerPayloadLength",
                                    (uint64_t)payloadLength, 32);
            }

            *reinterpret_cast<UInt32 *>(
                envelope + kIOUCRequestLengthOffset) = payloadLength;

            const UInt32 dispatcherCommand = isGet
                ? (UInt32)SIOCGA80211
                : (UInt32)SIOCSA80211;
            /* 0.3.50: GET27/254 on Tahoe arrives through the working
             * compatibility API user client created on the role-1 Skywalk
             * service.  The historical AirportRTW89Interface direct bridge
             * is dormant in this topology, so perform its proven used-prefix
             * marshalling here at the actual live boundary.  Keep the
             * canonical controller builder and channel flags unchanged. */
            if (_owner && wireIsGet &&
                (request == APPLE80211_IOC_SUPPORTED_CHANNELS ||
                 request == APPLE80211_IOC_HW_SUPPORTED_CHANNELS)) {
                apple80211_sup_channel_data channelData = {};
                result = (IOReturn)_owner->apple80211Request(
                    (UInt32)SIOCGA80211, request, _owner->_iface, &channelData);
                dispatcherCalled = true;
                dispatcherResult = result;
                modernGet27Handled = true;

                UInt32 count = channelData.num_channels;
                if (count > APPLE80211_MAX_CHANNELS)
                    count = APPLE80211_MAX_CHANNELS;
                size_t usedLength =
                    offsetof(apple80211_sup_channel_data, supported_channels) +
                    (size_t)count * sizeof(apple80211_channel);

                if (result == kIOReturnSuccess) {
                    if (usedLength > kIOUCPayloadCapacity ||
                        kIOUCPayloadOffset + usedLength > kIOUCRequestOffset) {
                        result = kIOReturnNoSpace;
                    } else {
                        bcopy(&channelData, envelope + kIOUCPayloadOffset,
                              usedLength);
                        payloadLength = (UInt32)usedLength;
                        *reinterpret_cast<UInt32 *>(
                            envelope + kIOUCRequestLengthOffset) =
                            payloadLength;
                    }
                }

                if (_owner) {
                    static volatile UInt32 modernGet27Count = 0;
                    const UInt32 seen =
                        __sync_add_and_fetch(&modernGet27Count, 1U);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeSeen", kOSBooleanTrue);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeCount",
                        (uint64_t)seen, 32);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeRequest",
                        (uint64_t)(uint32_t)request, 32);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeEnvelopeShape",
                        (uint64_t)decodedEnvelopeShape, 32);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeOutputCapacity",
                        (uint64_t)decodedOutputCapacity, 64);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeUsedLength",
                        (uint64_t)usedLength, 64);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeNumChannels",
                        (uint64_t)count, 32);
                    _owner->setProperty(
                        "AirportRTW89ModernGet27BridgeInnerReturn",
                        (uint64_t)(uint32_t)dispatcherResult, 32);
                }
            } else if (_owner && isGet &&
                request == APPLE80211_IOC_SCAN_RESULT) {
                /* The controller ABI for GET/11 returns a kernel pointer to
                 * one apple80211_scan_result through its data argument.  The
                 * IOUC wire ABI instead carries the result object itself.
                 * Never place that pointer in the shared descriptor. */
                apple80211_scan_result *scanResult = nullptr;
                result = (IOReturn)_owner->apple80211Request(
                    dispatcherCommand, request, _owner->_iface, &scanResult);
                dispatcherCalled = true;
                dispatcherResult = result;
                if (result == kIOReturnSuccess) {
                    const UInt32 scanResultLength =
                        (UInt32)sizeof(apple80211_scan_result);
                    if (!scanResult) {
                        result = kIOReturnNotReady;
                    } else if (scanResultLength > kIOUCPayloadCapacity ||
                               kIOUCPayloadOffset + scanResultLength >
                                   kIOUCRequestOffset) {
                        result = kIOReturnNoSpace;
                    } else {
                        bcopy(scanResult,
                              envelope + kIOUCPayloadOffset,
                              scanResultLength);
                        payloadLength = scanResultLength;
                        *reinterpret_cast<UInt32 *>(
                            envelope + kIOUCRequestLengthOffset) =
                            payloadLength;
                        if (_owner) {
                            _owner->setProperty(
                                "AirportRTW89IOUCMarshallerScanResultCopied",
                                kOSBooleanTrue);
                            _owner->setProperty(
                                "AirportRTW89IOUCMarshallerScanResultLength",
                                (uint64_t)payloadLength, 32);
                        }
                    }
                }
            } else {
                result = _owner
                    ? (IOReturn)_owner->apple80211Request(
                          dispatcherCommand, request, _owner->_iface,
                          payloadLength
                              ? envelope + kIOUCPayloadOffset
                              : nullptr)
                    : kIOReturnNotReady;
                dispatcherCalled = _owner != nullptr;
                dispatcherResult = result;
            }

            /* 0.5.10: the Apple-named IO80211APIUserClient established in
             * 0.5.9 is now airportd's live command path.  It intentionally
             * dispatches straight to apple80211Request(), so the older BSD
             * performCommand wrapper's bounded disconnected-state handling
             * is not reached.  During Tahoe's SET22 -> SET20 preflight this
             * leaves empty GET1/GET9/GET103 replies at raw status 6, which
             * IO80211Old exposes to airportd as fatal -3903 before SET20.
             *
             * Represent only an entirely empty payload as successful "not
             * currently associated" state, only for those three getters and
             * only during the bounded controller-owned SET22 epoch.  Do not
             * fabricate an SSID, BSSID, candidate network, or
             * association request.  Keep dispatcherResult as the unmodified
             * inner result so diagnostics can distinguish the normalization.
             */
            if (_owner && isGet && result == 6 && payloadLength != 0 &&
                (request == APPLE80211_IOC_SSID ||
                 request == APPLE80211_IOC_BSSID ||
                 request == APPLE80211_IOC_CURRENT_NETWORK)) {
                const UInt64 epochStartMS =
                    _owner->_airportIOUCAssociationCaptureStartMS;
                const UInt64 epochAgeMS =
                    epochStartMS != 0 && callMS >= epochStartMS
                        ? callMS - epochStartMS
                        : UINT64_MAX;
                /* 0.5.37: validate the empty disconnected output here.  It is
                 * normalized only during Type-0 startup or SET22 preflight;
                 * global empty success made airportd suppress JOIN because it
                 * believed the interface was already associated. */
                bool payloadEmpty = true;
                bool currentNetworkCapacitySeedOnly = false;
                if (payloadEmpty) {
                    const UInt8 *payload = envelope + kIOUCPayloadOffset;
                    UInt32 nonZeroBytes = 0;
                    UInt32 firstNonZeroOffset = UINT32_MAX;
                    UInt8 firstNonZeroValue = 0;
                    for (UInt32 i = 0; i < payloadLength; ++i) {
                        if (payload[i] != 0) {
                            if (nonZeroBytes == 0) {
                                firstNonZeroOffset = i;
                                firstNonZeroValue = payload[i];
                            }
                            ++nonZeroBytes;
                        }
                    }
                    payloadEmpty = nonZeroBytes == 0;

                    /* Tahoe initializes only asr_ie_len to the available IE
                     * capacity (0x0400) before GET103.  This is caller-owned
                     * capacity metadata, not current-network state. */
                    if (!payloadEmpty &&
                        request == APPLE80211_IOC_CURRENT_NETWORK &&
                        payloadLength == sizeof(apple80211_scan_result)) {
                        const UInt32 ieLengthOffset = (UInt32)__builtin_offsetof(
                            apple80211_scan_result, asr_ie_len);
                        UInt16 ieLength = 0;
                        bcopy(payload + ieLengthOffset, &ieLength,
                              sizeof(ieLength));
                        currentNetworkCapacitySeedOnly =
                            ieLength == 1024U && nonZeroBytes == 1U &&
                            firstNonZeroOffset == ieLengthOffset + 1U &&
                            firstNonZeroValue == 4U;
                        if (currentNetworkCapacitySeedOnly)
                            payloadEmpty = true;
                    }
                }

                static volatile UInt32 preSET20CandidateCount = 0;
                static volatile UInt32 preSET20AppliedCount = 0;
                const UInt32 candidateCount = __sync_add_and_fetch(
                    &preSET20CandidateCount, 1U);
                UInt32 appliedCount = __sync_add_and_fetch(
                    &preSET20AppliedCount, 0U);
                const UInt64 startupStartMS =
                    gAirportRTW89Type0StartupStartMS;
                const UInt64 startupAgeMS =
                    startupStartMS != 0 && callMS >= startupStartMS
                        ? callMS - startupStartMS
                        : UINT64_MAX;
                const bool startupGraceActive = startupAgeMS <= 3000ULL;
                /* 0.5.39: the measured Tahoe power-cycle/manual WPA2 path
                 * reached "Will associate" 21.3 seconds after SET22.  Eight
                 * seconds therefore rejected its identity preflight before
                 * SET20.  Forty-five seconds covers that observed UI path yet
                 * still expires, unlike 0.5.34's global unknown-network
                 * behavior. */
                const bool associationEpochActive = epochAgeMS <= 45000ULL;
                const UInt64 linkLossStartMS =
                    gAirportRTW89LinkLossTransitionStartMS;
                const UInt64 linkLossAgeMS =
                    linkLossStartMS != 0 && callMS >= linkLossStartMS
                        ? callMS - linkLossStartMS
                        : UINT64_MAX;
                /* 0.5.38: when an associated AP changes security or
                 * disappears, Tahoe performs these disconnected identity
                 * GETs before it emits SET22.  Permit only that bounded
                 * connected->disconnected transition; the window expires so
                 * an idle interface cannot remain an unknown association. */
                const bool linkLossTransitionActive =
                    linkLossAgeMS <= 8000ULL;
                const bool emptySuccessAllowed =
                    startupGraceActive || associationEpochActive ||
                    linkLossTransitionActive;
                if (payloadEmpty && emptySuccessAllowed) {
                    result = kIOReturnSuccess;
                    appliedCount = __sync_add_and_fetch(
                        &preSET20AppliedCount, 1U);
                }

                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessSeen",
                    kOSBooleanTrue);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessCandidateCount",
                    (uint64_t)candidateCount, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessAppliedCount",
                    (uint64_t)appliedCount, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessRequest",
                    (uint64_t)(uint32_t)request, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessPayloadLength",
                    (uint64_t)payloadLength, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessEpochAgeMS",
                    (uint64_t)epochAgeMS, 64);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessEpochBoundMS",
                    (uint64_t)45000U, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCDisconnectedEmptySuccessGlobal",
                    kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCDisconnectedEmptyStartupAgeMS",
                    (uint64_t)startupAgeMS, 64);
                _owner->setProperty(
                    "AirportRTW89IOUCDisconnectedEmptyStartupGraceActive",
                    startupGraceActive ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCDisconnectedEmptyAssociationEpochActive",
                    associationEpochActive ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCDisconnectedEmptyLinkLossAgeMS",
                    (uint64_t)linkLossAgeMS, 64);
                _owner->setProperty(
                    "AirportRTW89IOUCDisconnectedEmptyLinkLossTransitionActive",
                    linkLossTransitionActive ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessInnerReturn",
                    (uint64_t)(uint32_t)dispatcherResult, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessApplied",
                    (payloadEmpty && emptySuccessAllowed)
                        ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20CurrentNetworkCapacitySeedOnly",
                    currentNetworkCapacitySeedOnly
                        ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessPayloadInvented",
                    kOSBooleanFalse);
                _owner->setProperty(
                    "AirportRTW89IOUCPreSET20EmptySuccessFinalReturn",
                    (uint64_t)(uint32_t)result, 32);
            }

            if (result == kIOReturnSuccess &&
                (isGet || modernGet27Handled) && payloadLength) {
                if (output) {
                    if (output != input) {
                        const IOByteCount outputLength = output->getLength();
                        if (outputLength < payloadLength ||
                            outputLength > kIOUCMaximumSize) {
                            result = kIOReturnNoSpace;
                            copyoutResult = result;
                            goto iouc_cleanup;
                        }
                        result = output->prepare(kIODirectionNone);
                        if (result != kIOReturnSuccess) {
                            copyoutResult = result;
                            goto iouc_cleanup;
                        }
                        outputPrepared = true;
                        outputMap = output->map(kIOMapAnywhere);
                        if (outputMap)
                            entry.ingressFlags |=
                                kIOUCIngressOutputDescriptorMapped;
                    } else {
                        outputMap = inputMap;
                        entry.ingressFlags |=
                            kIOUCIngressOutputDescriptorMapped;
                    }
                    if (!outputMap || outputMap->getLength() < payloadLength ||
                        outputMap->getVirtualAddress() == 0) {
                        result = kIOReturnVMError;
                        copyoutResult = result;
                        goto iouc_cleanup;
                    }
                    bcopy(envelope + kIOUCPayloadOffset,
                          reinterpret_cast<void *>(
                              outputMap->getVirtualAddress()),
                          payloadLength);
                    copyoutAttempted = true;
                    copyoutResult = kIOReturnSuccess;
                    args->structureOutputDescriptorSize = payloadLength;
                    if (_owner && modernGet27Handled) {
                        _owner->setProperty(
                            "AirportRTW89ModernGet27BridgeCopyoutAttempted",
                            kOSBooleanTrue);
                        _owner->setProperty(
                            "AirportRTW89ModernGet27BridgeCopyoutReturn",
                            (uint64_t)(uint32_t)copyoutResult, 32);
                        _owner->setProperty(
                            "AirportRTW89ModernGet27BridgeReturnedLength",
                            (uint64_t)payloadLength, 64);
                    }
                } else if (args->structureOutput &&
                           request != APPLE80211_IOC_SCAN_RESULT &&
                           args->structureOutputSize >= payloadLength) {
                    /* Ordinary fixed-size control GETs return their payload
                     * through the small method reply (POWER included). */
                    bcopy(envelope + kIOUCPayloadOffset,
                          args->structureOutput, payloadLength);
                    copyoutAttempted = true;
                    copyoutResult = kIOReturnSuccess;
                    args->structureOutputSize = payloadLength;
                    if (_owner && modernGet27Handled) {
                        _owner->setProperty(
                            "AirportRTW89ModernGet27BridgeCopyoutAttempted",
                            kOSBooleanTrue);
                        _owner->setProperty(
                            "AirportRTW89ModernGet27BridgeCopyoutReturn",
                            (uint64_t)(uint32_t)copyoutResult, 32);
                        _owner->setProperty(
                            "AirportRTW89ModernGet27BridgeReturnedLength",
                            (uint64_t)payloadLength, 64);
                    }
                } else if (args->structureOutput &&
                           request == APPLE80211_IOC_SCAN_RESULT) {
                    /* Apple's helper copies min(req_len, output capacity)
                     * from req_data into the direct method output.  The full
                     * translated object remains in the shared descriptor. */
                    const UInt32 copyLength =
                        args->structureOutputSize < payloadLength
                            ? args->structureOutputSize
                            : payloadLength;
                    if (copyLength) {
                        bcopy(envelope + kIOUCPayloadOffset,
                              args->structureOutput, copyLength);
                        copyoutAttempted = true;
                        copyoutResult = kIOReturnSuccess;
                        args->structureOutputSize = copyLength;
                    }
                    if (_owner)
                        _owner->setProperty(
                            "AirportRTW89IOUCMarshallerScanResultReplyLength",
                            (uint64_t)copyLength, 32);
                } else {
                    result = kIOReturnNoSpace;
                    copyoutResult = result;
                }
            }
        }

iouc_cleanup:
        if (requestTraceEntry) {
            requestTraceEntry->result = (SInt32)result;
            requestTraceEntry->completed = 1U;
            if (associationRequestTraceEntry) {
                associationRequestTraceEntry->result = (SInt32)result;
                associationRequestTraceEntry->completed = 1U;
            }
            if (_owner) {
                _owner->setProperty("AirportRTW89IOUCRequestTraceCount",
                                    (uint64_t)requestTraceCount, 32);
                OSData *requestTraceData = OSData::withBytes(
                    requestTrace, sizeof(requestTrace));
                if (requestTraceData) {
                    _owner->setProperty("AirportRTW89IOUCRequestTrace",
                                        requestTraceData);
                    requestTraceData->release();
                }
                _owner->setProperty(
                    "AirportRTW89IOUCAssociationRequestTraceCount",
                    (uint64_t)associationRequestTraceCount, 32);
                _owner->setProperty(
                    "AirportRTW89IOUCAssociationRequestTraceWindow",
                    (uint64_t)associationRequestTraceWindow, 32);
                OSData *associationTraceData = OSData::withBytes(
                    associationRequestTrace,
                    sizeof(associationRequestTrace));
                if (associationTraceData) {
                    _owner->setProperty(
                        "AirportRTW89IOUCAssociationRequestTrace",
                        associationTraceData);
                    associationTraceData->release();
                }
            }
        }
        if (outputMap && outputMap != inputMap)
            outputMap->release();
        if (outputPrepared)
            output->complete(kIODirectionNone);
        if (inputMap)
            inputMap->release();
        if (inputPrepared)
            input->complete(kIODirectionNone);
        if (_owner)
            _owner->setProperty("AirportRTW89IOUCMarshallerLastReturn",
                                (uint64_t)(uint32_t)result, 32);
        if (_owner && selector == 0) {
            _owner->setProperty("AirportRTW89IOUCSelector0DispatcherCalled",
                                dispatcherCalled
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0DispatcherReturn",
                                (uint64_t)(uint32_t)dispatcherResult, 32);
            _owner->setProperty("AirportRTW89IOUCSelector0Return",
                                (uint64_t)(uint32_t)result, 32);
            _owner->setProperty("AirportRTW89IOUCIngressLastFlags",
                                (uint64_t)entry.ingressFlags, 32);
            if (OSData *traceData = OSData::withBytes(trace, sizeof(trace))) {
                _owner->setProperty("AirportRTW89AppleEndpointCallTrace",
                                    traceData);
                traceData->release();
            }
        }
        if (_owner && get207Decoded) {
            _owner->setProperty("AirportRTW89IOUCGet207DispatcherReturn",
                                (uint64_t)(uint32_t)dispatcherResult, 32);
            _owner->setProperty("AirportRTW89IOUCGet207CopyoutAttempted",
                                copyoutAttempted
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCGet207CopyoutReturn",
                                (uint64_t)(uint32_t)copyoutResult, 32);
            _owner->setProperty("AirportRTW89IOUCGet207Return",
                                (uint64_t)(uint32_t)result, 32);
            _owner->setProperty("AirportRTW89IOUCGet207EffectivePayloadLength",
                                (uint64_t)decodedEffectivePayloadLength, 32);
            _owner->setProperty("AirportRTW89IOUCGet207PayloadPresent",
                                decodedPayloadPresent
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCGet207IsGet",
                                decodedIsGet ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCGet207IsSet",
                                decodedIsSet ? kOSBooleanTrue : kOSBooleanFalse);
        }
        return result;
    }

    if (selector == 0 && args && args->structureOutput &&
        args->structureOutputSize > 0) {
        static const char version[] = "0.13.36";
        size_t length = sizeof(version);
        if (length > args->structureOutputSize)
            length = args->structureOutputSize;
        bcopy(version, args->structureOutput, length);
        static_cast<char *>(args->structureOutput)[length - 1] = '\0';
        args->structureOutputSize = static_cast<uint32_t>(length);
        if (_owner) {
            static volatile UInt32 versionSelector0Count = 0;
            const UInt32 sequence =
                __sync_add_and_fetch(&versionSelector0Count, 1U);
            _owner->setProperty("AirportRTW89AppleEndpointVersionReturned",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89SecurityControlSelector0Count",
                                (uint64_t)sequence, 32);
            _owner->setProperty("AirportRTW89SecurityControlSelector0LastMS",
                                (uint64_t)callMS, 64);
            _owner->setProperty("AirportRTW89IOUCSelector0DispatcherCalled",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0Return",
                                (uint64_t)(uint32_t)kIOReturnSuccess, 32);
        }
        return kIOReturnSuccess;
    }

    if (selector == 1 && args && args->structureOutput &&
        args->structureOutputSize >= sizeof(UInt8)) {
        /* 0.5.5: 0.5.4 proved that Tahoe reaches this type-0 endpoint and
         * immediately asks selector 1 whether the operational Apple80211
         * IOUC transport is available.  Returning false makes IO80211Old
         * close the successfully-created client and surface
         * kIOReturnUnsupported, leaving WPA2 userspace before SET20.  The
         * selector-0 bridge below now implements the command envelope, so
         * advertise that transport and let association enter the driver. */
        *static_cast<UInt8 *>(args->structureOutput) = 1;
        args->structureOutputSize = sizeof(UInt8);
        if (_owner) {
            _owner->setProperty("AirportRTW89AppleEndpointIOUCSelected",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89AppleEndpointIOUCHandshakeReturnedTrue",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89AppleEndpointIOUCHandshakeReturnedFalse",
                                kOSBooleanFalse);
            static volatile UInt32 selector1Count = 0;
            const UInt32 sequence = __sync_add_and_fetch(&selector1Count, 1U);
            _owner->setProperty("AirportRTW89SecurityControlSelector1Count",
                                (uint64_t)sequence, 32);
            _owner->setProperty("AirportRTW89SecurityControlSelector1LastMS",
                                (uint64_t)callMS, 64);
            _owner->setProperty("AirportRTW89SecurityControlSelector1ReturnedLegacy",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89SecurityControlSelector1ReturnedIOUC",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89IOUCOperationalDiscoveryEnabled",
                                kOSBooleanTrue);
        }
        return kIOReturnSuccess;
    }

    if (selector == 5 && args && args->structureOutput &&
        args->structureOutputSize >= sizeof(UInt8)) {
        /* 0.5.6: selector 1 alone activates command probes, but 0.5.5 proved
         * airportd closes the endpoint before a join when selector 5 rejects
         * event transport. Advertise the event endpoint so Tahoe proceeds to
         * registerNotificationPort/clientMemoryForType; those methods retain
         * exact telemetry for completing the event-pipe ABI. */
        *static_cast<UInt8 *>(args->structureOutput) = 1;
        args->structureOutputSize = sizeof(UInt8);
        if (_owner) {
            _owner->setProperty("AirportRTW89IOUCEventPipeSelected",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89IOUCEventPipeDiscoveryBuild",
                                (uint64_t)506, 32);
        }
        return kIOReturnSuccess;
    }

    if (selector == 3 && args && args->scalarInputCount == 0 &&
        args->scalarOutputCount == 0 && args->structureInputSize == 0 &&
        args->structureOutputSize == 0 &&
        !args->structureInputDescriptor && !args->structureOutputDescriptor) {
        /* 0.5.13: runtime shows airportd invokes this argument-free method
         * after selector 5 advertises the event endpoint.  Rejecting it is
         * reported by IO80211Old as "Failed to init event monitoring in
         * IOUC" and leaves the native association wrapper returning -3903
         * before SET20.  Acknowledge the monitor-enable handshake.  Actual
         * Apple80211 state/link notifications continue to use the existing
         * IO80211Interface notification path; no event is synthesized here. */
        if (_owner) {
            static volatile UInt32 selector3Count = 0;
            const UInt32 sequence = __sync_add_and_fetch(
                &selector3Count, 1U);
            _owner->setProperty(
                "AirportRTW89IOUCEventMonitoringInitialized",
                kOSBooleanTrue);
            _owner->setProperty(
                "AirportRTW89IOUCEventMonitoringSelector3Count",
                (uint64_t)sequence, 32);
            _owner->setProperty(
                "AirportRTW89IOUCEventMonitoringSelector3LastMS",
                (uint64_t)callMS, 64);
            _owner->setProperty(
                "AirportRTW89IOUCEventMonitoringSyntheticEvents",
                kOSBooleanFalse);
        }
        return kIOReturnSuccess;
    }

    if (selector == 2 && args && args->scalarInputCount == 0 &&
        args->scalarOutputCount == 0 && args->structureInputSize == 0 &&
        args->structureOutputSize == 0 &&
        !args->structureInputDescriptor && !args->structureOutputDescriptor) {
        /* 0.5.18: Tahoe invokes this argument-free Type-0 method once per
         * client immediately before the selector-3 event-monitor enable and
         * memory-ring mappings.  The Apple IO80211APIUserClient metaclass is
         * absent from the restored legacy image, so our identity-compatible
         * endpoint cannot inherit its private implementation.  Rejecting the
         * handshake is the only unsupported client operation observed before
         * CWEAPOLClient reports that it cannot retrieve supplicant state.
         * Acknowledge initialization only; no event or association state is
         * synthesized. */
        if (_owner) {
            static volatile UInt32 selector2Count = 0;
            const UInt32 sequence = __sync_add_and_fetch(
                &selector2Count, 1U);
            _owner->setProperty(
                "AirportRTW89IOUCSupplicantControlInitialized",
                kOSBooleanTrue);
            _owner->setProperty(
                "AirportRTW89IOUCSupplicantControlSelector2Count",
                (uint64_t)sequence, 32);
            _owner->setProperty(
                "AirportRTW89IOUCSupplicantControlSelector2LastMS",
                (uint64_t)callMS, 64);
            _owner->setProperty(
                "AirportRTW89IOUCSupplicantControlSyntheticState",
                kOSBooleanFalse);
        }
        return kIOReturnSuccess;
    }

    /* 0.3.16: secured-control boundary telemetry.
     *
     * Open association is proven to work through this fallback endpoint,
     * while WPA2 aborts in userspace before SET20.  Record the complete
     * external-method envelope shape for any selector we do not implement so
     * a CWEAPOLClient-only selector cannot disappear behind a generic
     * kIOReturnUnsupported.  Metadata only: never capture payload bytes,
     * credentials, task identity, or key material. */
    static UInt32 unsupportedSelectorCount = 0;
    ++unsupportedSelectorCount;
    if (_owner) {
        const UInt64 nowMS = airportWPA2PreflightMonotonicMS();
        _owner->setProperty("AirportRTW89AppleEndpointUnsupportedSelectorSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89AppleEndpointLastUnsupportedSelector",
                            (uint64_t)selector, 32);
        _owner->setProperty("AirportRTW89AppleEndpointUnsupportedSelectorCount",
                            (uint64_t)unsupportedSelectorCount, 32);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedSelectorMS",
                            (uint64_t)nowMS, 64);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedScalarInputCount",
                            (uint64_t)(args ? args->scalarInputCount : 0), 32);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedScalarOutputCount",
                            (uint64_t)(args ? args->scalarOutputCount : 0), 32);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedStructureInputSize",
                            (uint64_t)(args ? args->structureInputSize : 0), 64);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedStructureOutputSize",
                            (uint64_t)(args ? args->structureOutputSize : 0), 64);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedInputDescriptorPresent",
                            (args && args->structureInputDescriptor)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SecuredControlUnsupportedOutputDescriptorPresent",
                            (args && args->structureOutputDescriptor)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        if (selector == 0) {
            _owner->setProperty("AirportRTW89IOUCSelector0DispatcherCalled",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89IOUCSelector0Return",
                                (uint64_t)(uint32_t)kIOReturnUnsupported, 32);
        }
    }
    return kIOReturnUnsupported;
}

bool AirportRTW89Interface::init(IO80211Controller *controller,
                                 RTW88PCIDevice *owner)
{
    if (!IO80211Interface::init(controller))
        return false;
    _owner = owner;

    /* 0.4.4 Ventura IO80211Reference parity: IO80211ReferenceInterface::init() only
     * calls IO80211Interface::init(controller) and stores its backend pointer.
     * Do not publish Sonoma-era WiFiDriver/root/role identity on the BSD
     * interface before Apple's native type-0 factory runs. */
    /* 0.5.41: exact IO80211ReferenceInterface::init() parity.  Its compiled
     * Ventura interface calls IO80211Interface::init(controller), stores the
     * backend pointer, and publishes no RSN state before Apple's inherited
     * Type-0 factory runs. */
    if (_owner)
        _owner->setProperty(
            "AirportRTW89InitialInterfaceRSNDonePublicationSuppressed",
            kOSBooleanTrue);
    if (_owner)
        _owner->setProperty("AirportRTW89VenturaInterfaceInitParity",
                            kOSBooleanTrue);
    return true;
}

IOReturn AirportRTW89Interface::newUserClient(
    task_t owningTask, void *securityID, UInt32 type,
    OSDictionary *properties, IOUserClient **handler)
{
    if (handler)
        *handler = nullptr;

    const IOReturn nativeResult = IO80211Interface::newUserClient(
        owningTask, securityID, type, properties, handler);
    const bool nativeCreated = handler && *handler;

    if (_owner) {
        _owner->setProperty("AirportRTW89PrimaryType0FactorySeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PrimaryType0NativeReturn",
                            (uint64_t)(uint32_t)nativeResult, 32);
        _owner->setProperty("AirportRTW89PrimaryType0NativeCreated",
                            nativeCreated ? kOSBooleanTrue : kOSBooleanFalse);
    }

    /* 0.5.44: IO80211Reference Ventura does not manufacture an API user client
     * when IO80211Interface rejects Tahoe's external type-0 open.  Tahoe's
     * IO80211Old deliberately treats that failure as its signal to bind the
     * legacy ifnet/IOCTL transport instead.  That transport is the path on
     * which IO80211Reference's inherited performCommand() ultimately delivers
     * APPLE80211_IOC_ASSOCIATE/20 to the controller.
     *
     * Do not translate external type 0 to factory type 2 here.  In the
     * restored 1200.12.2b1 family, type 2 creates the entitlement-gated
     * IO80211AsyncEventUserClient (with internal interface type 0); it is an
     * event endpoint, not Tahoe's Apple80211 command endpoint.  Preserve the
     * exact inherited failure under the existing Ventura-parity boot gate so
     * IO80211Old can select its native IOCTL fallback.  The non-parity path
     * retains the custom endpoint as a boot-argument rollback.
     */
    if (type == 0 && airportVenturaInterfaceParity()) {
        if (_owner) {
            _owner->setProperty(
                "AirportRTW89VenturaType0CustomFallbackSuppressed",
                kOSBooleanTrue);
            _owner->setProperty(
                "AirportRTW89VenturaIOCTLBindingExpected",
                kOSBooleanTrue);
            _owner->setProperty(
                "AirportRTW89VenturaType0InheritedReturn",
                (uint64_t)(uint32_t)nativeResult, 32);
        }
        return nativeResult;
    }

    /* 0.5.33: on Tahoe 26.5 with the restored Ventura IO80211FamilyLegacy,
     * airportd opens the registered AirportRTW89Interface (enX), not the
     * controller or the optional Skywalk service.  The inherited factory
     * has now been observed returning both Unsupported and BadArgument on
     * Type-0 opens, depending on its initialization state.  Preserve every
     * successful/native result and every other client type; manufacture the
     * existing Apple-named command endpoint only for either observed failed
     * Type-0 result. */
    const bool nativeType0FactoryFailure =
        nativeResult == kIOReturnUnsupported ||
        nativeResult == kIOReturnBadArgument;
    if (type != 0 || !nativeType0FactoryFailure || nativeCreated)
        return nativeResult;

    IO80211APIUserClient *client = new IO80211APIUserClient;
    IOReturn result = kIOReturnNoMemory;
    if (client) {
        if (!client->initWithTaskAndOwner(
                owningTask, securityID, type, properties, _owner)) {
            client->release();
            result = kIOReturnBadArgument;
        } else if (!client->attach(this)) {
            client->release();
            result = kIOReturnCannotLock;
        } else if (!client->start(this)) {
            client->detach(this);
            client->release();
            result = kIOReturnNotReady;
        } else {
            if (handler)
                *handler = client;
            result = kIOReturnSuccess;
            if (gAirportRTW89Type0StartupStartMS == 0) {
                uint64_t nowNs = 0;
                absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
                const UInt64 nowMS = nowNs / 1000000ULL;
                (void)__sync_bool_compare_and_swap(
                    &gAirportRTW89Type0StartupStartMS, 0ULL, nowMS);
                if (_owner) {
                    _owner->setProperty(
                        "AirportRTW89IOUCType0StartupStartMS",
                        (uint64_t)gAirportRTW89Type0StartupStartMS, 64);
                    _owner->setProperty(
                        "AirportRTW89IOUCType0StartupTimestampFileLocal",
                        kOSBooleanTrue);
                }
            }
        }
    }

    if (_owner) {
        _owner->setProperty("AirportRTW89PrimaryType0CompatibilityFallback",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PrimaryType0FallbackFromBadArgument",
                            nativeResult == kIOReturnBadArgument
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PrimaryType0CompatibilityReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89PrimaryType0CompatibilityCreated",
                            (handler && *handler) ? kOSBooleanTrue
                                                  : kOSBooleanFalse);
    }
    return result;
}

bool AirportRTW89Interface::isPrimaryInterface(void) const
{
    /* 0.5.21: the legacy-only topology has exactly one BSD 802.11 interface.
     * Return that invariant directly so secured-association policy cannot
     * classify the station endpoint as secondary. */
    return true;
}

int AirportRTW89Interface::errnoFromReturn(int rtn)
{
    const int mapped = IO80211Interface::errnoFromReturn(rtn);
    if (_owner) {
        struct ParityErrnoMapEntry {
            UInt64 monotonicMS;
            UInt32 sequence;
            SInt32 input;
            SInt32 output;
            UInt32 reserved;
        };
        static_assert(sizeof(ParityErrnoMapEntry) == 24,
                      "parity errno map entry size mismatch");
        static ParityErrnoMapEntry errnoMapRing[32] = {};
        static volatile UInt32 errnoMapCount = 0;
        const UInt32 sequence = __sync_add_and_fetch(&errnoMapCount, 1);
        ParityErrnoMapEntry &entry = errnoMapRing[(sequence - 1U) & 31U];
        entry.monotonicMS = airportWPA2PreflightMonotonicMS();
        entry.sequence = sequence;
        entry.input = rtn;
        entry.output = mapped;
        entry.reserved = 0;
        _owner->setProperty("AirportRTW89InterfaceErrnoFromReturnSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89InterfaceErrnoFromReturnCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89InterfaceErrnoFromReturnInput",
                            (uint64_t)(uint32_t)rtn, 32);
        _owner->setProperty("AirportRTW89InterfaceErrnoFromReturnOutput",
                            (uint64_t)(uint32_t)mapped, 32);
        _owner->setProperty("AirportRTW89InterfaceErrnoFromReturnMS",
                            (uint64_t)entry.monotonicMS, 64);
        _owner->setProperty("AirportRTW89ParityErrnoMapEntrySize",
                            (uint64_t)sizeof(ParityErrnoMapEntry), 32);
        _owner->setProperty("AirportRTW89ParityErrnoMapCount",
                            (uint64_t)(sequence < 32U ? sequence : 32U), 32);
        if (OSData *ringData = OSData::withBytes(
                errnoMapRing, sizeof(errnoMapRing))) {
            _owner->setProperty("AirportRTW89ParityErrnoMapRing", ringData);
            ringData->release();
        }
    }
    return mapped;
}

void AirportRTW89Interface::setPoweredOnByUser(bool value)
{
    const bool baseBefore = poweredOnByUser();

    if (_owner) {
        const UInt32 sequence = ++_owner->_airportPowerEventSequence;
        ++_owner->_airportFrameworkUserPowerSetCount;
        _owner->_airportFrameworkUserPowerLastSequence = sequence;

        _owner->setProperty("AirportRTW89PowerEventSequence",
                            (uint64_t)_owner->_airportPowerEventSequence, 32);
        _owner->setProperty("AirportRTW89FrameworkUserPowerSetSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89FrameworkUserPowerSetCount",
                            (uint64_t)_owner->_airportFrameworkUserPowerSetCount, 32);
        _owner->setProperty("AirportRTW89FrameworkUserPowerSequence",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89FrameworkUserPowerRequested",
                            value ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkUserPowerLogicalAtEntry",
                            _owner->_airportLogicalPowerOn
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkUserPowerBaseBefore",
                            baseBefore ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkUserPowerDiagnosticOnly",
                            kOSBooleanTrue);
    }

    /* 0.5.46: Tahoe can make the first framework user-power callback false
     * after the outer POWER request has already brought the controller and
     * persistent logical state ON.  The inherited latch may already have
     * been published as true by the outer request, so baseBefore alone
     * cannot distinguish this startup replay.  Suppress a false first
     * callback while logical power is ON; later true->false edges remain
     * authoritative user-off requests.
     *
     * 0.5.27: Tahoe replays a stale false latch while bringing up this
     * legacy interface even though AirportRTW's controller and persistent
     * logical state are already ON.  It is distinguishable from a genuine
     * user OFF edge because the inherited latch is already false.  Publish
     * ON for that idempotent startup replay.  Once ON has been published, a
     * later true->false edge is authoritative and is forwarded to the RTW89
     * logical-power path. */
    const bool firstFrameworkPowerCallback =
        _owner && _owner->_airportFrameworkUserPowerSetCount == 1U;
    const bool staleStartupOff =
        !value && _owner && _owner->_airportLogicalPowerOn &&
        (!baseBefore || firstFrameworkPowerCallback);
    const bool effectiveValue = staleStartupOff ? true : value;

    if (_owner) {
        _owner->setProperty("AirportRTW89FrameworkUserPowerStartupOffSuppressed",
                            staleStartupOff ? kOSBooleanTrue
                                            : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkUserPowerFirstCallback",
                            firstFrameworkPowerCallback ? kOSBooleanTrue
                                                        : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkUserPowerEffective",
                            effectiveValue ? kOSBooleanTrue
                                           : kOSBooleanFalse);
    }

    IO80211Interface::setPoweredOnByUser(effectiveValue);

    if (_owner && !staleStartupOff &&
        effectiveValue != _owner->_airportLogicalPowerOn) {
        const IOReturn transition = _owner->applyAirportUserPowerState(
            effectiveValue,
            RTW88PCIDevice::kAirportLogicalPowerFrameworkUserLatch);
        _owner->setProperty("AirportRTW89FrameworkUserPowerTransitionReturn",
                            (uint64_t)(uint32_t)transition, 32);
    }

    if (_owner) {
        const bool baseAfter = poweredOnByUser();
        _owner->setProperty("AirportRTW89FrameworkUserPowerBaseAfter",
                            baseAfter ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkUserPowerLogicalAfter",
                            _owner->_airportLogicalPowerOn
                                ? kOSBooleanTrue : kOSBooleanFalse);
    }
}

void AirportRTW89Interface::setEnabledBySystem(bool value)
{
    const bool baseBefore = enabledBySystem();

    if (_owner) {
        const UInt32 sequence = ++_owner->_airportPowerEventSequence;
        ++_owner->_airportFrameworkSystemEnableSetCount;
        _owner->_airportFrameworkSystemEnableLastSequence = sequence;

        _owner->setProperty("AirportRTW89PowerEventSequence",
                            (uint64_t)_owner->_airportPowerEventSequence, 32);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableSetSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableSetCount",
                            (uint64_t)_owner->_airportFrameworkSystemEnableSetCount, 32);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableSequence",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableRequested",
                            value ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableLogicalAtEntry",
                            _owner->_airportLogicalPowerOn
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableBaseBefore",
                            baseBefore ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableDiagnosticOnly",
                            kOSBooleanTrue);
    }

    /* Diagnostic-only build: preserve inherited framework behavior.  Do not
     * modify the IO80211Reference-style stored logical power state here. */
    IO80211Interface::setEnabledBySystem(value);

    if (_owner) {
        const bool baseAfter = enabledBySystem();
        _owner->setProperty("AirportRTW89FrameworkSystemEnableBaseAfter",
                            baseAfter ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89FrameworkSystemEnableLogicalAfter",
                            _owner->_airportLogicalPowerOn
                                ? kOSBooleanTrue : kOSBooleanFalse);
    }
}

bool AirportRTW89Interface::prepareStackSafeOuterPowerSet(
    SInt32 reqVal, UInt32 reqLen, user_addr_t reqData,
    bool *requestedOn, bool *changed, IOReturn *applyResult)
{
    if (requestedOn)
        *requestedOn = false;
    if (changed)
        *changed = false;
    if (applyResult)
        *applyResult = kIOReturnSuccess;
    if (!_owner)
        return false;

    static UInt32 outerPowerSetCount = 0;
    ++outerPowerSetCount;
    const UInt32 eventSequence = ++_owner->_airportPowerEventSequence;

    _owner->setProperty("AirportRTW89PowerEventSequence",
                        (uint64_t)_owner->_airportPowerEventSequence, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetSeen", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89OuterPowerSetCount",
                        (uint64_t)outerPowerSetCount, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetEventSequence",
                        (uint64_t)eventSequence, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetReqVal",
                        (uint64_t)(UInt32)reqVal, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetReqLen",
                        (uint64_t)reqLen, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetReqDataPresent",
                        reqData != 0 ? kOSBooleanTrue : kOSBooleanFalse);

    UInt8 powerSnapshot[32] = {};
    UInt32 powerCopyLength = reqLen;
    if (powerCopyLength > sizeof(powerSnapshot))
        powerCopyLength = sizeof(powerSnapshot);
    const int powerCopyin =
        (reqData != 0 && powerCopyLength != 0)
            ? copyin(reqData, powerSnapshot, powerCopyLength)
            : EINVAL;

    _owner->setProperty("AirportRTW89OuterPowerSetCopyLength",
                        (uint64_t)powerCopyLength, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetCopyinReturn",
                        (uint64_t)(UInt32)powerCopyin, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetTruncated",
                        reqLen > sizeof(powerSnapshot)
                            ? kOSBooleanTrue : kOSBooleanFalse);

    if (powerCopyin != 0)
        return false;

    UInt32 nonZeroByteCount = 0;
    UInt32 nonZeroWordMask = 0;
    for (UInt32 i = 0; i < powerCopyLength; ++i) {
        if (powerSnapshot[i] != 0)
            ++nonZeroByteCount;
    }

    for (UInt32 wordIndex = 0; wordIndex < 8; ++wordIndex) {
        UInt32 word = 0;
        const UInt32 offset = wordIndex * sizeof(UInt32);
        if (powerCopyLength >= offset + sizeof(UInt32)) {
            memcpy(&word, powerSnapshot + offset, sizeof(word));
            if (word != 0)
                nonZeroWordMask |= (1U << wordIndex);
        }

        char property[80] = {};
        snprintf(property, sizeof(property),
                 "AirportRTW89OuterPowerSetWord%u",
                 (unsigned)wordIndex);
        _owner->setProperty(property, (uint64_t)word, 32);
    }

    _owner->setProperty("AirportRTW89OuterPowerSetNonZeroByteCount",
                        (uint64_t)nonZeroByteCount, 32);
    _owner->setProperty("AirportRTW89OuterPowerSetNonZeroWordMask",
                        (uint64_t)nonZeroWordMask, 32);

    if (OSData *powerData =
            OSData::withBytes(powerSnapshot, powerCopyLength)) {
        _owner->setProperty("AirportRTW89OuterPowerSetPayload", powerData);
        powerData->release();
    }

    const bool lengthSufficient =
        powerCopyLength >= sizeof(apple80211_power_data);
    bool shapeValid = false;
    bool uniformRadioState = false;
    UInt32 requestedPower = APPLE80211_POWER_OFF;

    if (lengthSufficient) {
        apple80211_power_data outerPower = {};
        memcpy(&outerPower, powerSnapshot, sizeof(outerPower));

        const bool versionValid = outerPower.version == APPLE80211_VERSION;
        const bool radioCountValid =
            outerPower.num_radios > 0 &&
            outerPower.num_radios <= APPLE80211_MAX_RADIO;
        const bool firstStateValid = radioCountValid &&
            (outerPower.power_state[0] == APPLE80211_POWER_OFF ||
             outerPower.power_state[0] == APPLE80211_POWER_ON);

        uniformRadioState = firstStateValid;
        if (firstStateValid) {
            requestedPower = outerPower.power_state[0];
            for (UInt32 i = 1; i < outerPower.num_radios; ++i) {
                if (outerPower.power_state[i] != requestedPower) {
                    uniformRadioState = false;
                    break;
                }
            }
        }

        shapeValid = versionValid && radioCountValid &&
                     firstStateValid && uniformRadioState;

        _owner->setProperty("AirportRTW89OuterPowerSetVersion",
                            (uint64_t)outerPower.version, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetRadios",
                            (uint64_t)outerPower.num_radios, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetUniformRadioState",
                            uniformRadioState ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterPowerSetRequested",
                            (uint64_t)requestedPower, 32);
    }

    _owner->setProperty("AirportRTW89OuterPowerSetLengthSufficient",
                        lengthSufficient ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89OuterPowerSetShapeValid",
                        shapeValid ? kOSBooleanTrue : kOSBooleanFalse);

    if (!shapeValid) {
        _owner->setProperty("AirportRTW89OuterPowerSetAuthoritative",
                            kOSBooleanFalse);
        return false;
    }

    const bool wantsOn = requestedPower == APPLE80211_POWER_ON;
    const bool logicalBefore = _owner->_airportLogicalPowerOn;
    const IOReturn apply = _owner->applyAirportUserPowerState(
        wantsOn, RTW88PCIDevice::kAirportLogicalPowerOuterApple80211);
    const bool didChange = logicalBefore != _owner->_airportLogicalPowerOn;

    _owner->setProperty("AirportRTW89OuterPowerSetAuthoritative",
                        kOSBooleanTrue);
    _owner->setProperty("AirportRTW89OuterPowerSetLogicalBefore",
                        logicalBefore ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89OuterPowerSetLogicalAfter",
                        _owner->_airportLogicalPowerOn
                            ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89OuterPowerSetChanged",
                        didChange ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89OuterPowerSetApplyReturn",
                        (uint64_t)(uint32_t)apply, 32);

    if (requestedOn)
        *requestedOn = wantsOn;
    if (changed)
        *changed = didChange;
    if (applyResult)
        *applyResult = apply;
    return true;
}

SInt32 AirportRTW89Interface::performCommand(
    IONetworkController *controller, unsigned long command,
    void *arg0, void *arg1)
{
    /* 0.2.246: stack-safe lifecycle marshaller.
     *
     * The 0.2.245 panic proves SET22 reached:
     *   performCommand -> apple80211Request -> airportSet -> cmdDisconnect.
     * On the user's unoptimized project build the old performCommand frame was
     * ~9.5 KiB at runtime, leaving too little kernel stack for scan-abort/log
     * frames.  Keep that large compatibility body for ordinary Tahoe IOCTLs,
     * but intercept only SET22 and SET20 here before entering it.
     *
     * ASSOCIATE is copied into heap storage so the lifecycle wrapper itself
     * remains small even without compiler optimization.  No payload pointer is
     * retained after apple80211Request returns. */
    static constexpr unsigned long kApple80211Set32 = 0x802069c8UL;
    static constexpr unsigned long kApple80211Set40 = 0x802869c8UL;
    static constexpr unsigned long kApple80211Set48 = 0x803069c8UL;
    static constexpr unsigned long kApple80211Get32 = 0xc02069c9UL;
    static constexpr unsigned long kApple80211Get40 = 0xc02869c9UL;
    static constexpr unsigned long kApple80211Get48 = 0xc03069c9UL;

    const bool isApple80211Command =
        command == kApple80211Get32 || command == kApple80211Get40 ||
        command == kApple80211Get48 || command == kApple80211Set32 ||
        command == kApple80211Set40 || command == kApple80211Set48;
    const bool isSet = command == kApple80211Set32 ||
                       command == kApple80211Set40 ||
                       command == kApple80211Set48;
    const bool is40 = command == kApple80211Get40 ||
                      command == kApple80211Set40;
    const bool is48 = command == kApple80211Get48 ||
                      command == kApple80211Set48;

    /* 0.5.2: 0.5.0/0.5.1 proved that Tahoe creates the inherited native
     * type-0 client, but also proved that routing Tahoe's outer ioctl ABI
     * directly through the restored Ventura marshaller hides supported
     * channels and scan results from the UI. Native-client parity is the
     * useful boundary; keep the established AirportRTW marshaller for all
     * commands so its Tahoe envelope normalization remains intact. */
    if (airportVenturaInterfaceParity() && _owner)
        _owner->setProperty("AirportRTW89VenturaParityLegacyMarshallerUsed",
                            kOSBooleanTrue);

    /* 0.3.13: pre-dispatch legacy Apple80211 ingress telemetry.
     * This ring is intentionally populated before any compatibility-body,
     * request-specific bridge, controller dispatcher, or superclass call.
     * It records only envelope metadata already consumed by this method and
     * never records req_data pointer values or payload bytes.  Its purpose is
     * to distinguish a userspace/IO80211Old rejection from a request that
     * actually entered AirportRTW89Interface::performCommand(). */
    if (isApple80211Command && _owner) {
        struct ApplePerformIngressTraceEntry {
            UInt64 monotonicMS;
            UInt64 command;
            UInt32 sequence;
            SInt32 request;
            UInt32 declaredLength;
            UInt32 flags;
        };
        static_assert(sizeof(ApplePerformIngressTraceEntry) == 32,
                      "Apple perform ingress trace entry size mismatch");
        enum : UInt32 {
            kApplePerformArg0Present = 1U << 0,
            kApplePerformArg1Present = 1U << 1,
            kApplePerformControllerMatches = 1U << 2,
            kApplePerformIsGet = 1U << 3,
            kApplePerformIsSet = 1U << 4,
            kApplePerformIs40 = 1U << 5,
            kApplePerformEnvelopeDecoded = 1U << 6,
            kApplePerformGet207 = 1U << 7,
        };
        static ApplePerformIngressTraceEntry applePerformTrace[64] = {};
        static volatile UInt32 applePerformTraceCount = 0;
        const UInt32 sequence =
            __sync_add_and_fetch(&applePerformTraceCount, 1U);
        ApplePerformIngressTraceEntry &entry =
            applePerformTrace[(sequence - 1U) & 63U];
        bzero(&entry, sizeof(entry));
        entry.monotonicMS = airportWPA2PreflightMonotonicMS();
        entry.command = command;
        entry.sequence = sequence;
        entry.request = -1;
        if (arg0) entry.flags |= kApplePerformArg0Present;
        if (arg1) entry.flags |= kApplePerformArg1Present;
        if (controller == static_cast<IONetworkController *>(_owner))
            entry.flags |= kApplePerformControllerMatches;
        if (!isSet) entry.flags |= kApplePerformIsGet;
        if (isSet) entry.flags |= kApplePerformIsSet;
        if (is40) entry.flags |= kApplePerformIs40;

        if (arg1) {
            if (is48) {
                struct AppleReq48Meta {
                    char ifname[IFNAMSIZ];
                    SInt32 type;
                    SInt32 val;
                    UInt32 len;
                    UInt32 pad;
                    UInt64 data;
                    UInt64 reserved;
                };
                static_assert(sizeof(AppleReq48Meta) == 48,
                              "Apple request 48 metadata size mismatch");
                const AppleReq48Meta *req =
                    static_cast<const AppleReq48Meta *>(arg1);
                entry.request = req->type;
                entry.declaredLength = req->len;
                entry.flags |= kApplePerformEnvelopeDecoded;
            } else if (is40) {
                struct AppleReq40Meta {
                    char ifname[IFNAMSIZ];
                    SInt32 type;
                    SInt32 val;
                    UInt32 len;
                    UInt32 pad;
                    UInt64 data;
                };
                static_assert(sizeof(AppleReq40Meta) == 40,
                              "Apple request 40 metadata size mismatch");
                const AppleReq40Meta *req =
                    static_cast<const AppleReq40Meta *>(arg1);
                entry.request = req->type;
                entry.declaredLength = req->len;
                entry.flags |= kApplePerformEnvelopeDecoded;
            } else {
                struct AppleReq32Meta {
                    char ifname[IFNAMSIZ];
                    SInt32 type;
                    SInt32 val;
                    UInt32 len;
                    UInt32 data;
                };
                static_assert(sizeof(AppleReq32Meta) == 32,
                              "Apple request 32 metadata size mismatch");
                const AppleReq32Meta *req =
                    static_cast<const AppleReq32Meta *>(arg1);
                entry.request = req->type;
                entry.declaredLength = req->len;
                entry.flags |= kApplePerformEnvelopeDecoded;
            }
        }
        if (entry.request == APPLE80211_IOC_CHANNELS_INFO)
            entry.flags |= kApplePerformGet207;

        _owner->setProperty("AirportRTW89ApplePerformIngressSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89ApplePerformIngressCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89ApplePerformIngressMS",
                            (uint64_t)entry.monotonicMS, 64);
        _owner->setProperty("AirportRTW89ApplePerformIngressCommand",
                            (uint64_t)command, 64);
        _owner->setProperty("AirportRTW89ApplePerformIngressRequest",
                            (uint64_t)(uint32_t)entry.request, 32);
        _owner->setProperty("AirportRTW89ApplePerformIngressDeclaredLength",
                            (uint64_t)entry.declaredLength, 32);
        _owner->setProperty("AirportRTW89ApplePerformIngressFlags",
                            (uint64_t)entry.flags, 32);
        if (entry.request == APPLE80211_IOC_CHANNELS_INFO) {
            _owner->setProperty("AirportRTW89ApplePerformGet207Seen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89ApplePerformGet207Sequence",
                                (uint64_t)sequence, 32);
            _owner->setProperty("AirportRTW89ApplePerformGet207MS",
                                (uint64_t)entry.monotonicMS, 64);
            _owner->setProperty("AirportRTW89ApplePerformGet207DeclaredLength",
                                (uint64_t)entry.declaredLength, 32);
        }
        if (OSData *traceData = OSData::withBytes(
                applePerformTrace, sizeof(applePerformTrace))) {
            _owner->setProperty("AirportRTW89ApplePerformIngressTrace",
                                traceData);
            traceData->release();
        }
    }

    /* 0.2.252 diagnostic: legacy IO80211Reference does not manufacture
     * APPLE80211_IOC_ASSOCIATE/20 inside its interface marshaller; IO80211
     * must first deliver the SIOCSA80211 envelope.  The 0.2.249-0.2.251
     * SET-only trace proves Tahoe never delivers request 20 to this service.
     * Before changing any return value or synthesizing an association, record
     * commands that reach this interface outside the four known legacy
     * Apple80211 GET/SET ioctl encodings.  If Tahoe uses another performCommand
     * command for the join, this ring will expose it without dereferencing
     * arg0/arg1 and without changing dispatch behavior.
     *
     * Each 32-byte entry is metadata only:
     *   u32 sequence, flags
     *   u64 raw command, entry monotonic milliseconds
     *   u64 argument-presence mask
     * flags: bit0=arg0 present, bit1=arg1 present, bit2=controller matches
     * owner.  No argument pointer value or pointed-to memory is captured. */
    if (!isApple80211Command && _owner) {
        struct NonLegacyCommandTraceEntry {
            UInt32 sequence;
            UInt32 flags;
            UInt64 command;
            UInt64 entryMS;
            UInt64 argsPresent;
        };
        static_assert(sizeof(NonLegacyCommandTraceEntry) == 32,
                      "non-legacy command trace entry size mismatch");
        static NonLegacyCommandTraceEntry commandTrace[128] = {};
        static volatile UInt32 commandTraceSequence = 0;

        const UInt32 sequence =
            __sync_add_and_fetch(&commandTraceSequence, 1U);
        const UInt32 slot = (sequence - 1U) & 127U;
        UInt32 flags = (arg0 ? 1U : 0U) | (arg1 ? 2U : 0U);
        if (controller == static_cast<IONetworkController *>(_owner))
            flags |= 4U;

        NonLegacyCommandTraceEntry &entry = commandTrace[slot];
        entry.sequence = sequence;
        entry.flags = flags;
        entry.command = (UInt64)command;
        entry.entryMS = airportWPA2PreflightMonotonicMS();
        entry.argsPresent = (arg0 ? 1ULL : 0ULL) | (arg1 ? 2ULL : 0ULL);

        _owner->setProperty("AirportRTW89NonLegacyCommandDiagSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagIndex",
                            (uint64_t)((slot + 1U) & 127U), 32);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagEntrySize",
                            (uint64_t)sizeof(NonLegacyCommandTraceEntry), 32);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagLastCommand",
                            (uint64_t)command, 64);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagLastEntryMS",
                            (uint64_t)entry.entryMS, 64);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagLastArg0Present",
                            arg0 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagLastArg1Present",
                            arg1 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagPayloadInspected",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagDiagnosticOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89NonLegacyCommandDiagReturnModified",
                            kOSBooleanFalse);
        if (OSData *traceData =
                OSData::withBytes(commandTrace, sizeof(commandTrace))) {
            _owner->setProperty("AirportRTW89NonLegacyCommandDiagRing",
                                traceData);
            traceData->release();
        }
    }

    /* 0.2.254 diagnostic: 0.2.253 proved that the only new raw
     * non-Apple80211 command bracketing the password-backed association edge is
     * 0xc02c6938.  Darwin sockio.h identifies that value as SIOCGIFMEDIA:
     * _IOWR('i', 56, struct ifmediareq), a normal media/link-status query, not
     * an association setter.  Characterize the controller state that Apple's
     * inherited IONetworkInterface marshaller sees for this exact command.
     *
     * Do not inspect arg1 or any ifmediareq bytes.  Call the same inherited
     * IO80211Interface::performCommand() that the compatibility body uses for
     * non-Apple80211 commands, preserve its return exactly, and record only
     * controller-owned link/medium metadata before and after the call.  Bypass
     * the ~9.5 KiB compatibility frame so this diagnostic cannot recreate the
     * stack-exhaustion class fixed for SCAN/IE/POWER. */
    static constexpr unsigned long kSIOCGIFMEDIA = 0xc02c6938UL;
    if (!isApple80211Command && _owner && command == kSIOCGIFMEDIA) {
        struct IfMediaAssociationEdgeEntry {
            UInt32 sequence;
            UInt32 flags;
            UInt64 entryMS;
            UInt64 exitMS;
            SInt32 inheritedReturn;
            UInt32 linkStatusBefore;
            UInt32 linkStatusAfter;
            UInt32 currentTypeBefore;
            UInt32 currentTypeAfter;
            UInt32 selectedTypeBefore;
            UInt32 selectedTypeAfter;
            UInt64 currentSpeedBefore;
            UInt64 currentSpeedAfter;
        };
        static_assert(sizeof(IfMediaAssociationEdgeEntry) == 72,
                      "SIOCGIFMEDIA diagnostic entry size mismatch");
        static IfMediaAssociationEdgeEntry ifMediaTrace[64] = {};
        static volatile UInt32 ifMediaSequence = 0;

        auto readLinkStatus = [&]() -> UInt32 {
            OSNumber *n = OSDynamicCast(
                OSNumber, _owner->getProperty(kIOLinkStatus));
            return n ? (UInt32)n->unsigned32BitValue() : 0U;
        };

        const UInt64 entryMS = airportWPA2PreflightMonotonicMS();
        const UInt32 linkBefore = readLinkStatus();
        const IONetworkMedium *currentBefore = _owner->getCurrentMedium();
        const IONetworkMedium *selectedBefore = _owner->getSelectedMedium();
        const bool idleBefore = !_owner->_ieee80211 ||
                                _owner->_ieee80211->isIdle();

        /* Preserve the only generic non-Apple80211 telemetry written by the
         * compatibility body before it delegates to the superclass. */
        _owner->setProperty("AirportRTW89InterfacePerformCommandSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89InterfacePerformCommand",
                            (uint64_t)command, 64);

        const SInt32 inherited = IO80211Interface::performCommand(
            controller, command, arg0, arg1);

        const UInt64 exitMS = airportWPA2PreflightMonotonicMS();
        const UInt32 linkAfter = readLinkStatus();
        const IONetworkMedium *currentAfter = _owner->getCurrentMedium();
        const IONetworkMedium *selectedAfter = _owner->getSelectedMedium();
        const bool idleAfter = !_owner->_ieee80211 ||
                               _owner->_ieee80211->isIdle();

        const UInt32 sequence = __sync_add_and_fetch(&ifMediaSequence, 1U);
        const UInt32 slot = (sequence - 1U) & 63U;
        UInt32 flags = (arg0 ? 1U : 0U) | (arg1 ? 2U : 0U);
        if (controller == static_cast<IONetworkController *>(_owner))
            flags |= 1U << 2;
        if (linkBefore & kIONetworkLinkActive)
            flags |= 1U << 3;
        if (linkAfter & kIONetworkLinkActive)
            flags |= 1U << 4;
        if (idleBefore)
            flags |= 1U << 5;
        if (idleAfter)
            flags |= 1U << 6;

        IfMediaAssociationEdgeEntry &entry = ifMediaTrace[slot];
        entry.sequence = sequence;
        entry.flags = flags;
        entry.entryMS = entryMS;
        entry.exitMS = exitMS;
        entry.inheritedReturn = inherited;
        entry.linkStatusBefore = linkBefore;
        entry.linkStatusAfter = linkAfter;
        entry.currentTypeBefore = currentBefore ? currentBefore->getType() : 0U;
        entry.currentTypeAfter = currentAfter ? currentAfter->getType() : 0U;
        entry.selectedTypeBefore = selectedBefore ? selectedBefore->getType() : 0U;
        entry.selectedTypeAfter = selectedAfter ? selectedAfter->getType() : 0U;
        entry.currentSpeedBefore = currentBefore ? currentBefore->getSpeed() : 0ULL;
        entry.currentSpeedAfter = currentAfter ? currentAfter->getSpeed() : 0ULL;

        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagEntrySize",
                            (uint64_t)sizeof(IfMediaAssociationEdgeEntry), 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagEntryMS",
                            (uint64_t)entryMS, 64);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagExitMS",
                            (uint64_t)exitMS, 64);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagInheritedReturn",
                            (uint64_t)(uint32_t)inherited, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagLinkStatusBefore",
                            (uint64_t)linkBefore, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagLinkStatusAfter",
                            (uint64_t)linkAfter, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagLinkActiveBefore",
                            (linkBefore & kIONetworkLinkActive)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagLinkActiveAfter",
                            (linkAfter & kIONetworkLinkActive)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagBackendIdleBefore",
                            idleBefore ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagBackendIdleAfter",
                            idleAfter ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagCurrentTypeBefore",
                            (uint64_t)entry.currentTypeBefore, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagCurrentTypeAfter",
                            (uint64_t)entry.currentTypeAfter, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagSelectedTypeBefore",
                            (uint64_t)entry.selectedTypeBefore, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagSelectedTypeAfter",
                            (uint64_t)entry.selectedTypeAfter, 32);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagCurrentSpeedBefore",
                            (uint64_t)entry.currentSpeedBefore, 64);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagCurrentSpeedAfter",
                            (uint64_t)entry.currentSpeedAfter, 64);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagPayloadInspected",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagDiagnosticOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagReturnNormalized",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagCompatBodyBypassed",
                            kOSBooleanTrue);
        if (OSData *traceData = OSData::withBytes(ifMediaTrace,
                                                  sizeof(ifMediaTrace))) {
            _owner->setProperty("AirportRTW89SIOCGIFMEDIADiagRing",
                                traceData);
            traceData->release();
        }

        return inherited;
    }

    /* 0.3.2 stack-safety repair: never keep the historical ~9.5 KiB
     * Apple80211 compatibility frame resident for ordinary BSD/network
     * ioctls.  The 0.3.1 configd SIOCSIFFLAGS panic showed that Apple's
     * inherited IO80211/IOEthernet path may synchronously update link
     * parameters and call back into apple80211Request(GET), exhausting the
     * 16 KiB x86_64 kernel stack when performCommandCompatBody is still live.
     *
     * Preserve dispatch semantics exactly: non-Apple commands still go to
     * IO80211Interface::performCommand(), and the generic metadata-only
     * telemetry above remains unchanged.  Only the unnecessary large shim
     * frame is removed from the call chain. */
    if (!isApple80211Command) {
        if (_owner) {
            /* These are the same generic properties that the compatibility
             * body published before its old direct superclass delegation. */
            _owner->setProperty("AirportRTW89InterfacePerformCommandSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89InterfacePerformCommand",
                                (uint64_t)command, 64);
            _owner->setProperty("AirportRTW89StackSafeNonAppleBypassSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89StackSafeNonAppleBypassLastCommand",
                                (uint64_t)command, 64);
            _owner->setProperty("AirportRTW89StackSafeNonAppleCompatBodyBypassed",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89StackSafeNonAppleReturnModified",
                                kOSBooleanFalse);
        }
        return IO80211Interface::performCommand(
            controller, command, arg0, arg1);
    }

    struct Apple80211Req32Thin {
        char req_if_name[IFNAMSIZ];
        SInt32 req_type;
        SInt32 req_val;
        UInt32 req_len;
        UInt32 req_data;
    };
    struct Apple80211Req40Thin {
        char req_if_name[IFNAMSIZ];
        SInt32 req_type;
        SInt32 req_val;
        UInt32 req_len;
        UInt32 req_pad;
        UInt64 req_data;
    };
    struct Apple80211Req48Thin {
        char req_if_name[IFNAMSIZ];
        SInt32 req_type;
        SInt32 req_val;
        UInt32 req_len;
        UInt32 req_pad;
        UInt64 req_data;
        UInt64 req_reserved;
    };
    static_assert(sizeof(Apple80211Req32Thin) == 32,
                  "Apple80211 thin 32-byte envelope size mismatch");
    static_assert(sizeof(Apple80211Req40Thin) == 40,
                  "Apple80211 thin 40-byte envelope size mismatch");
    static_assert(sizeof(Apple80211Req48Thin) == 48,
                  "Apple80211 thin 48-byte envelope size mismatch");

    SInt32 reqType = -1;
    SInt32 reqVal = -1;
    UInt32 reqLen = 0;
    user_addr_t reqData = 0;
    if (_owner && arg1) {
        if (is48) {
            const Apple80211Req48Thin *req =
                static_cast<const Apple80211Req48Thin *>(arg1);
            reqType = req->req_type;
            reqVal = req->req_val;
            reqLen = req->req_len;
            reqData = (user_addr_t)req->req_data;
        } else if (is40) {
            const Apple80211Req40Thin *req =
                static_cast<const Apple80211Req40Thin *>(arg1);
            reqType = req->req_type;
            reqVal = req->req_val;
            reqLen = req->req_len;
            reqData = (user_addr_t)req->req_data;
        } else {
            const Apple80211Req32Thin *req =
                static_cast<const Apple80211Req32Thin *>(arg1);
            reqType = req->req_type;
            reqVal = req->req_val;
            reqLen = req->req_len;
            reqData = (user_addr_t)req->req_data;
        }
    }

    /* 0.4.14: this thin dispatcher is the real common ingress for stack-safe
     * SET22 and hot GET1; both bypass performCommandCompatBody. */
    if (_owner && isSet && reqType == APPLE80211_IOC_DISASSOCIATE) {
        _owner->_airportIOUCAssociationCaptureStartMS =
            airportWPA2PreflightMonotonicMS();
        _owner->setProperty("AirportRTW89IOUCAssociationThinEpochArmed",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89IOUCAssociationThinEpochStartMS",
                            (uint64_t)_owner->_airportIOUCAssociationCaptureStartMS,
                            64);
    }

    /* 0.5.28: CHANNELS_INFO must precede the 0.5.24 all-GET dispatcher.
     * Keeping this dedicated marshaller below that dispatcher made it
     * unreachable; the generic explicit marshaller rejected request 207 and
     * IO80211Old returned -3903.  CoreWiFi consequently discarded the
     * supported-channel list and never completed its interface capability
     * cache. */
    if (!isSet && _owner && arg1 &&
        reqType == APPLE80211_IOC_CHANNELS_INFO) {
        const SInt32 result = airportDirectGetChannelsInfo(
            _owner, reqLen, reqData);
        _owner->setProperty("AirportRTW89StackSafeChannelsInfoHandled",
                            kOSBooleanTrue);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return result;
    }

    /* 0.3.10 stack-safety hotfix: the 0.3.9 airportd double-fault proved
     * that ordinary status GETs cannot remain inside performCommandCompatBody.
     * The failing chain kept the ~9.5 KiB compatibility frame resident while
     * IO80211Family synchronously called back into ASSOCIATE_RESULT, whose
     * controller getter then entered IORegistry allocation.  Move the public
     * fixed-size status GETs that can participate in association/UI polling to
     * the already-proven explicit marshaller here, before the compatibility
     * body exists.  If a private/invalid shape is not handled, delegate
     * directly to Apple with the small performCommand frame; never re-enter the
     * large compatibility body for this request class.
     *
     * This changes transport/stack ownership only.  Payload semantics remain
     * those of the same controller apple80211Request handlers used in 0.3.9. */
    /* 0.5.24: all GET requests must remain outside the historical 0x2650-byte
     * compatibility frame. A system_profiler GET MCS/57 proved that limiting
     * this bypass to UI/status requests still lets an ordinary getter retain
     * performCommandCompatBody while IO80211 calls airportGetBody (0x730) and
     * then allocates an OSSymbol, overflowing the 16 KiB kernel stack. The
     * explicit marshaller already accepts every fixed-size legacy GET; if it
     * rejects a private shape, fall through to Apple's inherited dispatcher
     * directly, still without creating the large compatibility frame. */
    const bool stackSafeHotGet = !isSet && _owner && arg1;
    if (stackSafeHotGet) {
        SInt32 hotResult = kIOReturnUnsupported;
        const bool handled = airportExplicitLegacyMarshal(
            _owner, this, false, (UInt32)reqType, reqLen, reqData, &hotResult);

        bool thinSSIDEmptySuccessApplied = false;
        UInt64 thinSSIDCaptureAgeMS = UINT64_MAX;
        if (handled && reqType == APPLE80211_IOC_SSID &&
            reqLen == APPLE80211_MAX_SSID_LEN && reqData != 0 &&
            hotResult == 6 &&
            _owner->_airportIOUCAssociationCaptureStartMS != 0) {
            const UInt64 nowMS = airportWPA2PreflightMonotonicMS();
            if (nowMS >= _owner->_airportIOUCAssociationCaptureStartMS)
                thinSSIDCaptureAgeMS =
                    nowMS - _owner->_airportIOUCAssociationCaptureStartMS;
            if (thinSSIDCaptureAgeMS <= 25U) {
                UInt8 rawSSID[APPLE80211_MAX_SSID_LEN] = {};
                if (copyin(reqData, rawSSID, sizeof(rawSSID)) == 0) {
                    bool empty = true;
                    for (UInt32 i = 0; i < sizeof(rawSSID); ++i) {
                        if (rawSSID[i] != 0) {
                            empty = false;
                            break;
                        }
                    }
                    if (empty) {
                        hotResult = kIOReturnSuccess;
                        thinSSIDEmptySuccessApplied = true;
                    }
                }
            }
        }
        if (thinSSIDEmptySuccessApplied) {
            static volatile UInt32 thinSSIDAppliedCount = 0;
            const UInt32 count = __sync_add_and_fetch(
                &thinSSIDAppliedCount, 1U);
            _owner->setProperty("AirportRTW89ThinSSIDEmptySuccessSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89ThinSSIDEmptySuccessCount",
                                (uint64_t)count, 32);
            _owner->setProperty("AirportRTW89ThinSSIDEmptySuccessCaptureAgeMS",
                                (uint64_t)thinSSIDCaptureAgeMS, 64);
            _owner->setProperty("AirportRTW89ThinSSIDEmptySuccessFinalReturn",
                                (uint64_t)(uint32_t)hotResult, 32);
        }

        static volatile UInt32 hotGetCount = 0;
        const UInt32 hotSequence = __sync_add_and_fetch(&hotGetCount, 1U);
        _owner->setProperty("AirportRTW89StackSafeHotGetSeen", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafeHotGetCount",
                            (uint64_t)hotSequence, 32);
        _owner->setProperty("AirportRTW89StackSafeHotGetLastRequest",
                            (uint64_t)(UInt32)reqType, 32);
        _owner->setProperty("AirportRTW89StackSafeHotGetHandled",
                            handled ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafeHotGetCompatBodyBypassed",
                            kOSBooleanTrue);

        if (handled) {
            _owner->setProperty("AirportRTW89StackSafeHotGetSuperclassFallback",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89StackSafeHotGetLastReturn",
                                (uint64_t)(uint32_t)hotResult, 32);
            _owner->setProperty(
                "AirportRTW89InterfaceApple80211PerformCommandReturn",
                (uint64_t)(uint32_t)hotResult, 32);
            return hotResult;
        }

        const SInt32 inherited = IO80211Interface::performCommand(
            controller, command, arg0, arg1);
        _owner->setProperty("AirportRTW89StackSafeHotGetSuperclassFallback",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafeHotGetLastReturn",
                            (uint64_t)(uint32_t)inherited, 32);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)inherited, 32);
        return inherited;
    }

    if (!isSet || !_owner || !arg1)
        return performCommandCompatBody(controller, command, arg0, arg1);

    /* 0.2.249 diagnostic: 0.2.248 is the first stable run in this line that
     * reaches a password-backed `Will associate` while the stack-safe
     * SCAN_REQ/10, IE/85 and DISASSOCIATE/22 paths all succeed.  SET20 still
     * never appears in either the outer or controller history.  The generic
     * outer ring is quickly overwritten by GET traffic, so keep a second
     * metadata-only ring containing SET envelopes only.
     *
     * Do not inspect request payload bytes and do not alter any request or
     * return value.  Each 32-byte entry is:
     *   u32 sequence, request type, request value, request length
     *   u32 flags, reserved
     *   u64 monotonic entry milliseconds
     * flags: bit0=40-byte envelope, bit1=data present, bit2=SCAN_REQ/10,
     * bit3=IE/85, bit4=DISASSOCIATE/22, bit5=ASSOCIATE/20, bit6=POWER/19,
     * bit7=BTCOEX_PROFILE/255. */
    struct OuterSetTraceEntry {
        UInt32 sequence;
        UInt32 requestType;
        UInt32 requestValue;
        UInt32 requestLength;
        UInt32 flags;
        UInt32 reserved;
        UInt64 entryMS;
    };
    static_assert(sizeof(OuterSetTraceEntry) == 32,
                  "outer SET trace entry size mismatch");
    static OuterSetTraceEntry outerSetTrace[64] = {};
    static volatile UInt32 outerSetTraceSequence = 0;

    const UInt32 setSequence =
        __sync_add_and_fetch(&outerSetTraceSequence, 1U);
    const UInt32 setSlot = (setSequence - 1U) & 63U;
    UInt32 setFlags = (is40 ? 1U : 0U) | (reqData ? 2U : 0U);
    if (reqType == APPLE80211_IOC_SCAN_REQ)
        setFlags |= 1U << 2;
    if (reqType == APPLE80211_IOC_IE)
        setFlags |= 1U << 3;
    if (reqType == APPLE80211_IOC_DISASSOCIATE)
        setFlags |= 1U << 4;
    if (reqType == APPLE80211_IOC_ASSOCIATE)
        setFlags |= 1U << 5;
    if (reqType == APPLE80211_IOC_POWER)
        setFlags |= 1U << 6;
    if (reqType == APPLE80211_IOC_BTCOEX_PROFILE)
        setFlags |= 1U << 7;

    OuterSetTraceEntry &setEntry = outerSetTrace[setSlot];
    setEntry.sequence = setSequence;
    setEntry.requestType = (UInt32)reqType;
    setEntry.requestValue = (UInt32)reqVal;
    setEntry.requestLength = reqLen;
    setEntry.flags = setFlags;
    setEntry.reserved = 0;
    setEntry.entryMS = airportWPA2PreflightMonotonicMS();

    _owner->setProperty("AirportRTW89OuterSetTraceSeen", kOSBooleanTrue);
    _owner->setProperty("AirportRTW89OuterSetTraceCount",
                        (uint64_t)setSequence, 32);
    _owner->setProperty("AirportRTW89OuterSetTraceIndex",
                        (uint64_t)((setSlot + 1U) & 63U), 32);
    _owner->setProperty("AirportRTW89OuterSetTraceEntrySize",
                        (uint64_t)sizeof(OuterSetTraceEntry), 32);
    _owner->setProperty("AirportRTW89OuterSetTraceLastRequest",
                        (uint64_t)(UInt32)reqType, 32);
    _owner->setProperty("AirportRTW89OuterSetTraceLastValue",
                        (uint64_t)(UInt32)reqVal, 32);
    _owner->setProperty("AirportRTW89OuterSetTraceLastLength",
                        (uint64_t)reqLen, 32);
    _owner->setProperty("AirportRTW89OuterSetTraceLastFlags",
                        (uint64_t)setFlags, 32);
    _owner->setProperty("AirportRTW89OuterSetTraceLastEntryMS",
                        (uint64_t)setEntry.entryMS, 64);
    _owner->setProperty("AirportRTW89OuterSetTracePayloadInspected",
                        kOSBooleanFalse);
    _owner->setProperty("AirportRTW89OuterSetTraceDiagnosticOnly",
                        kOSBooleanTrue);
    _owner->setProperty("AirportRTW89OuterSetTraceReturnModified",
                        kOSBooleanFalse);
    if (OSData *setTraceData =
            OSData::withBytes(outerSetTrace, sizeof(outerSetTrace))) {
        _owner->setProperty("AirportRTW89OuterSetTraceRing", setTraceData);
        setTraceData->release();
    }

    /* 0.2.253: the 0.2.252 panic proves POWER/19 has the same stack
     * hazard as SCAN_REQ/10 and IE/85 when the historical compatibility body
     * delegates to IO80211Interface::performCommand():
     *   performCommandCompatBody (~9.5 KiB at -O0)
     *     -> IO80211Interface::performCommand
     *     -> Apple setPower()
     *     -> apple80211Request(SET,19)
     *     -> airportSet(POWER)
     *     -> IOLog / double fault at the stack guard.
     *
     * Preserve the proven 0.2.175 POWER semantics exactly: first consume the
     * canonical outer power_data as authoritative logical state, then let
     * Apple's inherited marshaller own its hidden inner callback, then re-pin
     * the always-live transport after the inherited call returns.  The outer
     * preparation runs in a separate non-virtual helper which fully unwinds
     * before Apple's callback can occur. */
    if (reqType == APPLE80211_IOC_POWER) {
        bool outerPowerSetRequestedOn = false;
        bool outerPowerSetChanged = false;
        IOReturn outerPowerSetApplyResult = kIOReturnSuccess;
        bool outerPowerSetAuthoritative = prepareStackSafeOuterPowerSet(
            reqVal, reqLen, reqData, &outerPowerSetRequestedOn,
            &outerPowerSetChanged, &outerPowerSetApplyResult);

        static volatile UInt32 powerCount = 0;
        const UInt32 powerSequence = __sync_add_and_fetch(&powerCount, 1U);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerCount",
                            (uint64_t)powerSequence, 32);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerRequest",
                            (uint64_t)(uint32_t)reqType, 32);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerOuterDataPresent",
                            reqData ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerAuthoritative",
                            outerPowerSetAuthoritative
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerCompatBodyBypassed",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89Apple80211LivePowerSetDelegatedToSuper",
                            kOSBooleanTrue);

        const SInt32 inherited = IO80211Interface::performCommand(
            controller, command, arg0, arg1);

        /* 0.5.25: Tahoe's boot-time POWER SET uses a version-only outer
         * apple80211_power_data (version=1, num_radios=0).  The inherited
         * Ventura marshaller consumes that envelope and updates the
         * IO80211Interface user-power latch, but there is no radio slot for
         * prepareStackSafeOuterPowerSet() to treat as authoritative.  Mirror
         * the resulting ON latch only for this otherwise non-authoritative
         * transaction.  The OFF direction remains owned by airportSet()'s
         * independently observed zero-radio/framework-latch path, and normal
         * four-radio POWER requests continue through the validated path
         * above. */
        const bool zeroRadioFrameworkOn =
            !outerPowerSetAuthoritative && inherited == kIOReturnSuccess &&
            poweredOnByUser() && enabledBySystem() && _owner->_enabled;
        if (zeroRadioFrameworkOn) {
            const bool logicalBefore = _owner->_airportLogicalPowerOn;
            outerPowerSetRequestedOn = true;
            outerPowerSetApplyResult = _owner->applyAirportUserPowerState(
                true, RTW88PCIDevice::kAirportLogicalPowerOuterApple80211);
            outerPowerSetChanged =
                logicalBefore != _owner->_airportLogicalPowerOn;
            outerPowerSetAuthoritative = true;
            _owner->setProperty("AirportRTW89ZeroRadioFrameworkOnSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89ZeroRadioFrameworkOnAccepted",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89ZeroRadioFrameworkOnLogicalBefore",
                                logicalBefore ? kOSBooleanTrue
                                              : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89ZeroRadioFrameworkOnLogicalAfter",
                                _owner->_airportLogicalPowerOn
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89ZeroRadioFrameworkOnApplyReturn",
                                (uint64_t)(uint32_t)outerPowerSetApplyResult,
                                32);
            _owner->setProperty("AirportRTW89StackSafePowerMarshallerAuthoritative",
                                kOSBooleanTrue);
        }

        if (outerPowerSetAuthoritative) {
            _owner->pinAirportTransportUserPowerOn(this);
            _owner->pinAirportTransportSystemEnableOn(this);
            _owner->_airportPowerRelatchPending = false;
            _owner->setProperty("AirportRTW89PrimaryTransportPowerPinnedOn",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89OuterPowerSetPostSuperRelatch",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89OuterPowerSetPostSuperUserPower",
                                poweredOnByUser()
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89OuterPowerSetPostSuperSystemEnable",
                                enabledBySystem()
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89OuterPowerSetSuperReturn",
                                (uint64_t)(uint32_t)inherited, 32);

            if (outerPowerSetRequestedOn &&
                outerPowerSetApplyResult == kIOReturnSuccess) {
                _owner->_airportPostSuperPowerOnNotifyPending = true;
                _owner->setProperty("AirportRTW89PostSuperPowerOnNotifyPending",
                                    kOSBooleanTrue);
                _owner->setProperty("AirportRTW89PostSuperPowerOnNotifyArmed",
                                    kOSBooleanTrue);
            }
        }

        SInt32 finalResult = inherited;
        if (outerPowerSetAuthoritative &&
            outerPowerSetApplyResult != kIOReturnSuccess)
            finalResult = outerPowerSetApplyResult;

        _owner->setProperty("AirportRTW89StackSafePowerMarshallerInheritedReturn",
                            (uint64_t)(uint32_t)inherited, 32);
        _owner->setProperty("AirportRTW89StackSafePowerMarshallerFinalReturn",
                            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty("AirportRTW89InterfaceApple80211PerformCommandReturn",
                            (uint64_t)(uint32_t)finalResult, 32);
        if (outerPowerSetAuthoritative) {
            _owner->setProperty("AirportRTW89OuterPowerSetFinalReturn",
                                (uint64_t)(uint32_t)finalResult, 32);
            _owner->setProperty("AirportRTW89OuterPowerSetRequestedOn",
                                outerPowerSetRequestedOn
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89OuterPowerSetChangedFinal",
                                outerPowerSetChanged
                                    ? kOSBooleanTrue : kOSBooleanFalse);
        }
        return finalResult;
    }

    /* 0.2.247: the 0.2.246 panic photograph proves SET SCAN_REQ/10 also
     * reaches a deep controller/backend chain while the historical ~9.5 KiB
     * compatibility body is resident:
     *   performCommandCompatBody -> apple80211Request -> cmdScan -> IOLog.
     * The final double fault occurs in logging with the stack guard adjacent,
     * exactly like the 0.2.245 SET22 panic.  Keep the existing typed explicit
     * marshaller, but invoke it here for exact SET10 so scan does not enter the
     * large compatibility frame.  No other scan/status request is changed. */
    if (reqType == APPLE80211_IOC_SCAN_REQ) {
        SInt32 scanResult = kIOReturnUnsupported;
        const bool handled = airportExplicitLegacyMarshal(
            _owner, this, true, (UInt32)reqType, reqLen, reqData, &scanResult);

        static volatile UInt32 scanCount = 0;
        const UInt32 scanSequence = __sync_add_and_fetch(&scanCount, 1U);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerCount",
                            (uint64_t)scanSequence, 32);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerRequest",
                            (uint64_t)(uint32_t)reqType, 32);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerDataPresent",
                            reqData ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerHandled",
                            handled ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerCompatBodyBypassed",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerFinalReturn",
                            (uint64_t)(uint32_t)scanResult, 32);

        if (handled)
            return scanResult;

        /* Invalid/private SCAN_REQ shapes must not re-enter the large
         * compatibility body.  Delegate directly to Apple instead. */
        const SInt32 inherited = IO80211Interface::performCommand(
            controller, command, arg0, arg1);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerFallbackToSuper",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafeScanMarshallerFinalReturn",
                            (uint64_t)(uint32_t)inherited, 32);
        return inherited;
    }

    /* 0.2.248: the 0.2.247 panic proves APPLE80211_IOC_IE/85 takes
     * Apple's private setIE() helper when it falls through the historical
     * compatibility body:
     *   performCommandCompatBody -> IO80211Interface::performCommand
     *   -> setIE -> apple80211Request -> airportSet(IE).
     * At -O0 the compatibility frame is ~9.5 KiB, so the callback reaches
     * airportSet with too little kernel stack and finally double-faults in
     * setProperty()/OSSymbol allocation.  IO80211Reference accepts SET IE and our
     * airportSet(IE) intentionally does not inspect the private payload.
     * Bypass the large compatibility body for this exact SET and provide a
     * tiny kernel-resident non-null token solely to satisfy the controller
     * dispatcher's generic non-null invariant.  No private IE bytes are read,
     * copied, stored, or interpreted by this path. */
    if (reqType == APPLE80211_IOC_IE) {
        static volatile UInt32 ieCount = 0;
        const UInt32 ieSequence = __sync_add_and_fetch(&ieCount, 1U);
        UInt8 ignoredPrivateIEPayload = 0;

        _owner->setProperty("AirportRTW89StackSafeIEMarshallerSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerCount",
                            (uint64_t)ieSequence, 32);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerRequest",
                            (uint64_t)(uint32_t)reqType, 32);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerOuterDataPresent",
                            reqData ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerPayloadInspected",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerCompatBodyBypassed",
                            kOSBooleanTrue);

        const SInt32 ieResult = _owner->apple80211Request(
            (unsigned int)SIOCSA80211, APPLE80211_IOC_IE, this,
            &ignoredPrivateIEPayload);
        _owner->setProperty("AirportRTW89StackSafeIEMarshallerFinalReturn",
                            (uint64_t)(uint32_t)ieResult, 32);
        _owner->setProperty("AirportRTW89InterfaceApple80211PerformCommandReturn",
                            (uint64_t)(uint32_t)ieResult, 32);
        return ieResult;
    }

    if (reqType != APPLE80211_IOC_DISASSOCIATE &&
        reqType != APPLE80211_IOC_ASSOCIATE)
        return performCommandCompatBody(controller, command, arg0, arg1);

    const AirportWPA2PreflightTraceCookie traceCookie =
        airportWPA2PreflightTraceBegin(_owner, true, is40, reqType, reqVal,
                                       reqLen, reqData);

    static volatile UInt32 lifecycleCount = 0;
    const UInt32 lifecycleSequence =
        __sync_add_and_fetch(&lifecycleCount, 1U);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerSeen",
                        kOSBooleanTrue);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerCount",
                        (uint64_t)lifecycleSequence, 32);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerRequest",
                        (uint64_t)(uint32_t)reqType, 32);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerReqLen",
                        (uint64_t)reqLen, 32);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerDataPresent",
                        reqData ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerHeapAssoc",
                        reqType == APPLE80211_IOC_ASSOCIATE
                            ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89StackSafeLifecycleMarshallerCompatBodyBypassed",
                        kOSBooleanTrue);

    if (reqType == APPLE80211_IOC_DISASSOCIATE) {
        static volatile UInt32 disassociateCount = 0;
        const UInt32 disSequence =
            __sync_add_and_fetch(&disassociateCount, 1U);
        const bool alreadyIdle = _owner->_ieee80211 &&
                                 _owner->_ieee80211->isIdle();

        _owner->setProperty("AirportRTW89OuterDISASSOCIATESeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATECount",
                            (uint64_t)disSequence, 32);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEAlreadyIdle",
                            alreadyIdle ? kOSBooleanTrue : kOSBooleanFalse);

        if (_owner->_airportLock) {
            IOLockLock(_owner->_airportLock);
            _owner->_airportGet11ControllerFirstResultJoinArmed = false;
            _owner->_airportGet11ControllerIoctlGetProbeActive = false;
            _owner->_airportGet11ControllerIoctlGetProbeThread = THREAD_NULL;
            IOLockUnlock(_owner->_airportLock);
        }
        _owner->setProperty("AirportRTW89Get11ControllerFirstResultJoinArmed",
                            kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89Get11ControllerFirstResultDisabledForWPA2Focus",
            kOSBooleanTrue);

        const SInt32 result = _owner->apple80211Request(
            (unsigned int)SIOCSA80211, APPLE80211_IOC_DISASSOCIATE,
            this, nullptr);

        const bool idleAfter = _owner->_ieee80211 &&
                               _owner->_ieee80211->isIdle();
        _owner->setProperty(
            "AirportRTW89OuterDISASSOCIATEDirectBackend", kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89OuterDISASSOCIATEPayloadDispatcherBypassed",
            kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89OuterDISASSOCIATEIO80211ReferenceControllerDispatch",
            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEBackendReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEIdleAfter",
                            idleAfter ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89StackSafeLifecycleDISASSOCIATEReturn",
            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(
            _owner, traceCookie, result, kWPA2TraceDirectBridge);
    }

    static volatile UInt32 associateCount = 0;
    const UInt32 assocSequence =
        __sync_add_and_fetch(&associateCount, 1U);
    const size_t assocLength = sizeof(apple80211_assoc_data);
    const bool payloadPresent = reqData != 0;
    const bool lengthSufficient = reqLen >= assocLength;
    SInt32 result = kIOReturnBadArgument;
    SInt32 innerResult = kIOReturnBadArgument;
    int assocCopyin = -1;

    _owner->setProperty("AirportRTW89DirectAssociate20BridgeSeen",
                        kOSBooleanTrue);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgeCount",
                        (uint64_t)assocSequence, 32);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgeReqLen",
                        (uint64_t)reqLen, 32);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgeStructSize",
                        (uint64_t)assocLength, 32);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgePayloadPresent",
                        payloadPresent ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgeLengthSufficient",
                        lengthSufficient ? kOSBooleanTrue : kOSBooleanFalse);

    apple80211_assoc_data *assocData = nullptr;
    if (payloadPresent && lengthSufficient) {
        assocData = static_cast<apple80211_assoc_data *>(IOMalloc(assocLength));
        if (!assocData) {
            result = kIOReturnNoMemory;
            innerResult = kIOReturnNoMemory;
        } else {
            bzero(assocData, assocLength);
            assocCopyin = copyin(reqData, assocData, assocLength);
            result = (SInt32)assocCopyin;
            innerResult = (SInt32)assocCopyin;
            if (assocCopyin == 0) {
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeVersion",
                                    (uint64_t)assocData->version, 32);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeSSIDLength",
                                    (uint64_t)assocData->ad_ssid_len, 32);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeAuthLower",
                                    (uint64_t)assocData->ad_auth_lower, 16);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeAuthUpper",
                                    (uint64_t)assocData->ad_auth_upper, 16);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeKeyLength",
                                    (uint64_t)assocData->ad_key.key_len, 32);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeKeyCipherType",
                                    (uint64_t)assocData->ad_key.key_cipher_type, 32);

                static const UInt8 zeroBSSID[6] = {};
                const bool bssidPresent =
                    memcmp(assocData->ad_bssid.octet, zeroBSSID,
                           sizeof(zeroBSSID)) != 0;
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeBSSIDPresent",
                                    bssidPresent ? kOSBooleanTrue
                                                 : kOSBooleanFalse);

                const bool shapeValid =
                    assocData->version == APPLE80211_VERSION &&
                    assocData->ad_ssid_len > 0 &&
                    assocData->ad_ssid_len <= APPLE80211_MAX_SSID_LEN &&
                    assocData->ad_key.key_len <= APPLE80211_KEY_BUFF_LEN;
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeShapeValid",
                                    shapeValid ? kOSBooleanTrue
                                               : kOSBooleanFalse);
                if (shapeValid) {
                    innerResult = _owner->apple80211Request(
                        (unsigned int)SIOCSA80211,
                        APPLE80211_IOC_ASSOCIATE, this, assocData);
                    result = innerResult;
                }
            }
        }
    }

    if (assocData) {
        bzero(assocData, assocLength);
        IOFree(assocData, assocLength);
    }

    _owner->setProperty("AirportRTW89DirectAssociate20BridgeCopyinReturn",
                        (uint64_t)(uint32_t)assocCopyin, 32);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgeInnerReturn",
                        (uint64_t)(uint32_t)innerResult, 32);
    _owner->setProperty("AirportRTW89DirectAssociate20BridgeReturn",
                        (uint64_t)(uint32_t)result, 32);
    _owner->setProperty("AirportRTW89StackSafeLifecycleASSOCIATEReturn",
                        (uint64_t)(uint32_t)result, 32);
    _owner->setProperty(
        "AirportRTW89InterfaceApple80211PerformCommandReturn",
        (uint64_t)(uint32_t)result, 32);
    return airportWPA2PreflightTraceFinish(
        _owner, traceCookie, result, kWPA2TraceDirectBridge);
}

SInt32 AirportRTW89Interface::performCommandCompatBody(
    IONetworkController *controller, unsigned long command,
    void *arg0, void *arg1)
{
    /* 0.2.110: keep the genuine AirportRTW89Interface/enX as the only BSD
     * frontend, but move the 0.2.106 direct POWER bridge onto this live path.
     *
     * The obsolete second-BSD bridge has been removed from the source tree.
     * Consequently 0.2.107 reached apple80211Request(POWER) through Apple's
     * hidden IO80211Interface::performCommand() marshaller, where the driver
     * returned canonical POWER=ON while CoreWLAN/networksetup still observed
     * OFF.  POWER alone is therefore marshalled explicitly here; every other
     * Apple80211 request remains delegated to Apple's implementation. */
    /* Darwin ioctl direction bits are part of the ABI here:
     *   0x80.. = IOC_IN  / _IOW  -> userspace writes a SET request
     *   0xc0.. = IOC_INOUT / _IOWR -> userspace issues a GET request
     * The 0.2.108/0.2.109 live bridge had these labels reversed, so its
     * "GET-only" experiment was actually intercepting SET traffic. */
    static constexpr unsigned long kApple80211Set32 = 0x802069c8UL;
    static constexpr unsigned long kApple80211Set40 = 0x802869c8UL;
    static constexpr unsigned long kApple80211Get32 = 0xc02069c9UL;
    static constexpr unsigned long kApple80211Get40 = 0xc02869c9UL;

    const bool isApple80211Command =
        command == kApple80211Get32 || command == kApple80211Get40 ||
        command == kApple80211Set32 || command == kApple80211Set40;
    const bool isSet = command == kApple80211Set32 ||
                       command == kApple80211Set40;
    const bool is40 = command == kApple80211Get40 ||
                      command == kApple80211Set40;

    if (_owner) {
        _owner->setProperty("AirportRTW89InterfacePerformCommandSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89InterfacePerformCommand",
                            (uint64_t)command, 64);
        if (isApple80211Command) {
            _owner->setProperty(
                "AirportRTW89InterfaceApple80211PerformCommandSeen",
                kOSBooleanTrue);
            _owner->setProperty(
                "AirportRTW89InterfaceApple80211PerformCommandArg1Present",
                arg1 ? kOSBooleanTrue : kOSBooleanFalse);
        }
    }

    if (!isApple80211Command || !_owner || !arg1) {
        const SInt32 result = IO80211Interface::performCommand(
            controller, command, arg0, arg1);
        if (_owner && isApple80211Command)
            _owner->setProperty(
                "AirportRTW89InterfaceApple80211PerformCommandReturn",
                (uint64_t)(uint32_t)result, 32);
        return result;
    }

    struct Apple80211Req32 {
        char req_if_name[IFNAMSIZ];
        SInt32 req_type;
        SInt32 req_val;
        UInt32 req_len;
        UInt32 req_data;
    };
    struct Apple80211Req40 {
        char req_if_name[IFNAMSIZ];
        SInt32 req_type;
        SInt32 req_val;
        UInt32 req_len;
        UInt32 req_pad;
        UInt64 req_data;
    };
    static_assert(sizeof(Apple80211Req32) == 32,
                  "Apple80211 32-byte request envelope size mismatch");
    static_assert(sizeof(Apple80211Req40) == 40,
                  "Apple80211 40-byte request envelope size mismatch");

    SInt32 reqType = -1;
    SInt32 reqVal = -1;
    UInt32 reqLen = 0;
    user_addr_t reqData = 0;
    char ifName[IFNAMSIZ + 1] = {};

    if (is40) {
        const Apple80211Req40 *req =
            static_cast<const Apple80211Req40 *>(arg1);
        reqType = req->req_type;
        reqVal = req->req_val;
        reqLen = req->req_len;
        reqData = (user_addr_t)req->req_data;
        memcpy(ifName, req->req_if_name, IFNAMSIZ);
    } else {
        const Apple80211Req32 *req =
            static_cast<const Apple80211Req32 *>(arg1);
        reqType = req->req_type;
        reqVal = req->req_val;
        reqLen = req->req_len;
        reqData = (user_addr_t)req->req_data;
        memcpy(ifName, req->req_if_name, IFNAMSIZ);
    }
    ifName[IFNAMSIZ] = '\0';

    /* 0.4.13: arm the association epoch at outer SET22 ingress, before the
     * inherited marshaller enters the controller. Tahoe dispatches its fatal
     * disconnected SSID preflight concurrently about one millisecond after
     * this point; arming only in airportSet(SET22) was therefore too late. */
    if (isSet && reqType == APPLE80211_IOC_DISASSOCIATE) {
        _owner->_airportIOUCAssociationCaptureStartMS =
            airportWPA2PreflightMonotonicMS();
        _owner->setProperty("AirportRTW89IOUCAssociationOuterEpochArmed",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89IOUCAssociationOuterEpochStartMS",
                            (uint64_t)_owner->_airportIOUCAssociationCaptureStartMS,
                            64);
    }

    _owner->setProperty("AirportRTW89Apple80211LiveOuterSeen",
                        kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterIsSet",
                        isSet ? kOSBooleanTrue : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterIsGet",
                        isSet ? kOSBooleanFalse : kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterDirectionFixed",
                        kOSBooleanTrue);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterReqType",
                        (uint64_t)(uint32_t)reqType, 32);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterReqVal",
                        (uint64_t)(uint32_t)reqVal, 32);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterReqLen",
                        (uint64_t)reqLen, 32);
    _owner->setProperty("AirportRTW89Apple80211LiveOuterReqData",
                        (uint64_t)reqData, 64);
    if (ifName[0])
        _owner->setProperty("AirportRTW89Apple80211LiveOuterIfName", ifName);

    /* 0.2.134: record the *outer* Apple80211 performCommand stream before
     * IO80211Interface has a chance to translate, reject, or swallow a
     * request.  The controller-side AirportRTW89Apple80211RequestHistory only
     * records requests that successfully reach apple80211Request(), so it
     * cannot identify Tahoe join commands that disappear in the superclass
     * marshaller.
     *
     * Keep metadata only.  In particular, do not snapshot arbitrary request
     * payloads here because an association payload may contain credentials.
     * Each 16-byte ring entry is:
     *   u32 request type
     *   u32 request value
     *   u32 request length
     *   u32 flags: bit0=SET, bit1=40-byte envelope, bit2=req_data present
     */
    struct OuterApple80211HistoryEntry {
        UInt32 requestType;
        UInt32 requestValue;
        UInt32 requestLength;
        UInt32 flags;
    };
    static_assert(sizeof(OuterApple80211HistoryEntry) == 16,
                  "outer Apple80211 history entry size mismatch");
    static OuterApple80211HistoryEntry outerHistory[64] = {};
    static UInt32 outerHistoryIndex = 0;
    static UInt32 outerHistoryCount = 0;

    const UInt32 outerSlot = outerHistoryIndex & 63U;
    OuterApple80211HistoryEntry &outerEntry = outerHistory[outerSlot];
    outerEntry.requestType = (UInt32)reqType;
    outerEntry.requestValue = (UInt32)reqVal;
    outerEntry.requestLength = reqLen;
    outerEntry.flags = (isSet ? 1U : 0U) | (is40 ? 2U : 0U) |
                       (reqData != 0 ? 4U : 0U);
    outerHistoryIndex = (outerSlot + 1U) & 63U;
    if (outerHistoryCount < 64U)
        ++outerHistoryCount;

    _owner->setProperty("AirportRTW89Apple80211OuterHistoryIndex",
                        (uint64_t)outerHistoryIndex, 32);
    _owner->setProperty("AirportRTW89Apple80211OuterHistoryCount",
                        (uint64_t)outerHistoryCount, 32);
    _owner->setProperty("AirportRTW89Apple80211OuterHistoryEntrySize",
                        (uint64_t)sizeof(OuterApple80211HistoryEntry), 32);
    if (OSData *outerHistoryData =
            OSData::withBytes(outerHistory, sizeof(outerHistory))) {
        _owner->setProperty("AirportRTW89Apple80211OuterHistory",
                            outerHistoryData);
        outerHistoryData->release();
    }

    const AirportWPA2PreflightTraceCookie wpa2TraceCookie =
        airportWPA2PreflightTraceBegin(
            _owner, isSet, is40, reqType, reqVal, reqLen, reqData);

    bool outerPowerSetAuthoritative = false;
    bool outerPowerSetRequestedOn = false;
    bool outerPowerSetChanged = false;
    IOReturn outerPowerSetApplyResult = kIOReturnSuccess;

    /* 0.2.175: the 0.2.174 trace proved Tahoe's outer POWER payload is the
     * canonical IO80211Reference structure (version=1, num_radios=4, four equal
     * power_state values), while Apple's superclass later delivers an all-zero
     * inner structure.  Validate and consume the outer payload as the
     * authoritative user-state edge before delegating to the superclass.
     * The hidden inner zero-radio callback remains a successful no-op.
     *
     * Keep the 0.2.174 raw POWER telemetry as evidence/debugging before
     * IO80211Interface::performCommand() marshals it.  Tahoe currently
     * delivers identical zero-radio inner POWER structures for user OFF and
     * ON, so this probe determines whether the direction is still present in
     * the outer request and is being lost by Apple's superclass marshaller.
     *
     * POWER data is non-credential state.  Still keep the capture tightly
     * bounded to request 19 and at most 32 bytes; no other request payload is
     * exposed by this diagnostic. */
    if (isSet && reqType == APPLE80211_IOC_POWER) {
        static UInt32 outerPowerSetCount = 0;
        ++outerPowerSetCount;
        const UInt32 eventSequence = ++_owner->_airportPowerEventSequence;

        _owner->setProperty("AirportRTW89PowerEventSequence",
                            (uint64_t)_owner->_airportPowerEventSequence, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetSeen", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterPowerSetCount",
                            (uint64_t)outerPowerSetCount, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetEventSequence",
                            (uint64_t)eventSequence, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetReqVal",
                            (uint64_t)(UInt32)reqVal, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetReqDataPresent",
                            reqData != 0 ? kOSBooleanTrue : kOSBooleanFalse);

        UInt8 powerSnapshot[32] = {};
        UInt32 powerCopyLength = reqLen;
        if (powerCopyLength > sizeof(powerSnapshot))
            powerCopyLength = sizeof(powerSnapshot);
        const int powerCopyin =
            (reqData != 0 && powerCopyLength != 0)
                ? copyin(reqData, powerSnapshot, powerCopyLength)
                : EINVAL;

        _owner->setProperty("AirportRTW89OuterPowerSetCopyLength",
                            (uint64_t)powerCopyLength, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetCopyinReturn",
                            (uint64_t)(UInt32)powerCopyin, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetTruncated",
                            reqLen > sizeof(powerSnapshot)
                                ? kOSBooleanTrue : kOSBooleanFalse);

        if (powerCopyin == 0) {
            UInt32 nonZeroByteCount = 0;
            UInt32 nonZeroWordMask = 0;
            for (UInt32 i = 0; i < powerCopyLength; ++i) {
                if (powerSnapshot[i] != 0)
                    ++nonZeroByteCount;
            }

            for (UInt32 wordIndex = 0; wordIndex < 8; ++wordIndex) {
                UInt32 word = 0;
                const UInt32 offset = wordIndex * sizeof(UInt32);
                if (powerCopyLength >= offset + sizeof(UInt32)) {
                    memcpy(&word, powerSnapshot + offset, sizeof(word));
                    if (word != 0)
                        nonZeroWordMask |= (1U << wordIndex);
                }

                char property[80] = {};
                snprintf(property, sizeof(property),
                         "AirportRTW89OuterPowerSetWord%u",
                         (unsigned)wordIndex);
                _owner->setProperty(property, (uint64_t)word, 32);
            }

            _owner->setProperty("AirportRTW89OuterPowerSetNonZeroByteCount",
                                (uint64_t)nonZeroByteCount, 32);
            _owner->setProperty("AirportRTW89OuterPowerSetNonZeroWordMask",
                                (uint64_t)nonZeroWordMask, 32);

            if (OSData *powerData =
                    OSData::withBytes(powerSnapshot, powerCopyLength)) {
                _owner->setProperty("AirportRTW89OuterPowerSetPayload",
                                    powerData);
                powerData->release();
            }

            const bool lengthSufficient =
                powerCopyLength >= sizeof(apple80211_power_data);
            bool shapeValid = false;
            bool uniformRadioState = false;
            UInt32 requestedPower = APPLE80211_POWER_OFF;

            if (lengthSufficient) {
                apple80211_power_data outerPower = {};
                memcpy(&outerPower, powerSnapshot, sizeof(outerPower));

                const bool versionValid =
                    outerPower.version == APPLE80211_VERSION;
                const bool radioCountValid =
                    outerPower.num_radios > 0 &&
                    outerPower.num_radios <= APPLE80211_MAX_RADIO;
                const bool firstStateValid = radioCountValid &&
                    (outerPower.power_state[0] == APPLE80211_POWER_OFF ||
                     outerPower.power_state[0] == APPLE80211_POWER_ON);

                uniformRadioState = firstStateValid;
                if (firstStateValid) {
                    requestedPower = outerPower.power_state[0];
                    for (UInt32 i = 1; i < outerPower.num_radios; ++i) {
                        if (outerPower.power_state[i] != requestedPower) {
                            uniformRadioState = false;
                            break;
                        }
                    }
                }

                shapeValid = versionValid && radioCountValid &&
                             firstStateValid && uniformRadioState;

                _owner->setProperty("AirportRTW89OuterPowerSetVersion",
                                    (uint64_t)outerPower.version, 32);
                _owner->setProperty("AirportRTW89OuterPowerSetRadios",
                                    (uint64_t)outerPower.num_radios, 32);
                _owner->setProperty("AirportRTW89OuterPowerSetUniformRadioState",
                                    uniformRadioState ? kOSBooleanTrue
                                                      : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89OuterPowerSetRequested",
                                    (uint64_t)requestedPower, 32);
            }

            _owner->setProperty("AirportRTW89OuterPowerSetLengthSufficient",
                                lengthSufficient ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89OuterPowerSetShapeValid",
                                shapeValid ? kOSBooleanTrue
                                           : kOSBooleanFalse);

            if (shapeValid) {
                outerPowerSetAuthoritative = true;
                outerPowerSetRequestedOn =
                    requestedPower == APPLE80211_POWER_ON;
                const bool logicalBefore = _owner->_airportLogicalPowerOn;

                outerPowerSetApplyResult = _owner->applyAirportUserPowerState(
                    outerPowerSetRequestedOn,
                    RTW88PCIDevice::kAirportLogicalPowerOuterApple80211);
                outerPowerSetChanged =
                    logicalBefore != _owner->_airportLogicalPowerOn;

                _owner->setProperty("AirportRTW89OuterPowerSetAuthoritative",
                                    kOSBooleanTrue);
                _owner->setProperty("AirportRTW89OuterPowerSetLogicalBefore",
                                    logicalBefore ? kOSBooleanTrue
                                                  : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89OuterPowerSetLogicalAfter",
                                    _owner->_airportLogicalPowerOn
                                        ? kOSBooleanTrue : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89OuterPowerSetChanged",
                                    outerPowerSetChanged ? kOSBooleanTrue
                                                         : kOSBooleanFalse);
                _owner->setProperty("AirportRTW89OuterPowerSetApplyReturn",
                                    (uint64_t)(uint32_t)outerPowerSetApplyResult,
                                    32);
            } else {
                _owner->setProperty("AirportRTW89OuterPowerSetAuthoritative",
                                    kOSBooleanFalse);
            }
        }
    }

    /* 0.2.173 diagnostic: request 255 (BTCOEX_PROFILE) is the only outer
     * SET that appears repeatedly in both the isolated Tahoe OFF and ON
     * bursts.  The 0.2.172 metadata ring showed identical request/value/len
     * metadata, so compare its payload without publishing the payload itself.
     *
     * BTCOEX_PROFILE is not an association/key request, but keep the privacy
     * boundary conservative anyway: copy at most 128 bytes, publish only a
     * 64-bit FNV-1a hash plus length/sequence, and never expose raw bytes. */
    if (isSet && reqType == APPLE80211_IOC_BTCOEX_PROFILE &&
        reqData != 0 && reqLen != 0) {
        static UInt32 btcoexProfileSetCount = 0;
        static UInt32 btcoexProfileHashIndex = 0;
        static UInt32 btcoexProfileHashCount = 0;
        struct BTCoexProfileHashEntry {
            UInt32 sequence;
            UInt32 length;
            UInt64 hash;
        };
        static_assert(sizeof(BTCoexProfileHashEntry) == 16,
                      "BTCOEX profile hash entry size mismatch");
        static BTCoexProfileHashEntry btcoexProfileHashes[16] = {};

        ++btcoexProfileSetCount;
        _owner->setProperty("AirportRTW89BTCoexProfileOuterSetSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89BTCoexProfileOuterSetCount",
                            (uint64_t)btcoexProfileSetCount, 32);
        _owner->setProperty("AirportRTW89BTCoexProfileOuterLastLength",
                            (uint64_t)reqLen, 32);

        UInt8 snapshot[128] = {};
        int copyResult = E2BIG;
        if (reqLen <= sizeof(snapshot))
            copyResult = copyin(reqData, snapshot, reqLen);
        _owner->setProperty("AirportRTW89BTCoexProfileOuterCopyinReturn",
                            (uint64_t)(uint32_t)copyResult, 32);

        if (copyResult == 0) {
            UInt64 hash = 14695981039346656037ULL;
            for (UInt32 i = 0; i < reqLen; ++i) {
                hash ^= (UInt64)snapshot[i];
                hash *= 1099511628211ULL;
            }

            const UInt32 slot = btcoexProfileHashIndex & 15U;
            btcoexProfileHashes[slot].sequence = btcoexProfileSetCount;
            btcoexProfileHashes[slot].length = reqLen;
            btcoexProfileHashes[slot].hash = hash;
            btcoexProfileHashIndex = (slot + 1U) & 15U;
            if (btcoexProfileHashCount < 16U)
                ++btcoexProfileHashCount;

            _owner->setProperty("AirportRTW89BTCoexProfileOuterLastHash",
                                (uint64_t)hash, 64);
            _owner->setProperty("AirportRTW89BTCoexProfileOuterHashIndex",
                                (uint64_t)btcoexProfileHashIndex, 32);
            _owner->setProperty("AirportRTW89BTCoexProfileOuterHashCount",
                                (uint64_t)btcoexProfileHashCount, 32);
            _owner->setProperty("AirportRTW89BTCoexProfileOuterHashEntrySize",
                                (uint64_t)sizeof(BTCoexProfileHashEntry), 32);
            if (OSData *hashData = OSData::withBytes(
                    btcoexProfileHashes, sizeof(btcoexProfileHashes))) {
                _owner->setProperty("AirportRTW89BTCoexProfileOuterHashHistory",
                                    hashData);
                hashData->release();
            }
        }
    }

    if (isSet) {
        /* 0.2.165: dedicated security-boundary counters survive the 64-entry
         * trace ring churn.  Metadata only; never snapshot key/credential
         * payloads here. */
        static UInt32 securitySet2Count = 0;
        static UInt32 securitySet3Count = 0;
        static UInt32 securitySet20Count = 0;
        static UInt32 securitySet46Count = 0;
        UInt32 *securityCounter = nullptr;
        const char *securitySeen = nullptr;
        const char *securityCount = nullptr;
        switch ((UInt32)reqType) {
        case APPLE80211_IOC_AUTH_TYPE:
            securityCounter = &securitySet2Count;
            securitySeen = "AirportRTW89WPA2OuterSetAUTH_TYPESeen";
            securityCount = "AirportRTW89WPA2OuterSetAUTH_TYPECount";
            break;
        case APPLE80211_IOC_CIPHER_KEY:
            securityCounter = &securitySet3Count;
            securitySeen = "AirportRTW89WPA2OuterSetCIPHER_KEYSeen";
            securityCount = "AirportRTW89WPA2OuterSetCIPHER_KEYCount";
            break;
        case APPLE80211_IOC_ASSOCIATE:
            securityCounter = &securitySet20Count;
            securitySeen = "AirportRTW89WPA2OuterSetASSOCIATESeen";
            securityCount = "AirportRTW89WPA2OuterSetASSOCIATECount";
            break;
        case APPLE80211_IOC_RSN_IE:
            securityCounter = &securitySet46Count;
            securitySeen = "AirportRTW89WPA2OuterSetRSN_IESeen";
            securityCount = "AirportRTW89WPA2OuterSetRSN_IECount";
            break;
        default:
            break;
        }
        if (securityCounter) {
            ++(*securityCounter);
            _owner->setProperty(securitySeen, kOSBooleanTrue);
            _owner->setProperty(securityCount, (uint64_t)*securityCounter, 32);
            _owner->setProperty("AirportRTW89WPA2OuterLastSecuritySetRequest",
                                (uint64_t)(UInt32)reqType, 32);
        }

        _owner->setProperty("AirportRTW89Apple80211OuterLastSetRequest",
                            (uint64_t)(UInt32)reqType, 32);
        _owner->setProperty("AirportRTW89Apple80211OuterLastSetValue",
                            (uint64_t)(UInt32)reqVal, 32);
        _owner->setProperty("AirportRTW89Apple80211OuterLastSetLength",
                            (uint64_t)reqLen, 32);
    } else {
        _owner->setProperty("AirportRTW89Apple80211OuterLastGetRequest",
                            (uint64_t)(UInt32)reqType, 32);
        _owner->setProperty("AirportRTW89Apple80211OuterLastGetValue",
                            (uint64_t)(UInt32)reqVal, 32);
        _owner->setProperty("AirportRTW89Apple80211OuterLastGetLength",
                            (uint64_t)reqLen, 32);

    }

    /* 0.2.177: preserve the original outer WPA2 security payload across
     * IO80211Interface::performCommand().  POWER debugging proved Tahoe's
     * superclass marshaller can erase state before the inner controller
     * callback.  Do not expose credential/key bytes: copy them only into
     * kernel-private owner caches, validate their public lengths, consume them
     * synchronously in airportSet(), and scrub any unconsumed cache after the
     * superclass returns. */
    bool outerSecurityCachedThisCall = false;
    UInt32 outerSecurityCacheSequence = 0;
    if (isSet && reqData != 0) {
        int securityCopyin = EINVAL;
        bool securityShapeValid = false;
        ++_owner->_airportOuterSecuritySequence;
        outerSecurityCacheSequence = _owner->_airportOuterSecuritySequence;

        if (reqType == APPLE80211_IOC_AUTH_TYPE &&
            reqLen >= sizeof(apple80211_authtype_data)) {
            apple80211_authtype_data snapshot = {};
            securityCopyin = copyin(reqData, &snapshot, sizeof(snapshot));
            securityShapeValid = securityCopyin == 0;
            if (securityShapeValid) {
                if (_owner->_airportLock) IOLockLock(_owner->_airportLock);
                _owner->_airportOuterAuthCache = snapshot;
                _owner->_airportOuterAuthCacheValid = true;
                _owner->_airportOuterAuthCacheSequence = outerSecurityCacheSequence;
                if (_owner->_airportLock) IOLockUnlock(_owner->_airportLock);
                outerSecurityCachedThisCall = true;
                _owner->setProperty("AirportRTW89WPA2OuterCachedAuthLower",
                                    (uint64_t)snapshot.authtype_lower, 32);
                _owner->setProperty("AirportRTW89WPA2OuterCachedAuthUpper",
                                    (uint64_t)snapshot.authtype_upper, 32);
            }
        } else if (reqType == APPLE80211_IOC_ASSOCIATE &&
                   reqLen >= sizeof(apple80211_assoc_data)) {
            apple80211_assoc_data snapshot = {};
            securityCopyin = copyin(reqData, &snapshot, sizeof(snapshot));
            securityShapeValid = securityCopyin == 0 &&
                snapshot.ad_ssid_len > 0 && snapshot.ad_ssid_len <= 32 &&
                snapshot.ad_key.key_len <= APPLE80211_KEY_BUFF_LEN &&
                (snapshot.ad_rsn_ie[0] == 0 ||
                 (snapshot.ad_rsn_ie[0] == 48 &&
                  (UInt32)snapshot.ad_rsn_ie[1] + 2U <=
                      APPLE80211_MAX_RSN_IE_LEN));
            if (securityShapeValid) {
                if (_owner->_airportLock) IOLockLock(_owner->_airportLock);
                bzero(&_owner->_airportOuterAssocCache,
                      sizeof(_owner->_airportOuterAssocCache));
                _owner->_airportOuterAssocCache = snapshot;
                _owner->_airportOuterAssocCacheValid = true;
                _owner->_airportOuterAssocCacheSequence = outerSecurityCacheSequence;
                if (_owner->_airportLock) IOLockUnlock(_owner->_airportLock);
                outerSecurityCachedThisCall = true;
                _owner->setProperty("AirportRTW89WPA2OuterCachedAssociateSSIDLength",
                                    (uint64_t)snapshot.ad_ssid_len, 32);
                _owner->setProperty("AirportRTW89WPA2OuterCachedAssociateAuthUpper",
                                    (uint64_t)snapshot.ad_auth_upper, 32);
                _owner->setProperty("AirportRTW89WPA2OuterCachedAssociateKeyLength",
                                    (uint64_t)snapshot.ad_key.key_len, 32);
                _owner->setProperty("AirportRTW89WPA2OuterCachedAssociateKeyCipher",
                                    (uint64_t)snapshot.ad_key.key_cipher_type, 32);
                const UInt32 outerAssocRSNLength =
                    snapshot.ad_rsn_ie[0] == 48
                        ? (UInt32)snapshot.ad_rsn_ie[1] + 2U : 0U;
                _owner->setProperty("AirportRTW89WPA2OuterCachedAssociateRSNLength",
                                    (uint64_t)outerAssocRSNLength, 16);
            }
        } else if (reqType == APPLE80211_IOC_RSN_IE &&
                   reqLen >= sizeof(apple80211_rsn_ie_data)) {
            apple80211_rsn_ie_data snapshot = {};
            securityCopyin = copyin(reqData, &snapshot, sizeof(snapshot));
            securityShapeValid = securityCopyin == 0 &&
                snapshot.len >= 2 && snapshot.len <= sizeof(snapshot.ie) &&
                snapshot.ie[0] == 48 &&
                (UInt32)snapshot.ie[1] + 2U <= snapshot.len;
            if (securityShapeValid) {
                if (_owner->_airportLock) IOLockLock(_owner->_airportLock);
                bzero(&_owner->_airportOuterRSNIECache,
                      sizeof(_owner->_airportOuterRSNIECache));
                _owner->_airportOuterRSNIECache = snapshot;
                _owner->_airportOuterRSNIECacheValid = true;
                _owner->_airportOuterRSNIECacheSequence = outerSecurityCacheSequence;
                if (_owner->_airportLock) IOLockUnlock(_owner->_airportLock);
                outerSecurityCachedThisCall = true;
                _owner->setProperty("AirportRTW89WPA2OuterCachedRSNIELength",
                                    (uint64_t)snapshot.len, 16);
            }
        } else if (reqType == APPLE80211_IOC_CIPHER_KEY &&
                   reqLen >= sizeof(apple80211_key)) {
            apple80211_key snapshot = {};
            securityCopyin = copyin(reqData, &snapshot, sizeof(snapshot));
            securityShapeValid = securityCopyin == 0 &&
                snapshot.key_len <= APPLE80211_KEY_BUFF_LEN &&
                snapshot.key_rsc_len <= APPLE80211_RSC_LEN;
            if (securityShapeValid) {
                if (_owner->_airportLock) IOLockLock(_owner->_airportLock);
                bzero(&_owner->_airportOuterCipherKeyCache,
                      sizeof(_owner->_airportOuterCipherKeyCache));
                _owner->_airportOuterCipherKeyCache = snapshot;
                _owner->_airportOuterCipherKeyCacheValid = true;
                _owner->_airportOuterCipherKeyCacheSequence = outerSecurityCacheSequence;
                if (_owner->_airportLock) IOLockUnlock(_owner->_airportLock);
                outerSecurityCachedThisCall = true;
                _owner->setProperty("AirportRTW89WPA2OuterCachedCipherKeyLength",
                                    (uint64_t)snapshot.key_len, 32);
                _owner->setProperty("AirportRTW89WPA2OuterCachedCipherKeyType",
                                    (uint64_t)snapshot.key_cipher_type, 32);
                _owner->setProperty("AirportRTW89WPA2OuterCachedCipherKeyFlags",
                                    (uint64_t)snapshot.key_flags, 16);
                _owner->setProperty("AirportRTW89WPA2OuterCachedCipherKeyIndex",
                                    (uint64_t)snapshot.key_index, 16);
            }
        }

        if (reqType == APPLE80211_IOC_AUTH_TYPE ||
            reqType == APPLE80211_IOC_ASSOCIATE ||
            reqType == APPLE80211_IOC_RSN_IE ||
            reqType == APPLE80211_IOC_CIPHER_KEY) {
            _owner->setProperty("AirportRTW89WPA2OuterSecurityCacheRequest",
                                (uint64_t)(UInt32)reqType, 32);
            _owner->setProperty("AirportRTW89WPA2OuterSecurityCacheSequence",
                                (uint64_t)outerSecurityCacheSequence, 32);
            _owner->setProperty("AirportRTW89WPA2OuterSecurityCopyinReturn",
                                (uint64_t)(uint32_t)securityCopyin, 32);
            _owner->setProperty("AirportRTW89WPA2OuterSecurityShapeValid",
                                securityShapeValid ? kOSBooleanTrue
                                                   : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89WPA2OuterSecurityCached",
                                outerSecurityCachedThisCall ? kOSBooleanTrue
                                                            : kOSBooleanFalse);
        }
    }

    /* 0.2.110: keep a bounded diagnostic snapshot for Tahoe request 363,
     * but retain GET and SET independently.  0.2.108 used one last-value slot;
     * the boot trace showed that slot ending on GET while
     * LastUnsupportedSetRequest independently proved SET 363 also occurred.
     * Its ABI is still unknown, so do not interpret or modify either payload. */
    if (reqType == 363 && reqData != 0 && reqLen != 0) {
        UInt8 snapshot[64] = {};
        size_t snapshotLength = reqLen;
        if (snapshotLength > sizeof(snapshot))
            snapshotLength = sizeof(snapshot);
        const int snapshotResult = copyin(reqData, snapshot, snapshotLength);
        _owner->setProperty("AirportRTW89Apple80211Request363Seen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89Apple80211Request363IsSet",
                            isSet ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Apple80211Request363ReqVal",
                            (uint64_t)(uint32_t)reqVal, 32);
        _owner->setProperty("AirportRTW89Apple80211Request363ReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89Apple80211Request363CopyinReturn",
                            (uint64_t)(uint32_t)snapshotResult, 32);

        const char *seenProperty = isSet
            ? "AirportRTW89Apple80211Request363SetSeen"
            : "AirportRTW89Apple80211Request363GetSeen";
        const char *reqValProperty = isSet
            ? "AirportRTW89Apple80211Request363SetReqVal"
            : "AirportRTW89Apple80211Request363GetReqVal";
        const char *reqLenProperty = isSet
            ? "AirportRTW89Apple80211Request363SetReqLen"
            : "AirportRTW89Apple80211Request363GetReqLen";
        const char *copyinProperty = isSet
            ? "AirportRTW89Apple80211Request363SetCopyinReturn"
            : "AirportRTW89Apple80211Request363GetCopyinReturn";
        const char *payloadProperty = isSet
            ? "AirportRTW89Apple80211Request363SetPayload"
            : "AirportRTW89Apple80211Request363GetPayload";

        _owner->setProperty(seenProperty, kOSBooleanTrue);
        _owner->setProperty(reqValProperty, (uint64_t)(uint32_t)reqVal, 32);
        _owner->setProperty(reqLenProperty, (uint64_t)reqLen, 32);
        _owner->setProperty(copyinProperty,
                            (uint64_t)(uint32_t)snapshotResult, 32);
        if (snapshotResult == 0) {
            OSData *snapshotData = OSData::withBytes(snapshot, snapshotLength);
            if (snapshotData) {
                _owner->setProperty("AirportRTW89Apple80211Request363Payload",
                                    snapshotData);
                _owner->setProperty(payloadProperty, snapshotData);
                snapshotData->release();
            }
        }
    }

    /* Direct POWER marshalling remains GET-only.  0.2.175 consumes the
     * validated outer SET state without bypassing Apple's SET sequencing:
     * the superclass still owns the ioctl transaction and hidden inner
     * callback.  This avoids the 0.2.108 recursion failure while preserving
     * the direction bit that Tahoe's marshaller drops from the inner buffer. */
    const bool outerPowerGetSeen =
        !isSet && reqType == APPLE80211_IOC_POWER;
    const bool directPowerGetBridge =
        outerPowerGetSeen && reqData != 0 &&
        reqLen >= sizeof(apple80211_power_data);

    if (outerPowerGetSeen) {
        static UInt32 outerPowerGetCount = 0;
        ++outerPowerGetCount;
        _owner->setProperty("AirportRTW89OuterPowerGetSeen", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterPowerGetCount",
                            (uint64_t)outerPowerGetCount, 32);
        _owner->setProperty("AirportRTW89OuterPowerGetReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89OuterPowerGetReqDataPresent",
                            reqData != 0 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterPowerGetNativeStructSize",
                            (uint64_t)sizeof(apple80211_power_data), 32);
        _owner->setProperty("AirportRTW89OuterPowerGetDirectEligible",
                            directPowerGetBridge ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterPowerGetLogicalOn",
                            _owner->_airportLogicalPowerOn
                                ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.3.34: raw POWER-GET ABI audit.  Tahoe reports this request as
         * successful but CoreWiFi still classifies en2 as OFF.  Record the
         * caller's requested envelope size and our compile-time layout before
         * changing any marshalling behavior. */
        _owner->setProperty("AirportRTW89PowerABIReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89PowerABIStructSize",
                            (uint64_t)sizeof(apple80211_power_data), 32);
        _owner->setProperty("AirportRTW89PowerABIVersionOffset",
                            (uint64_t)offsetof(apple80211_power_data, version), 32);
        _owner->setProperty("AirportRTW89PowerABINumRadiosOffset",
                            (uint64_t)offsetof(apple80211_power_data, num_radios), 32);
        _owner->setProperty("AirportRTW89PowerABIState0Offset",
                            (uint64_t)offsetof(apple80211_power_data, power_state[0]), 32);
        _owner->setProperty("AirportRTW89PowerABIReqLenEqualsStruct",
                            reqLen == sizeof(apple80211_power_data)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PowerABIReqLenLargerThanStruct",
                            reqLen > sizeof(apple80211_power_data)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PowerABIReqLenSmallerThanStruct",
                            reqLen < sizeof(apple80211_power_data)
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PowerABIReqExtraBytes",
                            (uint64_t)(reqLen > sizeof(apple80211_power_data)
                                ? reqLen - sizeof(apple80211_power_data) : 0), 32);
    }

    if (isSet && reqType == APPLE80211_IOC_POWER) {
        _owner->setProperty(
            "AirportRTW89Apple80211LivePowerSetDelegatedToSuper",
            kOSBooleanTrue);
    }

    if (directPowerGetBridge) {
        apple80211_power_data powerData = {};
        const size_t powerLength = sizeof(powerData);
        int powerCopyin = 0;
        /* GET starts from a zeroed kernel buffer; there is no userspace
         * payload to import on the GET-only direct path. */

        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeLivePath",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeIsSet",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Apple80211DirectPowerGetOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeUserPower",
                            poweredOnByUser() ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeSystemEnable",
                            enabledBySystem() ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeCopyinReturn",
                            (uint64_t)(uint32_t)powerCopyin, 32);

        SInt32 result = powerCopyin;
        int powerCopyout = 0;
        if (powerCopyin == 0) {
            result = _owner->apple80211Request(
                APPLE80211_IOC_POWER, 1, this, &powerData);

            const UInt32 *words =
                reinterpret_cast<const UInt32 *>(&powerData);

            /* 0.3.34: preserve the exact 24 output bytes that will be copied
             * to CoreWiFi.  OSData gives us the byte representation without
             * relying on our interpretation of the structure fields. */
            OSData *rawPowerData = OSData::withBytes(&powerData, powerLength);
            if (rawPowerData) {
                _owner->setProperty("AirportRTW89PowerABIRawOutput", rawPowerData);
                rawPowerData->release();
            }
            _owner->setProperty("AirportRTW89PowerABIOutputVersion",
                                (uint64_t)powerData.version, 32);
            _owner->setProperty("AirportRTW89PowerABIOutputNumRadios",
                                (uint64_t)powerData.num_radios, 32);
            for (UInt32 i = 0; i < APPLE80211_MAX_RADIO; ++i) {
                char stateProperty[72] = {};
                snprintf(stateProperty, sizeof(stateProperty),
                         "AirportRTW89PowerABIOutputState%u", (unsigned)i);
                _owner->setProperty(stateProperty,
                                    (uint64_t)powerData.power_state[i], 32);
            }
            for (UInt32 i = 0; i < 6; ++i) {
                char property[80] = {};
                snprintf(property, sizeof(property),
                         "AirportRTW89Apple80211DirectPowerWord%u",
                         (unsigned)i);
                _owner->setProperty(property, (uint64_t)words[i], 32);
            }

            if (result == kIOReturnSuccess)
                powerCopyout = copyout(&powerData, reqData, powerLength);
            _owner->setProperty(
                "AirportRTW89Apple80211DirectPowerBridgeCopyoutReturn",
                (uint64_t)(uint32_t)powerCopyout, 32);
            _owner->setProperty("AirportRTW89OuterPowerGetCopyoutLength",
                                (uint64_t)powerLength, 32);
            _owner->setProperty("AirportRTW89PowerABICopyoutLength",
                                (uint64_t)powerLength, 32);
            _owner->setProperty("AirportRTW89PowerABICopyoutCoversReqLen",
                                powerLength >= reqLen
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89OuterPowerGetReturnedLogicalOn",
                                powerData.power_state[0] == APPLE80211_POWER_ON
                                    ? kOSBooleanTrue : kOSBooleanFalse);
            if (result == kIOReturnSuccess && powerCopyout != 0)
                result = powerCopyout;

            /* 0.2.188: 0.2.110 already proved that a successful canonical
             * GET copyout can coexist with a stale CoreWLAN power cache.
             * Repair propagation, not payload shape: arm exactly one deferred
             * POWER_CHANGED after the first successful ON GET.  The timer edge
             * is outside this GET stack and therefore cannot recurse here. */
            static bool powerGetOnRepairArmedOnce = false;
            if (result == kIOReturnSuccess && powerCopyout == 0 &&
                powerData.power_state[0] == APPLE80211_POWER_ON &&
                !powerGetOnRepairArmedOnce) {
                powerGetOnRepairArmedOnce = true;
                _owner->_airportPostSuperPowerOnNotifyPending = true;
                _owner->setProperty("AirportRTW89PowerGetOnRepairNotifyArmed",
                                    kOSBooleanTrue);
                _owner->setProperty("AirportRTW89PostSuperPowerOnNotifyPending",
                                    kOSBooleanTrue);
            }
        }

        _owner->setProperty("AirportRTW89Apple80211DirectPowerBridgeReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, result,
                                             kWPA2TraceDirectBridge);
    }

    /* 0.2.130: direct GET/SET COUNTRY_CODE bridge on the genuine Airport
     * interface.  GET-51 already required explicit copyout on Tahoe.  The
     * 0.2.129 registry trace also showed no controller-side COUNTRY_CODE SET,
     * so forward the fixed-size SET payload explicitly as well.  Unlike POWER
     * SET, this handler does not call setPoweredOnByUser()/setEnabledBySystem()
     * and therefore does not enter the power-command recursion that made a
     * direct POWER SET bridge unsafe. */
    const bool directCountryBridge =
        reqType == APPLE80211_IOC_COUNTRY_CODE && reqData != 0 &&
        reqLen >= sizeof(apple80211_country_code_data);

    if (directCountryBridge) {
        static UInt32 directCountryGetCount = 0;
        static UInt32 directCountrySetCount = 0;
        apple80211_country_code_data countryData = {};

        int countryCopyin = 0;
        if (isSet)
            countryCopyin = copyin(reqData, &countryData, sizeof(countryData));

        if (isSet)
            ++directCountrySetCount;
        else
            ++directCountryGetCount;

        _owner->setProperty("AirportRTW89DirectCountry51BridgeSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeIsSet",
                            isSet ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeGetCount",
                            (uint64_t)directCountryGetCount, 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeSetCount",
                            (uint64_t)directCountrySetCount, 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeCopyinReturn",
                            (uint64_t)(uint32_t)countryCopyin, 32);

        SInt32 result = countryCopyin;
        SInt32 innerResult = countryCopyin;
        int countryCopyout = 0;
        if (countryCopyin == 0) {
            innerResult = _owner->apple80211Request(
                APPLE80211_IOC_COUNTRY_CODE, isSet ? 0 : 1,
                this, &countryData);
            result = innerResult;

            if (!isSet && result == kIOReturnSuccess) {
                countryCopyout =
                    copyout(&countryData, reqData, sizeof(countryData));
                if (countryCopyout != 0)
                    result = countryCopyout;
            }
        }

        _owner->setProperty("AirportRTW89DirectCountry51BridgeInnerReturn",
                            (uint64_t)(uint32_t)innerResult, 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeCopyoutReturn",
                            (uint64_t)(uint32_t)countryCopyout, 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeVersion",
                            (uint64_t)countryData.version, 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeCC0",
                            (uint64_t)countryData.cc[0], 32);
        _owner->setProperty("AirportRTW89DirectCountry51BridgeCC1",
                            (uint64_t)countryData.cc[1], 32);

        /* Preserve the 0.2.129 GET-only property names so the existing test
         * commands remain useful while the new symmetric bridge is evaluated. */
        if (!isSet) {
            _owner->setProperty("AirportRTW89DirectGet51BridgeSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89DirectGet51BridgeCount",
                                (uint64_t)directCountryGetCount, 32);
            _owner->setProperty("AirportRTW89DirectGet51BridgeReqLen",
                                (uint64_t)reqLen, 32);
            _owner->setProperty("AirportRTW89DirectGet51BridgeInnerReturn",
                                (uint64_t)(uint32_t)innerResult, 32);
            _owner->setProperty("AirportRTW89DirectGet51BridgeCopyoutReturn",
                                (uint64_t)(uint32_t)countryCopyout, 32);
            _owner->setProperty("AirportRTW89DirectGet51BridgeVersion",
                                (uint64_t)countryData.version, 32);
            _owner->setProperty("AirportRTW89DirectGet51BridgeCC0",
                                (uint64_t)countryData.cc[0], 32);
            _owner->setProperty("AirportRTW89DirectGet51BridgeCC1",
                                (uint64_t)countryData.cc[1], 32);
        } else {
            _owner->setProperty("AirportRTW89DirectSet51BridgeSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89DirectSet51BridgeCount",
                                (uint64_t)directCountrySetCount, 32);
            _owner->setProperty("AirportRTW89DirectSet51BridgeCopyinReturn",
                                (uint64_t)(uint32_t)countryCopyin, 32);
            _owner->setProperty("AirportRTW89DirectSet51BridgeInnerReturn",
                                (uint64_t)(uint32_t)innerResult, 32);
        }

        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, result,
                                             kWPA2TraceDirectBridge);
    }

    /* 0.2.184: dedicated SET-22 DISASSOCIATE bridge on the genuine Airport
     * interface.  Tahoe performs this lifecycle operation immediately before
     * a user join.  On 0.2.182 the restored IO80211Interface marshaller
     * returned -3900 while the backend was already idle, causing airportd to
     * abort the WPA2 join before APPLE80211_IOC_ASSOCIATE/SET20 was emitted.
     *
     * DISASSOCIATE has no userspace payload and cmdDisconnect() is explicitly
     * idempotent, so handle request 22 directly and return the backend result.
     * This is deliberately request-specific: POWER SET and all unrelated SET
     * requests retain their existing superclass ownership. */
    const bool directDisassociate22Bridge =
        isSet && reqType == APPLE80211_IOC_DISASSOCIATE;

    if (directDisassociate22Bridge) {
        static UInt32 directDisassociate22Count = 0;
        ++directDisassociate22Count;

        const bool alreadyIdle = _owner->_ieee80211 &&
                                 _owner->_ieee80211->isIdle();
        _owner->setProperty("AirportRTW89OuterDISASSOCIATESeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATECount",
                            (uint64_t)directDisassociate22Count, 32);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEAlreadyIdle",
                            alreadyIdle ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.2.214: WPA2-only focus. 0.2.208's association-scoped GET11
         * ownership probe is now disabled in the functional path. The direct
         * GET11 bridge remains authoritative, but SET22 no longer arms any
         * scan/import experiment during the native join window. */
        if (_owner->_airportLock) {
            IOLockLock(_owner->_airportLock);
            _owner->_airportGet11ControllerFirstResultJoinArmed = false;
            _owner->_airportGet11ControllerIoctlGetProbeActive = false;
            _owner->_airportGet11ControllerIoctlGetProbeThread = THREAD_NULL;
            IOLockUnlock(_owner->_airportLock);
        }
        _owner->setProperty(
            "AirportRTW89Get11ControllerFirstResultJoinArmed",
            kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89Get11ControllerFirstResultDisabledForWPA2Focus",
            kOSBooleanTrue);

        /* 0.2.245: now that the controller dispatcher explicitly permits the
         * one payload-less IO80211Reference lifecycle request, route SET22 through
         * the same apple80211Request(SIOCSA80211, request) ingress that a real
         * IO80211Interface marshaller uses.  This keeps DISASSOCIATE and the
         * eventual ASSOCIATE/20 on one controller contract instead of mixing a
         * direct backend shortcut with controller dispatch. */
        const SInt32 result = _owner->apple80211Request(
            (unsigned int)SIOCSA80211, APPLE80211_IOC_DISASSOCIATE,
            this, nullptr);

        _owner->setProperty(
            "AirportRTW89OuterDISASSOCIATEDirectBackend", kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89OuterDISASSOCIATEPayloadDispatcherBypassed",
            kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89OuterDISASSOCIATEIO80211ReferenceControllerDispatch",
            kOSBooleanTrue);

        const bool idleAfter = _owner->_ieee80211 &&
                               _owner->_ieee80211->isIdle();
        const bool normalizedSuccess =
            result == kIOReturnSuccess && (alreadyIdle || idleAfter);

        _owner->setProperty("AirportRTW89OuterDISASSOCIATEBackendReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATEIdleAfter",
                            idleAfter ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterDISASSOCIATENormalizedSuccess",
                            normalizedSuccess ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, result,
                                             kWPA2TraceDirectBridge);
    }

    /* 0.2.133: direct SET-20 ASSOCIATE bridge on the genuine Airport
     * interface.  The 0.2.132 boot trace proved that a user-initiated join
     * never reached RTW88PCIDevice::airportSet(APPLE80211_IOC_ASSOCIATE):
     * none of the controller-side Apple80211Associate/Connect diagnostics
     * appeared even though the Wi-Fi UI issued a join and later reported a
     * generic failure.  This is the same marshalling boundary that previously
     * swallowed GET 11 and GET 27 results on Tahoe.
     *
     * ASSOCIATE is a one-shot SET that does not call back into
     * IO80211Interface power setters, so it does not carry the re-entrancy
     * hazard of the old direct POWER SET experiment.  Copy only the public
     * apple80211_assoc_data prefix from userspace, validate its basic shape,
     * then invoke the already-existing controller SET-20 implementation.
     * Unknown Tahoe-private bytes beyond the public structure are left alone. */
    const bool directAssociate20Bridge =
        isSet && reqType == APPLE80211_IOC_ASSOCIATE;

    if (directAssociate20Bridge) {
        static UInt32 directAssociate20Count = 0;
        ++directAssociate20Count;

        apple80211_assoc_data assocData = {};
        const size_t assocLength = sizeof(assocData);
        const bool payloadPresent = reqData != 0;
        const bool lengthSufficient = reqLen >= assocLength;
        int assocCopyin = 0;
        SInt32 result = kIOReturnBadArgument;
        SInt32 innerResult = kIOReturnBadArgument;

        _owner->setProperty("AirportRTW89DirectAssociate20BridgeSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgeCount",
                            (uint64_t)directAssociate20Count, 32);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgeReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgeStructSize",
                            (uint64_t)assocLength, 32);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgePayloadPresent",
                            payloadPresent ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgeLengthSufficient",
                            lengthSufficient ? kOSBooleanTrue : kOSBooleanFalse);

        if (payloadPresent && lengthSufficient) {
            assocCopyin = copyin(reqData, &assocData, assocLength);
            if (assocCopyin == 0) {
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeVersion",
                                    (uint64_t)assocData.version, 32);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeSSIDLength",
                                    (uint64_t)assocData.ad_ssid_len, 32);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeAuthLower",
                                    (uint64_t)assocData.ad_auth_lower, 16);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeAuthUpper",
                                    (uint64_t)assocData.ad_auth_upper, 16);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeKeyLength",
                                    (uint64_t)assocData.ad_key.key_len, 32);
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeKeyCipherType",
                                    (uint64_t)assocData.ad_key.key_cipher_type, 32);

                static const UInt8 zeroBSSID[6] = {};
                const bool bssidPresent =
                    memcmp(assocData.ad_bssid.octet, zeroBSSID,
                           sizeof(zeroBSSID)) != 0;
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeBSSIDPresent",
                                    bssidPresent ? kOSBooleanTrue
                                                 : kOSBooleanFalse);

                /* Refuse obviously incompatible payload layouts rather than
                 * handing arbitrary Tahoe-private bytes to the join path. */
                const bool shapeValid =
                    assocData.version == APPLE80211_VERSION &&
                    assocData.ad_ssid_len > 0 &&
                    assocData.ad_ssid_len <= APPLE80211_MAX_SSID_LEN &&
                    assocData.ad_key.key_len <= APPLE80211_KEY_BUFF_LEN;
                _owner->setProperty("AirportRTW89DirectAssociate20BridgeShapeValid",
                                    shapeValid ? kOSBooleanTrue
                                               : kOSBooleanFalse);

                if (shapeValid) {
                    innerResult = _owner->apple80211Request(
                        APPLE80211_IOC_ASSOCIATE, 0, this, &assocData);
                    result = innerResult;
                }
            } else {
                result = assocCopyin;
                innerResult = assocCopyin;
            }
        }

        _owner->setProperty("AirportRTW89DirectAssociate20BridgeCopyinReturn",
                            (uint64_t)(uint32_t)assocCopyin, 32);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgeInnerReturn",
                            (uint64_t)(uint32_t)innerResult, 32);
        _owner->setProperty("AirportRTW89DirectAssociate20BridgeReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, result,
                                             kWPA2TraceDirectBridge);
    }

    /* 0.2.199: non-destructive outer ABI probe for
     * APPLE80211_IOC_LAST_BCAST_SCAN_TIME (GET 110).
     *
     * 0.2.198 proved two independent facts: GET11 copyout is valid, while
     * CoreWiFi computes result age from a zero-origin monotonic timestamp.
     * The SDK names GET 110 exactly for the last broadcast-scan time, but does
     * not expose a trustworthy payload type.  Therefore do not guess or write
     * any fields in this build.  Snapshot at most 32 caller bytes before/after
     * the inherited marshaller, record the exact req_len and return value, and
     * correlate the call with the real scan-completion checkpoint maintained
     * by the controller.  Runtime behavior remains whatever the superclass
     * already did for this request.
     */
    const bool lastBcastScanTimeOuterProbe =
        !isSet && reqType == APPLE80211_IOC_LAST_BCAST_SCAN_TIME;

    if (lastBcastScanTimeOuterProbe) {
        static volatile UInt32 outer110Count = 0;
        const UInt32 sequence = __sync_add_and_fetch(&outer110Count, 1);
        UInt8 before[32] = {};
        UInt8 after[32] = {};
        UInt32 copyLength = reqLen;
        if (copyLength > sizeof(before))
            copyLength = sizeof(before);

        int preCopyin = -1;
        if (reqData != 0 && copyLength != 0)
            preCopyin = copyin(reqData, before, copyLength);

        uint64_t beforeNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &beforeNowNs);
        const UInt64 beforeNowMS = beforeNowNs / 1000000ULL;
        const UInt64 lastCompletionMS =
            _owner->_airportLastRealScanCompletionMonotonicMS;

        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterDiagnosticOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterReqVal",
                            (uint64_t)(uint32_t)reqVal, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterReqDataPresent",
                            reqData != 0 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterEnvelope40",
                            is40 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterCommand",
                            (uint64_t)command, 64);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterCopyLength",
                            (uint64_t)copyLength, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterPreCopyinReturn",
                            (uint64_t)(uint32_t)preCopyin, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterNowMonotonicMS",
                            beforeNowMS, 64);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterLastCompletionMS",
                            lastCompletionMS, 64);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterDeltaFromCompletionMS",
                            beforeNowMS >= lastCompletionMS
                                ? beforeNowMS - lastCompletionMS : 0,
                            64);

        if (preCopyin == 0) {
            for (UInt32 i = 0; i < 8; ++i) {
                UInt32 word = 0;
                const UInt32 offset = i * sizeof(UInt32);
                if (offset + sizeof(UInt32) <= copyLength)
                    memcpy(&word, before + offset, sizeof(word));
                char key[80] = {};
                snprintf(key, sizeof(key),
                         "AirportRTW89LastBcastScanTimeOuterPreWord%u",
                         (unsigned)i);
                _owner->setProperty(key, (uint64_t)word, 32);
            }
        }

        const SInt32 result = IO80211Interface::performCommand(
            controller, command, arg0, arg1);

        int postCopyin = -1;
        if (reqData != 0 && copyLength != 0)
            postCopyin = copyin(reqData, after, copyLength);
        bool changed = false;
        UInt32 nonZeroBytes = 0;
        if (postCopyin == 0) {
            changed = preCopyin == 0 &&
                      memcmp(before, after, copyLength) != 0;
            for (UInt32 i = 0; i < copyLength; ++i) {
                if (after[i] != 0)
                    ++nonZeroBytes;
            }
            for (UInt32 i = 0; i < 8; ++i) {
                UInt32 word = 0;
                const UInt32 offset = i * sizeof(UInt32);
                if (offset + sizeof(UInt32) <= copyLength)
                    memcpy(&word, after + offset, sizeof(word));
                char key[80] = {};
                snprintf(key, sizeof(key),
                         "AirportRTW89LastBcastScanTimeOuterPostWord%u",
                         (unsigned)i);
                _owner->setProperty(key, (uint64_t)word, 32);
            }
        }

        uint64_t afterNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &afterNowNs);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterSuperReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterPostCopyinReturn",
                            (uint64_t)(uint32_t)postCopyin, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterBufferChanged",
                            changed ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterPostNonZeroBytes",
                            (uint64_t)nonZeroBytes, 32);
        _owner->setProperty("AirportRTW89LastBcastScanTimeOuterAfterMonotonicMS",
                            afterNowNs / 1000000ULL, 64);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, result,
                                             kWPA2TraceSuperclass);
    }

    /* 0.2.121: direct GET-11 bridge on the genuine Airport interface.
     *
     * The 0.2.120 outer probe proved that Tahoe's restored
     * IO80211Interface::performCommand() returns 16 for the userspace GET
     * APPLE80211_IOC_SCAN_RESULT envelope, does not enter our inner
     * apple80211Request(GET 11), and leaves the 1164-byte userspace buffer
     * unchanged.  The inner GET-11 implementation itself is already proven
     * to enumerate populated per-BSS apple80211_scan_result objects.
     *
     * POWER GET required the same kind of live-interface bridge in 0.2.110.
     * Apply that pattern only to GET SCAN_RESULT: ask the existing controller
     * handler for one result pointer, copy exactly one ABI-sized result to the
     * userspace request buffer, and preserve the handler's 5/12 end/no-result
     * returns without copyout.  SET SCAN_REQ and every other Apple80211 ioctl
     * remain owned by IO80211Interface::performCommand(). */
    const bool directGet11Bridge =
        !isSet && reqType == APPLE80211_IOC_SCAN_RESULT && reqData != 0 &&
        reqLen >= sizeof(apple80211_scan_result);

    if (directGet11Bridge) {
        /* 0.2.197: direct GET11 outer-contract probe.
         *
         * 0.2.196 proved that the native controller-helper experiment is not
         * a safe ownership test: a global inner-count delta can be caused by
         * concurrent GET11 traffic, while apple80211RequestIoctl() can still
         * return kIOReturnUnsupported with no result pointer.  When that
         * happened the helper error escaped this outer bridge and IO80211Old
         * reported APPLE80211_IOC_SCAN_RESULT return -1.
         *
         * Restore the proven 0.2.121 contract unconditionally: each userspace
         * GET11 causes exactly one direct apple80211Request(GET, 11), followed
         * by exactly one 1164-byte copyout only on success.  Preserve 5/12 as
         * end/no-result returns.  The native helper is deliberately not called
         * in this build, so there is no double-consume ambiguity.
         *
         * A small request-scoped trace ring records the inner return, pointer,
         * copyout result, copied age, and final performCommand return.  The
         * sequence/complete-sequence pair makes partially overwritten slots
         * detectable without using the old global inner-count delta as logic.
         */
        /* 0.2.198: one-shot, request-scoped native marshaller parity test.
         *
         * 0.2.197 proved the direct virtual call + 1164-byte copyout contract.
         * The unresolved difference from IO80211Reference is that its GET11 result
         * normally crosses IO80211Interface::performCommand(), while our
         * direct bridge bypasses that hidden marshalling layer.  0.2.120 found
         * that superclass path returned 16 before entering the controller, but
         * the tree has changed substantially since then.  Re-probe it once,
         * only after a successful direct result and with at least two cached
         * BSS entries available.
         *
         * Ownership is acknowledged by fields on this exact interface object
         * from RTW88PCIDevice::apple80211Request().  No global count delta is
         * used.  Therefore:
         *   - no inner GET11 + nonzero superclass return => safe direct fallback;
         *   - inner GET11 entered => never direct-fallback that same request;
         *   - superclass success without inner entry is respected as native
         *     ownership and is not followed by a direct consume.
         *
         * The inner handler temporarily stamps rssi=-42 and asr_age=42 only
         * for this native probe result, then this outer scope restores the
         * persistent BSS object after the superclass returns.  airportd's
         * maxAge log prints both fields, making native consumption visible.
         */
        static volatile UInt32 nativeMarshallerProbeState = 0;
        /* state: 0=pending, 1=no-inner/direct-fallback, 2=entered+success,
         *        3=entered+nonzero, 4=probe-in-progress, 5=no-inner+success */
        static volatile UInt32 nativeMarshallerProbeAttemptCount = 0;
        static volatile UInt32 nativeMarshallerNoInnerFallbackCount = 0;

        /* 0.2.199: 0.2.198 decisively returned 16 without entering inner
         * GET11.  Keep the old probe code compiled for auditability but never
         * arm it again; all live GET11 requests stay on the proven direct
         * bridge. */
        const bool runNativeMarshallerProbe = false;
        _owner->setProperty(
            "AirportRTW89Get11NativeMarshallerProbeDisabledAfter198",
            kOSBooleanTrue);

        if (runNativeMarshallerProbe) {
            const UInt32 attempt =
                __sync_add_and_fetch(&nativeMarshallerProbeAttemptCount, 1);
            UInt32 preAge = 0;
            UInt32 postAge = 0;
            SInt16 preRSSI = 0;
            SInt16 postRSSI = 0;
            const int preAgeCopyin = copyin(
                reqData + offsetof(apple80211_scan_result, asr_age),
                &preAge, sizeof(preAge));
            const int preRSSICopyin = copyin(
                reqData + offsetof(apple80211_scan_result, asr_rssi),
                &preRSSI, sizeof(preRSSI));

            _get11NativeProbeEnteredInner = false;
            _get11NativeProbeInnerReturn = kIOReturnNotReady;
            _get11NativeProbeResult = nullptr;
            _get11NativeProbeMarkerApplied = false;
            _get11NativeProbeThread = current_thread();
            _get11NativeProbeActive = true;

            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeActive",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeAttemptCount",
                                (uint64_t)attempt, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeReqLen",
                                (uint64_t)reqLen, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePreAgeCopyin",
                                (uint64_t)(uint32_t)preAgeCopyin, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePreRSSICopyin",
                                (uint64_t)(uint32_t)preRSSICopyin, 32);
            if (preAgeCopyin == 0)
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePreAgeMS",
                                    (uint64_t)preAge, 32);
            if (preRSSICopyin == 0)
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePreRSSI",
                                    (uint64_t)(SInt64)preRSSI, 64);

            const SInt32 nativeReturn = IO80211Interface::performCommand(
                controller, command, arg0, arg1);

            _get11NativeProbeActive = false;
            _get11NativeProbeThread = THREAD_NULL;
            const bool enteredInner = _get11NativeProbeEnteredInner;
            const SInt32 nativeInnerReturn = _get11NativeProbeInnerReturn;
            apple80211_scan_result *nativeResult = _get11NativeProbeResult;
            const bool markerApplied = _get11NativeProbeMarkerApplied;
            const SInt16 originalRSSI = _get11NativeProbeOriginalRSSI;
            const UInt32 originalAge = _get11NativeProbeOriginalAge;

            const int postAgeCopyin = copyin(
                reqData + offsetof(apple80211_scan_result, asr_age),
                &postAge, sizeof(postAge));
            const int postRSSICopyin = copyin(
                reqData + offsetof(apple80211_scan_result, asr_rssi),
                &postRSSI, sizeof(postRSSI));

            /* Restore the persistent kernel-side scan object immediately after
             * the native wrapper has had its chance to copy the marker out. */
            if (markerApplied && nativeResult) {
                nativeResult->asr_rssi = originalRSSI;
                nativeResult->asr_age = originalAge;
            }

            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeActive",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeSuperReturn",
                                (uint64_t)(uint32_t)nativeReturn, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeEnteredInner",
                                enteredInner ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeInnerReturn",
                                (uint64_t)(uint32_t)nativeInnerReturn, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeMarkerApplied",
                                markerApplied ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeResultPointerPresent",
                                nativeResult ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePostAgeCopyin",
                                (uint64_t)(uint32_t)postAgeCopyin, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePostRSSICopyin",
                                (uint64_t)(uint32_t)postRSSICopyin, 32);
            if (postAgeCopyin == 0)
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePostAgeMS",
                                    (uint64_t)postAge, 32);
            if (postRSSICopyin == 0)
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbePostRSSI",
                                    (uint64_t)(SInt64)postRSSI, 64);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeExpectedMarkerAgeMS",
                                (uint64_t)42, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeExpectedMarkerRSSI",
                                (uint64_t)(SInt64)-42, 64);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeKernelRestored",
                                (!markerApplied || nativeResult)
                                    ? kOSBooleanTrue : kOSBooleanFalse);

            if (enteredInner) {
                const UInt32 finalState =
                    nativeReturn == kIOReturnSuccess ? 2U : 3U;
                nativeMarshallerProbeState = finalState;
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeState",
                                    (uint64_t)finalState, 32);
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeUsedNativeReturn",
                                    kOSBooleanTrue);
                _owner->setProperty(
                    "AirportRTW89InterfaceApple80211PerformCommandReturn",
                    (uint64_t)(uint32_t)nativeReturn, 32);
                return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, nativeReturn,
                                             kWPA2TraceSuperclass);
            }

            if (nativeReturn == kIOReturnSuccess) {
                nativeMarshallerProbeState = 5U;
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeState",
                                    (uint64_t)5, 32);
                _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeUsedNativeReturn",
                                    kOSBooleanTrue);
                _owner->setProperty(
                    "AirportRTW89InterfaceApple80211PerformCommandReturn",
                    (uint64_t)(uint32_t)nativeReturn, 32);
                return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, nativeReturn,
                                             kWPA2TraceSuperclass);
            }

            nativeMarshallerProbeState = 1U;
            __sync_add_and_fetch(&nativeMarshallerNoInnerFallbackCount, 1);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeState",
                                (uint64_t)1, 32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeNoInnerFallbackCount",
                                (uint64_t)nativeMarshallerNoInnerFallbackCount,
                                32);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeUsedNativeReturn",
                                kOSBooleanFalse);
            _owner->setProperty("AirportRTW89Get11NativeMarshallerProbeFallbackSafe",
                                kOSBooleanTrue);
            /* No inner GET11 occurred, so this exact userspace request has not
             * consumed a BSS from our controller.  Continue into the proven
             * direct 0.2.197 bridge below. */
        }

        static volatile UInt32 directGet11Sequence = 0;
        static volatile UInt32 directGet11SuccessCount = 0;
        static volatile UInt32 directGet11CopyoutCount = 0;
        static volatile UInt32 directGet11EndCount = 0;
        static volatile UInt32 directGet11TraceSlotSequence[8] = {};

        static const char * const traceSequenceKey[8] = {
            "AirportRTW89DirectGet11Trace0Sequence",
            "AirportRTW89DirectGet11Trace1Sequence",
            "AirportRTW89DirectGet11Trace2Sequence",
            "AirportRTW89DirectGet11Trace3Sequence",
            "AirportRTW89DirectGet11Trace4Sequence",
            "AirportRTW89DirectGet11Trace5Sequence",
            "AirportRTW89DirectGet11Trace6Sequence",
            "AirportRTW89DirectGet11Trace7Sequence",
        };
        static const char * const traceCompleteKey[8] = {
            "AirportRTW89DirectGet11Trace0CompleteSequence",
            "AirportRTW89DirectGet11Trace1CompleteSequence",
            "AirportRTW89DirectGet11Trace2CompleteSequence",
            "AirportRTW89DirectGet11Trace3CompleteSequence",
            "AirportRTW89DirectGet11Trace4CompleteSequence",
            "AirportRTW89DirectGet11Trace5CompleteSequence",
            "AirportRTW89DirectGet11Trace6CompleteSequence",
            "AirportRTW89DirectGet11Trace7CompleteSequence",
        };
        static const char * const traceInnerReturnKey[8] = {
            "AirportRTW89DirectGet11Trace0InnerReturn",
            "AirportRTW89DirectGet11Trace1InnerReturn",
            "AirportRTW89DirectGet11Trace2InnerReturn",
            "AirportRTW89DirectGet11Trace3InnerReturn",
            "AirportRTW89DirectGet11Trace4InnerReturn",
            "AirportRTW89DirectGet11Trace5InnerReturn",
            "AirportRTW89DirectGet11Trace6InnerReturn",
            "AirportRTW89DirectGet11Trace7InnerReturn",
        };
        static const char * const tracePointerKey[8] = {
            "AirportRTW89DirectGet11Trace0PointerPresent",
            "AirportRTW89DirectGet11Trace1PointerPresent",
            "AirportRTW89DirectGet11Trace2PointerPresent",
            "AirportRTW89DirectGet11Trace3PointerPresent",
            "AirportRTW89DirectGet11Trace4PointerPresent",
            "AirportRTW89DirectGet11Trace5PointerPresent",
            "AirportRTW89DirectGet11Trace6PointerPresent",
            "AirportRTW89DirectGet11Trace7PointerPresent",
        };
        static const char * const traceCopyoutReturnKey[8] = {
            "AirportRTW89DirectGet11Trace0CopyoutReturn",
            "AirportRTW89DirectGet11Trace1CopyoutReturn",
            "AirportRTW89DirectGet11Trace2CopyoutReturn",
            "AirportRTW89DirectGet11Trace3CopyoutReturn",
            "AirportRTW89DirectGet11Trace4CopyoutReturn",
            "AirportRTW89DirectGet11Trace5CopyoutReturn",
            "AirportRTW89DirectGet11Trace6CopyoutReturn",
            "AirportRTW89DirectGet11Trace7CopyoutReturn",
        };
        static const char * const traceAgeKey[8] = {
            "AirportRTW89DirectGet11Trace0CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace1CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace2CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace3CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace4CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace5CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace6CopiedElapsedAgeMS",
            "AirportRTW89DirectGet11Trace7CopiedElapsedAgeMS",
        };
        static const char * const traceFinalReturnKey[8] = {
            "AirportRTW89DirectGet11Trace0FinalReturn",
            "AirportRTW89DirectGet11Trace1FinalReturn",
            "AirportRTW89DirectGet11Trace2FinalReturn",
            "AirportRTW89DirectGet11Trace3FinalReturn",
            "AirportRTW89DirectGet11Trace4FinalReturn",
            "AirportRTW89DirectGet11Trace5FinalReturn",
            "AirportRTW89DirectGet11Trace6FinalReturn",
            "AirportRTW89DirectGet11Trace7FinalReturn",
        };

        const UInt32 sequence = __sync_add_and_fetch(&directGet11Sequence, 1);
        const UInt32 traceSlot = sequence & 7U;
        directGet11TraceSlotSequence[traceSlot] = sequence;

        _owner->setProperty("AirportRTW89DirectGet11BridgeSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectGet11BridgeLivePath",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectGet11BridgeGetOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectGet11BridgeNativeHelperDisabled",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectGet11BridgeSequence",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeCount",
                            (uint64_t)sequence, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeLastSuccessPointerPresent",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89DirectGet11BridgeCopyoutAttempted",
                            kOSBooleanFalse);
        _owner->setProperty(traceSequenceKey[traceSlot],
                            (uint64_t)sequence, 32);
        _owner->setProperty(traceCompleteKey[traceSlot], (uint64_t)0, 32);

        /* 0.2.208: first-real-result controller ioctl-get ownership probe.
         *
         * 0.2.207 proved Tahoe can reach our declared
         * IO80211Controller::apple80211_ioctl_get() override, but the probe was
         * armed after the direct bridge had already drained the iterator.
         *
         * SET22 now records the current scan-cache refresh serial. Only the
         * first GET11 of a LATER refreshed snapshot (count > 0, index == 0) is
         * claimed for the inherited IO80211Interface path. This matches the
         * association-relevant IO80211Reference ownership model without touching
         * GET11 bytes or asr_age semantics. The controller hook temporarily
         * stamps rssi=-44 / age=44 only for observability. */
        bool firstRealResultReady = false;
        UInt32 firstResultCount = 0;
        UInt32 firstResultIndex = 0;
        UInt32 firstResultSnapshotSerial = 0;
        UInt32 armSnapshotSerial = 0;
        UInt32 firstResultAttempt = 0;
        if (_owner->_airportLock) {
            IOLockLock(_owner->_airportLock);
            firstResultCount = _owner->_airportBSSCount;
            firstResultIndex = _owner->_airportBSSIndex;
            firstResultSnapshotSerial = _owner->_airportScanCacheRefreshSerial;
            armSnapshotSerial =
                _owner->_airportGet11ControllerFirstResultArmSnapshotSerial;
            firstRealResultReady =
                _owner->_airportGet11ControllerFirstResultJoinArmed &&
                firstResultSnapshotSerial != 0U &&
                firstResultSnapshotSerial != armSnapshotSerial &&
                firstResultCount != 0U && firstResultIndex == 0U;
            if (firstRealResultReady) {
                /* Claim the association-scoped probe before releasing the lock.
                 * Mark the exact thread active at the same time so concurrent
                 * GET11 callers cannot steal index zero in the tiny handoff
                 * window before inherited performCommand() reaches the hook. */
                _owner->_airportGet11ControllerFirstResultJoinArmed = false;
                _owner->_airportGet11ControllerIoctlGetProbeActive = true;
                _owner->_airportGet11ControllerIoctlGetProbeThread =
                    current_thread();
                firstResultAttempt =
                    ++_owner->_airportGet11ControllerFirstResultAttemptCount;
            }
            IOLockUnlock(_owner->_airportLock);
        }

        if (firstRealResultReady) {
            const UInt32 entryBefore =
                _owner->_airportGet11ControllerIoctlGetEntryCount;
            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeSeen",
                kOSBooleanTrue);
            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeState",
                (uint64_t)4, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeEntryBefore",
                (uint64_t)entryBefore, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultAttemptCount",
                (uint64_t)firstResultAttempt, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultBSSCountBefore",
                (uint64_t)firstResultCount, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultBSSIndexBefore",
                (uint64_t)firstResultIndex, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultSnapshotSerial",
                (uint64_t)firstResultSnapshotSerial, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultArmSnapshotSerial",
                (uint64_t)armSnapshotSerial, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultJoinArmed",
                kOSBooleanFalse);

            const SInt32 nativeIoctlResult =
                IO80211Interface::performCommand(
                    controller, command, arg0, arg1);

            _owner->_airportGet11ControllerIoctlGetProbeActive = false;
            _owner->_airportGet11ControllerIoctlGetProbeThread = THREAD_NULL;

            const UInt32 entryAfter =
                _owner->_airportGet11ControllerIoctlGetEntryCount;
            const bool enteredControllerIoctl =
                entryAfter != entryBefore;
            UInt32 indexAfter = 0;
            UInt32 countAfter = 0;
            if (_owner->_airportLock) {
                IOLockLock(_owner->_airportLock);
                indexAfter = _owner->_airportBSSIndex;
                countAfter = _owner->_airportBSSCount;
                IOLockUnlock(_owner->_airportLock);
            }
            const UInt32 finalProbeState =
                !enteredControllerIoctl
                    ? 1U
                    : (nativeIoctlResult == kIOReturnSuccess ? 2U : 3U);

            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeEntryAfter",
                (uint64_t)entryAfter, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeEntered",
                enteredControllerIoctl ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeOuterReturn",
                (uint64_t)(uint32_t)nativeIoctlResult, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeState",
                (uint64_t)finalProbeState, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultBSSCountAfter",
                (uint64_t)countAfter, 32);
            _owner->setProperty(
                "AirportRTW89Get11ControllerFirstResultBSSIndexAfter",
                (uint64_t)indexAfter, 32);

            if (enteredControllerIoctl) {
                /* The controller hook owns this request and may already have
                 * advanced the per-BSS iterator. Never consume a second result. */
                return airportWPA2PreflightTraceFinish(
                    _owner, wpa2TraceCookie, nativeIoctlResult,
                    kWPA2TraceSuperclass);
            }

            _owner->setProperty(
                "AirportRTW89Get11ControllerIoctlGetProbeFallbackSafe",
                kOSBooleanTrue);
        }

        apple80211_scan_result *scanResult = nullptr;
        const SInt32 innerResult = _owner->apple80211Request(
            APPLE80211_IOC_SCAN_RESULT, 1, this, &scanResult);
        SInt32 result = innerResult;

        _owner->setProperty("AirportRTW89DirectGet11BridgeInnerReturn",
                            (uint64_t)(uint32_t)innerResult, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeResultPointerPresent",
                            scanResult ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89DirectGet11BridgeLastWasEndOfList",
                            (innerResult == 5 || innerResult == 12)
                                ? kOSBooleanTrue : kOSBooleanFalse);

        SInt32 scanCopyout = -1; /* 0xffffffff means copyout was not attempted. */
        UInt32 copiedElapsedAgeMS = 0;
        bool copyoutAttempted = false;
        if (result == kIOReturnSuccess) {
            if (!scanResult) {
                result = kIOReturnNotReady;
            } else {
                __sync_add_and_fetch(&directGet11SuccessCount, 1);
                copyoutAttempted = true;
                scanCopyout = copyout(scanResult, reqData,
                                      sizeof(apple80211_scan_result));
                if (scanCopyout == 0) {
                    __sync_add_and_fetch(&directGet11CopyoutCount, 1);
                    _owner->setProperty(
                        "AirportRTW89Get11NativeMarshallerDirectBaselineSuccessSeen",
                        kOSBooleanTrue);
                    copiedElapsedAgeMS = scanResult->asr_age;
                    _owner->setProperty(
                        "AirportRTW89DirectGet11BridgeLastSuccessPointerPresent",
                        kOSBooleanTrue);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeLastVersion",
                                        (uint64_t)scanResult->version, 32);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeLastChannel",
                                        (uint64_t)scanResult->asr_channel.channel, 32);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeLastChannelFlags",
                                        (uint64_t)scanResult->asr_channel.flags, 32);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeLastSSIDLength",
                                        (uint64_t)scanResult->asr_ssid_len, 32);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeLastIELength",
                                        (uint64_t)(UInt16)scanResult->asr_ie_len, 32);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeLastCapability",
                                        (uint64_t)(UInt16)scanResult->asr_cap, 32);
                    _owner->setProperty("AirportRTW89DirectGet11BridgeCopiedElapsedAgeMS",
                                        (uint64_t)copiedElapsedAgeMS, 32);
                } else {
                    result = scanCopyout;
                }
            }
        } else if (result == 5 || result == 12) {
            __sync_add_and_fetch(&directGet11EndCount, 1);
        }

        _owner->setProperty("AirportRTW89DirectGet11BridgeCopyoutAttempted",
                            copyoutAttempted ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89DirectGet11BridgeCopyoutReturn",
                            (uint64_t)(uint32_t)scanCopyout, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeSuccessCount",
                            (uint64_t)directGet11SuccessCount, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeCopyoutCount",
                            (uint64_t)directGet11CopyoutCount, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeEndCount",
                            (uint64_t)directGet11EndCount, 32);
        _owner->setProperty("AirportRTW89DirectGet11BridgeReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89InterfaceApple80211PerformCommandReturn",
            (uint64_t)(uint32_t)result, 32);

        if (directGet11TraceSlotSequence[traceSlot] == sequence) {
            _owner->setProperty(traceInnerReturnKey[traceSlot],
                                (uint64_t)(uint32_t)innerResult, 32);
            _owner->setProperty(tracePointerKey[traceSlot],
                                scanResult ? kOSBooleanTrue : kOSBooleanFalse);
            _owner->setProperty(traceCopyoutReturnKey[traceSlot],
                                (uint64_t)(uint32_t)scanCopyout, 32);
            _owner->setProperty(traceAgeKey[traceSlot],
                                (uint64_t)copiedElapsedAgeMS, 32);
            _owner->setProperty(traceFinalReturnKey[traceSlot],
                                (uint64_t)(uint32_t)result, 32);
            _owner->setProperty(traceCompleteKey[traceSlot],
                                (uint64_t)sequence, 32);
        }
        return airportWPA2PreflightTraceFinish(
            _owner, wpa2TraceCookie, result,
            kWPA2TraceDirectBridge | kWPA2TraceDirectGet11);
    }

    /* 0.3.8 handles primary GET207 in the stack-safe thin performCommand
     * wrapper before this historical compatibility body is entered. */

    /* 0.2.130: direct GET-27/HW-254 bridge on the genuine Airport interface.
     * 0.2.129 proved the controller builds a valid 22-channel object while the
     * restored superclass marshaller returns success without copying it to the
     * userspace request buffer.  GET 11 and GET 51 already require explicit
     * copyout on this Tahoe path, so use the same proven pattern here. */
    const bool directGet27Bridge =
        !isSet &&
        (reqType == APPLE80211_IOC_SUPPORTED_CHANNELS ||
         reqType == APPLE80211_IOC_HW_SUPPORTED_CHANNELS) &&
        reqData != 0 && reqLen >= (sizeof(UInt32) * 2);

    if (directGet27Bridge) {
        static UInt32 directGet27Count = 0;
        static UInt32 directGet27SuccessCount = 0;
        static UInt32 directGet27CopyoutCount = 0;
        ++directGet27Count;

        apple80211_sup_channel_data channelData = {};
        const SInt32 innerResult = _owner->apple80211Request(
            (unsigned int)reqType, 1, this, &channelData);
        SInt32 result = innerResult;
        int channelCopyout = 0;
        size_t copyLength = 0;

        if (result == kIOReturnSuccess) {
            UInt32 count = channelData.num_channels;
            if (count > APPLE80211_MAX_CHANNELS)
                count = APPLE80211_MAX_CHANNELS;
            const size_t usedLength =
                offsetof(apple80211_sup_channel_data, supported_channels) +
                (size_t)count * sizeof(apple80211_channel);

            if (reqLen < usedLength) {
                result = kIOReturnBadArgument;
            } else {
                /* The bundled newer IO80211 headers retain the same
                 * version/count + 12-byte channel-entry prefix. Tahoe's
                 * observed request is larger (4824 bytes), so copy only the
                 * populated prefix and leave its unknown private tail alone. */
                copyLength = usedLength;
                channelCopyout = copyout(&channelData, reqData, copyLength);
                if (channelCopyout != 0) {
                    result = channelCopyout;
                } else {
                    ++directGet27SuccessCount;
                    ++directGet27CopyoutCount;
                }
            }
        }

        _owner->setProperty("AirportRTW89DirectGet27BridgeSeen", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89DirectGet27BridgeCount",
                            (uint64_t)directGet27Count, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeRequest",
                            (uint64_t)(UInt32)reqType, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeStructSize",
                            (uint64_t)sizeof(channelData), 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeCopyLength",
                            (uint64_t)copyLength, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeInnerReturn",
                            (uint64_t)(uint32_t)innerResult, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeCopyoutReturn",
                            (uint64_t)(uint32_t)channelCopyout, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeNumChannels",
                            (uint64_t)channelData.num_channels, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeSuccessCount",
                            (uint64_t)directGet27SuccessCount, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeCopyoutCount",
                            (uint64_t)directGet27CopyoutCount, 32);
        _owner->setProperty("AirportRTW89DirectGet27BridgeReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89InterfaceApple80211PerformCommandReturn",
                            (uint64_t)(uint32_t)result, 32);
        return airportWPA2PreflightTraceFinish(_owner, wpa2TraceCookie, result,
                                             kWPA2TraceDirectBridge);
    }

    /* 0.2.176 diagnostic-only current-network/status copyout probe.
     * The backend is demonstrably connected while Tahoe reports "Not
     * Connected".  Snapshot only the public result buffers for STATE, SSID,
     * BSSID, RSSI, ASSOCIATE_RESULT, and ASSOCIATION_STATUS before/after the
     * superclass marshaller.  SSID/BSSID are represented only by length/hash
     * telemetry so network identity is not published in IORegistry. */
    const bool statusOuterProbe =
        !isSet && reqData != 0 &&
        (reqType == APPLE80211_IOC_SSID ||
         reqType == APPLE80211_IOC_BSSID ||
         reqType == APPLE80211_IOC_STATE ||
         reqType == APPLE80211_IOC_RSSI ||
         reqType == APPLE80211_IOC_ASSOCIATE_RESULT ||
         reqType == APPLE80211_IOC_ASSOCIATION_STATUS);

    static UInt32 statusOuterProbeSequence = 0;
    UInt8 statusOuterBefore[64] = {};
    UInt32 statusOuterCopyLength = reqLen;
    if (statusOuterCopyLength > sizeof(statusOuterBefore))
        statusOuterCopyLength = sizeof(statusOuterBefore);
    int statusOuterPreCopyin = -1;

    if (statusOuterProbe) {
        ++statusOuterProbeSequence;
        if (statusOuterCopyLength != 0)
            statusOuterPreCopyin = copyin(reqData, statusOuterBefore,
                                          statusOuterCopyLength);
        _owner->setProperty("AirportRTW89StatusDiagOuterSeen", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89StatusDiagOuterSequence",
                            (uint64_t)statusOuterProbeSequence, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterRequest",
                            (uint64_t)(UInt32)reqType, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterCopyLength",
                            (uint64_t)statusOuterCopyLength, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterPreCopyinReturn",
                            (uint64_t)(uint32_t)statusOuterPreCopyin, 32);
    }

    /* 0.2.120 diagnostic-only GET-11 copyout probe.  The inner
     * apple80211Request(SCAN_RESULT) path is demonstrably returning populated
     * per-BSS objects, but Tahoe/IO80211Old still reports an empty public scan
     * cache.  Do not replace Apple's hidden marshaller yet.  Instead snapshot
     * the userspace 1164-byte result buffer before and after the superclass
     * performCommand() call so we can prove whether IO80211Interface actually
     * copies the driver result to userspace. */
    const bool get11CopyoutProbe =
        !isSet && reqType == APPLE80211_IOC_SCAN_RESULT && reqData != 0 &&
        reqLen >= sizeof(apple80211_scan_result);

    static UInt32 get11OuterCount = 0;
    static UInt32 get11OuterSuccessCount = 0;
    static UInt32 get11PostCopyinSuccessCount = 0;
    static UInt32 get11UserBufferChangedCount = 0;
    static UInt32 get11SuccessfulCopyoutCount = 0;
    apple80211_scan_result get11Before = {};
    int get11PreCopyin = -1;
    UInt32 get11InnerSuccessBefore = 0;

    if (get11CopyoutProbe) {
        ++get11OuterCount;
        get11InnerSuccessBefore = _owner->_airportScanResultSuccessCount;
        get11PreCopyin = copyin(reqData, &get11Before, sizeof(get11Before));
        _owner->setProperty("AirportRTW89Get11OuterProbeSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89Get11OuterProbeCount",
                            (uint64_t)get11OuterCount, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeReqData",
                            (uint64_t)reqData, 64);
        _owner->setProperty("AirportRTW89Get11OuterProbePreCopyinReturn",
                            (uint64_t)(uint32_t)get11PreCopyin, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeInnerSuccessBefore",
                            (uint64_t)get11InnerSuccessBefore, 32);
    }

    /* 0.2.217: allocate a request-scoped IO80211Reference parity slot only for
     * the bounded SET22->SET20 window and only on the inherited superclass
     * path. Direct bridges remain covered by the existing WPA2 preflight ring.
     * The controller-side apple80211Request() callback marks this exact slot
     * when Apple's marshaller reaches us synchronously on the same thread. */
    AirportRTW89Interface::IO80211ReferenceParityScope *parityScope = nullptr;
    UInt32 parityOuterSequence = 0;
    bool parityScopeCollision = false;
    IO80211ReferenceParityTraceEntry *parityTraceEntry = nullptr;
    UInt32 parityTraceOrdinal = 0;
    AirportUserBufferMetadata parityCurrentNetworkPre = {};
    AirportUserBufferMetadata parityCurrentNetworkPost = {};
    const bool parityCurrentNetworkProbe =
        wpa2TraceCookie.active && !isSet &&
        reqType == APPLE80211_IOC_CURRENT_NETWORK && reqData != 0 &&
        reqLen == sizeof(apple80211_scan_result);

    if (wpa2TraceCookie.active) {
        parityOuterSequence = __sync_add_and_fetch(
            &_io80211ReferenceParitySequence, 1U);
        const UInt32 scopeIndex = (parityOuterSequence - 1U) & 15U;
        AirportRTW89Interface::IO80211ReferenceParityScope &candidate =
            _io80211ReferenceParityScopes[scopeIndex];
        if (!candidate.active) {
            candidate.thread = current_thread();
            candidate.sequence = parityOuterSequence;
            candidate.outerRequestType = reqType;
            candidate.outerIsSet = isSet;
            candidate.dispatcherEntered = false;
            candidate.dispatcherRawRequestType = 0;
            candidate.dispatcherRawRequestNumber = 0;
            candidate.dispatcherNormalizedRequest = 0;
            candidate.dispatcherIsGet = false;
            candidate.dispatcherReturn = kIOReturnNotReady;
            __sync_synchronize();
            candidate.active = true;
            parityScope = &candidate;
        } else {
            parityScopeCollision = true;
        }

        parityTraceOrdinal = __sync_add_and_fetch(
            &gIO80211ReferenceParityTraceOrdinal, 1U);
        IO80211ReferenceParityTraceEntry &entry =
            gIO80211ReferenceParityTraceRing[(parityTraceOrdinal - 1U) & 255U];
        bzero(&entry, sizeof(entry));
        entry.enterMonotonicMS = airportWPA2PreflightMonotonicMS();
        entry.sequence = parityOuterSequence;
        entry.windowSequence = wpa2TraceCookie.windowSequence;
        entry.requestType = reqType;
        entry.requestValue = reqVal;
        entry.requestLength = reqLen;
        entry.flags = (isSet ? kParityTraceSet : 0U) |
                      (is40 ? kParityTraceEnvelope40 : 0U) |
                      (reqData != 0 ? kParityTraceDataPresent : 0U) |
                      (parityScope ? kParityTraceScopeAllocated : 0U) |
                      (parityScopeCollision ? kParityTraceScopeCollision : 0U) |
                      (controller == _owner
                           ? kParityTraceControllerMatchesOwner : 0U) |
                      (_owner->_ieee80211 &&
                               _owner->_ieee80211->hasActiveAssociation()
                           ? kParityTraceConnectedBefore : 0U) |
                      (_owner->_airportLogicalPowerOn
                           ? kParityTraceLogicalPowerBefore : 0U) |
                      (poweredOnByUser() ? kParityTraceUserPowerBefore : 0U) |
                      (enabledBySystem() ? kParityTraceSystemEnabledBefore : 0U) |
                      (_owner->_airportAssocPending
                           ? kParityTraceAssocPendingBefore : 0U) |
                      (isSet && reqType == APPLE80211_IOC_DISASSOCIATE
                           ? kParityTraceSET22 : 0U) |
                      (isSet && reqType == APPLE80211_IOC_ASSOCIATE
                           ? kParityTraceSET20 : 0U);
        entry.rawStateBefore = _owner->_airportLastState;
        entry.bssCountBefore = _owner->_airportBSSCount;
        entry.scanSerialBefore = _owner->_airportScanCacheRefreshSerial;
        entry.superclassReturn = (SInt32)0x7fffffff;
        entry.finalReturn = (SInt32)0x7fffffff;
        entry.dispatcherReturn = (SInt32)0x7fffffff;
        entry.preFirstNonZeroOffset = 0xffffffffU;
        entry.postFirstNonZeroOffset = 0xffffffffU;
        parityTraceEntry = &entry;

        _owner->setProperty("AirportRTW89ParityOuterSeen", kOSBooleanTrue);
        _owner->setProperty("AirportRTW89ParityOuterSequence",
                            (uint64_t)parityOuterSequence, 32);
        _owner->setProperty("AirportRTW89ParityOuterWindowSequence",
                            (uint64_t)wpa2TraceCookie.windowSequence, 32);
        _owner->setProperty("AirportRTW89ParityOuterRequest",
                            (uint64_t)(uint32_t)reqType, 32);
        _owner->setProperty("AirportRTW89ParityOuterIsSet",
                            isSet ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterScopeAllocated",
                            parityScope ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterScopeCollision",
                            parityScopeCollision ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterControllerMatchesOwner",
                            controller == _owner ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterPrimaryInterfaceMatches",
                            _owner->_iface == this ? kOSBooleanTrue
                                                   : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterStateBefore",
                            (uint64_t)_owner->_airportLastState, 32);
        _owner->setProperty("AirportRTW89ParityOuterBSSCountBefore",
                            (uint64_t)_owner->_airportBSSCount, 32);
        _owner->setProperty("AirportRTW89ParityOuterScanSerialBefore",
                            (uint64_t)_owner->_airportScanCacheRefreshSerial,
                            32);
        _owner->setProperty("AirportRTW89ParityOuterAssociationTruthBefore",
                            (_owner->_ieee80211 &&
                             _owner->_ieee80211->hasActiveAssociation())
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterLogicalPowerBefore",
                            _owner->_airportLogicalPowerOn
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterUserPowerBefore",
                            poweredOnByUser() ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterSystemEnabledBefore",
                            enabledBySystem() ? kOSBooleanTrue
                                              : kOSBooleanFalse);
    }

    if (parityCurrentNetworkProbe) {
        parityCurrentNetworkPre = airportInspectUserBuffer(reqData, reqLen);
        if (parityTraceEntry) {
            parityTraceEntry->flags |= kParityTraceCurrentNetworkScanned;
            parityTraceEntry->preNonZeroBytes =
                parityCurrentNetworkPre.nonZeroBytes;
            parityTraceEntry->preFirstNonZeroOffset =
                parityCurrentNetworkPre.firstNonZeroOffset;
            parityTraceEntry->preFirstNonZeroValue =
                parityCurrentNetworkPre.firstNonZeroValue;
            parityTraceEntry->preHash = parityCurrentNetworkPre.hash;
        }
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPreCopyinReturn",
                            (uint64_t)(uint32_t)
                                parityCurrentNetworkPre.copyinResult, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPreBytesChecked",
                            (uint64_t)parityCurrentNetworkPre.bytesChecked, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPreNonZeroBytes",
                            (uint64_t)parityCurrentNetworkPre.nonZeroBytes, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPreFirstNonZeroOffset",
                            (uint64_t)parityCurrentNetworkPre.firstNonZeroOffset,
                            32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPreFirstNonZeroValue",
                            (uint64_t)parityCurrentNetworkPre.firstNonZeroValue,
                            32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPreHash",
                            (uint64_t)parityCurrentNetworkPre.hash, 32);
    }

    /* 0.2.234: retain bounded GET4/CHANNEL shape capture for proof.
     *
     * 0.2.232 proved the exact GET16/RSSI seed-only normalization applies
     * without payload mutation, while SET20 still never appears.  The live
     * airportd window then shows APPLE80211_IOC_CHANNEL (4) returning -3903
     * repeatedly immediately before "Will associate", and again in the
     * short follow-up ASSOC request.  The 0.2.233 run then characterized the 16-byte CHANNEL caller
     * buffer as one stable unchanged version-only seed.
     *
     * Retain the 0.2.233 structural capture.  Only inside the existing
     * SET22 -> SET20 trace window, snapshot the public apple80211_channel_data
     * buffer before and after the inherited superclass call and publish only
     * structural metadata: version fields, channel/flags, non-zero shape,
     * hashes, and whether the superclass changed the buffer.  This provides
     * proof that the 0.2.234 exact seed-only normalization matched.
     */
    const bool preSET20ChannelDiagCandidate =
        wpa2TraceCookie.active && !isSet &&
        reqType == APPLE80211_IOC_CHANNEL && reqData != 0 &&
        reqLen == sizeof(apple80211_channel_data);
    apple80211_channel_data preSET20ChannelDiagPre = {};
    int preSET20ChannelDiagPreCopyin = -1;
    bool preSET20ChannelSuperclassUnchanged = false;
    bool preSET20ChannelSeedOnlyMatch = false;
    bool preSET20ChannelEmptySuccessWouldApply = false;
    if (preSET20ChannelDiagCandidate)
        preSET20ChannelDiagPreCopyin = copyin(
            reqData, &preSET20ChannelDiagPre,
            sizeof(preSET20ChannelDiagPre));

    /* 0.2.245: for fixed-size public Apple80211 payloads that were not
     * consumed by an earlier Tahoe-specific raw-layout bridge, perform the
     * IO80211Interface marshalling contract explicitly.  Unknown/private
     * shapes still fall back unchanged to Apple's inherited implementation. */
    SInt32 explicitMarshallerResult = kIOReturnUnsupported;
    const bool explicitMarshallerHandled = airportExplicitLegacyMarshal(
        _owner, this, isSet, (UInt32)reqType, reqLen, reqData,
        &explicitMarshallerResult);
    const SInt32 result = explicitMarshallerHandled
        ? explicitMarshallerResult
        : IO80211Interface::performCommand(controller, command, arg0, arg1);

    _owner->setProperty("AirportRTW89ExplicitLegacyMarshallerLastHandled",
                        explicitMarshallerHandled ? kOSBooleanTrue
                                                  : kOSBooleanFalse);
    _owner->setProperty("AirportRTW89ExplicitLegacyMarshallerFallbackToSuper",
                        explicitMarshallerHandled ? kOSBooleanFalse
                                                  : kOSBooleanTrue);
    _owner->setProperty("AirportRTW89ExplicitLegacyMarshallerLastOuterRequest",
                        (uint64_t)(uint32_t)reqType, 32);

    if (wpa2TraceCookie.active) {
        const bool dispatcherEntered =
            parityScope && parityScope->active &&
            parityScope->sequence == parityOuterSequence &&
            parityScope->dispatcherEntered;
        const bool dispatcherRequestMatches =
            dispatcherEntered &&
            parityScope->dispatcherNormalizedRequest == (UInt32)reqType;
        const bool dispatcherDirectionMatches =
            dispatcherEntered &&
            parityScope->dispatcherIsGet == !isSet;

        if (parityTraceEntry) {
            parityTraceEntry->superclassReturn = result;
            parityTraceEntry->rawStateAfter = _owner->_airportLastState;
            parityTraceEntry->bssCountAfter = _owner->_airportBSSCount;
            parityTraceEntry->scanSerialAfter =
                _owner->_airportScanCacheRefreshSerial;
            if (_owner->_ieee80211 &&
                _owner->_ieee80211->hasActiveAssociation())
                parityTraceEntry->flags |= kParityTraceConnectedAfter;
            if (dispatcherEntered) {
                parityTraceEntry->flags |= kParityTraceDispatcherEntered;
                parityTraceEntry->dispatcherRawRequestType =
                    parityScope->dispatcherRawRequestType;
                parityTraceEntry->dispatcherRawRequestNumber =
                    parityScope->dispatcherRawRequestNumber;
                parityTraceEntry->dispatcherNormalizedRequest =
                    parityScope->dispatcherNormalizedRequest;
                parityTraceEntry->dispatcherReturn =
                    parityScope->dispatcherReturn;
                if (dispatcherRequestMatches)
                    parityTraceEntry->flags |=
                        kParityTraceDispatcherRequestMatch;
                if (dispatcherDirectionMatches)
                    parityTraceEntry->flags |=
                        kParityTraceDispatcherDirectionMatch;
                if (_owner->_iface == this)
                    parityTraceEntry->flags |=
                        kParityTraceDispatcherInterfaceMatch;
            }
        }

        _owner->setProperty("AirportRTW89ParityOuterSuperclassReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89ParityOuterDispatcherEntered",
                            dispatcherEntered ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterDispatcherRequestMatches",
                            dispatcherRequestMatches ? kOSBooleanTrue
                                                     : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89ParityOuterDispatcherDirectionMatches",
                            dispatcherDirectionMatches ? kOSBooleanTrue
                                                       : kOSBooleanFalse);
        if (dispatcherEntered) {
            _owner->setProperty("AirportRTW89ParityOuterDispatcherRawType",
                                (uint64_t)
                                    parityScope->dispatcherRawRequestType, 32);
            _owner->setProperty("AirportRTW89ParityOuterDispatcherRawNumber",
                                (uint64_t)(uint32_t)
                                    parityScope->dispatcherRawRequestNumber,
                                32);
            _owner->setProperty("AirportRTW89ParityOuterDispatcherNormalizedRequest",
                                (uint64_t)
                                    parityScope->dispatcherNormalizedRequest,
                                32);
            _owner->setProperty("AirportRTW89ParityOuterDispatcherReturn",
                                (uint64_t)(uint32_t)
                                    parityScope->dispatcherReturn, 32);
        }
        _owner->setProperty("AirportRTW89ParityOuterStateAfter",
                            (uint64_t)_owner->_airportLastState, 32);
        _owner->setProperty("AirportRTW89ParityOuterBSSCountAfter",
                            (uint64_t)_owner->_airportBSSCount, 32);
        _owner->setProperty("AirportRTW89ParityOuterScanSerialAfter",
                            (uint64_t)_owner->_airportScanCacheRefreshSerial,
                            32);
        _owner->setProperty("AirportRTW89ParityOuterAssociationTruthAfter",
                            (_owner->_ieee80211 &&
                             _owner->_ieee80211->hasActiveAssociation())
                                ? kOSBooleanTrue : kOSBooleanFalse);
    }

    if (parityCurrentNetworkProbe) {
        parityCurrentNetworkPost = airportInspectUserBuffer(reqData, reqLen);
        const bool changed =
            parityCurrentNetworkPre.copyinResult == 0 &&
            parityCurrentNetworkPost.copyinResult == 0 &&
            (parityCurrentNetworkPre.hash != parityCurrentNetworkPost.hash ||
             parityCurrentNetworkPre.nonZeroBytes !=
                 parityCurrentNetworkPost.nonZeroBytes);
        if (parityTraceEntry) {
            parityTraceEntry->postNonZeroBytes =
                parityCurrentNetworkPost.nonZeroBytes;
            parityTraceEntry->postFirstNonZeroOffset =
                parityCurrentNetworkPost.firstNonZeroOffset;
            parityTraceEntry->postFirstNonZeroValue =
                parityCurrentNetworkPost.firstNonZeroValue;
            parityTraceEntry->postHash = parityCurrentNetworkPost.hash;
            if (changed)
                parityTraceEntry->flags |= kParityTraceCurrentNetworkChanged;
        }
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPostCopyinReturn",
                            (uint64_t)(uint32_t)
                                parityCurrentNetworkPost.copyinResult, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPostBytesChecked",
                            (uint64_t)parityCurrentNetworkPost.bytesChecked, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPostNonZeroBytes",
                            (uint64_t)parityCurrentNetworkPost.nonZeroBytes, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPostFirstNonZeroOffset",
                            (uint64_t)parityCurrentNetworkPost.firstNonZeroOffset,
                            32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPostFirstNonZeroValue",
                            (uint64_t)parityCurrentNetworkPost.firstNonZeroValue,
                            32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkPostHash",
                            (uint64_t)parityCurrentNetworkPost.hash, 32);
        _owner->setProperty("AirportRTW89ParityCurrentNetworkSuperclassModifiedBuffer",
                            changed ? kOSBooleanTrue : kOSBooleanFalse);
    }

    /* 0.2.177: inner Apple80211 dispatch is synchronous on this path (the
     * POWER traces established outer -> inner ordering).  Any same-sequence
     * credential cache still pending after the superclass returns was not
     * consumed, so scrub it immediately rather than retaining secrets. */
    if (outerSecurityCachedThisCall) {
        bool consumed = true;
        if (_owner->_airportLock) IOLockLock(_owner->_airportLock);
        switch ((UInt32)reqType) {
        case APPLE80211_IOC_AUTH_TYPE:
            if (_owner->_airportOuterAuthCacheValid &&
                _owner->_airportOuterAuthCacheSequence == outerSecurityCacheSequence) {
                bzero(&_owner->_airportOuterAuthCache,
                      sizeof(_owner->_airportOuterAuthCache));
                _owner->_airportOuterAuthCacheValid = false;
                consumed = false;
            }
            break;
        case APPLE80211_IOC_ASSOCIATE:
            if (_owner->_airportOuterAssocCacheValid &&
                _owner->_airportOuterAssocCacheSequence == outerSecurityCacheSequence) {
                bzero(&_owner->_airportOuterAssocCache,
                      sizeof(_owner->_airportOuterAssocCache));
                _owner->_airportOuterAssocCacheValid = false;
                consumed = false;
            }
            break;
        case APPLE80211_IOC_RSN_IE:
            if (_owner->_airportOuterRSNIECacheValid &&
                _owner->_airportOuterRSNIECacheSequence == outerSecurityCacheSequence) {
                bzero(&_owner->_airportOuterRSNIECache,
                      sizeof(_owner->_airportOuterRSNIECache));
                _owner->_airportOuterRSNIECacheValid = false;
                consumed = false;
            }
            break;
        case APPLE80211_IOC_CIPHER_KEY:
            if (_owner->_airportOuterCipherKeyCacheValid &&
                _owner->_airportOuterCipherKeyCacheSequence == outerSecurityCacheSequence) {
                bzero(&_owner->_airportOuterCipherKeyCache,
                      sizeof(_owner->_airportOuterCipherKeyCache));
                _owner->_airportOuterCipherKeyCacheValid = false;
                consumed = false;
            }
            break;
        default:
            break;
        }
        if (_owner->_airportLock) IOLockUnlock(_owner->_airportLock);
        _owner->setProperty("AirportRTW89WPA2OuterSecurityConsumedByInner",
                            consumed ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89WPA2OuterSecurityScrubbedPostSuper",
                            consumed ? kOSBooleanFalse : kOSBooleanTrue);
    }

    if (statusOuterProbe) {
        UInt8 statusOuterAfter[64] = {};
        int statusOuterPostCopyin = -1;
        if (statusOuterCopyLength != 0)
            statusOuterPostCopyin = copyin(reqData, statusOuterAfter,
                                           statusOuterCopyLength);

        bool changed = false;
        UInt32 nonZeroBytes = 0;
        UInt64 postHash = airportOuterStatusDiagHash(nullptr, 0);
        if (statusOuterPostCopyin == 0) {
            if (statusOuterPreCopyin == 0)
                changed = memcmp(statusOuterBefore, statusOuterAfter,
                                 statusOuterCopyLength) != 0;
            for (UInt32 i = 0; i < statusOuterCopyLength; ++i) {
                if (statusOuterAfter[i] != 0)
                    ++nonZeroBytes;
            }
            postHash = airportOuterStatusDiagHash(statusOuterAfter,
                                                  statusOuterCopyLength);
        }

        _owner->setProperty("AirportRTW89StatusDiagOuterSuperReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterPostCopyinReturn",
                            (uint64_t)(uint32_t)statusOuterPostCopyin, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterBufferChanged",
                            changed ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89StatusDiagOuterPostNonZeroBytes",
                            (uint64_t)nonZeroBytes, 32);
        _owner->setProperty("AirportRTW89StatusDiagOuterPostHash",
                            postHash, 64);

        const char *statusReqPrefix = nullptr;
        if (reqType == APPLE80211_IOC_SSID)
            statusReqPrefix = "SSID";
        else if (reqType == APPLE80211_IOC_BSSID)
            statusReqPrefix = "BSSID";
        else if (reqType == APPLE80211_IOC_STATE)
            statusReqPrefix = "State";
        else if (reqType == APPLE80211_IOC_RSSI)
            statusReqPrefix = "RSSI";
        else if (reqType == APPLE80211_IOC_ASSOCIATE_RESULT)
            statusReqPrefix = "AssocResult";
        else if (reqType == APPLE80211_IOC_ASSOCIATION_STATUS)
            statusReqPrefix = "AssocStatus";

        if (statusReqPrefix) {
            char key[96] = {};
            snprintf(key, sizeof(key), "AirportRTW89StatusDiagOuter%sReqLen",
                     statusReqPrefix);
            _owner->setProperty(key, (uint64_t)reqLen, 32);
            snprintf(key, sizeof(key),
                     "AirportRTW89StatusDiagOuter%sSuperReturn",
                     statusReqPrefix);
            _owner->setProperty(key, (uint64_t)(uint32_t)result, 32);
            snprintf(key, sizeof(key),
                     "AirportRTW89StatusDiagOuter%sPostCopyinReturn",
                     statusReqPrefix);
            _owner->setProperty(key,
                                (uint64_t)(uint32_t)statusOuterPostCopyin, 32);
            snprintf(key, sizeof(key),
                     "AirportRTW89StatusDiagOuter%sBufferChanged",
                     statusReqPrefix);
            _owner->setProperty(key, changed ? kOSBooleanTrue
                                             : kOSBooleanFalse);
            snprintf(key, sizeof(key),
                     "AirportRTW89StatusDiagOuter%sPostNonZeroBytes",
                     statusReqPrefix);
            _owner->setProperty(key, (uint64_t)nonZeroBytes, 32);
        }

        if (statusOuterPostCopyin == 0) {
            if (reqType == APPLE80211_IOC_STATE &&
                statusOuterCopyLength >= sizeof(apple80211_state_data)) {
                apple80211_state_data value = {};
                memcpy(&value, statusOuterAfter, sizeof(value));
                _owner->setProperty("AirportRTW89StatusDiagOuterStateVersion",
                                    (uint64_t)value.version, 32);
                _owner->setProperty("AirportRTW89StatusDiagOuterStateValue",
                                    (uint64_t)value.state, 32);
            } else if (reqType == APPLE80211_IOC_RSSI &&
                       statusOuterCopyLength >= sizeof(apple80211_rssi_data)) {
                apple80211_rssi_data value = {};
                memcpy(&value, statusOuterAfter, sizeof(value));
                _owner->setProperty("AirportRTW89StatusDiagOuterRSSIVersion",
                                    (uint64_t)value.version, 32);
                _owner->setProperty("AirportRTW89StatusDiagOuterRSSINumRadios",
                                    (uint64_t)value.num_radios, 32);
                _owner->setProperty("AirportRTW89StatusDiagOuterRSSIUnit",
                                    (uint64_t)value.rssi_unit, 32);
                _owner->setProperty("AirportRTW89StatusDiagOuterRSSI0",
                                    (uint64_t)(SInt64)value.rssi[0], 64);
                _owner->setProperty("AirportRTW89StatusDiagOuterRSSIAggregate",
                                    (uint64_t)(SInt64)value.aggregate_rssi, 64);
            } else if (reqType == APPLE80211_IOC_ASSOCIATE_RESULT &&
                       statusOuterCopyLength >= sizeof(apple80211_assoc_result_data)) {
                apple80211_assoc_result_data value = {};
                memcpy(&value, statusOuterAfter, sizeof(value));
                _owner->setProperty("AirportRTW89StatusDiagOuterAssocResultVersion",
                                    (uint64_t)value.version, 32);
                _owner->setProperty("AirportRTW89StatusDiagOuterAssocResultValue",
                                    (uint64_t)value.result, 32);
            } else if (reqType == APPLE80211_IOC_ASSOCIATION_STATUS &&
                       statusOuterCopyLength >= sizeof(apple80211_assoc_status_data)) {
                apple80211_assoc_status_data value = {};
                memcpy(&value, statusOuterAfter, sizeof(value));
                _owner->setProperty("AirportRTW89StatusDiagOuterAssocStatusVersion",
                                    (uint64_t)value.version, 32);
                _owner->setProperty("AirportRTW89StatusDiagOuterAssocStatusValue",
                                    (uint64_t)value.status, 32);
            } else if (reqType == APPLE80211_IOC_SSID) {
                if (statusOuterCopyLength >= sizeof(apple80211_ssid_data)) {
                    apple80211_ssid_data value = {};
                    memcpy(&value, statusOuterAfter, sizeof(value));
                    UInt32 ssidLength = value.ssid_len;
                    if (ssidLength > APPLE80211_MAX_SSID_LEN)
                        ssidLength = APPLE80211_MAX_SSID_LEN;
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDStructuredLayout",
                                        kOSBooleanTrue);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDRawLayout",
                                        kOSBooleanFalse);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDVersion",
                                        (uint64_t)value.version, 32);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDLength",
                                        (uint64_t)ssidLength, 32);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDHash",
                                        airportOuterStatusDiagHash(
                                            value.ssid_bytes, ssidLength), 64);
                } else {
                    UInt32 ssidLength = statusOuterCopyLength;
                    if (ssidLength > APPLE80211_MAX_SSID_LEN)
                        ssidLength = APPLE80211_MAX_SSID_LEN;
                    while (ssidLength != 0 &&
                           statusOuterAfter[ssidLength - 1] == 0)
                        --ssidLength;
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDStructuredLayout",
                                        kOSBooleanFalse);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDRawLayout",
                                        kOSBooleanTrue);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDLength",
                                        (uint64_t)ssidLength, 32);
                    _owner->setProperty("AirportRTW89StatusDiagOuterSSIDHash",
                                        airportOuterStatusDiagHash(
                                            statusOuterAfter, ssidLength), 64);
                }
            } else if (reqType == APPLE80211_IOC_BSSID) {
                const UInt8 *bssidBytes = nullptr;
                if (statusOuterCopyLength >= sizeof(apple80211_bssid_data)) {
                    apple80211_bssid_data value = {};
                    memcpy(&value, statusOuterAfter, sizeof(value));
                    bssidBytes = value.bssid.octet;
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDStructuredLayout",
                                        kOSBooleanTrue);
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDRawLayout",
                                        kOSBooleanFalse);
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDVersion",
                                        (uint64_t)value.version, 32);
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDHash",
                                        airportOuterStatusDiagHash(
                                            bssidBytes, APPLE80211_ADDR_LEN), 64);
                } else if (statusOuterCopyLength >= APPLE80211_ADDR_LEN) {
                    bssidBytes = statusOuterAfter;
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDStructuredLayout",
                                        kOSBooleanFalse);
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDRawLayout",
                                        kOSBooleanTrue);
                    _owner->setProperty("AirportRTW89StatusDiagOuterBSSIDHash",
                                        airportOuterStatusDiagHash(
                                            bssidBytes, APPLE80211_ADDR_LEN), 64);
                }
            }
        }
    }

    if (preSET20ChannelDiagCandidate) {
        apple80211_channel_data post = {};
        const int postCopyin = copyin(reqData, &post, sizeof(post));

        UInt32 preNonZeroBytes = 0;
        UInt32 preFirstNonZeroOffset = 0xffffffffU;
        UInt32 preFirstNonZeroValue = 0;
        UInt32 postNonZeroBytes = 0;
        UInt32 postFirstNonZeroOffset = 0xffffffffU;
        UInt32 postFirstNonZeroValue = 0;

        if (preSET20ChannelDiagPreCopyin == 0) {
            const UInt8 *raw = reinterpret_cast<const UInt8 *>(
                &preSET20ChannelDiagPre);
            for (UInt32 i = 0; i < sizeof(preSET20ChannelDiagPre); ++i) {
                if (raw[i] == 0)
                    continue;
                if (preNonZeroBytes == 0) {
                    preFirstNonZeroOffset = i;
                    preFirstNonZeroValue = raw[i];
                }
                ++preNonZeroBytes;
            }
        }
        if (postCopyin == 0) {
            const UInt8 *raw = reinterpret_cast<const UInt8 *>(&post);
            for (UInt32 i = 0; i < sizeof(post); ++i) {
                if (raw[i] == 0)
                    continue;
                if (postNonZeroBytes == 0) {
                    postFirstNonZeroOffset = i;
                    postFirstNonZeroValue = raw[i];
                }
                ++postNonZeroBytes;
            }
        }

        const UInt64 preHash = preSET20ChannelDiagPreCopyin == 0
            ? airportOuterStatusDiagHash(
                  reinterpret_cast<const UInt8 *>(&preSET20ChannelDiagPre),
                  sizeof(preSET20ChannelDiagPre))
            : 0;
        const UInt64 postHash = postCopyin == 0
            ? airportOuterStatusDiagHash(
                  reinterpret_cast<const UInt8 *>(&post), sizeof(post))
            : 0;
        const bool unchanged =
            preSET20ChannelDiagPreCopyin == 0 && postCopyin == 0 &&
            memcmp(&preSET20ChannelDiagPre, &post, sizeof(post)) == 0;
        preSET20ChannelSuperclassUnchanged = unchanged;
        preSET20ChannelSeedOnlyMatch =
            preSET20ChannelDiagPreCopyin == 0 && postCopyin == 0 &&
            preNonZeroBytes == 1U && postNonZeroBytes == 1U &&
            preFirstNonZeroOffset == 0U && postFirstNonZeroOffset == 0U &&
            preFirstNonZeroValue == (UInt32)APPLE80211_VERSION &&
            postFirstNonZeroValue == (UInt32)APPLE80211_VERSION &&
            preSET20ChannelDiagPre.version == APPLE80211_VERSION &&
            preSET20ChannelDiagPre.channel.version == 0U &&
            preSET20ChannelDiagPre.channel.channel == 0U &&
            preSET20ChannelDiagPre.channel.flags == 0U &&
            post.version == APPLE80211_VERSION &&
            post.channel.version == 0U &&
            post.channel.channel == 0U &&
            post.channel.flags == 0U;
        preSET20ChannelEmptySuccessWouldApply =
            result == 6 && preSET20ChannelSuperclassUnchanged &&
            preSET20ChannelSeedOnlyMatch;

        static volatile UInt32 preSET20ChannelDiagCandidateCount = 0;
        const UInt32 candidateCount = __sync_add_and_fetch(
            &preSET20ChannelDiagCandidateCount, 1U);

        _owner->setProperty("AirportRTW89PreSET20ChannelDiagSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagCandidateCount",
                            (uint64_t)candidateCount, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagInheritedReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagReturnIs6",
                            result == 6 ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreCopyinReturn",
                            (uint64_t)(uint32_t)
                                preSET20ChannelDiagPreCopyin, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostCopyinReturn",
                            (uint64_t)(uint32_t)postCopyin, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreNonZeroBytes",
                            (uint64_t)preNonZeroBytes, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelDiagPreFirstNonZeroOffset",
            (uint64_t)preFirstNonZeroOffset, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelDiagPreFirstNonZeroValue",
            (uint64_t)preFirstNonZeroValue, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostNonZeroBytes",
                            (uint64_t)postNonZeroBytes, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelDiagPostFirstNonZeroOffset",
            (uint64_t)postFirstNonZeroOffset, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelDiagPostFirstNonZeroValue",
            (uint64_t)postFirstNonZeroValue, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreHash",
                            preHash, 64);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostHash",
                            postHash, 64);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagSuperclassUnchanged",
                            unchanged ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreVersion",
                            (uint64_t)preSET20ChannelDiagPre.version, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreChannelVersion",
                            (uint64_t)
                                preSET20ChannelDiagPre.channel.version, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreChannelNumber",
                            (uint64_t)
                                preSET20ChannelDiagPre.channel.channel, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPreChannelFlags",
                            (uint64_t)preSET20ChannelDiagPre.channel.flags, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostVersion",
                            (uint64_t)post.version, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostChannelVersion",
                            (uint64_t)post.channel.version, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostChannelNumber",
                            (uint64_t)post.channel.channel, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPostChannelFlags",
                            (uint64_t)post.channel.flags, 32);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagDiagnosticOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20ChannelDiagPayloadModified",
                            kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessSuperclassUnchanged",
            preSET20ChannelSuperclassUnchanged
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessSeedOnlyMatch",
            preSET20ChannelSeedOnlyMatch
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessWouldApply",
            preSET20ChannelEmptySuccessWouldApply
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessPayloadInvented",
            kOSBooleanFalse);
    }

    /* 0.2.175: Tahoe follows the hidden inner POWER callback with
     * setPoweredOnByUser(false).  Re-pin the primary transport only after
     * IO80211Interface::performCommand() has fully returned, so that cleanup
     * cannot strand the Apple80211 control path OFF.  This does not alter the
     * persistent logical state used by GET POWER / Control Center. */
    if (outerPowerSetAuthoritative) {
        _owner->pinAirportTransportUserPowerOn(this);
        _owner->pinAirportTransportSystemEnableOn(this);
        _owner->_airportPowerRelatchPending = false;
        _owner->setProperty("AirportRTW89PrimaryTransportPowerPinnedOn",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterPowerSetPostSuperRelatch",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89OuterPowerSetPostSuperUserPower",
                            poweredOnByUser() ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterPowerSetPostSuperSystemEnable",
                            enabledBySystem() ? kOSBooleanTrue
                                              : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterPowerSetSuperReturn",
                            (uint64_t)(uint32_t)result, 32);

        /* 0.2.188: the authoritative ON edge was applied before the hidden
         * superclass marshaller ran.  Tahoe can therefore cache an earlier
         * framework state before 0.2.175 performs this post-super transport
         * re-pin.  Do not post recursively from this SET stack.  Ask the
         * controller timer to publish one POWER_CHANGED after performCommand
         * has fully unwound.  OFF keeps its proven 0.2.175 notification
         * behavior unchanged. */
        if (outerPowerSetRequestedOn &&
            outerPowerSetApplyResult == kIOReturnSuccess) {
            _owner->_airportPostSuperPowerOnNotifyPending = true;
            _owner->setProperty("AirportRTW89PostSuperPowerOnNotifyPending",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89PostSuperPowerOnNotifyArmed",
                                kOSBooleanTrue);
        }
    }

    if (get11CopyoutProbe) {
        apple80211_scan_result get11After = {};
        const int postCopyin = copyin(reqData, &get11After, sizeof(get11After));
        if (result == kIOReturnSuccess)
            ++get11OuterSuccessCount;
        if (postCopyin == 0)
            ++get11PostCopyinSuccessCount;

        const UInt32 get11InnerSuccessAfter =
            _owner->_airportScanResultSuccessCount;
        const UInt32 get11InnerSuccessDelta =
            get11InnerSuccessAfter >= get11InnerSuccessBefore
                ? get11InnerSuccessAfter - get11InnerSuccessBefore : 0;

        bool changed = false;
        UInt32 nonZeroBytes = 0;
        if (postCopyin == 0) {
            if (get11PreCopyin == 0)
                changed = memcmp(&get11Before, &get11After,
                                 sizeof(get11After)) != 0;
            const UInt8 *bytes =
                reinterpret_cast<const UInt8 *>(&get11After);
            for (size_t i = 0; i < sizeof(get11After); ++i) {
                if (bytes[i] != 0)
                    ++nonZeroBytes;
            }
            if (changed)
                ++get11UserBufferChangedCount;
        }

        const bool successfulCopyoutObserved =
            result == kIOReturnSuccess && postCopyin == 0 &&
            get11InnerSuccessDelta != 0 && get11After.version != 0 &&
            get11After.asr_channel.channel != 0;
        if (successfulCopyoutObserved)
            ++get11SuccessfulCopyoutCount;

        _owner->setProperty("AirportRTW89Get11OuterProbeSuperReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeSuccessCount",
                            (uint64_t)get11OuterSuccessCount, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbePostCopyinReturn",
                            (uint64_t)(uint32_t)postCopyin, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbePostCopyinSuccessCount",
                            (uint64_t)get11PostCopyinSuccessCount, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeUserBufferChanged",
                            changed ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Get11OuterProbeUserBufferChangedCount",
                            (uint64_t)get11UserBufferChangedCount, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbePostNonZeroBytes",
                            (uint64_t)nonZeroBytes, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeInnerSuccessAfter",
                            (uint64_t)get11InnerSuccessAfter, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeInnerSuccessDelta",
                            (uint64_t)get11InnerSuccessDelta, 32);
        _owner->setProperty("AirportRTW89Get11OuterProbeSuccessfulCopyoutObserved",
                            successfulCopyoutObserved ? kOSBooleanTrue
                                                      : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89Get11OuterProbeSuccessfulCopyoutCount",
                            (uint64_t)get11SuccessfulCopyoutCount, 32);

        if (postCopyin == 0) {
            _owner->setProperty("AirportRTW89Get11OuterProbePostVersion",
                                (uint64_t)get11After.version, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostChannelVersion",
                                (uint64_t)get11After.asr_channel.version, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostChannel",
                                (uint64_t)get11After.asr_channel.channel, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostChannelFlags",
                                (uint64_t)get11After.asr_channel.flags, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostRSSI",
                                (uint64_t)(SInt64)get11After.asr_rssi, 64);
            _owner->setProperty("AirportRTW89Get11OuterProbePostNoise",
                                (uint64_t)(SInt64)get11After.asr_noise, 64);
            _owner->setProperty("AirportRTW89Get11OuterProbePostCapability",
                                (uint64_t)(UInt16)get11After.asr_cap, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostBeaconInterval",
                                (uint64_t)(UInt16)get11After.asr_beacon_int, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostSSIDLength",
                                (uint64_t)get11After.asr_ssid_len, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostIELength",
                                (uint64_t)(UInt16)get11After.asr_ie_len, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostRateCount",
                                (uint64_t)get11After.asr_nrates, 32);
            _owner->setProperty("AirportRTW89Get11OuterProbePostAge",
                                (uint64_t)get11After.asr_age, 32);

            OSData *bssid =
                OSData::withBytes(get11After.asr_bssid,
                                  sizeof(get11After.asr_bssid));
            if (bssid) {
                _owner->setProperty("AirportRTW89Get11OuterProbePostBSSID",
                                    bssid);
                bssid->release();
            }
            if (get11After.asr_ssid_len != 0 &&
                get11After.asr_ssid_len <= sizeof(get11After.asr_ssid)) {
                OSData *ssid =
                    OSData::withBytes(get11After.asr_ssid,
                                      get11After.asr_ssid_len);
                if (ssid) {
                    _owner->setProperty("AirportRTW89Get11OuterProbePostSSID",
                                        ssid);
                    ssid->release();
                }
            }

            if (successfulCopyoutObserved) {
                _owner->setProperty("AirportRTW89Get11OuterProbeSuccessVersion",
                                    (uint64_t)get11After.version, 32);
                _owner->setProperty("AirportRTW89Get11OuterProbeSuccessChannel",
                                    (uint64_t)get11After.asr_channel.channel, 32);
                _owner->setProperty("AirportRTW89Get11OuterProbeSuccessSSIDLength",
                                    (uint64_t)get11After.asr_ssid_len, 32);
                _owner->setProperty("AirportRTW89Get11OuterProbeSuccessIELength",
                                    (uint64_t)(UInt16)get11After.asr_ie_len, 32);
                _owner->setProperty("AirportRTW89Get11OuterProbeSuccessCapability",
                                    (uint64_t)(UInt16)get11After.asr_cap, 32);
                OSData *successBSSID =
                    OSData::withBytes(get11After.asr_bssid,
                                      sizeof(get11After.asr_bssid));
                if (successBSSID) {
                    _owner->setProperty("AirportRTW89Get11OuterProbeSuccessBSSID",
                                        successBSSID);
                    successBSSID->release();
                }
                if (get11After.asr_ssid_len != 0 &&
                    get11After.asr_ssid_len <= sizeof(get11After.asr_ssid)) {
                    OSData *successSSID =
                        OSData::withBytes(get11After.asr_ssid,
                                          get11After.asr_ssid_len);
                    if (successSSID) {
                        _owner->setProperty("AirportRTW89Get11OuterProbeSuccessSSID",
                                            successSSID);
                        successSSID->release();
                    }
                }
            }

            const size_t snapshotLength =
                sizeof(get11After) < 96 ? sizeof(get11After) : 96;
            OSData *snapshot = OSData::withBytes(&get11After, snapshotLength);
            if (snapshot) {
                _owner->setProperty("AirportRTW89Get11OuterProbePostFirst96",
                                    snapshot);
                snapshot->release();
            }
        }
    }

    SInt32 finalResult = result;
    if (outerPowerSetAuthoritative &&
        outerPowerSetApplyResult != kIOReturnSuccess)
        finalResult = outerPowerSetApplyResult;

    /* 0.2.234: bounded GET4/CHANNEL seed-empty-success experiment.
     *
     * 0.2.233 measured the exact failing CHANNEL caller shape instead of
     * guessing it.  Every observed bounded candidate had len=16, inherited
     * return 6, an unchanged pre/post buffer, and exactly one non-zero byte:
     * byte 0 == APPLE80211_VERSION (1).  Structurally that is outer version=1
     * with channel.version=0, channel.channel=0 and channel.flags=0.
     *
     * Preserve the inherited superclass call and every payload byte.  Only
     * inside the existing SET22 -> SET20 window, only for GET4 len 16 with
     * inherited return 6, and only when the buffer remains byte-identical and
     * matches that exact proven seed-only structure, normalize the *outer
     * return* to success.  No channel number, flags or band information is
     * invented; NOISE/RATE/MCS/AUTH/ASSOC/EAPOL/key behavior is unchanged.
     */
    /* 0.3.14: Tahoe validates disconnected CHANNEL state after SET22 and
     * before it emits ASSOCIATE/20.  The captured open- and secured-network
     * join windows both stop at the same untouched, version-only GET4 when
     * its inherited return 6 is exposed as -3903.  A successful empty
     * channel object means "not currently associated" and matches the
     * disconnected SSID/BSSID/CURRENT_NETWORK getters; it does not select a
     * BSS or invent channel identity.  Keep this bounded to the already
     * proven SET22 -> SET20 candidate shape. */
    const bool preSET20ChannelEmptySuccessApplied =
        preSET20ChannelEmptySuccessWouldApply;
    if (preSET20ChannelEmptySuccessApplied)
        finalResult = kIOReturnSuccess;

    if (preSET20ChannelDiagCandidate && result == 6) {
        static volatile UInt32 preSET20ChannelEmptySuccessCandidateCount = 0;
        static volatile UInt32 preSET20ChannelEmptySuccessAppliedCount = 0;
        const UInt32 candidateCount = __sync_add_and_fetch(
            &preSET20ChannelEmptySuccessCandidateCount, 1U);
        UInt32 appliedCount = __sync_add_and_fetch(
            &preSET20ChannelEmptySuccessAppliedCount, 0U);
        if (preSET20ChannelEmptySuccessApplied)
            appliedCount = __sync_add_and_fetch(
                &preSET20ChannelEmptySuccessAppliedCount, 1U);

        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessSeen", kOSBooleanTrue);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessCandidateCount",
            (uint64_t)candidateCount, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessAppliedCount",
            (uint64_t)appliedCount, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessReqLen",
            (uint64_t)reqLen, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessInheritedReturn",
            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessExpectedVersion",
            (uint64_t)APPLE80211_VERSION, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessSuperclassUnchanged",
            preSET20ChannelSuperclassUnchanged
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessSeedOnlyMatch",
            preSET20ChannelSeedOnlyMatch
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessWouldApply",
            preSET20ChannelEmptySuccessWouldApply
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessApplied",
            preSET20ChannelEmptySuccessApplied
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessDiagnosticOnly",
            kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessFinalReturn",
            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20ChannelEmptySuccessPayloadInvented",
            kOSBooleanFalse);
    }

    /* 0.2.230: activate the previously diagnostic-only exact raw GET1
     * empty-success condition together with a newly proven raw GET9/BSSID
     * empty-success condition.  Both are bounded to the SET22 -> SET20 window
     * and require post-super all-zero output; no network identity is invented. */
    /* 0.2.215 historical experiment:
     *
     * The 0.2.214 trace proved that Tahoe reaches "Will associate" after the
     * successful SET22 bridge, then repeatedly asks GET SSID with the raw
     * 32-byte Tahoe ABI.  The inherited marshaller reaches airportGet(SSID),
     * which correctly sees no active association and returns 6; IO80211Old
     * exposes that as -3903.  The final GET immediately before airportd's
     * first "Failed to associate ... -3903" is another raw GET1, and SET20
     * never reaches this driver.
     *
     * Do not fabricate a current SSID and do not bypass the superclass.  Let
     * IO80211Interface/airportGet run normally so all existing diagnostics
     * remain authoritative.  Only inside the bounded SET22->SET20 trace
     * window, and only when the exact 32-byte GET1 buffer remains completely
     * empty after the superclass returns 6, normalize the *outer return* to
     * success.  This tests one question only: does Tahoe require "no current
     * SSID" to be represented as empty-success rather than error during the
     * join preflight?
     *
     * Any non-empty output, different length, different inherited error, or
     * traffic outside the association window keeps the original result.
     */
    bool preSET20SSIDEmptySuccessApplied = false;
    bool preSET20SSIDEmptySuccessWouldApply = false;
    int preSET20SSIDPostCopyin = -1;
    UInt32 preSET20SSIDNonZeroBytes = 0;
    const UInt64 preSET20SSIDNowMS = airportWPA2PreflightMonotonicMS();
    const UInt64 preSET20SSIDCaptureStartMS =
        _owner->_airportIOUCAssociationCaptureStartMS;
    const UInt64 preSET20SSIDCaptureAgeMS =
        preSET20SSIDNowMS >= preSET20SSIDCaptureStartMS
            ? preSET20SSIDNowMS - preSET20SSIDCaptureStartMS
            : UINT64_MAX;
    /* 0.5.17: the Tahoe trace finally established the ordering: its secured
     * join wrapper performs a burst of disconnected raw GET1 calls *before*
     * SET22.  Consequently a window armed by SET22 can never cover the
     * status check which aborts the join.  Recognize that preflight by shape
     * and timing instead: at least two exact empty 32-byte GET1 failures in a
     * <= 20 ms burst.  The first isolated query retains the inherited error,
     * avoiding the persistent "unknown network" state seen when every idle
     * SSID query was normalized.  No SSID is synthesized. */
    const bool preSET20SSIDAssociationEpochActive =
        preSET20SSIDCaptureStartMS != 0 &&
        preSET20SSIDCaptureAgeMS <= 25U;
    const bool preSET20SSIDRawCandidate =
        !isSet && reqType == APPLE80211_IOC_SSID && reqData != 0 &&
        reqLen == APPLE80211_MAX_SSID_LEN && result == 6;

    static volatile UInt64 disconnectedSSIDBurstLastMS = 0;
    static volatile UInt64 disconnectedSSIDBurstStartMS = 0;
    static volatile UInt32 disconnectedSSIDBurstCount = 0;
    UInt64 preSET20SSIDBurstStartMS = 0;
    UInt32 preSET20SSIDBurstCount = 0;
    UInt64 previousBurstLastMS = 0;

    if (preSET20SSIDRawCandidate) {
        previousBurstLastMS = __sync_lock_test_and_set(
            &disconnectedSSIDBurstLastMS, preSET20SSIDNowMS);
        if (previousBurstLastMS != 0 &&
            preSET20SSIDNowMS >= previousBurstLastMS &&
            preSET20SSIDNowMS - previousBurstLastMS <= 12U) {
            preSET20SSIDBurstCount = __sync_add_and_fetch(
                &disconnectedSSIDBurstCount, 1U);
            preSET20SSIDBurstStartMS = __sync_add_and_fetch(
                &disconnectedSSIDBurstStartMS, 0U);
        } else {
            __sync_lock_test_and_set(&disconnectedSSIDBurstStartMS,
                                     preSET20SSIDNowMS);
            __sync_lock_test_and_set(&disconnectedSSIDBurstCount, 1U);
            preSET20SSIDBurstStartMS = preSET20SSIDNowMS;
            preSET20SSIDBurstCount = 1U;
        }
    }

    const UInt64 preSET20SSIDBurstAgeMS =
        preSET20SSIDNowMS >= preSET20SSIDBurstStartMS
            ? preSET20SSIDNowMS - preSET20SSIDBurstStartMS
            : UINT64_MAX;
    /* 0.5.42: a GET1 that races immediately after SET22 is already inside
     * the controller-owned association epoch and must not wait for a second
     * GET1 before being normalized.  0.5.41 captured the synchronous Join
     * thread losing that race with raw status 6/-3903, while later
     * concurrent GET1 calls succeeded after the burst counter reached two.
     * Keep the two-call burst recognizer only for the pre-SET22 ordering; the
     * first post-SET22 call is bounded by the much tighter 25 ms epoch. */
    const bool preSET20SSIDCandidate =
        preSET20SSIDRawCandidate &&
        (preSET20SSIDAssociationEpochActive ||
         (preSET20SSIDBurstCount >= 2U && preSET20SSIDBurstAgeMS <= 20U));

    if (preSET20SSIDCandidate) {
        UInt8 rawSSID[APPLE80211_MAX_SSID_LEN] = {};
        preSET20SSIDPostCopyin =
            copyin(reqData, rawSSID, sizeof(rawSSID));
        if (preSET20SSIDPostCopyin == 0) {
            for (UInt32 i = 0; i < sizeof(rawSSID); ++i) {
                if (rawSSID[i] != 0)
                    ++preSET20SSIDNonZeroBytes;
            }
            if (preSET20SSIDNonZeroBytes == 0) {
                preSET20SSIDEmptySuccessWouldApply = true;
                /* 0.4.10: Tahoe 26.5's IO80211Old association wrapper treats
                 * this exact disconnected preflight status as fatal -3903
                 * before it can issue SET20.  Normalize only the outer return;
                 * the empty payload still means no current association. */
                preSET20SSIDEmptySuccessApplied = true;
                finalResult = kIOReturnSuccess;
            }
        }

        static volatile UInt32 preSET20SSIDCandidateCount = 0;
        static volatile UInt32 preSET20SSIDAppliedCount = 0;
        const UInt32 candidateCount = __sync_add_and_fetch(
            &preSET20SSIDCandidateCount, 1U);
        UInt32 appliedCount = __sync_add_and_fetch(
            &preSET20SSIDAppliedCount, 0U);
        if (preSET20SSIDEmptySuccessApplied)
            appliedCount = __sync_add_and_fetch(
                &preSET20SSIDAppliedCount, 1U);

        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessCandidateCount",
                            (uint64_t)candidateCount, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessAppliedCount",
                            (uint64_t)appliedCount, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessCaptureStartMS",
                            (uint64_t)preSET20SSIDCaptureStartMS, 64);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessCaptureAgeMS",
                            (uint64_t)preSET20SSIDCaptureAgeMS, 64);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessEpochBoundMS",
                            (uint64_t)25U, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessCrossThreadEpoch",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessInheritedReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessPostCopyinReturn",
                            (uint64_t)(uint32_t)preSET20SSIDPostCopyin, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessNonZeroBytes",
                            (uint64_t)preSET20SSIDNonZeroBytes, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessApplied",
                            preSET20SSIDEmptySuccessApplied
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessWouldApply",
                            preSET20SSIDEmptySuccessWouldApply
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessDiagnosticOnly",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessFinalReturn",
                            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty("AirportRTW89PreSET20SSIDEmptySuccessPayloadInvented",
                            kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET22SSIDBurstRecognized",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET22SSIDBurstCount",
                            (uint64_t)preSET20SSIDBurstCount, 32);
        _owner->setProperty("AirportRTW89PreSET22SSIDBurstStartMS",
                            (uint64_t)preSET20SSIDBurstStartMS, 64);
        _owner->setProperty("AirportRTW89PreSET22SSIDBurstAgeMS",
                            (uint64_t)preSET20SSIDBurstAgeMS, 64);
        _owner->setProperty("AirportRTW89PreSET22SSIDBurstGapBoundMS",
                            (uint64_t)12U, 32);
        _owner->setProperty("AirportRTW89PreSET22SSIDBurstAgeBoundMS",
                            (uint64_t)20U, 32);
    }

    /* 0.2.230: bounded GET9/BSSID empty-success experiment.
     *
     * The 0.2.229 runtime captured Tahoe issuing a raw six-byte disconnected
     * BSSID getter during the SET22 -> SET20 preflight window.  The inner and
     * superclass paths both return 6 and the six-byte caller buffer remains
     * completely zero.  Treat only that exact empty raw form as successful
     * "no current BSSID" status.  Never copy a candidate AP BSSID into this
     * status getter and never synthesize SET20.
     */
    bool preSET20BSSIDEmptySuccessApplied = false;
    bool preSET20BSSIDEmptySuccessWouldApply = false;
    int preSET20BSSIDPostCopyin = -1;
    UInt32 preSET20BSSIDNonZeroBytes = 0;
    const bool preSET20BSSIDCandidate =
        wpa2TraceCookie.active && !isSet &&
        reqType == APPLE80211_IOC_BSSID && reqData != 0 &&
        reqLen == APPLE80211_ADDR_LEN && result == 6;

    if (preSET20BSSIDCandidate) {
        UInt8 rawBSSID[APPLE80211_ADDR_LEN] = {};
        preSET20BSSIDPostCopyin =
            copyin(reqData, rawBSSID, sizeof(rawBSSID));
        if (preSET20BSSIDPostCopyin == 0) {
            for (UInt32 i = 0; i < sizeof(rawBSSID); ++i) {
                if (rawBSSID[i] != 0)
                    ++preSET20BSSIDNonZeroBytes;
            }
            if (preSET20BSSIDNonZeroBytes == 0) {
                preSET20BSSIDEmptySuccessWouldApply = true;
                /* 0.3.5: diagnostic only; retain inherited IO80211Reference-style error. */
            }
        }

        static volatile UInt32 preSET20BSSIDCandidateCount = 0;
        static volatile UInt32 preSET20BSSIDAppliedCount = 0;
        const UInt32 candidateCount = __sync_add_and_fetch(
            &preSET20BSSIDCandidateCount, 1U);
        UInt32 appliedCount = __sync_add_and_fetch(
            &preSET20BSSIDAppliedCount, 0U);
        if (preSET20BSSIDEmptySuccessApplied)
            appliedCount = __sync_add_and_fetch(
                &preSET20BSSIDAppliedCount, 1U);

        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessCandidateCount",
                            (uint64_t)candidateCount, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessAppliedCount",
                            (uint64_t)appliedCount, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessInheritedReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessPostCopyinReturn",
                            (uint64_t)(uint32_t)preSET20BSSIDPostCopyin, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessNonZeroBytes",
                            (uint64_t)preSET20BSSIDNonZeroBytes, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessApplied",
                            preSET20BSSIDEmptySuccessApplied
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessWouldApply",
                            preSET20BSSIDEmptySuccessWouldApply
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessDiagnosticOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessFinalReturn",
                            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty("AirportRTW89PreSET20BSSIDEmptySuccessPayloadInvented",
                            kOSBooleanFalse);
    }

    /* 0.2.231: bounded GET103/CURRENT_NETWORK seed-empty-success experiment.
     *
     * The 0.2.230 run falsified raw GET1/SSID + GET9/BSSID empty-success as
     * the remaining pre-SET20 gate.  Tahoe still never emitted SET20, while
     * GET103 immediately around "Will associate" continued to return 102
     * through the inherited path (surfaced by IO80211Old as -3903).
     *
     * The retained 0.2.217 metadata now proves the 1164-byte GET103 caller
     * buffer is not an all-zero object: it contains exactly one non-zero byte
     * at offset 139 with value 4, is byte-for-byte unchanged by the superclass,
     * and otherwise remains empty.  With this Monterey+ packed ABI,
     * apple80211_scan_result::asr_ie_len occupies offsets 138..139, so that
     * one-byte signature is the little-endian representation of the caller's
     * asr_ie_len capacity seed 0x0400 == 1024.
     *
     * Preserve the superclass call and preserve every payload byte.  Only in
     * the existing SET22 -> SET20 window, only for GET103 len 1164 with
     * inherited return 102, only when pre/post metadata is unchanged, and only
     * when the complete post-super buffer has exactly the proven seed-only
     * shape (asr_ie_len == 1024 and every other byte zero), normalize the
     * *outer return* to success.  No SSID/BSSID/channel/security/current-network
     * payload is invented and SET20 is never synthesized.
     */
    bool preSET20CurrentNetworkEmptySuccessApplied = false;
    bool preSET20CurrentNetworkEmptySuccessWouldApply = false;
    int preSET20CurrentNetworkPostCopyin =
        parityCurrentNetworkPost.copyinResult;
    UInt32 preSET20CurrentNetworkNonZeroBytes =
        parityCurrentNetworkPost.nonZeroBytes;
    UInt32 preSET20CurrentNetworkBytesChecked =
        parityCurrentNetworkPost.bytesChecked;
    const UInt32 preSET20CurrentNetworkIELengthOffset =
        (UInt32)__builtin_offsetof(apple80211_scan_result, asr_ie_len);
    int preSET20CurrentNetworkSeedCopyin = -1;
    UInt16 preSET20CurrentNetworkSeedIELength = 0;
    bool preSET20CurrentNetworkSuperclassUnchanged = false;
    bool preSET20CurrentNetworkSeedOnlyMatch = false;
    const bool preSET20CurrentNetworkCandidate =
        wpa2TraceCookie.active && !isSet &&
        reqType == APPLE80211_IOC_CURRENT_NETWORK && reqData != 0 &&
        reqLen == sizeof(apple80211_scan_result) && result == 102;

    if (preSET20CurrentNetworkCandidate) {
        preSET20CurrentNetworkSuperclassUnchanged =
            parityCurrentNetworkPre.copyinResult == 0 &&
            parityCurrentNetworkPost.copyinResult == 0 &&
            parityCurrentNetworkPre.bytesChecked == reqLen &&
            parityCurrentNetworkPost.bytesChecked == reqLen &&
            parityCurrentNetworkPre.hash == parityCurrentNetworkPost.hash &&
            parityCurrentNetworkPre.nonZeroBytes ==
                parityCurrentNetworkPost.nonZeroBytes &&
            parityCurrentNetworkPre.firstNonZeroOffset ==
                parityCurrentNetworkPost.firstNonZeroOffset &&
            parityCurrentNetworkPre.firstNonZeroValue ==
                parityCurrentNetworkPost.firstNonZeroValue;

        preSET20CurrentNetworkSeedCopyin = copyin(
            reqData + preSET20CurrentNetworkIELengthOffset,
            &preSET20CurrentNetworkSeedIELength,
            sizeof(preSET20CurrentNetworkSeedIELength));

        if (preSET20CurrentNetworkSeedCopyin == 0 &&
            preSET20CurrentNetworkSeedIELength == 1024U &&
            preSET20CurrentNetworkNonZeroBytes == 1U &&
            parityCurrentNetworkPost.firstNonZeroOffset ==
                preSET20CurrentNetworkIELengthOffset + 1U &&
            parityCurrentNetworkPost.firstNonZeroValue == 4U) {
            preSET20CurrentNetworkSeedOnlyMatch = true;
        }

        if (preSET20CurrentNetworkSuperclassUnchanged &&
            preSET20CurrentNetworkSeedOnlyMatch) {
            preSET20CurrentNetworkEmptySuccessWouldApply = true;
            /* 0.3.5: diagnostic only; retain inherited IO80211Reference-style error. */
        }

        static volatile UInt32 preSET20CurrentNetworkCandidateCount = 0;
        static volatile UInt32 preSET20CurrentNetworkAppliedCount = 0;
        const UInt32 candidateCount = __sync_add_and_fetch(
            &preSET20CurrentNetworkCandidateCount, 1U);
        UInt32 appliedCount = __sync_add_and_fetch(
            &preSET20CurrentNetworkAppliedCount, 0U);
        if (preSET20CurrentNetworkEmptySuccessApplied)
            appliedCount = __sync_add_and_fetch(
                &preSET20CurrentNetworkAppliedCount, 1U);

        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSeen",
            kOSBooleanTrue);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessCandidateCount",
            (uint64_t)candidateCount, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessAppliedCount",
            (uint64_t)appliedCount, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessReqLen",
            (uint64_t)reqLen, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessInheritedReturn",
            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessPostCopyinReturn",
            (uint64_t)(uint32_t)preSET20CurrentNetworkPostCopyin, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessBytesChecked",
            (uint64_t)preSET20CurrentNetworkBytesChecked, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessNonZeroBytes",
            (uint64_t)preSET20CurrentNetworkNonZeroBytes, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSeedCopyinReturn",
            (uint64_t)(uint32_t)preSET20CurrentNetworkSeedCopyin, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSeedIELength",
            (uint64_t)preSET20CurrentNetworkSeedIELength, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSeedIELengthOffset",
            (uint64_t)preSET20CurrentNetworkIELengthOffset, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSeedExpectedIELength",
            (uint64_t)1024U, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSuperclassUnchanged",
            preSET20CurrentNetworkSuperclassUnchanged
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessSeedOnlyMatch",
            preSET20CurrentNetworkSeedOnlyMatch
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessApplied",
            preSET20CurrentNetworkEmptySuccessApplied
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessWouldApply",
            preSET20CurrentNetworkEmptySuccessWouldApply
                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessDiagnosticOnly",
            kOSBooleanTrue);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessFinalReturn",
            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty(
            "AirportRTW89PreSET20CurrentNetworkEmptySuccessPayloadInvented",
            kOSBooleanFalse);
    }

    /* 0.2.232: bounded GET16/RSSI seed-empty-success experiment.
     *
     * 0.2.231 proved the exact GET103 seed-only normalization applies and
     * changes the public CURRENT_NETWORK return to success, yet Tahoe still
     * never emits SET20.  The same bounded trace identifies GET16/RSSI as the
     * last persistent non-success request (return 6).  Existing status-probe
     * telemetry proves the 52-byte caller buffer is byte-for-byte unchanged
     * by the superclass and contains only the public version seed: version=1,
     * num_radios=0, unit=0, all RSSI fields zero.
     *
     * Preserve the superclass call and every payload byte.  Only inside the
     * existing SET22 -> SET20 window, only for GET16 len 52 with inherited
     * return 6, and only when the post-super buffer is identical to the
     * pre-super buffer and has exactly the proven seed-only form, normalize
     * the *outer return* to success.  No RSSI value is invented and CHANNEL,
     * NOISE, RATE, MCS, AUTH/ASSOC/EAPOL/key behavior remains untouched.
     */
    bool preSET20RSSIEmptySuccessApplied = false;
    bool preSET20RSSIEmptySuccessWouldApply = false;
    int preSET20RSSIPostCopyin = -1;
    UInt32 preSET20RSSINonZeroBytes = 0;
    UInt32 preSET20RSSIFirstNonZeroOffset = 0xffffffffU;
    UInt32 preSET20RSSIFirstNonZeroValue = 0;
    bool preSET20RSSISuperclassUnchanged = false;
    bool preSET20RSSISeedOnlyMatch = false;
    apple80211_rssi_data preSET20RSSIPost = {};
    const bool preSET20RSSICandidate =
        wpa2TraceCookie.active && !isSet &&
        reqType == APPLE80211_IOC_RSSI && reqData != 0 &&
        reqLen == sizeof(apple80211_rssi_data) && result == 6;

    if (preSET20RSSICandidate) {
        preSET20RSSIPostCopyin = copyin(
            reqData, &preSET20RSSIPost, sizeof(preSET20RSSIPost));

        if (statusOuterPreCopyin == 0 && preSET20RSSIPostCopyin == 0 &&
            statusOuterCopyLength == sizeof(preSET20RSSIPost)) {
            preSET20RSSISuperclassUnchanged =
                memcmp(statusOuterBefore, &preSET20RSSIPost,
                       sizeof(preSET20RSSIPost)) == 0;
        }

        if (preSET20RSSIPostCopyin == 0) {
            const UInt8 *raw =
                reinterpret_cast<const UInt8 *>(&preSET20RSSIPost);
            for (UInt32 i = 0; i < sizeof(preSET20RSSIPost); ++i) {
                if (raw[i] == 0)
                    continue;
                if (preSET20RSSINonZeroBytes == 0) {
                    preSET20RSSIFirstNonZeroOffset = i;
                    preSET20RSSIFirstNonZeroValue = raw[i];
                }
                ++preSET20RSSINonZeroBytes;
            }

            preSET20RSSISeedOnlyMatch =
                preSET20RSSIPost.version == APPLE80211_VERSION &&
                preSET20RSSIPost.num_radios == 0U &&
                preSET20RSSIPost.rssi_unit == 0U &&
                preSET20RSSINonZeroBytes == 1U &&
                preSET20RSSIFirstNonZeroOffset == 0U &&
                preSET20RSSIFirstNonZeroValue ==
                    (UInt32)APPLE80211_VERSION;
        }

        if (preSET20RSSISuperclassUnchanged &&
            preSET20RSSISeedOnlyMatch) {
            preSET20RSSIEmptySuccessWouldApply = true;
            /* 0.3.5: diagnostic only; retain inherited IO80211Reference-style error. */
        }

        static volatile UInt32 preSET20RSSICandidateCount = 0;
        static volatile UInt32 preSET20RSSIAppliedCount = 0;
        const UInt32 candidateCount = __sync_add_and_fetch(
            &preSET20RSSICandidateCount, 1U);
        UInt32 appliedCount = __sync_add_and_fetch(
            &preSET20RSSIAppliedCount, 0U);
        if (preSET20RSSIEmptySuccessApplied)
            appliedCount = __sync_add_and_fetch(
                &preSET20RSSIAppliedCount, 1U);

        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessSeen",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessCandidateCount",
                            (uint64_t)candidateCount, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessAppliedCount",
                            (uint64_t)appliedCount, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessReqLen",
                            (uint64_t)reqLen, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessInheritedReturn",
                            (uint64_t)(uint32_t)result, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessPostCopyinReturn",
                            (uint64_t)(uint32_t)preSET20RSSIPostCopyin, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessNonZeroBytes",
                            (uint64_t)preSET20RSSINonZeroBytes, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessFirstNonZeroOffset",
                            (uint64_t)preSET20RSSIFirstNonZeroOffset, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessFirstNonZeroValue",
                            (uint64_t)preSET20RSSIFirstNonZeroValue, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessVersion",
                            (uint64_t)preSET20RSSIPost.version, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessExpectedVersion",
                            (uint64_t)APPLE80211_VERSION, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessNumRadios",
                            (uint64_t)preSET20RSSIPost.num_radios, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessUnit",
                            (uint64_t)preSET20RSSIPost.rssi_unit, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessRSSI0",
                            (uint64_t)(uint32_t)preSET20RSSIPost.rssi[0], 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessAggregate",
                            (uint64_t)(uint32_t)preSET20RSSIPost.aggregate_rssi,
                            32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessSuperclassUnchanged",
                            preSET20RSSISuperclassUnchanged
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessSeedOnlyMatch",
                            preSET20RSSISeedOnlyMatch
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessApplied",
                            preSET20RSSIEmptySuccessApplied
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessWouldApply",
                            preSET20RSSIEmptySuccessWouldApply
                                ? kOSBooleanTrue : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessDiagnosticOnly",
                            kOSBooleanTrue);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessFinalReturn",
                            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty("AirportRTW89PreSET20RSSIEmptySuccessPayloadInvented",
                            kOSBooleanFalse);
    }

    /* 0.3.5: finish the inherited-path parity record.  The historical
     * normalization predicates remain visible as WouldNormalize flags, but
     * no GET1/4/9/16/103 return is rewritten. */
    if (parityTraceEntry) {
        if (preSET20SSIDEmptySuccessWouldApply)
            parityTraceEntry->flags |= kParityTraceGET1WouldNormalize;
        if (preSET20BSSIDEmptySuccessWouldApply)
            parityTraceEntry->flags |= kParityTraceGET9WouldNormalize;
        if (preSET20CurrentNetworkEmptySuccessWouldApply)
            parityTraceEntry->flags |= kParityTraceGET103WouldNormalize;
        if (preSET20RSSIEmptySuccessWouldApply)
            parityTraceEntry->flags |= kParityTraceGET16WouldNormalize;
        parityTraceEntry->finalReturn = finalResult;
        parityTraceEntry->exitMonotonicMS =
            airportWPA2PreflightMonotonicMS();
        parityTraceEntry->flags |= kParityTraceComplete;
        __sync_synchronize();

        const UInt32 ringCount =
            parityTraceOrdinal < 256U ? parityTraceOrdinal : 256U;
        _owner->setProperty("AirportRTW89ParityTraceEntrySize",
                            (uint64_t)sizeof(IO80211ReferenceParityTraceEntry), 32);
        _owner->setProperty("AirportRTW89ParityTraceRingCount",
                            (uint64_t)ringCount, 32);
        _owner->setProperty("AirportRTW89ParityTraceRingIndex",
                            (uint64_t)(parityTraceOrdinal & 255U), 32);
        _owner->setProperty("AirportRTW89ParityTracePayloadCaptured",
                            kOSBooleanFalse);
        if (OSData *traceData = OSData::withBytes(
                gIO80211ReferenceParityTraceRing,
                sizeof(gIO80211ReferenceParityTraceRing))) {
            _owner->setProperty("AirportRTW89ParityTraceRing", traceData);
            traceData->release();
        }
    }

    if (parityScope && parityScope->sequence == parityOuterSequence) {
        __sync_synchronize();
        parityScope->active = false;
        parityScope->thread = THREAD_NULL;
    }

    _owner->setProperty(
        "AirportRTW89InterfaceApple80211PerformCommandReturn",
        (uint64_t)(uint32_t)finalResult, 32);
    if (outerPowerSetAuthoritative) {
        _owner->setProperty("AirportRTW89OuterPowerSetFinalReturn",
                            (uint64_t)(uint32_t)finalResult, 32);
        _owner->setProperty("AirportRTW89OuterPowerSetRequestedOn",
                            outerPowerSetRequestedOn ? kOSBooleanTrue
                                                     : kOSBooleanFalse);
        _owner->setProperty("AirportRTW89OuterPowerSetChangedFinal",
                            outerPowerSetChanged ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
    }
    return airportWPA2PreflightTraceFinish(
        _owner, wpa2TraceCookie, finalResult, kWPA2TraceSuperclass);
}

UInt32 AirportRTW89Interface::inputPacket(mbuf_t packet, UInt32 length,
                                          IOOptionBits options,
                                          void *parameter)
{
    const size_t packetLength = mbuf_len(packet);
    const ether_header_t *header =
        static_cast<const ether_header_t *>(mbuf_data(packet));

    if (packetLength >= sizeof(ether_header_t) &&
        header->ether_type == htons(ETHERTYPE_PAE)) {
        if (_owner) {
            static volatile UInt32 eapolInputCount = 0;
            const UInt32 sequence = __sync_add_and_fetch(&eapolInputCount, 1U);
            const UInt64 nowMS = airportWPA2PreflightMonotonicMS();
            _owner->setProperty("AirportRTW89SecurityControlEAPOLInputSeen",
                                kOSBooleanTrue);
            _owner->setProperty("AirportRTW89SecurityControlEAPOLInputCount",
                                (uint64_t)sequence, 32);
            if (sequence == 1U)
                _owner->setProperty("AirportRTW89SecurityControlEAPOLInputFirstMS",
                                    (uint64_t)nowMS, 64);
            _owner->setProperty("AirportRTW89SecurityControlEAPOLInputLastMS",
                                (uint64_t)nowMS, 64);
            _owner->setProperty("AirportRTW89SecurityControlEAPOLRoutedViaIO80211",
                                kOSBooleanTrue);
        }
        return IO80211Interface::inputPacket(
            packet, static_cast<UInt32>(packetLength), 0, parameter);
    }
    return IOEthernetInterface::inputPacket(packet, length, options, parameter);
}

IONetworkInterface *RTW88PCIDevice::createInterface(void)
{
    if (_creatingSkywalkBSDCompanion) {
        setProperty("AirportRTW89SkywalkBSDCompanionCreateInterfaceCalled",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkBSDCompanionCreateSkywalkPresent",
                    _skywalkInterface ? kOSBooleanTrue : kOSBooleanFalse);
        AirportRTW89SkywalkBSDInterface *interface =
            new AirportRTW89SkywalkBSDInterface;
        setProperty("AirportRTW89SkywalkBSDCompanionAllocationSucceeded",
                    interface ? kOSBooleanTrue : kOSBooleanFalse);
        if (!interface)
            return nullptr;
        const bool initOK = interface->initWithSkywalkInterfaceAndProvider(
                this, _skywalkInterface);
        setProperty("AirportRTW89SkywalkBSDCompanionInitSucceeded",
                    initOK ? kOSBooleanTrue : kOSBooleanFalse);
        if (!initOK) {
            interface->release();
            return nullptr;
        }
        setProperty("AirportRTW89SkywalkBSDCompanionCreateInterfaceReturned",
                    kOSBooleanTrue);
        return interface;
    }

    /* 0.2.142: exactly one BSD owner.  The Skywalk control object is never
     * returned from createInterface() and cannot create or claim another enX. */
    AirportRTW89Interface *interface = new AirportRTW89Interface;
    if (!interface)
        return nullptr;
    if (!interface->init(this, this)) {
        interface->release();
        return nullptr;
    }
    return interface;
}

IOReturn RTW88PCIDevice::enable(IO80211SkywalkInterface *interface)
{
    setProperty("AirportRTW89SkywalkEnableSeen", kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkEnableIsPrimary",
                interface && interface == _skywalkInterface
                    ? kOSBooleanTrue : kOSBooleanFalse);

    /* The final Skywalk object is a passive registration/control identity.
     * If the restored framework probes enable(), acknowledge it without
     * entering private Skywalk power code or touching the RTW89 backend. */
    if (interface && interface == _skywalkInterface &&
        interface->getProperty("AirportRTW89ControlOnlySkywalkService") ==
            kOSBooleanTrue) {
        setProperty("AirportRTW89ControlOnlySkywalkEnableSuppressed",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }

    /* 0.2.80 is a publication-only probe.  If simply registering the
     * Skywalk service makes the framework ask for enable(), record that fact
     * but do not enter restored-framework power code or touch the hardware. */
    if (_skywalkRegisterOnlyProbe) {
        setProperty("AirportRTW89SkywalkRegisterOnlyEnableSuppressed",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }

    publishSkywalkPowerState("before-super-enable");

    IOReturn frameworkResult = super::enable(interface);
    setProperty("AirportRTW89SkywalkSuperEnableReturn",
                (uint64_t)(uint32_t)frameworkResult, 32);
    publishSkywalkPowerState("after-super-enable");
    if (frameworkResult != kIOReturnSuccess)
        return frameworkResult;

    /* Keep hardware enable idempotent with the already-working legacy path.
     * Avoid recursively calling the IONetworkInterface overload. */
    IOReturn hardwareResult = kIOReturnSuccess;
    if (!_enabled) {
        if (!_ieee80211) {
            hardwareResult = kIOReturnNotReady;
        } else {
            hardwareResult = _ieee80211->powerOn();
            if (hardwareResult == kIOReturnSuccess) {
                if (_txQueue)
                    _txQueue->start();
                if (_intrSrc)
                    _intrSrc->enable();
                _enabled = true;
                setProperty("AirportRTW89ControllerEnabled", kOSBooleanTrue);
            }
        }
    }

    setProperty("AirportRTW89SkywalkHardwareEnableReturn",
                (uint64_t)(uint32_t)hardwareResult, 32);
    publishSkywalkPowerState("after-hardware-enable");
    return hardwareResult;
}

IOReturn RTW88PCIDevice::disable(IO80211SkywalkInterface *interface)
{
    setProperty("AirportRTW89SkywalkDisableSeen", kOSBooleanTrue);
    if (interface && interface == _skywalkInterface &&
        interface->getProperty("AirportRTW89ControlOnlySkywalkService") ==
            kOSBooleanTrue) {
        setProperty("AirportRTW89ControlOnlySkywalkDisableSuppressed",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    if (_skywalkRegisterOnlyProbe) {
        setProperty("AirportRTW89SkywalkRegisterOnlyDisableSuppressed",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    publishSkywalkPowerState("before-super-disable");

    IOReturn frameworkResult = super::disable(interface);
    setProperty("AirportRTW89SkywalkSuperDisableReturn",
                (uint64_t)(uint32_t)frameworkResult, 32);
    publishSkywalkPowerState("after-super-disable");

    /* Match the legacy bring-up policy: do not power the Realtek backend down
     * merely because Tahoe replays a saved Off state while the interface graph
     * is still settling.  The explicit teardown path owns hardware shutdown. */
    setProperty("AirportRTW89SkywalkHardwareDisableSuppressed",
                kOSBooleanTrue);
    return frameworkResult;
}
#endif

IOReturn RTW88PCIDevice::enable(IONetworkInterface *iface)
{
    IOLog("rtw88: enable\n");
#ifdef RTW_AIRPORT
    if (iface && iface == _skywalkBSDCompanion) {
        setProperty("AirportRTW89SkywalkBSDCompanionEnableSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkBSDCompanionEnableLegacyPathSuppressed",
                    kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionEnableForwardedToController",
                    kOSBooleanTrue);
    }

    const UInt32 powerEventSequence = ++_airportPowerEventSequence;
    ++_airportControllerEnableCount;
    setProperty("AirportRTW89PowerEventSequence",
                (uint64_t)_airportPowerEventSequence, 32);
    setProperty("AirportRTW89ControllerEnableSequence",
                (uint64_t)powerEventSequence, 32);
    setProperty("AirportRTW89ControllerEnableCount",
                (uint64_t)_airportControllerEnableCount, 32);
    setProperty("AirportRTW89ControllerEnableLogicalBefore",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);

    IO80211Interface *powerAuthority = OSDynamicCast(
        IO80211Interface, iface ? iface : _iface);
    const bool primaryPowerAuthority =
        powerAuthority != nullptr && powerAuthority == _iface;
    setProperty("AirportRTW89ControllerEnablePrimaryPowerAuthority",
                primaryPowerAuthority ? kOSBooleanTrue : kOSBooleanFalse);

    /* 0.3.26: in the legacy topology, controller enable() remains transport
     * lifecycle only and does not author user-visible Wi-Fi power.  In the
     * exclusive-native topology, however, the legacy IO80211Interface has been
     * deliberately removed; the accepted Skywalk BSD companion is now the only
     * IO80211 network interface that Tahoe enables.  Treat that first native
     * companion enable edge as the initial logical ON authority so the existing
     * Apple80211 power state and RTW89 logical-power machinery are rejoined. */
    const bool nativeCompanionPowerAuthority =
        airportNativeTopologyExperiment() && airportExclusiveNativeTopology() &&
        iface && iface == _skywalkBSDCompanion;
    const bool userPowerTransitionOn =
        nativeCompanionPowerAuthority && !_airportLogicalPowerOn;
    setProperty("AirportRTW89NativeCompanionPowerAuthority",
                nativeCompanionPowerAuthority ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NativeCompanionInitialLogicalOnRequested",
                userPowerTransitionOn ? kOSBooleanTrue : kOSBooleanFalse);

    IOReturn nativeLogicalPowerResult = kIOReturnSuccess;
    if (userPowerTransitionOn) {
        nativeLogicalPowerResult = applyAirportUserPowerState(
            true, kAirportLogicalPowerControllerEnable);
        setProperty("AirportRTW89NativeCompanionInitialLogicalOnReturn",
                    (uint64_t)(uint32_t)nativeLogicalPowerResult, 32);
    }

    setProperty("AirportRTW89ControllerEnablePowerStatePreserved",
                nativeCompanionPowerAuthority ? kOSBooleanFalse : kOSBooleanTrue);
    setProperty("AirportRTW89ControllerEnableLogicalAfter",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);
#if __IO80211_TARGET >= __MAC_13_0
    if (_skywalkInterface)
        _skywalkInterface->IO80211InfraInterface::setPoweredOnByUser(true);
#endif

    /* Match IO80211Reference's legacy lifecycle: let IO80211FamilyLegacy enable
     * its interface bookkeeping before powering/relatching the radio. */
    super::enable(iface);
    setProperty("AirportRTW89ControllerEnableSeen", kOSBooleanTrue);
    setProperty("AirportRTW89ControllerEnableWasAlreadyEnabled",
                _enabled ? kOSBooleanTrue : kOSBooleanFalse);
#endif
    if (_enabled) {
#ifdef RTW_AIRPORT
        if (_ieee80211)
            _ieee80211->cmdSetUserPower(_airportLogicalPowerOn);
        synchronizeAirportPowerState(iface);

        /* OFF -> ON is a user-visible rescan edge.  Keep the RTW89 hardware
         * alive across OFF, then force exactly one fresh real RF scan here so
         * toggling Wi-Fi restores/repopulates the network list. */
        if (userPowerTransitionOn && _ieee80211) {
            airportResetScanCache();
            _airportScanObserved = true;
            IOReturn scanResult = _ieee80211->cmdScan();
            if (scanResult == kIOReturnBusy)
                scanResult = kIOReturnSuccess;
            if (scanResult != kIOReturnSuccess)
                _airportScanObserved = false;
            setProperty("AirportRTW89UserPowerOnFreshScanTriggered",
                        kOSBooleanTrue);
            setProperty("AirportRTW89UserPowerOnFreshScanReturn",
                        (uint64_t)(uint32_t)scanResult, 32);
            if (scanResult == kIOReturnSuccess && _airportScanDoneTimer) {
                _airportScanDoneTimer->cancelTimeout();
                _airportScanDoneTimerPending = true;
                _airportScanDoneTimer->setTimeoutMS(100);
            }
        }
        setProperty("AirportRTW89ControllerEnableReturn", (uint64_t)0, 32);
#endif
        return kIOReturnSuccess;
    }
    if (!_ieee80211) {
#ifdef RTW_AIRPORT
        setProperty("AirportRTW89ControllerEnableReturn",
                    (uint64_t)(uint32_t)kIOReturnNotReady, 32);
#endif
        return kIOReturnNotReady;
    }

    /* Probe ran in start(); now power on the hardware for TX/RX.  For rtw89
     * this is normally already true, making the operation idempotent. */
    IOReturn ret = _ieee80211->powerOn();
    if (ret != kIOReturnSuccess) {
        IOLog("rtw88: powerOn failed (0x%08x)\n", ret);
#ifdef RTW_AIRPORT
        setProperty("AirportRTW89ControllerEnableFailed", kOSBooleanTrue);
        setProperty("AirportRTW89ControllerEnableReturn",
                    (uint64_t)(uint32_t)ret, 32);
#endif
        return ret;
    }

    if (_txQueue && !_skywalkOwnsBSDQueue) _txQueue->start();
#ifdef RTW_AIRPORT
    if (!_skywalkOwnsBSDQueue)
        airportPublishOutputQueueDiagnostics("enable-after-start");
    else
        setProperty("AirportRTW89LegacyOutputQueueEnableSuppressed",
                    kOSBooleanTrue);
#endif
    if (_intrSrc) _intrSrc->enable();
    _enabled = true;
#ifdef RTW_AIRPORT
    setProperty("AirportRTW89ControllerEnabled", kOSBooleanTrue);
    setProperty("AirportRTW89ControllerEnableReturn", (uint64_t)0, 32);
    if (_ieee80211)
        _ieee80211->cmdSetUserPower(_airportLogicalPowerOn);
    synchronizeAirportPowerState(iface);

    if (userPowerTransitionOn && _ieee80211) {
        airportResetScanCache();
        _airportScanObserved = true;
        IOReturn scanResult = _ieee80211->cmdScan();
        if (scanResult == kIOReturnBusy)
            scanResult = kIOReturnSuccess;
        if (scanResult != kIOReturnSuccess)
            _airportScanObserved = false;
        setProperty("AirportRTW89UserPowerOnFreshScanTriggered",
                    kOSBooleanTrue);
        setProperty("AirportRTW89UserPowerOnFreshScanReturn",
                    (uint64_t)(uint32_t)scanResult, 32);
        if (scanResult == kIOReturnSuccess && _airportScanDoneTimer) {
            _airportScanDoneTimer->cancelTimeout();
            _airportScanDoneTimerPending = true;
            _airportScanDoneTimer->setTimeoutMS(100);
        }
    }
#endif
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::disable(IONetworkInterface *iface)
{
    IOLog("rtw88: disable\n");
#ifdef RTW_AIRPORT
    if (iface && iface == _skywalkBSDCompanion) {
        setProperty("AirportRTW89SkywalkBSDCompanionDisableSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkBSDCompanionDisableLegacyPathSuppressed",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }

    const UInt32 powerEventSequence = ++_airportPowerEventSequence;
    ++_airportControllerDisableCount;
    setProperty("AirportRTW89PowerEventSequence",
                (uint64_t)_airportPowerEventSequence, 32);
    setProperty("AirportRTW89ControllerDisableSequence",
                (uint64_t)powerEventSequence, 32);
    setProperty("AirportRTW89ControllerDisableCount",
                (uint64_t)_airportControllerDisableCount, 32);
    setProperty("AirportRTW89ControllerDisableLogicalBefore",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);

    IO80211Interface *powerAuthority = OSDynamicCast(
        IO80211Interface, iface ? iface : _iface);
    const bool primaryPowerAuthority =
        powerAuthority != nullptr && powerAuthority == _iface;
    setProperty("AirportRTW89ControllerDisablePrimaryPowerAuthority",
                primaryPowerAuthority ? kOSBooleanTrue : kOSBooleanFalse);

    /* 0.2.170: match IO80211Reference's lifecycle semantics.  disable() does
     * not modify the persistent user power_state; only a valid Apple80211
     * POWER SET with num_radios > 0 may do that. */
    (void)primaryPowerAuthority;
    setProperty("AirportRTW89ControllerDisablePowerStatePreserved",
                kOSBooleanTrue);
    setProperty("AirportRTW89ControllerDisableLogicalAfter",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ControllerDisableBackendPowerPreserved",
                kOSBooleanTrue);

    IO80211Interface *wifi = OSDynamicCast(
        IO80211Interface, iface ? iface : _iface);
    if (wifi) {
        /* Lifecycle disable is not a user POWER transition in the
         * IO80211Reference model.  Keep the Tahoe control transport live while
         * preserving the stored logical state unchanged. */
        pinAirportTransportUserPowerOn(wifi);
        pinAirportTransportSystemEnableOn(wifi);
        setProperty("AirportRTW89PrimaryTransportPowerPinnedOn",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ControllerDisableTransportPinnedOn",
                    kOSBooleanTrue);
    }
#if __IO80211_TARGET >= __MAC_13_0
    /* Preserve the non-BSD control endpoint across a controller lifecycle
     * disable without treating that callback as user power OFF. */
    if (_skywalkInterface) {
        _skywalkInterface->IO80211InfraInterface::setPoweredOnByUser(true);
        setProperty("AirportRTW89ControlPlanePowerPinnedOn",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ControllerDisableControlTransportPinnedOn",
                    kOSBooleanTrue);
    }
#endif

    setProperty("AirportRTW89DisableSeen", kOSBooleanTrue);
    setProperty("AirportRTW89DisableSuppressed", kOSBooleanFalse);
    setProperty("AirportRTW89HardwarePowerOffSuppressedForRestartSafety",
                kOSBooleanTrue);
    setProperty("AirportRTW89LogicalPowerOn",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);
    return kIOReturnSuccess;
#else
    if (!_enabled) return kIOReturnSuccess;
    _enabled = false;
    if (_intrSrc) _intrSrc->disable();
    if (_txQueue) _txQueue->stop();
    if (_txQueue) _txQueue->flush();
    if (_ieee80211) _ieee80211->powerOff();
    return kIOReturnSuccess;
#endif
}

IOOutputQueue *RTW88PCIDevice::createOutputQueue()
{
    /*
     * Without an output queue, IONetworkController delivers outputPacket()
     * straight from the networking stack, which can call it concurrently from
     * multiple threads.  rtw_pci_tx_write_data() computes the TX buffer-
     * descriptor slot from ring->r.wp and fills it BEFORE taking irq_lock
     * (only the wp increment is locked), so two concurrent submissions fill the
     * same slot and skip the next, leaving a zeroed descriptor in the BE ring.
     * The chip then stalls its TX DMA on that zero descriptor (HW rp frozen,
     * FIFO empty) and the shared DMA wedges RX too.
     *
     * An IOGatedOutputQueue runs every outputPacket() under the work-loop gate,
     * serializing submission so the ring fill is single-threaded.
     */
    /* 0.2.31 explicit output queue action.  The IO80211 controller
     * overload can resolve to the family-owned handler rather than this
     * driver's outputPacket().  Bind the action explicitly so dequeued mbufs
     * are delivered to RTW88PCIDevice::outputPacket(). */
    IOOutputAction action =
        (IOOutputAction)&RTW88PCIDevice::outputPacket;
    IOGatedOutputQueue *queue = IOGatedOutputQueue::withTarget(
        static_cast<OSObject *>(this), action, getWorkLoop(), 256);
#ifdef RTW_AIRPORT
    setProperty("AirportRTW89CreateOutputQueueExplicitAction", kOSBooleanTrue);
    setProperty("AirportRTW89CreateOutputQueueActionPresent",
                action ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89CreateOutputQueueRequestedCapacity",
                (uint64_t)256, 32);
    setProperty("AirportRTW89CreateOutputQueueCalled", kOSBooleanTrue);
    setProperty("AirportRTW89CreateOutputQueueSucceeded",
                queue ? kOSBooleanTrue : kOSBooleanFalse);
    if (queue) {
        setProperty("AirportRTW89CreateOutputQueueCapacity",
                    (uint64_t)queue->getCapacity(), 32);
        const OSMetaClass *meta = queue->getMetaClass();
        if (meta)
            setProperty("AirportRTW89CreateOutputQueueClass",
                        meta->getClassName());
    }
#endif
    return queue;
}

UInt32 RTW88PCIDevice::outputPacket(mbuf_t m, void *param)
{
    drainPendingFree();
#ifdef RTW_AIRPORT
    /* 0.2.29 ordinary output diagnostics.  A zero count after link-up proves
     * macOS never submitted DHCP/ARP; non-zero counts move the fault below the
     * IONetwork interface boundary. */
    size_t packetLength = mbuf_pkthdr_len(m);
    if (!packetLength)
        packetLength = mbuf_len(m);
    _airportOutputPacketCount++;
    _airportOutputPacketBytes += packetLength;
#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
    setProperty("AirportRTW89OutputPacketCount",
                (uint64_t)_airportOutputPacketCount, 64);
    setProperty("AirportRTW89OutputPacketBytes",
                (uint64_t)_airportOutputPacketBytes, 64);

    uint8_t hdr[64] = {};
    size_t inspectLength = packetLength < sizeof(hdr) ? packetLength : sizeof(hdr);
    if (inspectLength >= 14 && mbuf_copydata(m, 0, inspectLength, hdr) == 0) {
        uint16_t etherType = (uint16_t)((hdr[12] << 8) | hdr[13]);
        if (etherType == 0x0806) {
            _airportOutputARPCount++;
            setProperty("AirportRTW89OutputARPCount",
                        (uint64_t)_airportOutputARPCount, 32);
        } else if (etherType == 0x0800) {
            _airportOutputIPv4Count++;
            setProperty("AirportRTW89OutputIPv4Count",
                        (uint64_t)_airportOutputIPv4Count, 32);
            if (inspectLength >= 34) {
                size_t ihl = (size_t)(hdr[14] & 0x0f) * 4;
                size_t udp = 14 + ihl;
                if (ihl >= 20 && inspectLength >= udp + 4 && hdr[23] == 17) {
                    uint16_t sport = (uint16_t)((hdr[udp] << 8) | hdr[udp + 1]);
                    uint16_t dport = (uint16_t)((hdr[udp + 2] << 8) | hdr[udp + 3]);
                    if ((sport == 67 || sport == 68) &&
                        (dport == 67 || dport == 68)) {
                        _airportOutputDHCPCount++;
                        setProperty("AirportRTW89OutputDHCPCount",
                                    (uint64_t)_airportOutputDHCPCount, 32);
                    }
                }
            }
        }
    }
#endif
#endif
#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
    setProperty("AirportRTW89ControllerOutputEnabled",
                _enabled ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ControllerOutputIEEEPresent",
                _ieee80211 ? kOSBooleanTrue : kOSBooleanFalse);
    if (_txQueue)
        setProperty("AirportRTW89ControllerOutputQueueSizeAtEntry",
                    (uint64_t)_txQueue->getSize(), 32);
#endif
    if (!_enabled || !_ieee80211) {
        setProperty("AirportRTW89ControllerOutputDroppedPrerequisite",
                    kOSBooleanTrue);
        freePacket(m);
        return kIOReturnOutputDropped;
    }
    /*
     * Backpressure instead of dropping.  When the BE ring is nearly full,
     * rtw_pci_tx_write_data() would return -ENOSPC and rtw_tx() would FREE the
     * skb — silently dropping it.  Under a sustained transfer those dropped
     * frames (TCP ACKs/data) stall the connection.  Returning
     * kIOReturnOutputStall makes IOGatedOutputQueue hold this exact packet and
     * stop dispatching; resumeTxIfStalled() (fired from the IRQ bottom-half
     * after tx_isr frees slots) re-services the queue.  Threshold leaves
     * headroom so rtw_tx never actually hits -ENOSPC.
     */
    if (rtw88_be_tx_avail() < kRTW88TxStallAvail) {
        _txStalled = true;
        return kIOReturnOutputStall;
    }
    return _ieee80211->outputPacket(m);
}

void RTW88PCIDevice::resumeTxIfStalled()
{
    /* Runs on the IRQ bottom-half thread (no rtw88 locks held). Use async
     * service so we never block on the output-queue gate from here. */
    if (_txStalled && rtw88_be_tx_avail() >= kRTW88TxResumeAvail) {
        _txStalled = false;
        if (_txQueue)
            _txQueue->service(IOBasicOutputQueue::kServiceAsync);
    }
}

IOReturn RTW88PCIDevice::getHardwareAddress(IOEthernetAddress *addr)
{
    if (!_ieee80211) return kIOReturnNotReady;
    _ieee80211->getMACAddress(addr->bytes);
    memcpy(_macAddr.bytes, addr->bytes, 6);
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::setHardwareAddress(const IOEthernetAddress *addr)
{
    memcpy(_macAddr.bytes, addr->bytes, 6);
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::getMaxPacketSize(UInt32 *maxSize) const
{
    *maxSize = 2346; /* IEEE80211 max MSDU */
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::setMaxPacketSize(UInt32 maxSize)
{
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::selectMedium(const IONetworkMedium *medium)
{
    setCurrentMedium(medium);
    return kIOReturnSuccess;
}

bool RTW88PCIDevice::configureInterface(IONetworkInterface *iface)
{
    const bool companion =
        OSDynamicCast(AirportRTW89SkywalkBSDInterface, iface) != nullptr;
    const bool baseConfigProbe =
        companion && airportNativeCompanionBaseConfigProbe() &&
        !airportExclusiveNativeTopology();
    if (companion) {
        /* 0.3.21: IO80211 configure-contract audit. 0.3.19 proved the
         * companion is valid under IOEthernetController configuration and
         * 0.3.20 proved IO80211 rejects it even with the legacy interface
         * removed. Record the observable IO80211/Skywalk invariants before
         * the superclass validates the BSD companion. No behavior is changed
         * by these properties. */
        setProperty("AirportRTW89SkywalkBSDCompanionConfigureEntered",
                    kOSBooleanTrue);
        if (iface && iface->getMetaClass())
            setProperty("AirportRTW89ConfigContractCompanionClass",
                        iface->getMetaClass()->getClassName());
        setProperty("AirportRTW89ConfigContractCompanionIsIO80211Interface",
                    OSDynamicCast(IO80211Interface, iface)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConfigContractCompanionIsIOEthernetInterface",
                    OSDynamicCast(IOEthernetInterface, iface)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        IOService *companionProvider = iface ? iface->getProvider() : nullptr;
        setProperty("AirportRTW89ConfigContractCompanionProviderPresent",
                    companionProvider ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConfigContractCompanionProviderIsController",
                    companionProvider == (IOService *)this
                        ? kOSBooleanTrue : kOSBooleanFalse);
        if (companionProvider && companionProvider->getMetaClass())
            setProperty("AirportRTW89ConfigContractCompanionProviderClass",
                        companionProvider->getMetaClass()->getClassName());

        AirportRTW89SkywalkControlInterface *control =
            OSDynamicCast(AirportRTW89SkywalkControlInterface, _skywalkInterface);
        setProperty("AirportRTW89ConfigContractSkywalkPresent",
                    control ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConfigContractSkywalkIsPrimary",
                    (control && getPrimarySkywalkInterface() == control)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        if (control && control->getMetaClass())
            setProperty("AirportRTW89ConfigContractSkywalkClass",
                        control->getMetaClass()->getClassName());
        if (control) {
            setProperty("AirportRTW89ConfigContractSkywalkRole",
                        (uint64_t)(uint32_t)control->getInterfaceRole(), 32);
            setProperty("AirportRTW89ConfigContractSkywalkProviderIsController",
                        control->getProvider() == (IOService *)this
                            ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ConfigContractNetworkExpansionPresent",
                        control->rawNetworkExpansion()
                            ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ConfigContractEthernetExpansionPresent",
                        control->rawEthernetExpansion()
                            ? kOSBooleanTrue : kOSBooleanFalse);
            void **networkRegistration = control->rawNetworkRegistrationSlot();
            void **ethernetRegistration = control->rawEthernetRegistrationSlot();
            setProperty("AirportRTW89ConfigContractNetworkRegistrationSlotPresent",
                        networkRegistration ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ConfigContractEthernetRegistrationSlotPresent",
                        ethernetRegistration ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ConfigContractNetworkRegistrationInitialized",
                        (networkRegistration && *networkRegistration)
                            ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89ConfigContractEthernetRegistrationInitialized",
                        (ethernetRegistration && *ethernetRegistration)
                            ? kOSBooleanTrue : kOSBooleanFalse);
        }
        setProperty("AirportRTW89ConfigContractInterfaceIdProgrammed",
                    getProperty("AirportRTW89ConcreteSkywalkInterfaceIdSet") ==
                            kOSBooleanTrue
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ConfigContractInterfaceIdSkippedZeroSymbol",
                    getProperty("AirportRTW89ConcreteSkywalkInterfaceIdSkippedZeroSymbol") ==
                            kOSBooleanTrue
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionConfigureIfnetBefore",
                    iface && iface->getIfnet() ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionLegacyInterfacePresentAtConfigure",
                    _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionLegacyIfnetPresentAtConfigure",
                    (_iface && _iface->getIfnet()) ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionBaseConfigProbeEnabled",
                    baseConfigProbe ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionConfigurePath",
                    baseConfigProbe ? "IOEthernetController" : "IO80211Controller");
    }

    /* 0.3.19 diagnostic fork: the normal path remains the exact IO80211
     * superclass call.  The opt-in probe skips only that layer for the
     * companion so we can distinguish malformed companion state from an
     * IO80211 single-interface/ownership rejection. */
    const bool superOK = baseConfigProbe
        ? IOEthernetController::configureInterface(iface)
        : super::configureInterface(iface);
    if (companion) {
        setProperty("AirportRTW89SkywalkBSDCompanionSuperConfigureSucceeded",
                    superOK ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionBaseConfigureSucceeded",
                    (baseConfigProbe && superOK) ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionIO80211ConfigureBypassed",
                    baseConfigProbe ? kOSBooleanTrue : kOSBooleanFalse);
    }
    if (!superOK)
        return false;

    IONetworkData *nd = iface->getNetworkData(kIONetworkStatsKey);
    if (companion) {
        setProperty("AirportRTW89SkywalkBSDCompanionNetworkStatsPresent",
                    nd ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkBSDCompanionConfigureIfnetAfter",
                    iface && iface->getIfnet() ? kOSBooleanTrue : kOSBooleanFalse);
    }
    if (nd)
        nd->setAccessTypes(kIONetworkDataAccessTypeRead);
    if (companion)
        setProperty("AirportRTW89SkywalkBSDCompanionConfigureSucceeded",
                    kOSBooleanTrue);
    return true;
}

IOReturn RTW88PCIDevice::getPacketFilters(const OSSymbol *group,
                                            UInt32 *filters) const
{
    if (group->isEqualTo(kIOEthernetWakeOnLANFilterGroup)) {
        *filters = 0;
        return kIOReturnSuccess;
    }
    return super::getPacketFilters(group, filters);
}

IOReturn RTW88PCIDevice::setMulticastMode(bool active)
{
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
    return kIOReturnSuccess;
}

IOReturn RTW88PCIDevice::setPromiscuousMode(bool active)
{
    return kIOReturnSuccess;
}

#ifdef RTW_AIRPORT
IOReturn RTW88PCIDevice::registerWithPolicyMaker(IOService *policyMaker)
{
    setProperty("AirportRTW89PMRegisterWithPolicyMakerSeen", kOSBooleanTrue);
    setProperty("AirportRTW89PMPolicyMakerPresent",
                policyMaker ? kOSBooleanTrue : kOSBooleanFalse);

    if (!policyMaker) {
        setProperty("AirportRTW89PMRegisterResult",
                    (uint64_t)(uint32_t)kIOReturnBadArgument, 32);
        return kIOReturnBadArgument;
    }

    gRTW89AirportPMState = 1;
    setProperty("AirportRTW89PMInitialState",
                (uint64_t)gRTW89AirportPMState, 32);

    policyMaker->registerPowerDriver(this, kRTW89AirportPowerStates, 2);

    setProperty("AirportRTW89PMRegisterResult", (uint64_t)0, 32);
    return IOPMAckImplied;
}

IOReturn RTW88PCIDevice::setPowerState(unsigned long powerStateOrdinal,
                                       IOService *whatDevice)
{
    (void)whatDevice;

    ++gRTW89AirportPMSetPowerStateCount;
    setProperty("AirportRTW89PMSetPowerStateCount",
                (uint64_t)gRTW89AirportPMSetPowerStateCount, 32);
    setProperty("AirportRTW89PMSetPowerStateRequested",
                (uint64_t)powerStateOrdinal, 32);
    setProperty("AirportRTW89PMSetPowerStatePrevious",
                (uint64_t)gRTW89AirportPMState, 32);

    if (powerStateOrdinal < 2)
        gRTW89AirportPMState = (UInt32)powerStateOrdinal;

    setProperty("AirportRTW89PMSetPowerStateCurrent",
                (uint64_t)gRTW89AirportPMState, 32);

    setProperty("AirportRTW89PMHardwarePowerChangeSuppressed", kOSBooleanTrue);

    if (powerStateOrdinal == 1 && _iface) {
        synchronizeAirportPowerState(_iface);
        setProperty("AirportRTW89PMOnInterfaceSync", kOSBooleanTrue);
    }

    return IOPMAckImplied;
}
#endif

IOReturn RTW88PCIDevice::powerStateWillChangeTo(IOPMPowerFlags flags,
                                                  unsigned long state,
                                                  IOService *actor)
{
    IOLog("rtw88: powerStateWillChangeTo %lu\n", state);
    return IOPMAckImplied;
}

/* ------------------------------------------------------------------ */
/*  RX injection (called from RTW88IEEE80211 on frame receive)         */
/* ------------------------------------------------------------------ */

mbuf_t RTW88PCIDevice::allocateInputPacket(uint32_t len)
{
    /* IONetworkController::allocatePacket returns an mbuf set up exactly the
     * way inputPacket() expects: m_len and m_pkthdr.len are both set and
     * consistent across every segment of the chain.  Hand-rolling this with
     * mbuf_allocpacket left m_len inconsistent with pkthdr.len, which the
     * dlil input validator rejects with "Failed mbuf validity check: len -14". */
    return allocatePacket(len);
}

void RTW88PCIDevice::injectRxFrame(mbuf_t m)
{
    drainPendingFree();
#ifdef RTW_AIRPORT
    /* 0.2.142: AirportRTW89Interface/en2 is the only BSD/data owner. */
    IOEthernetInterface *dataInterface =
        OSDynamicCast(IOEthernetInterface, _iface);
#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
    setProperty("AirportRTW89RxUsingLegacyInterface",
                dataInterface ? kOSBooleanTrue : kOSBooleanFalse);
#endif
#else
    IOEthernetInterface *dataInterface =
        OSDynamicCast(IOEthernetInterface, _iface);
#endif

    /* 0.2.44: independently recognize the reconstructed Ethernet DHCP Offer. */
    bool rxInjectOffer = false;
    uint8_t rxHead[96] = {};
    size_t rxInitialPlen = mbuf_pkthdr_len(m);
    size_t rxInspect = rxInitialPlen < sizeof(rxHead) ? rxInitialPlen
                                                      : sizeof(rxHead);
    if (rxInspect >= 42 && mbuf_copydata(m, 0, rxInspect, rxHead) == 0) {
        uint16_t rxEthertype = (uint16_t)((rxHead[12] << 8) | rxHead[13]);
        if (rxEthertype == 0x0800 && rxHead[23] == 17) {
            size_t rxIHL = (size_t)(rxHead[14] & 0x0f) * 4;
            size_t rxUDP = 14 + rxIHL;
            if (rxIHL >= 20 && rxInspect >= rxUDP + 8) {
                uint16_t rxSport =
                    (uint16_t)((rxHead[rxUDP] << 8) | rxHead[rxUDP + 1]);
                uint16_t rxDport =
                    (uint16_t)((rxHead[rxUDP + 2] << 8) | rxHead[rxUDP + 3]);
                rxInjectOffer = (rxSport == 67 && rxDport == 68);
            }
        }
    }

    if (rxInjectOffer) {
        static uint32_t injectSeenCount = 0;
        injectSeenCount++;
        setProperty("AirportRTW89RxInjectOfferSeenCount",
                    (uint64_t)injectSeenCount, 32);
        setProperty("AirportRTW89RxInjectIfacePresent",
                    dataInterface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89RxInjectEnabled",
                    _enabled ? kOSBooleanTrue : kOSBooleanFalse);
    }
    if (!dataInterface || !_enabled) {
        if (rxInjectOffer) {
            static uint32_t gateDropCount = 0;
            gateDropCount++;
            setProperty("AirportRTW89RxInjectGatePassed", kOSBooleanFalse);
            setProperty("AirportRTW89RxInjectGateDropCount",
                        (uint64_t)gateDropCount, 32);
        }
        freePacket(m);
        return;
    }
    if (rxInjectOffer)
        setProperty("AirportRTW89RxInjectGatePassed", kOSBooleanTrue);

    /* Last line of defense: never hand the networking stack a malformed
     * packet.  Validate BOTH length fields — the dlil validator panics on
     * m_len (printed as "len"), not just pkthdr.len.  mbuf_len/mbuf_pkthdr_len
     * return size_t, so a negative m_len shows up as a huge value here. */
    size_t plen = mbuf_pkthdr_len(m);
    size_t mlen = mbuf_len(m);
    if (rxInjectOffer) {
        setProperty("AirportRTW89RxInjectPkthdrLen", (uint64_t)plen, 32);
        setProperty("AirportRTW89RxInjectMLen", (uint64_t)mlen, 32);
    }
    if (plen < 14 || plen > 4096 || mlen < 14 || mlen > 4096) {
        if (rxInjectOffer) {
            static uint32_t invalidLenCount = 0;
            invalidLenCount++;
            setProperty("AirportRTW89RxInjectLengthValid", kOSBooleanFalse);
            setProperty("AirportRTW89RxInjectInvalidLengthCount",
                        (uint64_t)invalidLenCount, 32);
        }
        IOLog("rtw88: injectRxFrame: dropping bogus mbuf (pkthdr.len=%zu m_len=%zu)\n",
              plen, mlen);
        freePacket(m);
        return;
    }
    if (rxInjectOffer)
        setProperty("AirportRTW89RxInjectLengthValid", kOSBooleanTrue);


    /* Queue + flush, matching the proven itlwm submission path.  Submitting
     * via the input queue keeps frame delivery off whatever thread called us. */
    IONetworkData *rxAuditND = dataInterface->getNetworkData(kIONetworkStatsKey);
    IONetworkStats *rxAuditStats =
        rxAuditND ? (IONetworkStats *)rxAuditND->getBuffer() : nullptr;
    uint64_t rxAuditBefore = rxAuditStats ? rxAuditStats->inputPackets : 0;

    if (rxInjectOffer) {
        static uint32_t inputCallCount = 0;
        inputCallCount++;
        setProperty("AirportRTW89RxInjectInputPacketCallCount",
                    (uint64_t)inputCallCount, 32);
        setProperty("AirportRTW89RxInjectNetworkInputPacketsBefore",
                    rxAuditBefore, 64);
    }

    /*
     * 0.2.45 direct-DHCP input probe.
     *
     * 0.2.44 proved DHCP Offers reach this exact point with a valid mbuf,
     * _iface present, _enabled true, and the length gate passed, but the
     * queued inputPacket()+flush path did not expose them to BPF/DHCP.
     *
     * For DHCP Offers only, bypass the IO80211 input queue.  Every other RX
     * frame falls through to the existing queued path unchanged.
     */
    if (rxInjectOffer) {
        static uint32_t directInputCount = 0;
        directInputCount++;

        IONetworkData *rxDirectBeforeND =
            dataInterface->getNetworkData(kIONetworkStatsKey);
        IONetworkStats *rxDirectBeforeStats =
            rxDirectBeforeND
                ? (IONetworkStats *)rxDirectBeforeND->getBuffer()
                : nullptr;
        uint64_t rxDirectBefore =
            rxDirectBeforeStats ? rxDirectBeforeStats->inputPackets : 0;

        setProperty("AirportRTW89RxInputMode", "direct-dhcp-offer");
        setProperty("AirportRTW89RxDirectDHCPEnabled", kOSBooleanTrue);
        setProperty("AirportRTW89RxDirectDHCPInputCount",
                    (uint64_t)directInputCount, 32);
        setProperty("AirportRTW89RxDirectDHCPPkthdrLen",
                    (uint64_t)plen, 32);
        setProperty("AirportRTW89RxDirectDHCPMLen",
                    (uint64_t)mlen, 32);
        setProperty("AirportRTW89RxDirectDHCPNetworkInputPacketsBefore",
                    rxDirectBefore, 64);

        /*
         * Ownership of m transfers to the network stack at this call.
         * Nothing below dereferences or frees m.
         */
        /*
         * 0.2.46 Ethernet-base input probe.
         *
         * IO80211Reference routes ordinary Ethernet frames through
         * IOEthernetInterface::inputPacket().  For DHCP Offers only, invoke
         * that base implementation explicitly and pass the real mbuf length.
         */
        static uint32_t ethernetBaseInputCount = 0;
        ethernetBaseInputCount++;

        setProperty("AirportRTW89RxInputMode", "ethernet-base-dhcp-offer");
        setProperty("AirportRTW89RxEthernetBaseEnabled", kOSBooleanTrue);
        setProperty("AirportRTW89RxEthernetBaseInputCount",
                    (uint64_t)ethernetBaseInputCount, 32);
        setProperty("AirportRTW89RxEthernetBasePkthdrLen",
                    (uint64_t)plen, 32);
        setProperty("AirportRTW89RxEthernetBaseMLen",
                    (uint64_t)mlen, 32);
        setProperty("AirportRTW89RxEthernetBaseLengthArg",
                    (uint64_t)plen, 32);

        UInt32 ethernetBaseSubmitted =
            dataInterface->IOEthernetInterface::inputPacket(
                m, (UInt32)plen, 0, nullptr);

        setProperty("AirportRTW89RxEthernetBaseReturn",
                    (uint64_t)ethernetBaseSubmitted, 32);
        if (ethernetBaseSubmitted != 0) {
            static uint32_t ethernetBaseAcceptedCount = 0;
            ethernetBaseAcceptedCount += ethernetBaseSubmitted;
            setProperty("AirportRTW89RxEthernetBaseAcceptedCount",
                        (uint64_t)ethernetBaseAcceptedCount, 32);
        }

        static uint32_t directReturnedCount = 0;
        directReturnedCount++;
        setProperty("AirportRTW89RxDirectDHCPReturnedCount",
                    (uint64_t)directReturnedCount, 32);

        IONetworkData *rxDirectAfterND =
            dataInterface->getNetworkData(kIONetworkStatsKey);
        IONetworkStats *rxDirectAfterStats =
            rxDirectAfterND
                ? (IONetworkStats *)rxDirectAfterND->getBuffer()
                : nullptr;
        setProperty("AirportRTW89RxDirectDHCPNetworkInputPacketsAfter",
                    rxDirectAfterStats
                        ? (uint64_t)rxDirectAfterStats->inputPackets
                        : 0,
                    64);

        /*
         * Preserve the driver's historical statistics accounting without
         * touching the transferred mbuf.
         */
        IONetworkData *rxDirectND =
            dataInterface->getNetworkData(kIONetworkStatsKey);
        if (rxDirectND) {
            IONetworkStats *rxDirectStats =
                (IONetworkStats *)rxDirectND->getBuffer();
            if (rxDirectStats)
                rxDirectStats->inputPackets++;
        }

        return;
    }

    static uint32_t queuedNonDHCPCount = 0;
    queuedNonDHCPCount++;
    setProperty("AirportRTW89RxQueuedNonDHCPInputCount",
                (uint64_t)queuedNonDHCPCount, 32);

    /*
     * 0.2.47 ordinary Ethernet RX fix.
     *
     * 0.2.46 proved the Ethernet-base input path is accepted by macOS and
     * makes DHCP visible to BPF/DHCP.  Extend that same submission path to
     * every remaining reconstructed Ethernet frame.  EAPOL is handled before
     * deliverEthernet()/injectRxFrame(), so EAPOL behavior is unchanged.
     */
    static uint32_t ordinaryEthernetInputCount = 0;
    ordinaryEthernetInputCount++;

#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
    setProperty("AirportRTW89RxInputMode", "ordinary-ethernet-base");
    setProperty("AirportRTW89RxOrdinaryEthernetEnabled", kOSBooleanTrue);
    setProperty("AirportRTW89RxOrdinaryEthernetInputCount",
                (uint64_t)ordinaryEthernetInputCount, 32);
    setProperty("AirportRTW89RxOrdinaryEthernetPkthdrLen",
                (uint64_t)plen, 32);
    setProperty("AirportRTW89RxOrdinaryEthernetMLen",
                (uint64_t)mlen, 32);
    setProperty("AirportRTW89RxOrdinaryEthernetLengthArg",
                (uint64_t)plen, 32);
#endif

    UInt32 ordinaryEthernetSubmitted =
        dataInterface->IOEthernetInterface::inputPacket(
            m, (UInt32)plen, 0, nullptr);

#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
    setProperty("AirportRTW89RxOrdinaryEthernetReturn",
                (uint64_t)ordinaryEthernetSubmitted, 32);
    if (ordinaryEthernetSubmitted != 0) {
        static uint32_t ordinaryEthernetAcceptedCount = 0;
        ordinaryEthernetAcceptedCount += ordinaryEthernetSubmitted;
        setProperty("AirportRTW89RxOrdinaryEthernetAcceptedCount",
                    (uint64_t)ordinaryEthernetAcceptedCount, 32);
    }
#else
    (void)ordinaryEthernetSubmitted;
#endif

    if (rxInjectOffer) {
        static uint32_t inputReturnedCount = 0;
        inputReturnedCount++;
        setProperty("AirportRTW89RxInjectInputPacketReturnedCount",
                    (uint64_t)inputReturnedCount, 32);
    }

    if (rxInjectOffer) {
        static uint32_t flushCount = 0;
        flushCount++;
        setProperty("AirportRTW89RxInjectFlushCount",
                    (uint64_t)flushCount, 32);
        IONetworkData *rxAuditAfterND = dataInterface->getNetworkData(kIONetworkStatsKey);
        IONetworkStats *rxAuditAfterStats =
            rxAuditAfterND ? (IONetworkStats *)rxAuditAfterND->getBuffer() : nullptr;
        setProperty("AirportRTW89RxInjectNetworkInputPacketsAfterFlush",
                    rxAuditAfterStats ? (uint64_t)rxAuditAfterStats->inputPackets : 0,
                    64);
    }

    IONetworkData *nd = dataInterface->getNetworkData(kIONetworkStatsKey);
    if (nd) {
        IONetworkStats *stats = (IONetworkStats *)nd->getBuffer();
        if (stats) stats->inputPackets++;
    }
}

/* ------------------------------------------------------------------ */
/*  DMA coherent allocation                                             */
/* ------------------------------------------------------------------ */

void *RTW88PCIDevice::allocCoherent(size_t size, IOPhysicalAddress *phys)
{
    /*
     * rtw88 TX ring descriptors store DMA addresses in 32-bit fields.
     * Restrict physical allocation to the first 4GB so truncation to
     * cpu_to_le32() in the ring descriptor is lossless.
     * 0x00000000FFFFFFF0 = below 4GB, 16-byte aligned.
     */
    IOBufferMemoryDescriptor *desc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        kIOMemoryPhysicallyContiguous | kIODirectionInOut | kIOMemoryKernelUserShared,
        size,
        0x00000000FFFFFFF0ULL);

    if (!desc) { IOLog("rtw88: dma alloc failed, size=%zu\n", size); return nullptr; }
    desc->prepare();

    IOPhysicalAddress pa = desc->getPhysicalAddress();
    void *va = desc->getBytesNoCopy();
    memset(va, 0, size);

    if (phys) *phys = pa;

    /* Allocate the tracking node OUTSIDE the spinlock — IOMallocZero is
     * sleepable, and IOSimpleLock disables preemption.  Calling a sleepable
     * allocator from a preemption-disabled context panics XNU with
     * "blocking while holding a spinlock". */
    DMAEntry *entry = (DMAEntry *)IOMallocZero(sizeof(DMAEntry));
    if (!entry) {
        desc->complete();
        desc->release();
        return nullptr;
    }
    entry->desc = desc;
    entry->virt = va;
    entry->phys = pa;
    entry->size = size;

    IOSimpleLockLock(_dmaLock);
    entry->next = _dmaList;
    _dmaList = entry;
    IOSimpleLockUnlock(_dmaLock);

    return va;
}

void RTW88PCIDevice::freeCoherent(size_t size, void *virt, IOPhysicalAddress phys)
{
    IOSimpleLockLock(_dmaLock);
    DMAEntry **prev = &_dmaList;
    for (DMAEntry *e = _dmaList; e; e = e->next) {
        if (e->virt == virt) {
            *prev = e->next;
            IOSimpleLockUnlock(_dmaLock);
            if (preemption_enabled()) {
                e->desc->complete();
                e->desc->release();
                IOFree(e, sizeof(*e));
            } else {
                IOSimpleLockLock(_pendingFreeLock);
                e->next = _dmaPendingFree;
                _dmaPendingFree = e;
                IOSimpleLockUnlock(_pendingFreeLock);
            }
            return;
        }
        prev = &e->next;
    }
    IOSimpleLockUnlock(_dmaLock);
    IOLog("rtw88: freeCoherent: virt %p not found\n", virt);
}

void RTW88PCIDevice::freeCoherentByPhys(IOPhysicalAddress phys)
{
    IOSimpleLockLock(_dmaLock);
    DMAEntry **prev = &_dmaList;
    for (DMAEntry *e = _dmaList; e; e = e->next) {
        if (e->phys == phys) {
            *prev = e->next;
            IOSimpleLockUnlock(_dmaLock);
            if (preemption_enabled()) {
                e->desc->complete();
                e->desc->release();
                IOFree(e, sizeof(*e));
            } else {
                IOSimpleLockLock(_pendingFreeLock);
                e->next = _dmaPendingFree;
                _dmaPendingFree = e;
                IOSimpleLockUnlock(_pendingFreeLock);
            }
            return;
        }
        prev = &e->next;
    }
    IOSimpleLockUnlock(_dmaLock);
}

void RTW88PCIDevice::drainPendingFree()
{
    if (!_pendingFreeLock) return;
    IOSimpleLockLock(_pendingFreeLock);
    DMAEntry *list      = _dmaPendingFree;
    _dmaPendingFree     = nullptr;
    IOSimpleLockUnlock(_pendingFreeLock);

    for (DMAEntry *e = list; e; ) {
        DMAEntry *next = e->next;
        e->desc->complete();
        e->desc->release();
        IOFree(e, sizeof(*e));
        e = next;
    }
}

void RTW88PCIDevice::setBounceOrigVA(IOPhysicalAddress phys, void *orig_va)
{
    IOSimpleLockLock(_dmaLock);
    for (DMAEntry *e = _dmaList; e; e = e->next) {
        if (e->phys == phys) {
            e->orig_va = orig_va;
            break;
        }
    }
    IOSimpleLockUnlock(_dmaLock);
}

void RTW88PCIDevice::syncBounceForCpu(IOPhysicalAddress dma, size_t size)
{
    /*
     * Called by dma_sync_single_for_cpu(DMA_FROM_DEVICE) after the chip
     * has finished writing received packet data into the bounce buffer.
     * Copy bounce → original skb->data so the driver can parse the packet.
     */
    IOSimpleLockLock(_dmaLock);
    for (DMAEntry *e = _dmaList; e; e = e->next) {
        if (e->phys == dma && e->orig_va && e->virt) {
            size_t copy_len = (size <= e->size) ? size : e->size;
            IOSimpleLockUnlock(_dmaLock);
            memcpy(e->orig_va, e->virt, copy_len);
            return;
        }
    }
    IOSimpleLockUnlock(_dmaLock);
}

/* ------------------------------------------------------------------ */
/*  PCI config space                                                    */
/* ------------------------------------------------------------------ */

UInt8 RTW88PCIDevice::pciReadByte(int offset)
{
    return _pciDev->configRead8((UInt8)offset);
}
UInt16 RTW88PCIDevice::pciReadWord(int offset)
{
    return _pciDev->configRead16((UInt8)offset);
}
UInt32 RTW88PCIDevice::pciReadDword(int offset)
{
    return _pciDev->configRead32((UInt8)offset);
}
void RTW88PCIDevice::pciWriteByte(int offset, UInt8 val)
{
    _pciDev->configWrite8((UInt8)offset, val);
}
void RTW88PCIDevice::pciWriteWord(int offset, UInt16 val)
{
    _pciDev->configWrite16((UInt8)offset, val);
}
void RTW88PCIDevice::pciWriteDword(int offset, UInt32 val)
{
    _pciDev->configWrite32((UInt8)offset, val);
}
int RTW88PCIDevice::pciFindCapability(int cap)
{
    /* Walk PCIe capability list */
    UInt8 cap_ptr = _pciDev->configRead8(0x34) & ~3;
    while (cap_ptr) {
        UInt8 cap_id = _pciDev->configRead8(cap_ptr);
        if (cap_id == cap) return cap_ptr;
        cap_ptr = _pciDev->configRead8(cap_ptr + 1) & ~3;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  IOUserClient creation                                               */
/* ------------------------------------------------------------------ */

IOReturn RTW88PCIDevice::newUserClient(task_t owningTask, void *securityID,
                                        UInt32 type, OSDictionary *properties,
                                        IOUserClient **handler)
{
#ifdef RTW_AIRPORT
    /* Preserve Apple's IO80211 controller user-client namespace.  In
     * particular, type 0 is used by airportd/CoreWLAN and must continue to
     * delegate to IO80211Controller.  rtw88ctl uses a dedicated private type
     * solely for root-only diagnostic probes. */
    if (type != kRTW88PrivateControlUserClientType) {
        airportRecordUserClientOpen(this, 1U, 0U, type,
                                    (SInt32)0x7fffffff, owningTask, securityID,
                                    properties, handler);
        setProperty("AirportRTW89AppleUserClientDelegated", kOSBooleanTrue);
        setProperty("AirportRTW89AppleUserClientType", (uint64_t)type, 32);
        IOReturn appleResult;
        if (type == 0 && _skywalkInterface) {
            /* 0.3.45: route the native type-0 open through the controller's
             * actual primary role-1 IO80211Skywalk/Infra interface.  The BSD
             * companion has no native setInterfaceRole()/getInterfaceRole()
             * API, while Apple's newUserClient diagnostics explicitly validate
             * interfaceRole.  Change only the route; preserve the caller's
             * task, securityID, type, properties and handler contract. */
            AirportRTW89SkywalkControlInterface *control =
                OSDynamicCast(AirportRTW89SkywalkControlInterface,
                              _skywalkInterface);
            const bool controlPrimary =
                control && getPrimarySkywalkInterface() == control;
            const int controlRole = control ? control->getInterfaceRole() : -1;

            setProperty("AirportRTW89Type0RoleRouteExperiment",
                        kOSBooleanTrue);
            setProperty("AirportRTW89Type0RoleRouteControlPresent",
                        control ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89Type0RoleRouteControlIsPrimary",
                        controlPrimary ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89Type0RoleRouteControlRole",
                        (uint64_t)(uint32_t)controlRole, 32);

            if (handler)
                *handler = nullptr;
            appleResult = _skywalkInterface->newUserClient(
                owningTask, securityID, type, properties, handler);

            const IOReturn nativeRole1Result = appleResult;
            setProperty("AirportRTW89Type0RoleRouteReturn",
                        (uint64_t)(uint32_t)nativeRole1Result, 32);
            bool routeCreated = handler && *handler;
            setProperty("AirportRTW89Type0RoleRouteCreated",
                        routeCreated ? kOSBooleanTrue : kOSBooleanFalse);
            if (routeCreated) {
                const OSMetaClass *meta = (*handler)->getMetaClass();
                if (meta && meta->getClassName())
                    setProperty("AirportRTW89Type0RoleRouteClass",
                                meta->getClassName());
            }

            /* 0.3.48: Tahoe's restored legacy IO80211 image reaches the real
             * role-1 Skywalk object but returns kIOReturnUnsupported before
             * constructing its API user client.  The existing compatibility
             * endpoint already implements the descriptor-backed Apple80211
             * command envelope and routes GET27/SUPPORTED_CHANNELS and
             * GET207/CHANNELS_INFO to the controller's canonical handlers.
             * Use it only after this exact native Unsupported result.  This
             * does not invent channel data and does not bypass a successful
             * native client. */
            const bool compatibilityEligible =
                nativeRole1Result == kIOReturnUnsupported && !routeCreated;
            setProperty("AirportRTW89Type0Role1CompatibilityEligible",
                        compatibilityEligible ? kOSBooleanTrue : kOSBooleanFalse);
            if (compatibilityEligible) {
                if (handler)
                    *handler = nullptr;
                AirportRTW89APIUserClient *client =
                    new IO80211APIUserClient;
                IOReturn compatibilityResult = kIOReturnNoMemory;
                if (client) {
                    if (!client->initWithTaskAndOwner(
                            owningTask, securityID, type, properties, this)) {
                        client->release();
                        compatibilityResult = kIOReturnBadArgument;
                    } else if (!client->attach(_skywalkInterface)) {
                        client->release();
                        compatibilityResult = kIOReturnCannotLock;
                    } else if (!client->start(_skywalkInterface)) {
                        client->detach(_skywalkInterface);
                        client->release();
                        compatibilityResult = kIOReturnNotReady;
                    } else {
                        if (handler)
                            *handler = client;
                        compatibilityResult = kIOReturnSuccess;
                    }
                }
                setProperty("AirportRTW89Type0Role1CompatibilityFallback",
                            kOSBooleanTrue);
                setProperty("AirportRTW89Type0Role1CompatibilityReturn",
                            (uint64_t)(uint32_t)compatibilityResult, 32);
                const bool compatibilityCreated = handler && *handler;
                setProperty("AirportRTW89Type0Role1CompatibilityCreated",
                            compatibilityCreated ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
                if (compatibilityCreated) {
                    const OSMetaClass *meta = (*handler)->getMetaClass();
                    if (meta && meta->getClassName())
                        setProperty("AirportRTW89Type0Role1CompatibilityClass",
                                    meta->getClassName());
                }
                appleResult = compatibilityResult;
            } else {
                setProperty("AirportRTW89Type0Role1CompatibilityFallback",
                            kOSBooleanFalse);
            }
        } else if (type == 0 && _iface) {
            /* Keep the previous BSD route only as a non-native fallback when
             * no primary Skywalk control object exists. */
            setProperty("AirportRTW89ControllerType0RoutedToInterface",
                        kOSBooleanTrue);
            if (handler)
                *handler = nullptr;
            appleResult = _iface->newUserClient(
                owningTask, securityID, type, properties, handler);
            setProperty("AirportRTW89ControllerType0InterfaceReturn",
                        (uint64_t)(uint32_t)appleResult, 32);
            setProperty("AirportRTW89ControllerType0InterfaceHandlerCreated",
                        (handler && *handler) ? kOSBooleanTrue
                                             : kOSBooleanFalse);
        } else {
            appleResult = super::newUserClient(
                owningTask, securityID, type, properties, handler);
        }
        airportRecordUserClientOpen(this, 1U, 4U, type, appleResult,
                                    owningTask, securityID, properties, handler);
        airportRecordNamedUserClientHistory(
            this, "AirportRTW89ControllerNativeUserClient", 
            &gAirportControllerUserClientHistorySequence, type, appleResult,
            handler);
        return appleResult;
    }

    setProperty("AirportRTW89PrivateProbeUserClientRequested", kOSBooleanTrue);
    setProperty("AirportRTW89PrivateProbeUserClientType", (uint64_t)type, 32);
#endif
    RTW88UserClient *client = new RTW88UserClient;
    if (!client) {
        IOLog("rtw88: RTW88UserClient allocation failed\n");
        return kIOReturnNoMemory;
    }

    /* initWithTask — not init() — binds the Mach task port.
     * Without this the kernel port is never "ready for callouts" and
     * IOServiceOpen returns kIOReturnBadArgument before our code runs. */
    if (!client->initWithTask(owningTask, securityID, type, properties)) {
        IOLog("rtw88: RTW88UserClient::initWithTask failed\n");
        client->release();
        return kIOReturnBadArgument;
    }

    if (!client->attach(this)) {
        IOLog("rtw88: RTW88UserClient::attach failed\n");
        client->release();
        return kIOReturnBadArgument;
    }

    if (!client->start(this)) {
        IOLog("rtw88: RTW88UserClient::start failed\n");
        client->detach(this);
        client->release();
        return kIOReturnBadArgument;
    }

    *handler = client;
    return kIOReturnSuccess;
}
#ifdef RTW_AIRPORT
OSDefineMetaClassAndStructors(AirportRTW89SkywalkControlInterface,
                              IO80211InfraInterface)
OSDefineMetaClassAndStructors(AirportRTW89SkywalkBSDInterface,
                              IO80211Interface)

bool AirportRTW89SkywalkBSDInterface::initWithSkywalkInterfaceAndProvider(
    IONetworkController *controller, IO80211SkywalkInterface *interface)
{
    if (controller)
        controller->setProperty("AirportRTW89SkywalkBSDCompanionInitEntered",
                                kOSBooleanTrue);
    if (!controller || !interface) {
        if (controller)
            controller->setProperty("AirportRTW89SkywalkBSDCompanionInitArgumentsValid",
                                    kOSBooleanFalse);
        return false;
    }
    controller->setProperty("AirportRTW89SkywalkBSDCompanionInitArgumentsValid",
                            kOSBooleanTrue);
    const bool ethernetInit = IO80211Interface::init(controller);
    controller->setProperty("AirportRTW89SkywalkBSDCompanionEthernetInitSucceeded",
                            ethernetInit ? kOSBooleanTrue : kOSBooleanFalse);
    if (!ethernetInit)
        return false;

    /* 0.3.44: match the Apple-facing runtime identity contract already used by
     * AirportRTW89Interface.  This changes no provider/topology, power state,
     * primary classification, user-client type, entitlement, or hardware
     * behavior; it only publishes the four identity properties on the native
     * BSD IO80211Interface that receives Apple's type-0 factory call. */
    setProperty("IONetworkRootType", "airport");
    setProperty("IOMatchCategory", "WiFiDriver");
    setProperty("IO80211InterfaceRole", "Infrastructure");
    setProperty("IO80211RSNDone", kOSBooleanFalse);

    controller->setProperty("AirportRTW89NativeBSDIdentityContractApplied",
                            kOSBooleanTrue);
    controller->setProperty("AirportRTW89NativeBSDIdentityRootTypePresent",
                            getProperty("IONetworkRootType")
                                ? kOSBooleanTrue : kOSBooleanFalse);
    controller->setProperty("AirportRTW89NativeBSDIdentityMatchCategoryPresent",
                            getProperty("IOMatchCategory")
                                ? kOSBooleanTrue : kOSBooleanFalse);
    controller->setProperty("AirportRTW89NativeBSDIdentityRolePresent",
                            getProperty("IO80211InterfaceRole")
                                ? kOSBooleanTrue : kOSBooleanFalse);
    controller->setProperty("AirportRTW89NativeBSDIdentityRSNDonePresent",
                            getProperty("IO80211RSNDone")
                                ? kOSBooleanTrue : kOSBooleanFalse);

    _skywalk = interface;
    _dataLinkAttached = false;
    setProperty("AirportRTW89SkywalkBSDCompanion", kOSBooleanTrue);
    return true;
}

IOReturn AirportRTW89SkywalkBSDInterface::attachToDataLinkLayer(
    IOOptionBits options, void *parameter)
{
    RTW88PCIDevice *controller =
        OSDynamicCast(RTW88PCIDevice, IOEthernetInterface::getProvider());
    if (controller)
        controller->setProperty("AirportRTW89SkywalkBSDCompanionDataLinkAttachEntered",
                                kOSBooleanTrue);
    IOReturn result = IO80211Interface::attachToDataLinkLayer(
        options, parameter);
    if (controller) {
        controller->setProperty("AirportRTW89SkywalkBSDCompanionDataLinkAttachReturn",
                                (uint64_t)(uint32_t)result, 32);
        controller->setProperty("AirportRTW89SkywalkBSDCompanionDataLinkAttachSucceeded",
                                result == kIOReturnSuccess ? kOSBooleanTrue : kOSBooleanFalse);
    }
    if (result == kIOReturnSuccess && _skywalk && getIfnet()) {
        char name[IFNAMSIZ] = {};
        const char *prefix = ifnet_name(getIfnet());
        const UInt32 unit = ifnet_unit(getIfnet());
        if (prefix)
            snprintf(name, sizeof(name), "%s%u", prefix, unit);
        if (name[0])
            _skywalk->setProperty("IOInterfaceName", name);
        if (prefix)
            _skywalk->setProperty(kIOInterfaceNamePrefix, prefix);
        _skywalk->setProperty(kIOInterfaceUnit, (uint64_t)unit, 32);
        _skywalk->setProperty("built-in", kOSBooleanTrue);
        _skywalk->prepareBSDInterface(getIfnet(), 0);
        _skywalk->registerService();
    }
    _dataLinkAttached = result == kIOReturnSuccess;
    return result;
}

void AirportRTW89SkywalkBSDInterface::detachFromDataLinkLayer(
    IOOptionBits options, void *parameter)
{
    IO80211Interface::detachFromDataLinkLayer(options, parameter);
    _dataLinkAttached = false;
}

SInt32 AirportRTW89SkywalkBSDInterface::performCommand(
    IONetworkController *controller, unsigned long command,
    void *arg0, void *arg1)
{
    /* 0.3.52: native BSD Apple80211 outer transport audit/bridge.
     *
     * 0.3.51 proved Apple's live GET27/HW254 callback reaches the controller
     * with this AirportRTW89SkywalkBSDInterface as the IO80211Interface.
     * The inner 776-byte apple80211_sup_channel_data is valid, yet System
     * Information still omits Supported Channels.  Decode all Tahoe GET
     * envelope sizes used by the restored stack (32/40/48), explicitly bridge
     * only GET27/HW254 to the already-proven canonical controller builder, and
     * copy out only the populated channel prefix.  POWER keeps the 0.3.48
     * direct bridge.  CHANNEL and RATE are telemetry-only and continue through
     * IO80211Interface::performCommand unchanged. */
    RTW88PCIDevice *owner = OSDynamicCast(RTW88PCIDevice, controller);
    if (!owner)
        owner = OSDynamicCast(RTW88PCIDevice, IO80211Interface::getProvider());

    static constexpr unsigned long kApple80211Get32 = 0xc02069c9UL;
    static constexpr unsigned long kApple80211Get40 = 0xc02869c9UL;
    static constexpr unsigned long kApple80211Get48 = 0xc03069c9UL;
    static constexpr unsigned long kApple80211Set32 = 0x802069c8UL;
    static constexpr unsigned long kApple80211Set40 = 0x802869c8UL;
    static constexpr unsigned long kApple80211Set48 = 0x803069c8UL;
    const bool isGet32 = command == kApple80211Get32;
    const bool isGet40 = command == kApple80211Get40;
    const bool isGet48 = command == kApple80211Get48;
    const bool isAppleGet = isGet32 || isGet40 || isGet48;
    const bool isSet32 = command == kApple80211Set32;
    const bool isSet40 = command == kApple80211Set40;
    const bool isSet48 = command == kApple80211Set48;
    const bool isAppleSet = isSet32 || isSet40 || isSet48;
    const bool isAppleCommand = isAppleGet || isAppleSet;

    if (owner) {
        owner->setProperty("AirportRTW89NativeBSDPerformCommandSeen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89NativeBSDPerformCommandCommand",
                           (uint64_t)command, 64);
        owner->setProperty("AirportRTW89NativeBSDPerformCommandIsApple80211",
                           isAppleCommand ? kOSBooleanTrue : kOSBooleanFalse);
        owner->setProperty("AirportRTW89NativeBSDPerformCommandEnvelopeShape",
                           (uint64_t)((isGet32 || isSet32) ? 32U :
                                      ((isGet40 || isSet40) ? 40U :
                                       ((isGet48 || isSet48) ? 48U : 0U))), 32);
    }

    if (!isAppleCommand || !arg1)
        return IO80211Interface::performCommand(controller, command, arg0, arg1);

    SInt32 reqType = -1;
    UInt32 reqLen = 0;
    user_addr_t reqData = 0;
    if (isGet48 || isSet48) {
        struct AppleReq48 {
            char ifname[IFNAMSIZ];
            SInt32 type;
            SInt32 val;
            UInt32 len;
            UInt32 pad;
            UInt64 data;
            UInt64 reserved;
        };
        static_assert(sizeof(AppleReq48) == 48,
                      "Apple request 48 size mismatch");
        const AppleReq48 *req = static_cast<const AppleReq48 *>(arg1);
        reqType = req->type;
        reqLen = req->len;
        reqData = (user_addr_t)req->data;
    } else if (isGet40 || isSet40) {
        struct AppleReq40 {
            char ifname[IFNAMSIZ];
            SInt32 type;
            SInt32 val;
            UInt32 len;
            UInt32 pad;
            UInt64 data;
        };
        static_assert(sizeof(AppleReq40) == 40,
                      "Apple request 40 size mismatch");
        const AppleReq40 *req = static_cast<const AppleReq40 *>(arg1);
        reqType = req->type;
        reqLen = req->len;
        reqData = (user_addr_t)req->data;
    } else {
        struct AppleReq32 {
            char ifname[IFNAMSIZ];
            SInt32 type;
            SInt32 val;
            UInt32 len;
            UInt32 data;
        };
        static_assert(sizeof(AppleReq32) == 32,
                      "Apple request 32 size mismatch");
        const AppleReq32 *req = static_cast<const AppleReq32 *>(arg1);
        reqType = req->type;
        reqLen = req->len;
        reqData = (user_addr_t)req->data;
    }

    /* 0.5.19: the native BSD companion previously decoded GET commands only.
     * Tahoe sends secured association through this companion's SET transport;
     * falling into IO80211Interface's inherited stub returns -3903 before the
     * controller ever sees ASSOCIATE/20.  Bridge only the exact association
     * request here.  Allocate the large ABI object on the heap, preserve its
     * complete password/RSN payload, and dispatch through the same controller
     * callback IO80211Reference uses. */
    if (isAppleSet && reqType == APPLE80211_IOC_ASSOCIATE && owner) {
        static volatile UInt32 nativeBSDAssociateCount = 0;
        const UInt32 sequence = __sync_add_and_fetch(
            &nativeBSDAssociateCount, 1U);
        owner->setProperty("AirportRTW89NativeBSDSet20Seen", kOSBooleanTrue);
        owner->setProperty("AirportRTW89NativeBSDSet20Count",
                           (uint64_t)sequence, 32);
        owner->setProperty("AirportRTW89NativeBSDSet20ReqLen",
                           (uint64_t)reqLen, 32);
        owner->setProperty("AirportRTW89NativeBSDSet20StructSize",
                           (uint64_t)sizeof(apple80211_assoc_data), 32);
        owner->setProperty("AirportRTW89NativeBSDSet20DataPresent",
                           reqData ? kOSBooleanTrue : kOSBooleanFalse);
        if (!reqData || reqLen < sizeof(apple80211_assoc_data)) {
            owner->setProperty("AirportRTW89NativeBSDSet20Eligible",
                               kOSBooleanFalse);
            return kIOReturnBadArgument;
        }
        owner->setProperty("AirportRTW89NativeBSDSet20Eligible",
                           kOSBooleanTrue);
        apple80211_assoc_data *assoc =
            static_cast<apple80211_assoc_data *>(
                IOMalloc(sizeof(apple80211_assoc_data)));
        if (!assoc)
            return kIOReturnNoMemory;
        bzero(assoc, sizeof(*assoc));
        const int copyinResult = copyin(reqData, assoc, sizeof(*assoc));
        owner->setProperty("AirportRTW89NativeBSDSet20CopyinReturn",
                           (uint64_t)(uint32_t)copyinResult, 32);
        SInt32 inner = copyinResult == 0
            ? owner->apple80211Request(
                  (unsigned int)SIOCSA80211, APPLE80211_IOC_ASSOCIATE,
                  this, assoc)
            : (SInt32)copyinResult;
        owner->setProperty("AirportRTW89NativeBSDSet20InnerReturn",
                           (uint64_t)(uint32_t)inner, 32);
        IOFree(assoc, sizeof(*assoc));
        return inner;
    }

    if (isAppleSet)
        return IO80211Interface::performCommand(controller, command, arg0, arg1);

    if (owner) {
        owner->setProperty("AirportRTW89NativeBSDAppleGetRequest",
                           (uint64_t)(uint32_t)reqType, 32);
        owner->setProperty("AirportRTW89NativeBSDAppleGetLength",
                           (uint64_t)reqLen, 32);
        owner->setProperty("AirportRTW89NativeBSDAppleGetDataPresent",
                           reqData ? kOSBooleanTrue : kOSBooleanFalse);

        if (reqType == APPLE80211_IOC_CHANNEL) {
            owner->setProperty("AirportRTW89NativeBSDChannelOuterSeen",
                               kOSBooleanTrue);
            owner->setProperty("AirportRTW89NativeBSDChannelOuterReqLen",
                               (uint64_t)reqLen, 32);
        } else if (reqType == APPLE80211_IOC_RATE) {
            owner->setProperty("AirportRTW89NativeBSDRateOuterSeen",
                               kOSBooleanTrue);
            owner->setProperty("AirportRTW89NativeBSDRateOuterReqLen",
                               (uint64_t)reqLen, 32);
        }
    }

    const bool supportedChannels =
        reqType == APPLE80211_IOC_SUPPORTED_CHANNELS ||
        reqType == APPLE80211_IOC_HW_SUPPORTED_CHANNELS;

    if (supportedChannels && owner) {
        static UInt32 bridgeCount = 0;
        ++bridgeCount;
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeSeen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeCount",
                           (uint64_t)bridgeCount, 32);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeRequest",
                           (uint64_t)(uint32_t)reqType, 32);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeEnvelopeShape",
                           (uint64_t)(isGet32 ? 32U : (isGet40 ? 40U : 48U)),
                           32);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeReqLen",
                           (uint64_t)reqLen, 32);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeReqDataPresent",
                           reqData ? kOSBooleanTrue : kOSBooleanFalse);

        if (!reqData || reqLen < (sizeof(UInt32) * 2)) {
            owner->setProperty("AirportRTW89NativeBSDGet27BridgeEligible",
                               kOSBooleanFalse);
            return IO80211Interface::performCommand(controller, command,
                                                    arg0, arg1);
        }
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeEligible",
                           kOSBooleanTrue);

        apple80211_sup_channel_data channelData = {};
        const SInt32 inner = owner->apple80211Request(
            (unsigned int)reqType, 1, this, &channelData);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeInnerReturn",
                           (uint64_t)(uint32_t)inner, 32);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeNumChannels",
                           (uint64_t)channelData.num_channels, 32);
        if (inner != kIOReturnSuccess)
            return inner;

        UInt32 count = channelData.num_channels;
        if (count > APPLE80211_MAX_CHANNELS)
            count = APPLE80211_MAX_CHANNELS;
        const size_t usedLength =
            offsetof(apple80211_sup_channel_data, supported_channels) +
            (size_t)count * sizeof(apple80211_channel);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeUsedLength",
                           (uint64_t)usedLength, 64);

        if (reqLen < usedLength) {
            owner->setProperty("AirportRTW89NativeBSDGet27BridgeBufferTooSmall",
                               kOSBooleanTrue);
            return kIOReturnBadArgument;
        }

        const int copyoutResult = copyout(&channelData, reqData, usedLength);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeCopyoutAttempted",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeCopyoutReturn",
                           (uint64_t)(uint32_t)copyoutResult, 32);
        owner->setProperty("AirportRTW89NativeBSDGet27BridgeReturnedLength",
                           (uint64_t)(copyoutResult == 0 ? usedLength : 0), 64);
        if (OSData *raw = OSData::withBytes(&channelData, usedLength)) {
            owner->setProperty("AirportRTW89NativeBSDGet27BridgeRawOutput", raw);
            raw->release();
        }
        return copyoutResult == 0 ? kIOReturnSuccess : copyoutResult;
    }

    /* 0.3.53: GET4/current-channel uses the same live BSD-companion outer
     * transport as GET27.  0.3.52 proved Tahoe supplies exactly 16 bytes,
     * which is sizeof(apple80211_channel_data), while System Information
     * still displayed channel 0 even though the controller has a canonical
     * connected-channel getter.  Bridge only GET4 here; RATE remains
     * telemetry-only until its zero-length outer ABI is understood. */
    if (reqType == APPLE80211_IOC_CHANNEL && owner) {
        static UInt32 channelBridgeCount = 0;
        ++channelBridgeCount;
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeSeen",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeCount",
                           (uint64_t)channelBridgeCount, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeEnvelopeShape",
                           (uint64_t)(isGet32 ? 32U : (isGet40 ? 40U : 48U)),
                           32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeReqLen",
                           (uint64_t)reqLen, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeStructSize",
                           (uint64_t)sizeof(apple80211_channel_data), 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeReqDataPresent",
                           reqData ? kOSBooleanTrue : kOSBooleanFalse);

        const bool eligible = reqData != 0 &&
                              reqLen >= sizeof(apple80211_channel_data);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeEligible",
                           eligible ? kOSBooleanTrue : kOSBooleanFalse);
        if (!eligible)
            return IO80211Interface::performCommand(controller, command,
                                                    arg0, arg1);

        apple80211_channel_data channelData = {};
        const SInt32 inner = owner->apple80211Request(
            APPLE80211_IOC_CHANNEL, 1, this, &channelData);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeInnerReturn",
                           (uint64_t)(uint32_t)inner, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeVersion",
                           (uint64_t)channelData.version, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeChannelVersion",
                           (uint64_t)channelData.channel.version, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeChannel",
                           (uint64_t)channelData.channel.channel, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeFlags",
                           (uint64_t)channelData.channel.flags, 32);
        if (inner != kIOReturnSuccess)
            return inner;

        const size_t copyLength = sizeof(channelData);
        const int copyoutResult = copyout(&channelData, reqData, copyLength);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeCopyoutAttempted",
                           kOSBooleanTrue);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeCopyoutLength",
                           (uint64_t)copyLength, 32);
        owner->setProperty("AirportRTW89NativeBSDChannelBridgeCopyoutReturn",
                           (uint64_t)(uint32_t)copyoutResult, 32);
        if (OSData *raw = OSData::withBytes(&channelData, copyLength)) {
            owner->setProperty("AirportRTW89NativeBSDChannelBridgeRawOutput", raw);
            raw->release();
        }
        return copyoutResult == 0 ? kIOReturnSuccess : copyoutResult;
    }

    if (reqType != APPLE80211_IOC_POWER)
        return IO80211Interface::performCommand(controller, command, arg0, arg1);

    if (!owner)
        return kIOReturnNotReady;

    const bool eligible = reqData != 0 &&
                          reqLen >= sizeof(apple80211_power_data);
    owner->setProperty("AirportRTW89NativeBSDPowerGetOuterSeen",
                       kOSBooleanTrue);
    owner->setProperty("AirportRTW89NativeBSDPowerGetReqLen",
                       (uint64_t)reqLen, 32);
    owner->setProperty("AirportRTW89NativeBSDPowerGetStructSize",
                       (uint64_t)sizeof(apple80211_power_data), 32);
    owner->setProperty("AirportRTW89NativeBSDPowerGetReqDataPresent",
                       reqData ? kOSBooleanTrue : kOSBooleanFalse);
    owner->setProperty("AirportRTW89NativeBSDPowerGetDirectEligible",
                       eligible ? kOSBooleanTrue : kOSBooleanFalse);

    if (!eligible)
        return IO80211Interface::performCommand(controller, command, arg0, arg1);

    apple80211_power_data powerData = {};
    const SInt32 inner = owner->apple80211Request(
        APPLE80211_IOC_POWER, 1, this, &powerData);

    owner->setProperty("AirportRTW89NativeBSDPowerGetInnerReturn",
                       (uint64_t)(uint32_t)inner, 32);
    owner->setProperty("AirportRTW89NativeBSDPowerGetVersion",
                       (uint64_t)powerData.version, 32);
    owner->setProperty("AirportRTW89NativeBSDPowerGetNumRadios",
                       (uint64_t)powerData.num_radios, 32);
    for (UInt32 i = 0; i < APPLE80211_MAX_RADIO; ++i) {
        char key[72] = {};
        snprintf(key, sizeof(key),
                 "AirportRTW89NativeBSDPowerGetState%u", (unsigned)i);
        owner->setProperty(key, (uint64_t)powerData.power_state[i], 32);
    }

    if (inner != kIOReturnSuccess)
        return inner;

    const size_t copyLength = sizeof(powerData);
    const int copyoutResult = copyout(&powerData, reqData, copyLength);
    owner->setProperty("AirportRTW89NativeBSDPowerGetCopyoutLength",
                       (uint64_t)copyLength, 32);
    owner->setProperty("AirportRTW89NativeBSDPowerGetCopyoutReturn",
                       (uint64_t)(uint32_t)copyoutResult, 32);
    owner->setProperty("AirportRTW89NativeBSDPowerGetReturnedLogicalOn",
                       powerData.power_state[0] == APPLE80211_POWER_ON
                           ? kOSBooleanTrue : kOSBooleanFalse);

    if (OSData *raw = OSData::withBytes(&powerData, copyLength)) {
        owner->setProperty("AirportRTW89NativeBSDPowerGetRawOutput", raw);
        raw->release();
    }

    return copyoutResult == 0 ? kIOReturnSuccess : copyoutResult;
}

IOReturn AirportRTW89SkywalkBSDInterface::newUserClient(
    task_t owningTask, void *securityID, UInt32 type,
    OSDictionary *properties, IOUserClient **handler)
{
    /* 0.3.30: audit the real Tahoe IO80211Interface user-client contract on
     * the BSD companion.  Do not manufacture a custom endpoint here: the
     * return value and handler from Apple's inherited implementation are the
     * experiment. */
    RTW88PCIDevice *controller =
        OSDynamicCast(RTW88PCIDevice, IO80211Interface::getProvider());
    if (!controller && _skywalk)
        controller = OSDynamicCast(RTW88PCIDevice, _skywalk->getProvider());

    if (handler)
        *handler = nullptr;

    /* 0.3.30: identify the userspace process currently driving this open.
     * This is diagnostic only: do not alter the supplied task, credentials,
     * entitlement result, requested type, or Apple's factory decision. */
    const int callerPid = proc_selfpid();
    char callerName[64] = {};
    proc_selfname(callerName, (int)sizeof(callerName));

    if (controller) {
        controller->setProperty("AirportRTW89NativeBSDNewUserClientCallerPID",
                                (uint64_t)(uint32_t)callerPid, 32);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientCallerNamePresent",
                                callerName[0] ? kOSBooleanTrue : kOSBooleanFalse);
        if (callerName[0])
            controller->setProperty("AirportRTW89NativeBSDNewUserClientCallerName",
                                    callerName);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientSeen",
                                kOSBooleanTrue);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientType",
                                (uint64_t)type, 32);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientTaskPresent",
                                owningTask ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientSecurityIDPresent",
                                securityID ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientPropertiesPresent",
                                properties ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientProviderPresent",
                                IO80211Interface::getProvider() ? kOSBooleanTrue
                                                               : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientProviderIsController",
                                IO80211Interface::getProvider() == controller
                                    ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientSkywalkPresent",
                                _skywalk ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientSkywalkProviderIsController",
                                (_skywalk && _skywalk->getProvider() == controller)
                                    ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientIfnetPresent",
                                getIfnet() ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientDataLinkAttached",
                                _dataLinkAttached ? kOSBooleanTrue
                                                  : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientRegistered",
                                isRegistered() ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientInactive",
                                isInactive() ? kOSBooleanTrue : kOSBooleanFalse);
        OSObject *bsdName = getProperty(kIOBSDNameKey);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientBSDNamePresent",
                                bsdName ? kOSBooleanTrue : kOSBooleanFalse);
        if (getIfnet()) {
            controller->setProperty("AirportRTW89NativeBSDNewUserClientBSDUnit",
                                    (uint64_t)ifnet_unit(getIfnet()), 32);
        }
    }

    /* 0.3.33: restore Apple's requested user-client type unchanged.  The
     * 0->2 bridge proved that type 2 selects the private async-event endpoint,
     * but 0.3.33 showed normal airportd/WiFiAgent/ControlCenter type-0 probes
     * do not carry that endpoint's entitlement.  Keep the native factory
     * untouched while tracing the real secured-association service opens. */
    const UInt32 nativeFactoryType = type;

    /* 0.3.29: Tahoe's IO80211AsyncEventUserClient::initWithTask() checks
     * this private Apple entitlement for infrastructure interface type 0.
     * Audit the caller using the same kernel API, but do not grant, spoof,
     * or bypass the entitlement. */
    OSObject *infraEventEntitlement = nullptr;
    if (owningTask) {
        infraEventEntitlement = IOUserClient::copyClientEntitlement(
            owningTask, "com.apple.wifi_infra.event_monitor");
    }
    if (controller) {
        controller->setProperty(
            "AirportRTW89NativeBSDInfraEventEntitlementPresent",
            infraEventEntitlement ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty(
            "AirportRTW89NativeBSDInfraEventEntitlementTrue",
            infraEventEntitlement == kOSBooleanTrue ? kOSBooleanTrue
                                                     : kOSBooleanFalse);
        if (infraEventEntitlement) {
            const OSMetaClass *entMeta = infraEventEntitlement->getMetaClass();
            if (entMeta && entMeta->getClassName())
                controller->setProperty(
                    "AirportRTW89NativeBSDInfraEventEntitlementClass",
                    entMeta->getClassName());
        }
    }
    const bool infraEventEntitlementPresent = infraEventEntitlement != nullptr;
    const bool infraEventEntitlementTrue = infraEventEntitlement == kOSBooleanTrue;
    if (infraEventEntitlement)
        infraEventEntitlement->release();

    /* 0.3.40: snapshot the complete native type-0 factory preconditions at
     * the exact inherited IO80211Interface::newUserClient() boundary.  This is
     * diagnostic-only: no type translation, entitlement bypass, lifecycle
     * mutation, power change, or manufactured user client is performed. */
    const bool bsdPowered = poweredOnByUser();
    const bool bsdSystemEnabled = enabledBySystem();
    const bool bsdPrimaryVirtual = isPrimaryInterface();
    const bool bsdPrimaryProperty =
        getProperty(kIOPrimaryInterface) == kOSBooleanTrue;
    IONetworkController *bsdController = getController();
    IOService *bsdBaseProvider = IO80211Interface::getProvider();
    IOService *bsdEffectiveProvider = getProvider();

    AirportRTW89SkywalkControlInterface *control = controller
        ? OSDynamicCast(AirportRTW89SkywalkControlInterface,
                        controller->_skywalkInterface)
        : nullptr;
    const bool controlIsPrimary = controller && control &&
        controller->getPrimarySkywalkInterface() == control;
    const bool controlStarted = controller && controller->_skywalkStarted;
    const bool controlSystemEnabled = control ? control->enabledBySystem() : false;
    const bool controlUserPowered = control ? control->poweredOnByUser() : false;
    const bool controlPostMessageReady =
        control && control->rawPostMessageContext() != nullptr;
    const bool controlRequestReady =
        control && control->rawControllerRequestObject() != nullptr;

    /* Bit layout intentionally stays compact so every ring entry can preserve
     * one caller's full precondition set without exposing credentials/data.
     *  0 ifnet, 1 registered, 2 active, 3 datalink, 4 user-power, 5 sys-enable
     *  6 virtual-primary, 7 property-primary, 8 controller-match,
     *  9 base-provider-controller, 10 effective-provider-control,
     * 11 control-present, 12 control-primary, 13 control-started,
     * 14 control-system-enabled, 15 control-user-powered,
     * 16 postMessage-context, 17 controller-request. */
    UInt32 factoryFlags = 0;
    if (getIfnet()) factoryFlags |= (1U << 0);
    if (isRegistered()) factoryFlags |= (1U << 1);
    if (!isInactive()) factoryFlags |= (1U << 2);
    if (_dataLinkAttached) factoryFlags |= (1U << 3);
    if (bsdPowered) factoryFlags |= (1U << 4);
    if (bsdSystemEnabled) factoryFlags |= (1U << 5);
    if (bsdPrimaryVirtual) factoryFlags |= (1U << 6);
    if (bsdPrimaryProperty) factoryFlags |= (1U << 7);
    if (controller && bsdController == controller) factoryFlags |= (1U << 8);
    if (controller && bsdBaseProvider == controller) factoryFlags |= (1U << 9);
    if (control && bsdEffectiveProvider == control) factoryFlags |= (1U << 10);
    if (control) factoryFlags |= (1U << 11);
    if (controlIsPrimary) factoryFlags |= (1U << 12);
    if (controlStarted) factoryFlags |= (1U << 13);
    if (controlSystemEnabled) factoryFlags |= (1U << 14);
    if (controlUserPowered) factoryFlags |= (1U << 15);
    if (controlPostMessageReady) factoryFlags |= (1U << 16);
    if (controlRequestReady) factoryFlags |= (1U << 17);

    /* 0.3.33: reserve a caller-history slot before delegating to Apple.
     * The slot is completed after newUserClient() returns, so one background
     * system_profiler probe can no longer erase the identities/results of
     * earlier opens that may have come from airportd/CoreWLAN/networksetup. */
    const UInt32 historySequence = _nativeUserClientHistorySequence++;
    const UInt32 historySlot = historySequence & 0x0f;

    if (controller) {
        controller->setProperty("AirportRTW89NativeBSDNewUserClientTypeBridgeApplied",
                                kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientDelegatedType",
                                (uint64_t)nativeFactoryType, 32);
        controller->setProperty("AirportRTW89NativeType0FactoryAuditSeen",
                                kOSBooleanTrue);
        controller->setProperty("AirportRTW89NativeType0FactoryFlags",
                                (uint64_t)factoryFlags, 32);
        controller->setProperty("AirportRTW89NativeType0BSDPoweredOnByUser",
                                bsdPowered ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0BSDEnabledBySystem",
                                bsdSystemEnabled ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0BSDVirtualIsPrimary",
                                bsdPrimaryVirtual ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0BSDPropertyPrimary",
                                bsdPrimaryProperty ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0BSDControllerMatchesOwner",
                                (bsdController == controller) ? kOSBooleanTrue
                                                              : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0BSDBaseProviderIsController",
                                (bsdBaseProvider == controller) ? kOSBooleanTrue
                                                                : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0BSDEffectiveProviderIsControl",
                                (control && bsdEffectiveProvider == control)
                                    ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlPresent",
                                control ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlIsPrimary",
                                controlIsPrimary ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlStarted",
                                controlStarted ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlEnabledBySystem",
                                controlSystemEnabled ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlPoweredOnByUser",
                                controlUserPowered ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlPostMessageReady",
                                controlPostMessageReady ? kOSBooleanTrue
                                                        : kOSBooleanFalse);
        controller->setProperty("AirportRTW89NativeType0ControlRequestReady",
                                controlRequestReady ? kOSBooleanTrue
                                                    : kOSBooleanFalse);
    }

    /* 0.3.44: restore the caller's native type-0 argument vector unchanged.
     * 0.3.43 proved that replacing a null properties pointer with an empty
     * dictionary does not change Apple's kIOReturnBadArgument result. */
    const IOReturn result = IO80211Interface::newUserClient(
        owningTask, securityID, nativeFactoryType, properties, handler);

    if (controller) {
        controller->setProperty("AirportRTW89NativeBSDNewUserClientReturn",
                                (uint64_t)(uint32_t)result, 32);
        const bool created = handler && *handler;
        controller->setProperty("AirportRTW89NativeBSDNewUserClientCreated",
                                created ? kOSBooleanTrue : kOSBooleanFalse);
        const char *createdClass = "-";
        if (created) {
            const OSMetaClass *meta = (*handler)->getMetaClass();
            if (meta && meta->getClassName()) {
                createdClass = meta->getClassName();
                controller->setProperty("AirportRTW89NativeBSDNewUserClientClass",
                                        createdClass);
            }
        }

        char historyKey[96] = {};
        char historyValue[512] = {};
        snprintf(historyKey, sizeof(historyKey),
                 "AirportRTW89NativeBSDNewUserClientHistory%02u",
                 historySlot);
        snprintf(historyValue, sizeof(historyValue),
                 "seq=%u pid=%d name=%s type=%u delegated=%u entPresent=%u entTrue=%u flags=0x%05x bsd[pwr=%u sys=%u prim=%u prop=%u ctl=%u baseprov=%u effctl=%u] ctrl[present=%u primary=%u started=%u sys=%u pwr=%u post=%u req=%u] ret=0x%08x created=%u class=%s",
                 historySequence, callerPid, callerName[0] ? callerName : "-",
                 type, nativeFactoryType,
                 infraEventEntitlementPresent ? 1U : 0U,
                 infraEventEntitlementTrue ? 1U : 0U, factoryFlags,
                 bsdPowered ? 1U : 0U, bsdSystemEnabled ? 1U : 0U,
                 bsdPrimaryVirtual ? 1U : 0U, bsdPrimaryProperty ? 1U : 0U,
                 (controller && bsdController == controller) ? 1U : 0U,
                 (controller && bsdBaseProvider == controller) ? 1U : 0U,
                 (control && bsdEffectiveProvider == control) ? 1U : 0U,
                 control ? 1U : 0U, controlIsPrimary ? 1U : 0U,
                 controlStarted ? 1U : 0U, controlSystemEnabled ? 1U : 0U,
                 controlUserPowered ? 1U : 0U, controlPostMessageReady ? 1U : 0U,
                 controlRequestReady ? 1U : 0U,
                 (uint32_t)result, created ? 1U : 0U, createdClass);
        controller->setProperty(historyKey, historyValue);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientHistorySequence",
                                (uint64_t)historySequence, 32);
        controller->setProperty("AirportRTW89NativeBSDNewUserClientHistorySlot",
                                (uint64_t)historySlot, 32);
    }
    return result;
}

IOService *AirportRTW89SkywalkBSDInterface::getProvider(void) const
{
    /* 0.3.40: during the inherited type-0 IO80211 user-client factory only,
     * expose the original controller provider.  This matches IO80211Reference's
     * plain IO80211Interface contract without changing the normal Skywalk
     * provider topology before or after the factory call. */
    if (_nativeType0FactoryUseBaseProvider)
        return IO80211Interface::getProvider();

    return _dataLinkAttached && _skywalk
        ? _skywalk
        : IO80211Interface::getProvider();
}

#ifdef IO80211FAMILY_V2
bool AirportRTW89SkywalkControlInterface::init(IOService *provider)
{
    if (!provider)
        return false;
    return IO80211InfraInterface::init();
}
#endif

const char *AirportRTW89SkywalkControlInterface::getBSDName(void) const
{
    /* 0.2.128: Tahoe's private CoreWiFi GET INTF NAME path asks the
     * IOSkywalkNetworkInterface object for its BSD identity.  A control-only
     * service intentionally has no BSD ifnet, so resolve the name from the
     * identity property published by the deferred probe instead.  The
     * OSString is retained by the registry entry, making getCStringNoCopy()
     * stable for the lifetime of the property. */
    AirportRTW89SkywalkControlInterface *self =
        const_cast<AirportRTW89SkywalkControlInterface *>(this);
    self->setProperty("AirportRTW89ControlOnlySkywalkGetBSDNameSeen",
                      kOSBooleanTrue);

    OSString *name = OSDynamicCast(OSString, getProperty("IOInterfaceName"));
    if (name && name->getLength() != 0) {
        self->setProperty("AirportRTW89ControlOnlySkywalkGetBSDNameFromIdentity",
                          kOSBooleanTrue);
        return name->getCStringNoCopy();
    }

    self->setProperty("AirportRTW89ControlOnlySkywalkGetBSDNameFromIdentity",
                      kOSBooleanFalse);
    return IO80211InfraInterface::getBSDName();
}

const char *AirportRTW89SkywalkControlInterface::getBSDNamePrefix(void)
{
    setProperty("AirportRTW89ControlOnlySkywalkGetBSDNamePrefixSeen",
                kOSBooleanTrue);

    OSString *prefix =
        OSDynamicCast(OSString, getProperty(kIOInterfaceNamePrefix));
    if (prefix && prefix->getLength() != 0) {
        setProperty("AirportRTW89ControlOnlySkywalkGetBSDNamePrefixFromIdentity",
                    kOSBooleanTrue);
        return prefix->getCStringNoCopy();
    }

    setProperty("AirportRTW89ControlOnlySkywalkGetBSDNamePrefixFromIdentity",
                kOSBooleanFalse);
    return IO80211InfraInterface::getBSDNamePrefix();
}

UInt AirportRTW89SkywalkControlInterface::getBSDUnitNumber(void)
{
    setProperty("AirportRTW89ControlOnlySkywalkGetBSDUnitNumberSeen",
                kOSBooleanTrue);

    OSNumber *unit = OSDynamicCast(OSNumber, getProperty(kIOInterfaceUnit));
    if (unit) {
        setProperty("AirportRTW89ControlOnlySkywalkGetBSDUnitFromIdentity",
                    kOSBooleanTrue);
        return unit->unsigned32BitValue();
    }

    setProperty("AirportRTW89ControlOnlySkywalkGetBSDUnitFromIdentity",
                kOSBooleanFalse);
    return IO80211InfraInterface::getBSDUnitNumber();
}

bool AirportRTW89SkywalkControlInterface::setLinkState(
    IO80211LinkState state, UInt reason, bool debounceTimeout, UInt code)
{
    (void)state;
    (void)reason;
    (void)debounceTimeout;
    (void)code;
    RTW88PCIDevice *controller =
        OSDynamicCast(RTW88PCIDevice, getProvider());
    if (controller) {
        controller->setProperty("AirportRTW89ControlLinkStateSuppressed",
                                kOSBooleanTrue);
        controller->setProperty("AirportRTW89PeerMonitorSafePublication",
                                kOSBooleanTrue);
    }
    /* This is an acknowledged no-op: the genuine AirportRTW89Interface/en2
     * owns carrier/link state.  Do not call IO80211InfraInterface here. */
    return true;
}

void AirportRTW89SkywalkControlInterface::setLQM(unsigned long long lqm)
{
    (void)lqm;
    RTW88PCIDevice *controller =
        OSDynamicCast(RTW88PCIDevice, getProvider());
    if (controller) {
        controller->setProperty("AirportRTW89ControlLQMSuppressed",
                                kOSBooleanTrue);
        controller->setProperty("AirportRTW89PeerMonitorSafePublication",
                                kOSBooleanTrue);
    }
    /* No peer/data path exists on this control-only service. */
}

IOReturn AirportRTW89SkywalkControlInterface::newUserClient(
    task_t owningTask, void *securityID, UInt32 type,
    OSDictionary *properties, IOUserClient **handler)
{
    RTW88PCIDevice *controller =
        OSDynamicCast(RTW88PCIDevice, getProvider());
    airportRecordUserClientOpen(controller, 3U, 0U, type,
                                (SInt32)0x7fffffff, owningTask, securityID,
                                properties, handler);
    if (controller) {
        controller->setProperty(
            "AirportRTW89SkywalkNativeNewUserClientSeen", kOSBooleanTrue);
        controller->setProperty(
            "AirportRTW89SkywalkNativeNewUserClientType",
            (uint64_t)type, 32);
    }

    if (controller) {
        controller->setProperty("AirportRTW89Type0SkywalkFactoryAudit",
                                kOSBooleanTrue);
        controller->setProperty("AirportRTW89Type0SkywalkRoleAtFactory",
                                (uint64_t)(uint32_t)getInterfaceRole(), 32);
        IOService *provider = getProvider();
        controller->setProperty("AirportRTW89Type0SkywalkProviderPresent",
                                provider ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89Type0SkywalkProviderIsController",
                                provider == controller ? kOSBooleanTrue
                                                       : kOSBooleanFalse);
        if (provider && provider->getMetaClass() &&
            provider->getMetaClass()->getClassName())
            controller->setProperty("AirportRTW89Type0SkywalkProviderClass",
                                    provider->getMetaClass()->getClassName());
        const OSMetaClass *selfMeta = getMetaClass();
        if (selfMeta && selfMeta->getClassName())
            controller->setProperty("AirportRTW89Type0SkywalkSelfClass",
                                    selfMeta->getClassName());
        controller->setProperty("AirportRTW89Type0SkywalkInactiveAtFactory",
                                isInactive() ? kOSBooleanTrue : kOSBooleanFalse);
        controller->setProperty("AirportRTW89Type0SkywalkCompileSize",
                                (uint64_t)sizeof(AirportRTW89SkywalkControlInterface), 32);
        const OSSymbol *skyName =
            OSSymbol::withCString("IO80211SkywalkInterface");
        const OSMetaClass *skyMeta = skyName
            ? OSMetaClass::getMetaClassWithName(skyName) : nullptr;
        if (skyMeta)
            controller->setProperty("AirportRTW89Type0AppleSkywalkMetaSize",
                                    (uint64_t)skyMeta->getClassSize(), 32);
        OSSafeReleaseNULL(skyName);
    }

    IOReturn ret = IO80211SkywalkInterface::newUserClient(
        owningTask, securityID, type, properties, handler);

    /* 0.3.48: real Tahoe/CoreWiFi type-0 opens arrive directly on this
     * role-1 Skywalk object, bypassing RTW88PCIDevice::newUserClient().
     * Therefore the 0.3.48 compatibility fallback must live at this exact
     * boundary. Preserve Apple's native result first; only substitute the
     * existing compatibility API user client when type 0 returns precisely
     * kIOReturnUnsupported and no native handler was created. */
    const IOReturn nativeRet = ret;
    const bool nativeCreated = handler && *handler;
    if (controller) {
        controller->setProperty("AirportRTW89Type0DirectNativeReturn",
                                (uint64_t)(uint32_t)nativeRet, 32);
        controller->setProperty("AirportRTW89Type0DirectNativeCreated",
                                nativeCreated ? kOSBooleanTrue : kOSBooleanFalse);
    }

    const bool directCompatibilityEligible =
        type == 0 && nativeRet == kIOReturnUnsupported && !nativeCreated;
    if (controller)
        controller->setProperty("AirportRTW89Type0DirectCompatibilityEligible",
                                directCompatibilityEligible ? kOSBooleanTrue
                                                            : kOSBooleanFalse);

    if (directCompatibilityEligible) {
        if (handler)
            *handler = nullptr;
        AirportRTW89APIUserClient *client = new IO80211APIUserClient;
        IOReturn compatibilityRet = kIOReturnNoMemory;
        if (client) {
            if (!client->initWithTaskAndOwner(owningTask, securityID, type,
                                              properties, controller)) {
                client->release();
                compatibilityRet = kIOReturnBadArgument;
            } else if (!client->attach(this)) {
                client->release();
                compatibilityRet = kIOReturnCannotLock;
            } else if (!client->start(this)) {
                client->detach(this);
                client->release();
                compatibilityRet = kIOReturnNotReady;
            } else {
                if (handler)
                    *handler = client;
                compatibilityRet = kIOReturnSuccess;
                controller->setProperty("AirportRTW89AppleEndpointOpenSucceeded",
                                        kOSBooleanTrue);
            }
        }
        if (controller) {
            controller->setProperty("AirportRTW89Type0DirectCompatibilityFallback",
                                    kOSBooleanTrue);
            controller->setProperty("AirportRTW89Type0DirectCompatibilityReturn",
                                    (uint64_t)(uint32_t)compatibilityRet, 32);
            const bool compatibilityCreated = handler && *handler;
            controller->setProperty("AirportRTW89Type0DirectCompatibilityCreated",
                                    compatibilityCreated ? kOSBooleanTrue
                                                         : kOSBooleanFalse);
            if (compatibilityCreated) {
                const OSMetaClass *meta = (*handler)->getMetaClass();
                if (meta && meta->getClassName())
                    controller->setProperty("AirportRTW89Type0DirectCompatibilityClass",
                                            meta->getClassName());
            }
        }
        ret = compatibilityRet;
    } else if (controller) {
        controller->setProperty("AirportRTW89Type0DirectCompatibilityFallback",
                                kOSBooleanFalse);
    }

    if (controller) {
        controller->setProperty("AirportRTW89Type0SkywalkFactoryReturn",
                                (uint64_t)(uint32_t)ret, 32);
        const bool created = handler && *handler;
        controller->setProperty("AirportRTW89Type0SkywalkFactoryCreated",
                                created ? kOSBooleanTrue : kOSBooleanFalse);
        if (created) {
            const OSMetaClass *meta = (*handler)->getMetaClass();
            if (meta && meta->getClassName())
                controller->setProperty("AirportRTW89Type0SkywalkFactoryClientClass",
                                        meta->getClassName());
        }
    }
    airportRecordUserClientOpen(controller, 3U, 4U, type, ret, owningTask,
                                securityID, properties, handler);
    airportRecordNamedUserClientHistory(
        controller, "AirportRTW89SkywalkNativeUserClient",
        &gAirportSkywalkUserClientHistorySequence, type, ret, handler);

    if (controller) {
        controller->setProperty(
            "AirportRTW89SkywalkNativeNewUserClientReturn",
            (uint64_t)(uint32_t)ret, 32);
        controller->setProperty(
            "AirportRTW89SkywalkNativeNewUserClientCreated",
            (handler && *handler) ? kOSBooleanTrue : kOSBooleanFalse);
        if (handler && *handler) {
            const OSMetaClass *meta = (*handler)->getMetaClass();
            if (meta && meta->getClassName())
                controller->setProperty(
                    "AirportRTW89SkywalkNativeNewUserClientClass",
                    meta->getClassName());
        }
    }
    return ret;
}

bool AirportRTW89SkywalkControlInterface::initAsControlService(
    RTW88PCIDevice *controller, AirportRTW89Interface *interface)
{
    const bool exclusiveNative = airportExclusiveNativeTopology();
    if (!controller || (!interface && !exclusiveNative) ||
        !IO80211InfraInterface::init())
        return false;

    /* Publish stable registry identities rather than OSObject properties;
     * retaining the controller/interface here would form an ownership cycle.
     * The real controller relationship is established by IOService::attach().
     * This service intentionally has no ifnet, BSD name, interface unit, or
     * data-link attachment. */
    setProperty("AirportRTW89ControlOnlySkywalkService", kOSBooleanTrue);
    setProperty("AirportRTW89BSDInterfaceCreationSuppressed", kOSBooleanTrue);
    setProperty("AirportRTW89ControllerRegistryEntryID",
                controller->getRegistryEntryID(), 64);
    if (interface)
        setProperty("AirportRTW89LegacyInterfaceRegistryEntryID",
                    interface->getRegistryEntryID(), 64);
    setProperty("AirportRTW89ExclusiveNativeControlInit",
                exclusiveNative ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("IO80211InterfaceRole", "Infrastructure");

    /* 0.2.123: keep this object strictly control-only/non-BSD, but publish
     * the real legacy interface identity before registerService(). Tahoe's
     * private CoreWiFi path announces this service to Control Center and then
     * asks for its interface name.  Without IOInterfaceName the request is
     * rejected as ENOTSUP even though the genuine IO80211Interface owns enX.
     * This mirrors only the identity properties used by the old companion
     * path; it deliberately does NOT call start(), prepareBSDInterface(),
     * attachToDataLinkLayer(), enable(), or create another ifnet. */
    ifnet_t ifp = interface ? interface->getIfnet() : nullptr;
    controller->setProperty("AirportRTW89ControlOnlySkywalkLegacyIfnetPresent",
                            ifp ? kOSBooleanTrue : kOSBooleanFalse);
    if (ifp) {
        const char *prefix = ifnet_name(ifp);
        const UInt32 unit = ifnet_unit(ifp);
        char interfaceName[IFNAMSIZ] = {};
        if (prefix)
            snprintf(interfaceName, sizeof(interfaceName), "%s%u", prefix, unit);

        if (interfaceName[0]) {
            setProperty("IOInterfaceName", interfaceName);
            controller->setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceName",
                                    interfaceName);
        }

        if (prefix && prefix[0]) {
            setProperty(kIOInterfaceNamePrefix, prefix);
            controller->setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceNamePrefix",
                                    prefix);
        }

        setProperty(kIOInterfaceUnit, (uint64_t)unit, 32);
        controller->setProperty("AirportRTW89ControlOnlySkywalkIOInterfaceUnit",
                                (uint64_t)unit, 32);
        controller->setProperty("AirportRTW89ControlOnlySkywalkIdentityPublished",
                                interfaceName[0] ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
    } else {
        controller->setProperty("AirportRTW89ControlOnlySkywalkIdentityPublished",
                                kOSBooleanFalse);
    }

    return true;
}

IOReturn RTW88PCIDevice::runSkywalkManualPrepareProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}

IOReturn RTW88PCIDevice::runSkywalkManualDeferProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}

IOReturn RTW88PCIDevice::runSkywalkManualStartProbe()
{
    /* 0.2.143: non-BSD start-only probe.
     *
     * 0.2.142 proved the final ownership model is stable:
     *   - AirportRTW89Interface is the sole BSD/ifnet owner;
     *   - AirportRTW89SkywalkControlInterface is controller-primary,
     *     published in IO80211Plane and has valid/preseeded RegistrationInfo;
     *   - native newUserClient(type 0) still returns kIOReturnNotFound.
     *
     * The restored IO80211SkywalkInterface::start() is the next lifecycle
     * boundary: successful start initializes the read-only postMessage and
     * controller-request contexts at +0x110/+0x118.  Test only that boundary.
     * We deliberately do NOT call prepareBSDInterface(), deferBSDAttach(),
     * controller Skywalk enable, setPoweredOnByUser(), create another ifnet,
     * or declare full Skywalk activation. */
    setProperty("AirportRTW89NonBSDManualStartProbeAvailable", kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDManualStartInvocationSeen", kOSBooleanTrue);

    AirportRTW89SkywalkControlInterface *control = _skywalkInterface;
    if (!control) {
        setProperty("AirportRTW89NonBSDManualStartPrerequisitesReady",
                    kOSBooleanFalse);
        return kIOReturnNotReady;
    }

    void **networkRegistration = control->rawNetworkRegistrationSlot();
    void **ethernetRegistration = control->rawEthernetRegistrationSlot();
    const bool registrationReady =
        networkRegistration && ethernetRegistration &&
        _skywalkNetworkRegistrationCopy && _skywalkEthernetRegistrationCopy &&
        *networkRegistration == _skywalkNetworkRegistrationCopy &&
        *ethernetRegistration == _skywalkEthernetRegistrationCopy;
    const bool primaryMatches =
        getPrimarySkywalkInterface() == control;
    const bool providerIsController =
        control->getProvider() == static_cast<IOService *>(this);
    const bool controlOnly =
        control->getProperty("AirportRTW89ControlOnlySkywalkService") ==
            kOSBooleanTrue;
    const bool noBSDName = control->getProperty(kIOBSDNameKey) == nullptr;
    const bool sharedBSDReady =
        _iface && _iface->getIfnet() &&
        control->rawNetworkBSDInterfaceSlot() &&
        *control->rawNetworkBSDInterfaceSlot() == _iface->getIfnet();
    const bool ready = registrationReady && primaryMatches &&
                       providerIsController && controlOnly &&
                       (noBSDName || sharedBSDReady);

    setProperty("AirportRTW89NonBSDManualStartRegistrationReady",
                registrationReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartPrimaryMatches",
                primaryMatches ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartProviderIsController",
                providerIsController ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartControlOnly",
                controlOnly ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartBSDNameAbsent",
                noBSDName ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartPrerequisitesReady",
                ready ? kOSBooleanTrue : kOSBooleanFalse);

    if (!ready)
        return kIOReturnNotReady;

    if (_skywalkStarted) {
        setProperty("AirportRTW89NonBSDManualStartAlreadyStarted",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }

    setProperty("AirportRTW89NonBSDManualStartPostMessageContextBefore",
                control->rawPostMessageContext() ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartControllerRequestBefore",
                control->rawControllerRequestObject() ? kOSBooleanTrue
                                                      : kOSBooleanFalse);

    /* Keep any framework-triggered controller enable/disable inert.  The
     * control-only enable()/disable() path already returns success without
     * touching RTW89 hardware; this latch provides the older second guard. */
    _skywalkRegisterOnlyProbe = true;
    setProperty("AirportRTW89NonBSDManualStartPowerSideEffectsSuppressed",
                kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkActivationGatePassed", kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartAttempted", kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDManualStartReturned", kOSBooleanFalse);

    IOLog("AirportRTW89 0.2.157: non-BSD Skywalk control start(controller) entering\n");
    const bool started = control->start(this);
    IOLog("AirportRTW89 0.2.157: non-BSD Skywalk control start returned %u (%s)\n",
          started ? 1U : 0U, started ? "success" : "failure");

    _skywalkStarted = started;
    setProperty("AirportRTW89NonBSDManualStartReturned", kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDManualStartRawResult",
                (uint64_t)(started ? 1 : 0), 8);
    setProperty("AirportRTW89NonBSDManualStartSucceeded",
                started ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartPostMessageContextAfter",
                control->rawPostMessageContext() ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartControllerRequestAfter",
                control->rawControllerRequestObject() ? kOSBooleanTrue
                                                      : kOSBooleanFalse);

    const bool registrationSurvived =
        networkRegistration && ethernetRegistration &&
        *networkRegistration == _skywalkNetworkRegistrationCopy &&
        *ethernetRegistration == _skywalkEthernetRegistrationCopy;
    setProperty("AirportRTW89NonBSDManualStartRegistrationSurvived",
                registrationSurvived ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDManualStartNoBSDPreparation",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDManualStartNoBSDDefer",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDManualStartNoSecondIfnet",
                kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkActivationGatePassed", kOSBooleanFalse);

    return started ? kIOReturnSuccess : kIOReturnError;
}


IOReturn RTW88PCIDevice::runSkywalkManualEnableProbe()
{
    /* 0.2.145: non-BSD system-enable-latch probe.
     *
     * 0.2.144 proved that start(controller) succeeds on the control-only
     * interface and creates both restored IO80211 contexts (+0x110/+0x118),
     * but a fresh airportd type-0 reopen still makes the native Skywalk
     * newUserClient path return kIOReturnNotFound.  Test one later framework
     * state bit only: IO80211InfraInterface::setEnabledBySystem(true).
     *
     * Do NOT call isInterfaceEnabled(): the restored implementation follows
     * the optional delegate at +0x1b8 and was proven unsafe when it is null.
     * Do NOT call controller enable(), prepareBSDInterface(), deferBSDAttach(),
     * setPoweredOnByUser(), or touch RTW89 hardware in this probe. */
    setProperty("AirportRTW89NonBSDSystemEnableProbeAvailable",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDSystemEnableInvocationSeen",
                kOSBooleanTrue);

    AirportRTW89SkywalkControlInterface *control = _skywalkInterface;
    if (!control || !_skywalkStarted) {
        setProperty("AirportRTW89NonBSDSystemEnablePrerequisitesReady",
                    kOSBooleanFalse);
        return kIOReturnNotReady;
    }

    void **networkRegistration = control->rawNetworkRegistrationSlot();
    void **ethernetRegistration = control->rawEthernetRegistrationSlot();
    const bool registrationReady =
        networkRegistration && ethernetRegistration &&
        _skywalkNetworkRegistrationCopy && _skywalkEthernetRegistrationCopy &&
        *networkRegistration == _skywalkNetworkRegistrationCopy &&
        *ethernetRegistration == _skywalkEthernetRegistrationCopy;
    const bool primaryMatches = getPrimarySkywalkInterface() == control;
    const bool providerIsController =
        control->getProvider() == static_cast<IOService *>(this);
    const bool controlOnly =
        control->getProperty("AirportRTW89ControlOnlySkywalkService") ==
            kOSBooleanTrue;
    const bool noBSDName = control->getProperty(kIOBSDNameKey) == nullptr;
    const bool sharedBSDReady =
        _iface && _iface->getIfnet() &&
        control->rawNetworkBSDInterfaceSlot() &&
        *control->rawNetworkBSDInterfaceSlot() == _iface->getIfnet();
    const bool postMessageReady = control->rawPostMessageContext() != nullptr;
    const bool controllerRequestReady =
        control->rawControllerRequestObject() != nullptr;
    const bool ready = registrationReady && primaryMatches &&
                       providerIsController && controlOnly &&
                       (noBSDName || sharedBSDReady) &&
                       postMessageReady && controllerRequestReady;

    setProperty("AirportRTW89NonBSDSystemEnableRegistrationReady",
                registrationReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnablePrimaryMatches",
                primaryMatches ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableProviderIsController",
                providerIsController ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableControlOnly",
                controlOnly ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableBSDNameAbsent",
                noBSDName ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnablePostMessageContextReady",
                postMessageReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableControllerRequestReady",
                controllerRequestReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnablePrerequisitesReady",
                ready ? kOSBooleanTrue : kOSBooleanFalse);

    if (!ready)
        return kIOReturnNotReady;

    const bool before = control->enabledBySystem();
    setProperty("AirportRTW89NonBSDSystemEnableBefore",
                before ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableAttempted", kOSBooleanTrue);

    control->IO80211InfraInterface::setEnabledBySystem(true);

    const bool after = control->enabledBySystem();
    setProperty("AirportRTW89NonBSDSystemEnableAfter",
                after ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableSucceeded",
                after ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDSystemEnableNoControllerEnable",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDSystemEnableNoUserPower",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDSystemEnableNoBSDPreparation",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDSystemEnableNoBSDDefer",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDSystemEnableNoSecondIfnet",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDSystemEnableNoHardwarePower",
                kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkActivationGatePassed", kOSBooleanFalse);

    return after ? kIOReturnSuccess : kIOReturnError;
}

IOReturn RTW88PCIDevice::runSkywalkManualUserPowerProbe()
{
    /* 0.2.146: non-BSD user-power-latch probe.
     *
     * 0.2.145 proved that start(controller) + enabledBySystem(true) are both
     * valid on the non-BSD control object, yet fresh airportd type-0 opens
     * still make native newUserClient() return kIOReturnNotFound.  Test the
     * next distinct IO80211 framework state only: setPoweredOnByUser(true).
     *
     * No BSD prepare/defer, no second ifnet, no controller enable(), no
     * POWER_CHANGED notification and no explicit RTW89 power operation are
     * performed here.  Note that Apple's setter may call the controller's
     * configureAntennae() hook on a false->true transition. */
    setProperty("AirportRTW89NonBSDUserPowerProbeAvailable", kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerInvocationSeen", kOSBooleanTrue);

    AirportRTW89SkywalkControlInterface *control = _skywalkInterface;
    if (!control || !_skywalkStarted) {
        setProperty("AirportRTW89NonBSDUserPowerPrerequisitesReady",
                    kOSBooleanFalse);
        return kIOReturnNotReady;
    }

    void **networkRegistration = control->rawNetworkRegistrationSlot();
    void **ethernetRegistration = control->rawEthernetRegistrationSlot();
    const bool registrationReady =
        networkRegistration && ethernetRegistration &&
        _skywalkNetworkRegistrationCopy && _skywalkEthernetRegistrationCopy &&
        *networkRegistration == _skywalkNetworkRegistrationCopy &&
        *ethernetRegistration == _skywalkEthernetRegistrationCopy;
    const bool primaryMatches = getPrimarySkywalkInterface() == control;
    const bool providerIsController =
        control->getProvider() == static_cast<IOService *>(this);
    const bool controlOnly =
        control->getProperty("AirportRTW89ControlOnlySkywalkService") ==
            kOSBooleanTrue;
    const bool noBSDName = control->getProperty(kIOBSDNameKey) == nullptr;
    const bool sharedBSDReady =
        _iface && _iface->getIfnet() &&
        control->rawNetworkBSDInterfaceSlot() &&
        *control->rawNetworkBSDInterfaceSlot() == _iface->getIfnet();
    const bool postMessageReady = control->rawPostMessageContext() != nullptr;
    const bool controllerRequestReady =
        control->rawControllerRequestObject() != nullptr;
    const bool systemEnabled = control->enabledBySystem();
    const bool ready = registrationReady && primaryMatches &&
                       providerIsController && controlOnly &&
                       (noBSDName || sharedBSDReady) &&
                       postMessageReady && controllerRequestReady &&
                       systemEnabled;

    setProperty("AirportRTW89NonBSDUserPowerRegistrationReady",
                registrationReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerPrimaryMatches",
                primaryMatches ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerProviderIsController",
                providerIsController ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerControlOnly",
                controlOnly ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerBSDNameAbsent",
                noBSDName ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerPostMessageContextReady",
                postMessageReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerControllerRequestReady",
                controllerRequestReady ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerSystemEnabled",
                systemEnabled ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerPrerequisitesReady",
                ready ? kOSBooleanTrue : kOSBooleanFalse);

    if (!ready)
        return kIOReturnNotReady;

    const bool before = control->poweredOnByUser();
    setProperty("AirportRTW89NonBSDUserPowerBefore",
                before ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerTransitionRequested",
                before ? kOSBooleanFalse : kOSBooleanTrue);

    if (!before) {
        setProperty("AirportRTW89NonBSDUserPowerAttempted", kOSBooleanTrue);
        IOLog("AirportRTW89 0.2.157: non-BSD setPoweredOnByUser(true) entering\n");
        control->IO80211InfraInterface::setPoweredOnByUser(true);
        IOLog("AirportRTW89 0.2.157: non-BSD setPoweredOnByUser(true) returned\n");
    } else {
        setProperty("AirportRTW89NonBSDUserPowerAlreadyApplied",
                    kOSBooleanTrue);
    }

    const bool after = control->poweredOnByUser();
    const bool systemAfter = control->enabledBySystem();
    const bool registrationSurvived =
        networkRegistration && ethernetRegistration &&
        *networkRegistration == _skywalkNetworkRegistrationCopy &&
        *ethernetRegistration == _skywalkEthernetRegistrationCopy;
    const bool topologySurvived =
        (control->getProperty(kIOBSDNameKey) == nullptr || sharedBSDReady) &&
        getPrimarySkywalkInterface() == control &&
        control->getProvider() == static_cast<IOService *>(this);
    const bool succeeded = after && systemAfter &&
                           registrationSurvived && topologySurvived;

    setProperty("AirportRTW89NonBSDUserPowerAfter",
                after ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerSystemAfter",
                systemAfter ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerRegistrationSurvived",
                registrationSurvived ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerTopologySurvived",
                topologySurvived ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerSucceeded",
                succeeded ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89NonBSDUserPowerNoControllerEnable",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerNoBSDPreparation",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerNoBSDDefer",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerNoSecondIfnet",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerNoPowerNotification",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerNoExplicitRTW89Power",
                kOSBooleanTrue);
    setProperty("AirportRTW89NonBSDUserPowerConfigureAntennaeMayRun",
                before ? kOSBooleanFalse : kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkActivationGatePassed", kOSBooleanFalse);

    return succeeded ? kIOReturnSuccess : kIOReturnError;
}

IOReturn RTW88PCIDevice::runSkywalkManualPowerNotifyProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}


IOReturn RTW88PCIDevice::runSkywalkManualBSDLinkProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}


IOReturn RTW88PCIDevice::runSkywalkManualRunningProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}


IOReturn RTW88PCIDevice::runSkywalkManualPrivateLinkProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}


IOReturn RTW88PCIDevice::runSkywalkManualReportLinkProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}


IOReturn RTW88PCIDevice::runSkywalkManualControllerPowerProbe()
{
    /* 0.2.142: historical full-Skywalk/BSD-companion experiments are inert.
     * The supported architecture is one legacy BSD owner plus one non-BSD
     * AirportRTW89SkywalkControlInterface. */
    setProperty("AirportRTW89DeprecatedSkywalkProbeBlocked", kOSBooleanTrue);
    return kIOReturnUnsupported;
}

bool RTW88PCIDevice::createAndAttachSkywalkPrimaryInterface()
{
    if (_skywalkInterface)
        return getPrimarySkywalkInterface() == _skywalkInterface;

    AirportRTW89SkywalkControlInterface *interface =
        new AirportRTW89SkywalkControlInterface;
    _skywalkInterface = interface;
    setProperty("AirportRTW89ConcreteSkywalkServiceInitAllocatable",
                interface ? kOSBooleanTrue : kOSBooleanFalse);
    if (!interface)
        return false;

    setProperty("AirportRTW89ConcreteSkywalkServiceInitAttempted",
                kOSBooleanTrue);
    bool initialized = interface->init((IOService *)this);
    setProperty("AirportRTW89ConcreteSkywalkServiceInitRawResult",
                (uint64_t)(initialized ? 1 : 0), 8);
    setProperty("AirportRTW89ConcreteSkywalkServiceInitSucceeded",
                initialized ? kOSBooleanTrue : kOSBooleanFalse);
    publishSkywalkExpansionCheckpoint(
        interface,
        "AirportRTW89SkywalkNetworkExpansionAfterInit",
        "AirportRTW89SkywalkEthernetExpansionAfterInit",
        "AirportRTW89SkywalkExpansionViewsAgreeAfterInit");
    if (!initialized)
        return false;

    interface->setInterfaceRole(1);
    /* 0.2.74: DO NOT call IO80211SkywalkInterface::setInterfaceId().
     * The exact restored IO80211FamilyLegacy 1200.12.2b1 used by the
     * Tahoe/OCLP stack carries a zero-valued symbol for this non-virtual
     * method.  Referencing it makes OpenCore reject the entire kext during
     * prelink, before the driver entry point can run.  Role assignment is
     * retained; interface-id programming remains intentionally ABI-pinned
     * off until its storage/implementation is recovered from this binary. */
    setProperty("AirportRTW89ConcreteSkywalkRoleAfterSet",
                (uint64_t)interface->getInterfaceRole(), 32);
    setProperty("AirportRTW89ConcreteSkywalkInterfaceIdSet",
                kOSBooleanFalse);
    setProperty("AirportRTW89ConcreteSkywalkInterfaceIdSkippedZeroSymbol",
                kOSBooleanTrue);

    IO80211SkywalkInterface *before = getPrimarySkywalkInterface();
    setProperty("AirportRTW89ConcreteSkywalkPrimaryBeforeAttachPresent",
                before ? kOSBooleanTrue : kOSBooleanFalse);

    setProperty("AirportRTW89ConcreteSkywalkAttachAttempted", kOSBooleanTrue);
    bool attached = interface->attach((IOService *)this);
    setProperty("AirportRTW89ConcreteSkywalkAttachRawResult",
                (uint64_t)(attached ? 1 : 0), 8);
    setProperty("AirportRTW89ConcreteSkywalkAttachSucceeded",
                attached ? kOSBooleanTrue : kOSBooleanFalse);
    publishSkywalkExpansionCheckpoint(
        interface,
        "AirportRTW89SkywalkNetworkExpansionAfterOrdinaryAttach",
        "AirportRTW89SkywalkEthernetExpansionAfterOrdinaryAttach",
        "AirportRTW89SkywalkExpansionViewsAgreeAfterOrdinaryAttach");
    if (!attached)
        return false;

    setProperty("AirportRTW89ConcreteSkywalkProviderIsController",
                interface->getProvider() == (IOService *)this
                    ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ConcreteSkywalkControllerAttachAttempted",
                kOSBooleanTrue);
    bool controllerAttached = attachInterface((IOSkywalkInterface *)interface,
                                              (IOService *)this);
    setProperty("AirportRTW89ConcreteSkywalkControllerAttachRawResult",
                (uint64_t)(controllerAttached ? 1 : 0), 8);
    setProperty("AirportRTW89ConcreteSkywalkControllerAttachSucceeded",
                controllerAttached ? kOSBooleanTrue : kOSBooleanFalse);
    publishSkywalkExpansionCheckpoint(
        interface,
        "AirportRTW89SkywalkNetworkExpansionAfterControllerAttach",
        "AirportRTW89SkywalkEthernetExpansionAfterControllerAttach",
        "AirportRTW89SkywalkExpansionViewsAgreeAfterControllerAttach");
    if (!controllerAttached)
        return false;

    IO80211SkywalkInterface *after = getPrimarySkywalkInterface();
    setProperty("AirportRTW89ConcreteSkywalkPrimaryAfterAttachPresent",
                after ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ConcreteSkywalkPrimaryAfterAttachIsProbe",
                after == interface ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ConcreteSkywalkCleanupSuppressed",
                kOSBooleanTrue);
    setProperty("AirportRTW89ConcreteSkywalkControllerReferenceRetained",
                kOSBooleanTrue);
    return after == interface;
}

void RTW88PCIDevice::publishSkywalkPowerState(const char *stage)
{
    if (!_skywalkInterface)
        return;

    setProperty("AirportRTW89SkywalkPowerStateStage", stage ? stage : "unknown");
    setProperty("AirportRTW89SkywalkEnabledBySystem",
                _skywalkInterface->enabledBySystem()
                    ? kOSBooleanTrue : kOSBooleanFalse);
    /* Do not call IO80211SkywalkInterface::isInterfaceEnabled() here.  The
     * exact restored binary dereferences a delegate at object +0x1b8 with no
     * null check; this port does not have that delegate. */
    setProperty("AirportRTW89SkywalkControlInterfaceEnabledGetterSuppressed",
                kOSBooleanTrue);
}

bool RTW88PCIDevice::preseedSkywalkRegistrationCopies(
    const AirportRTW89SkywalkControlInterface::RegistrationInfo &registrationInfo)
{
    if (!_skywalkInterface)
        return false;

    void **networkRegistration =
        _skywalkInterface->rawNetworkRegistrationSlot();
    void **ethernetRegistration =
        _skywalkInterface->rawEthernetRegistrationSlot();
    bool slotsPresent = networkRegistration && ethernetRegistration;
    bool slotsEmpty = slotsPresent && *networkRegistration == nullptr &&
                      *ethernetRegistration == nullptr;

    setProperty("AirportRTW89SkywalkRawRegistrationSlotsPresent",
                slotsPresent ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRegistrationSlotsInitiallyEmpty",
                slotsEmpty ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkPreseedUsesExactBinaryOrdering",
                kOSBooleanTrue);

    /* Do not weaken the old post-prepare gate: replace it for this exact ABI
     * with a different pre-prepare invariant proven by disassembly.  In
     * IOSkywalkNetworkInterface::prepareBSDInterface, expansion +0x00 is
     * dereferenced before expansion +0x08 is populated with the ifnet.  Thus
     * requiring a BSD round-trip before filling +0x00 is impossible and was
     * the direct cause of the 0.2.82 NULL+0x4c panic. */
    if (!slotsPresent || !slotsEmpty)
        return false;

    static_assert(sizeof(AirportRTW89SkywalkControlInterface::RegistrationInfo) ==
                      AirportRTW89SkywalkControlInterface::kRegistrationInfoSize,
                  "restored Skywalk registration-info size changed");

    const UInt8 *bytes = (const UInt8 *)&registrationInfo;
    UInt32 version = *(const UInt32 *)(bytes + 0x0);
    UInt32 size = *(const UInt32 *)(bytes + 0x4);
    UInt32 mtu = *(const UInt32 *)(bytes + 0x4c);
    setProperty("AirportRTW89SkywalkPreseedRegistrationVersion",
                (uint64_t)version, 32);
    setProperty("AirportRTW89SkywalkPreseedRegistrationSize",
                (uint64_t)size, 32);
    setProperty("AirportRTW89SkywalkPreseedRegistrationMTU",
                (uint64_t)mtu, 32);
    bool headerSane = version == 1 && size == 0x130 && mtu != 0;
    setProperty("AirportRTW89SkywalkPreseedRegistrationHeaderSane",
                headerSane ? kOSBooleanTrue : kOSBooleanFalse);
    if (!headerSane)
        return false;

    _skywalkNetworkRegistrationCopy = IOMallocZero(
        AirportRTW89SkywalkControlInterface::kNetworkRegistrationCopySize);
    _skywalkEthernetRegistrationCopy = IOMallocZero(
        AirportRTW89SkywalkControlInterface::kRegistrationInfoSize);
    if (!_skywalkNetworkRegistrationCopy || !_skywalkEthernetRegistrationCopy)
        return false;

    /* registerNetworkInterface() in this exact IOSkywalkFamily allocates and
     * copies 0x108 bytes, while registerEthernetInterface() keeps the full
     * 0x130-byte record.  Mirror those exact copy sizes. */
    memcpy(_skywalkNetworkRegistrationCopy, &registrationInfo,
           AirportRTW89SkywalkControlInterface::kNetworkRegistrationCopySize);
    memcpy(_skywalkEthernetRegistrationCopy, &registrationInfo,
           AirportRTW89SkywalkControlInterface::kRegistrationInfoSize);

    *networkRegistration = _skywalkNetworkRegistrationCopy;
    *ethernetRegistration = _skywalkEthernetRegistrationCopy;

    bool pointerRoundTrip =
        *networkRegistration == _skywalkNetworkRegistrationCopy &&
        *ethernetRegistration == _skywalkEthernetRegistrationCopy;
    bool dataRoundTrip = pointerRoundTrip &&
        memcmp(*networkRegistration, &registrationInfo,
               AirportRTW89SkywalkControlInterface::kNetworkRegistrationCopySize) == 0 &&
        memcmp(*ethernetRegistration, &registrationInfo,
               AirportRTW89SkywalkControlInterface::kRegistrationInfoSize) == 0;

    setProperty("AirportRTW89SkywalkRegistrationPointerRoundTrip",
                pointerRoundTrip ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRegistrationDataRoundTrip",
                dataRoundTrip ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRegistrationPreseedSucceeded",
                dataRoundTrip ? kOSBooleanTrue : kOSBooleanFalse);
    return dataRoundTrip;
}


void RTW88PCIDevice::publishSkywalkExpansionCheckpoint(
    AirportRTW89SkywalkControlInterface *interface,
    const char *networkKey, const char *ethernetKey,
    const char *agreementKey)
{
    if (!interface)
        return;

    void *rawNetwork = interface->rawNetworkExpansion();
    void *rawEthernet = interface->rawEthernetExpansion();
    void *typedNetwork = interface->typedNetworkExpansion();
    void *typedEthernet = interface->typedEthernetExpansion();
    setProperty(networkKey, rawNetwork ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty(ethernetKey, rawEthernet ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty(agreementKey,
                rawNetwork == typedNetwork && rawEthernet == typedEthernet
                    ? kOSBooleanTrue : kOSBooleanFalse);
}
#ifndef IO80211FAMILY_V2
/* The legacy framework keeps this tiny vtable override local (lowercase `t`) rather
 * than exporting it to third-party kexts.  Supply an inert ABI-equivalent
 * definition so the allocation-only subclass vtable is fully resolvable. */
void IO80211InfraInterface::removePacketQueue(IO80211FlowQueueHash *) {}
/* Tahoe's IONetworkingFamily no longer exports these unused legacy reserve
 * slots.  The concrete Skywalk subclass vtable still carries relocations for
 * them, so provide inert definitions solely to make that vtable linkable. */
void IONetworkController::_RESERVEDIONetworkController2() {}
void IONetworkController::_RESERVEDIONetworkController3() {}
void IONetworkController::_RESERVEDIONetworkController4() {}
void IONetworkController::_RESERVEDIONetworkController5() {}
void IONetworkController::_RESERVEDIONetworkController6() {}
void IONetworkController::_RESERVEDIONetworkController7() {}
static_assert(sizeof(IO80211SkywalkInterface) == 0x320,
              "1200.12.2b1 IO80211SkywalkInterface ABI mismatch");
static_assert(sizeof(IO80211InfraInterface) == 0x4b8,
              "1200.12.2b1 IO80211InfraInterface ABI mismatch");
static_assert(sizeof(AirportRTW89SkywalkControlInterface) == 0x4b8,
              "AirportRTW89 Skywalk subclass unexpectedly adds storage");
#endif
#endif
