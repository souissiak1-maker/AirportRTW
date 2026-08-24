/* 0.2.245: permit the IO80211Reference-style payload-less DISASSOCIATE/22 controller request; all other null Apple80211 payloads remain rejected. */
/* 0.2.241: diagnostic-only Skywalk CARD_CAPABILITIES / antenna buffer-shape capture in the existing boot-proven apple80211SkywalkRequest hook; no return changes and no new IO80211 virtual overrides. */
/* 0.2.226: for disconnected scans, do not post Tahoe's early SCAN_DONE while
 * the manual RF sweep is still running. Combined with known-BSS channel
 * priority in RTW88IEEE80211, this makes the completion edge reflect actual
 * refreshed observations instead of a 100 ms partial snapshot. */
/* 0.2.225: add per-BSS truthful age/generation diagnostics for the
 * persistent cache experiment. No association request behavior is changed. */
/* 0.2.180: consume persistent per-BSSID RSN/WPA state for scan results and
 * WPA2 association classification, matching IO80211Reference's node ownership model. */
/* 0.2.179: resolve WPA2 association security from the live RTW BSS list and
 * pin the connect attempt to that exact BSSID so Tahoe's empty auth-upper
 * SET20 cannot be misclassified as an open-network join. */
/* 0.2.178: classify Tahoe SET20 security from the matching scanned BSS when
 * ad_auth_upper is missing, select Apple RSN for credential-less WPA2-PSK,
 * and constrain WPA2 joins to a scanned CCMP+PSK candidate. */
/* 0.2.177: preserve Tahoe's original outer WPA2 security SET payloads
 * across IO80211Interface marshalling and prefer the existing internal WPA2
 * handshake whenever SET20 already carries usable PMK/passphrase material. */
/* 0.2.165: canonicalize only proven WPA2-PSK/CCMP scan RSN IEs so Tahoe
 * qualifies secured candidates through the same narrow security contract used
 * by our association/key path.  Keep the raw AP RSN bytes for diagnostics. */
/* 0.2.160: Apple-originated scans are cache-only while associated to preserve throughput. */
/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Experimental legacy IO80211/Apple80211 frontend for Feixiao.
 *
 * This intentionally keeps Feixiao's existing internal WPA2-PSK state
 * machine.  macOS owns network selection and presents the native Wi-Fi UI,
 * while this file translates Apple80211 requests into RTW88IEEE80211 calls.
 * 0.2.106 retains the IO80211Reference-compatible Apple80211 control
 * surface.  Framework contracts may be emulated/no-op where RTW89 lacks an
 * equivalent hardware path; those cases publish explicit diagnostic markers.
 */

#include "RTW88PCIDevice.hpp"

/* ABI-safe file-level transition epoch owned by RTW88PCIDevice.cpp. */
extern volatile UInt64 gAirportRTW89LinkLossTransitionStartMS;

#ifdef RTW_AIRPORT

#include "RTW88IEEE80211.hpp"
#include "RTW88UserClient.hpp"
#include "../net80211/RTW89Net80211Core.hpp"

#include <IOKit/IOLib.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/80211/IO80211VirtualInterface.h>
#include <pexpert/pexpert.h>

/* MacKernelSDK in this tree predates a few private Apple80211 structures that
 * current IO80211Reference uses.  Keep private local ABI mirrors instead of
 * modifying the imported SDK headers. */
struct AirportRTW89VHTMCSIndexSetData {
    UInt32 version;
    UInt16 mcs_map;
} __attribute__((packed));

struct AirportRTW89MCSVHTData {
    UInt32 version;
    UInt32 index;
    UInt32 nss;
    UInt32 bw;
    UInt32 guard_interval;
} __attribute__((packed));

struct AirportRTW89AwdlBSSIDData {
    UInt32 version;
    UInt8 bssid[APPLE80211_ADDR_LEN];
    UInt8 unknown_mac[APPLE80211_ADDR_LEN];
} __attribute__((packed));

struct AirportRTW89VersionedScalar {
    UInt32 version;
    UInt32 value;
} __attribute__((packed));

static void airportSetCapability(apple80211_capability_data *caps, UInt32 bit)
{
    if (bit <= APPLE80211_CAP_MAX)
        caps->capabilities[bit >> 3] |= (UInt8)(1U << (bit & 7));
}

static size_t airportBoundedStringLength(const char *text, size_t maximum)
{
    size_t length = 0;
    if (!text)
        return 0;
    while (length < maximum && text[length] != '\0')
        ++length;
    return length;
}

static UInt64 airportSecurityControlMonotonicMS()
{
    uint64_t nowNs = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
    return nowNs / 1000000ULL;
}

/* 0.3.9 diagnostic: allow an explicitly configured pre-RUN target channel
 * to be returned by GET4/APPLE80211_IOC_CHANNEL.  This intentionally changes
 * the semantic from "current operating channel" only when the boot arg is
 * present.  It is not automatic target inference and must never guess from
 * the last/strongest scan result. */
static bool airportPreRunTargetChannelOverride(UInt32 *channelOut)
{
    if (!channelOut)
        return false;
    int value = 0;
    if (!PE_parse_boot_argn("rtw89_get4_target_channel", &value, sizeof(value)))
        return false;

    const UInt32 channel = value > 0 ? (UInt32)value : 0U;
    const bool valid2GHz = channel >= 1U && channel <= 14U;
    const bool valid5GHz = channel == 36U || channel == 40U ||
        channel == 44U || channel == 48U || channel == 149U ||
        channel == 153U || channel == 157U || channel == 161U ||
        channel == 165U;
    if (!valid2GHz && !valid5GHz)
        return false;

    *channelOut = channel;
    return true;
}

/* 0.2.176 diagnostic-only: privacy-preserving hashes for current-network
 * identity comparisons across the inner Apple80211 getter and Tahoe's outer
 * userspace buffer.  FNV-1a is sufficient here because this is correlation
 * telemetry, not a security primitive. */
static UInt64 airportStatusDiagHash(const UInt8 *bytes, size_t length)
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


/* 0.2.165 WPA2 pre-join helpers.  Linux encodes both cipher and AKM suites as
 * the 4-byte OUI/type value 00:0f:ac:XX.  Keep local constants here rather
 * than making the Apple frontend depend on Linux WLAN header internals. */
static constexpr UInt32 kAirportRsnCipherTKIP = 0x000FAC02U;
static constexpr UInt32 kAirportRsnCipherCCMP = 0x000FAC04U;
static constexpr UInt32 kAirportRsnAkmPSK = 0x000FAC02U;

static void airportWriteRsnSuite(UInt8 *out, UInt32 suite)
{
    out[0] = (UInt8)((suite >> 24) & 0xff);
    out[1] = (UInt8)((suite >> 16) & 0xff);
    out[2] = (UInt8)((suite >> 8) & 0xff);
    out[3] = (UInt8)(suite & 0xff);
}

static UInt32 airportReadRsnSuite(const UInt8 *in)
{
    return ((UInt32)in[0] << 24) | ((UInt32)in[1] << 16) |
           ((UInt32)in[2] << 8) | (UInt32)in[3];
}

static UInt16 airportBuildCanonicalWPA2PSKRsnIE(UInt8 out[22],
                                                UInt32 groupCipher)
{
    if (groupCipher != kAirportRsnCipherTKIP)
        groupCipher = kAirportRsnCipherCCMP;

    UInt8 *p = out;
    *p++ = 48;            /* RSN element */
    *p++ = 20;            /* body length */
    *p++ = 1; *p++ = 0;  /* version 1 */
    airportWriteRsnSuite(p, groupCipher); p += 4;
    *p++ = 1; *p++ = 0;  /* one pairwise suite */
    airportWriteRsnSuite(p, kAirportRsnCipherCCMP); p += 4;
    *p++ = 1; *p++ = 0;  /* one AKM suite */
    airportWriteRsnSuite(p, kAirportRsnAkmPSK); p += 4;
    *p++ = 0; *p++ = 0;  /* no PMF/extended RSN capabilities advertised */
    return (UInt16)(p - out);
}

struct AirportRTW89RsnSummary {
    UInt16 version;
    UInt16 pairwiseCount;
    UInt16 akmCount;
    UInt16 capabilities;
    UInt32 groupCipher;
    bool capabilitiesPresent;
    bool hasCCMP;
    bool hasPSK;
    bool hasSAE;
    bool has8021X;
};

static bool airportParseRsnSummary(const UInt8 *ie, size_t ieLength,
                                   AirportRTW89RsnSummary *summary)
{
    if (!summary)
        return false;
    bzero(summary, sizeof(*summary));
    if (!ie || ieLength < 10 || ie[0] != 48 || (size_t)ie[1] + 2 > ieLength)
        return false;

    const UInt8 *p = ie + 2;
    const UInt8 *end = ie + 2 + ie[1];
    if (p + 2 + 4 + 2 > end)
        return false;
    summary->version = (UInt16)(p[0] | ((UInt16)p[1] << 8)); p += 2;
    summary->groupCipher = airportReadRsnSuite(p); p += 4;
    summary->pairwiseCount = (UInt16)(p[0] | ((UInt16)p[1] << 8)); p += 2;
    if (p + (size_t)summary->pairwiseCount * 4 > end)
        return false;
    for (UInt16 i = 0; i < summary->pairwiseCount; ++i, p += 4) {
        if (airportReadRsnSuite(p) == kAirportRsnCipherCCMP)
            summary->hasCCMP = true;
    }
    if (p + 2 > end)
        return false;
    summary->akmCount = (UInt16)(p[0] | ((UInt16)p[1] << 8)); p += 2;
    if (p + (size_t)summary->akmCount * 4 > end)
        return false;
    for (UInt16 i = 0; i < summary->akmCount; ++i, p += 4) {
        const UInt32 suite = airportReadRsnSuite(p);
        if (suite == 0x000FAC02U)
            summary->hasPSK = true;
        else if (suite == 0x000FAC08U)
            summary->hasSAE = true;
        else if (suite == 0x000FAC01U || suite == 0x000FAC05U)
            summary->has8021X = true;
    }
    if (p + 2 <= end) {
        summary->capabilities = (UInt16)(p[0] | ((UInt16)p[1] << 8));
        summary->capabilitiesPresent = true;
    }
    return true;
}

IOReturn RTW88PCIDevice::getHardwareAddressForInterface(
    IO80211Interface *interface, IOEthernetAddress *address)
{
    (void)interface;
    return getHardwareAddress(address);
}

void RTW88PCIDevice::inputMonitorPacket(mbuf_t packet, UInt32 channel,
                                         void *metadata,
                                         unsigned long metadataLength)
{
    (void)packet;
    (void)channel;
    (void)metadata;
    (void)metadataLength;
}

SInt32 RTW88PCIDevice::monitorModeSetEnabled(
    IO80211Interface *interface, bool enabled, UInt flags)
{
    (void)interface;
    (void)flags;
    /* 0.2.103: IO80211Reference accepts both monitor enable/disable requests as
     * control-plane no-ops.  Mirror that ABI contract so CoreWLAN is not
     * gated by an unsupported return; RTW89 monitor RX remains unimplemented. */
    setProperty("AirportRTW89Apple80211MonitorModeRequested",
                enabled ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89Apple80211MonitorModeEmulated", kOSBooleanTrue);
    return kIOReturnSuccess;
}

SInt32 RTW88PCIDevice::stopDMA()
{
    if (_intrSrc)
        _intrSrc->disable();
    if (_txQueue) {
        _txQueue->stop();
        _txQueue->flush();
    }
    return kIOReturnSuccess;
}

UInt32 RTW88PCIDevice::hardwareOutputQueueDepth(IO80211Interface *interface)
{
    (void)interface;
    return 256;
}

SInt32 RTW88PCIDevice::performCountryCodeOperation(
    IO80211Interface *interface, IO80211CountryCodeOp operation)
{
    (void)interface;
    (void)operation;
    return kIOReturnSuccess;
}

SInt32 RTW88PCIDevice::enableFeature(IO80211FeatureCode feature, void *data)
{
    (void)data;
    return feature == kIO80211Feature80211n ? kIOReturnSuccess
                                            : kIOReturnUnsupported;
}

bool RTW88PCIDevice::useAppleRSNSupplicant(IO80211Interface *interface)
{
    const UInt64 queryMS = airportSecurityControlMonotonicMS();
    /* 0.2.163/0.2.165: match IO80211Reference's primary STA policy.  The
     * 0.2.163 runtime proved Tahoe does not query this callback at our current
     * pre-SET20 WPA2 gate, so keep it enabled for the later RSN transaction
     * without treating it as the candidate-qualification trigger. */
    const bool primary = !interface || interface == _iface;
    static UInt32 queryCount = 0;
    ++queryCount;
    setProperty("AirportRTW89AppleRSNSupplicantQueried", kOSBooleanTrue);
    setProperty("AirportRTW89AppleRSNSupplicantQueryCount",
                (uint64_t)queryCount, 32);
    if (queryCount == 1U)
        setProperty("AirportRTW89SecurityControlRSNPolicyFirstMS",
                    (uint64_t)queryMS, 64);
    setProperty("AirportRTW89SecurityControlRSNPolicyLastMS",
                (uint64_t)queryMS, 64);
    setProperty("AirportRTW89SecurityControlRSNPolicyReturn",
                kOSBooleanTrue);
    setProperty("AirportRTW89AppleRSNSupplicantPrimary",
                primary ? kOSBooleanTrue : kOSBooleanFalse);
    /* IO80211Reference ignores the legacy IO80211Interface argument and returns
     * true whenever its Apple supplicant build is active.  Do the same here:
     * some IO80211FamilyLegacy call sites pass a null interface while asking
     * the controller policy question before SET20 exists. */
    setProperty("AirportRTW89AppleRSNSupplicantEnabled", kOSBooleanTrue);
    return true;
}

SInt32 RTW88PCIDevice::apple80211_ioctl(IO80211SkywalkInterface *interface,
                                         unsigned long command, void *data)
{
    /* IO80211Reference's Sonoma controller observes this entry point and then
     * delegates to IO80211Controller.  Preserve that exact ownership model;
     * the 0.2.102 outer BSD-ioctl probe remains in the companion path. */
    setProperty("AirportRTW89SkywalkIoctlSeen", kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkIoctlCommand", (uint64_t)command, 32);

    /* Tahoe's periodic CHANNELS_INFO query reaches this Skywalk controller
     * ioctl entry, bypassing both the primary interface performCommand and
     * the legacy controller ioctl_get virtual.  Serve GET207 from the same
     * canonical builder used by those paths.  Keep the large private payload
     * heap-backed and bound copyout to the caller's declared length. */
    apple80211req *req = data ? static_cast<apple80211req *>(data) : nullptr;
    if (req && req->req_type == APPLE80211_IOC_CHANNELS_INFO &&
        req->req_data != nullptr) {
        static volatile UInt32 skywalkGet207Count = 0;
        static volatile UInt32 skywalkGet207SuccessCount = 0;
        const UInt32 sequence =
            __sync_add_and_fetch(&skywalkGet207Count, 1U);
        const size_t structSize = sizeof(AirportRTW89ChannelsInfoData);
        const size_t minimumUseful =
            offsetof(AirportRTW89ChannelsInfoData, chan_num) + 22U;
        SInt32 result = kIOReturnBadArgument;
        size_t copyLength = 0;
        int copyoutResult = -1;

        if (req->req_len >= minimumUseful) {
            AirportRTW89ChannelsInfoData *value =
                static_cast<AirportRTW89ChannelsInfoData *>(
                    IOMallocZero(structSize));
            if (!value) {
                result = kIOReturnNoMemory;
            } else {
                airportFillChannelsInfo(value);
                copyLength = req->req_len < structSize
                    ? req->req_len : structSize;
                copyoutResult = copyout(
                    value, (user_addr_t)req->req_data, copyLength);
                result = copyoutResult == 0 ? kIOReturnSuccess
                                            : (SInt32)copyoutResult;
                IOFree(value, structSize);
                if (result == kIOReturnSuccess)
                    __sync_add_and_fetch(&skywalkGet207SuccessCount, 1U);
            }
        }

        setProperty("AirportRTW89SkywalkGet207BridgeSeen", kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkGet207BridgeCount",
                    (uint64_t)sequence, 32);
        setProperty("AirportRTW89SkywalkGet207BridgeSuccessCount",
                    (uint64_t)skywalkGet207SuccessCount, 32);
        setProperty("AirportRTW89SkywalkGet207BridgeReqLen",
                    (uint64_t)req->req_len, 32);
        setProperty("AirportRTW89SkywalkGet207BridgeCopyLength",
                    (uint64_t)copyLength, 32);
        setProperty("AirportRTW89SkywalkGet207BridgeCopyoutReturn",
                    (uint64_t)(uint32_t)copyoutResult, 32);
        setProperty("AirportRTW89SkywalkGet207BridgeReturn",
                    (uint64_t)(uint32_t)result, 32);
        return result;
    }

    return IO80211Controller::apple80211_ioctl(interface, command, data);
}

SInt32 RTW88PCIDevice::apple80211_ioctl_get(
    IO80211Interface *interface, IO80211VirtualInterface *virtualInterface,
    ifnet_t net, void *data)
{
    /* 0.2.235: diagnostic-only controller GET4/CHANNEL boundary probe.
     *
     * 0.2.234 proved that our exact version-only CHANNEL seed matcher does
     * normalize GET4 calls that reach AirportRTW89Interface::performCommand()
     * after DISASSOCIATE arms the WPA2 trace window.  The live airportd log,
     * however, still shows two APPLE80211_IOC_CHANNEL failures immediately
     * before "Will associate"; the outer performCommand history does not
     * contain those calls before the DISASSOCIATE arm.
     *
     * Characterize the controller-owned apple80211_ioctl_get() boundary
     * without changing semantics.  For exact GET4 len 16,
     * snapshot the caller buffer before and after delegating to Apple's base
     * IO80211Controller implementation.  Publish only structural metadata,
     * return value and monotonic timestamps.  Never modify the payload and
     * never normalize the base return in this build. */
    apple80211req *outerReq =
        data ? static_cast<apple80211req *>(data) : nullptr;

    /* Tahoe's Apple80211GetWithIOCTL issues CHANNELS_INFO through the
     * controller-owned ioctl_get virtual, not necessarily through the BSD
     * interface performCommand wrapper.  The interface-only 0.3.8 bridge
     * therefore never saw the repeated GET207 calls and IO80211Old returned
     * -3903.  Marshal the same canonical payload at the boundary that owns
     * this request.  Keep the 0xA0C object off the kernel stack and copy only
     * the caller-provided bounded length. */
    if (outerReq && outerReq->req_type == APPLE80211_IOC_CHANNELS_INFO &&
        outerReq->req_data != nullptr) {
        static volatile UInt32 controllerGet207Count = 0;
        static volatile UInt32 controllerGet207SuccessCount = 0;
        const UInt32 sequence =
            __sync_add_and_fetch(&controllerGet207Count, 1U);
        const size_t structSize = sizeof(AirportRTW89ChannelsInfoData);
        const size_t minimumUseful =
            offsetof(AirportRTW89ChannelsInfoData, chan_num) + 22U;
        SInt32 result = kIOReturnBadArgument;
        size_t copyLength = 0;
        int copyoutResult = -1;

        if (outerReq->req_len >= minimumUseful) {
            AirportRTW89ChannelsInfoData *value =
                static_cast<AirportRTW89ChannelsInfoData *>(
                    IOMallocZero(structSize));
            if (!value) {
                result = kIOReturnNoMemory;
            } else {
                airportFillChannelsInfo(value);
                copyLength = outerReq->req_len < structSize
                    ? outerReq->req_len : structSize;
                copyoutResult = copyout(
                    value, (user_addr_t)outerReq->req_data, copyLength);
                result = copyoutResult == 0 ? kIOReturnSuccess
                                            : (SInt32)copyoutResult;
                IOFree(value, structSize);
                if (result == kIOReturnSuccess)
                    __sync_add_and_fetch(&controllerGet207SuccessCount, 1U);
            }
        }

        setProperty("AirportRTW89ControllerGet207BridgeSeen", kOSBooleanTrue);
        setProperty("AirportRTW89ControllerGet207BridgeCount",
                    (uint64_t)sequence, 32);
        setProperty("AirportRTW89ControllerGet207BridgeSuccessCount",
                    (uint64_t)controllerGet207SuccessCount, 32);
        setProperty("AirportRTW89ControllerGet207BridgeReqLen",
                    (uint64_t)outerReq->req_len, 32);
        setProperty("AirportRTW89ControllerGet207BridgeCopyLength",
                    (uint64_t)copyLength, 32);
        setProperty("AirportRTW89ControllerGet207BridgeCopyoutReturn",
                    (uint64_t)(uint32_t)copyoutResult, 32);
        setProperty("AirportRTW89ControllerGet207BridgeReturn",
                    (uint64_t)(uint32_t)result, 32);
        return result;
    }

    const bool controllerGET4DiagCandidate =
        outerReq != nullptr &&
        outerReq->req_type == APPLE80211_IOC_CHANNEL &&
        outerReq->req_data != nullptr &&
        outerReq->req_len == sizeof(apple80211_channel_data);

    if (controllerGET4DiagCandidate) {
        static volatile UInt32 controllerGET4DiagCount = 0;
        const UInt32 candidateCount =
            __sync_add_and_fetch(&controllerGET4DiagCount, 1U);

        apple80211_channel_data pre = {};
        apple80211_channel_data post = {};
        const user_addr_t userData = (user_addr_t)outerReq->req_data;
        const int preCopyin =
            copyin(userData, &pre, sizeof(pre));
        const bool associationActiveBefore =
            _ieee80211 && _ieee80211->hasActiveAssociation();

        uint64_t entryNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &entryNowNs);
        const UInt64 entryMS = entryNowNs / 1000000ULL;

        const SInt32 baseReturn =
            IO80211Controller::apple80211_ioctl_get(
                interface, virtualInterface, net, data);

        uint64_t exitNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &exitNowNs);
        const UInt64 exitMS = exitNowNs / 1000000ULL;

        const int postCopyin =
            copyin(userData, &post, sizeof(post));
        const bool associationActiveAfter =
            _ieee80211 && _ieee80211->hasActiveAssociation();

        UInt32 preNonZeroBytes = 0;
        UInt32 preFirstNonZeroOffset = 0xffffffffU;
        UInt8 preFirstNonZeroValue = 0;
        if (preCopyin == 0) {
            const UInt8 *bytes =
                reinterpret_cast<const UInt8 *>(&pre);
            for (UInt32 i = 0; i < sizeof(pre); ++i) {
                if (bytes[i] == 0)
                    continue;
                ++preNonZeroBytes;
                if (preFirstNonZeroOffset == 0xffffffffU) {
                    preFirstNonZeroOffset = i;
                    preFirstNonZeroValue = bytes[i];
                }
            }
        }

        UInt32 postNonZeroBytes = 0;
        UInt32 postFirstNonZeroOffset = 0xffffffffU;
        UInt8 postFirstNonZeroValue = 0;
        if (postCopyin == 0) {
            const UInt8 *bytes =
                reinterpret_cast<const UInt8 *>(&post);
            for (UInt32 i = 0; i < sizeof(post); ++i) {
                if (bytes[i] == 0)
                    continue;
                ++postNonZeroBytes;
                if (postFirstNonZeroOffset == 0xffffffffU) {
                    postFirstNonZeroOffset = i;
                    postFirstNonZeroValue = bytes[i];
                }
            }
        }

        const bool unchanged =
            preCopyin == 0 && postCopyin == 0 &&
            memcmp(&pre, &post, sizeof(pre)) == 0;
        const UInt64 preHash =
            preCopyin == 0
                ? airportStatusDiagHash(
                      reinterpret_cast<const UInt8 *>(&pre), sizeof(pre))
                : 0;
        const UInt64 postHash =
            postCopyin == 0
                ? airportStatusDiagHash(
                      reinterpret_cast<const UInt8 *>(&post), sizeof(post))
                : 0;

        /* 0.2.236: active controller-boundary GET4/CHANNEL seed-empty-success
         * experiment.  0.2.235 correlated this exact controller hook with
         * airportd's pre-"Will associate" GET4 failures: the primary STA,
         * no virtual interface, req_val 0, len-16 caller buffer is unchanged
         * by Apple's base implementation, contains only outer version=1, and
         * the base return is 6.
         *
         * Keep the test narrower than a generic CHANNEL-success override:
         * require primary interface, no virtual interface, disconnected
         * association truth before/after the base call, base return 6, and
         * the exact measured version-only seed shape.  Do not populate any
         * channel number, width, band, version or flags.  Only the outer
         * return changes to success when every predicate matches. */
        const bool controllerGET4EmptySuccessCandidate =
            interface == _iface && virtualInterface == nullptr &&
            outerReq->req_val == 0 && baseReturn == 6 &&
            !associationActiveBefore && !associationActiveAfter &&
            preCopyin == 0 && postCopyin == 0;
        static volatile UInt32 controllerGET4EmptySuccessCandidateCount = 0;
        static volatile UInt32 controllerGET4EmptySuccessAppliedCount = 0;
        UInt32 emptySuccessCandidateCount =
            controllerGET4EmptySuccessCandidate
                ? __sync_add_and_fetch(
                      &controllerGET4EmptySuccessCandidateCount, 1U)
                : controllerGET4EmptySuccessCandidateCount;

        const bool controllerGET4EmptySuccessSeedOnlyMatch =
            controllerGET4EmptySuccessCandidate && unchanged &&
            preNonZeroBytes == 1 && postNonZeroBytes == 1 &&
            preFirstNonZeroOffset == 0 && postFirstNonZeroOffset == 0 &&
            preFirstNonZeroValue == APPLE80211_VERSION &&
            postFirstNonZeroValue == APPLE80211_VERSION &&
            pre.version == APPLE80211_VERSION &&
            post.version == APPLE80211_VERSION &&
            pre.channel.version == 0 && post.channel.version == 0 &&
            pre.channel.channel == 0 && post.channel.channel == 0 &&
            pre.channel.flags == 0 && post.channel.flags == 0;
        const bool controllerGET4EmptySuccessWouldApply =
            controllerGET4EmptySuccessSeedOnlyMatch;
        const bool controllerGET4EmptySuccessApplied =
            controllerGET4EmptySuccessWouldApply;
        UInt32 emptySuccessAppliedCount =
            controllerGET4EmptySuccessApplied
                ? __sync_add_and_fetch(
                      &controllerGET4EmptySuccessAppliedCount, 1U)
                : controllerGET4EmptySuccessAppliedCount;
        const SInt32 finalReturn = controllerGET4EmptySuccessApplied
                                       ? kIOReturnSuccess
                                       : baseReturn;

        setProperty("AirportRTW89ControllerGET4EmptySuccessSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ControllerGET4EmptySuccessCandidateCount",
                    (uint64_t)emptySuccessCandidateCount, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessAppliedCount",
                    (uint64_t)emptySuccessAppliedCount, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessReqLen",
                    (uint64_t)outerReq->req_len, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessReqVal",
                    (uint64_t)(uint32_t)outerReq->req_val, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessBaseReturn",
                    (uint64_t)(uint32_t)baseReturn, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessInterfaceMatchesPrimary",
                    interface == _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessVirtualInterfacePresent",
                    virtualInterface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessAssociationActiveBefore",
                    associationActiveBefore ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessAssociationActiveAfter",
                    associationActiveAfter ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreCopyinReturn",
                    (uint64_t)(uint32_t)preCopyin, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostCopyinReturn",
                    (uint64_t)(uint32_t)postCopyin, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreNonZeroBytes",
                    (uint64_t)preNonZeroBytes, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostNonZeroBytes",
                    (uint64_t)postNonZeroBytes, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreFirstNonZeroOffset",
                    (uint64_t)preFirstNonZeroOffset, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostFirstNonZeroOffset",
                    (uint64_t)postFirstNonZeroOffset, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreFirstNonZeroValue",
                    (uint64_t)preFirstNonZeroValue, 8);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostFirstNonZeroValue",
                    (uint64_t)postFirstNonZeroValue, 8);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreVersion",
                    (uint64_t)pre.version, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostVersion",
                    (uint64_t)post.version, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreChannelVersion",
                    (uint64_t)pre.channel.version, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostChannelVersion",
                    (uint64_t)post.channel.version, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreChannelNumber",
                    (uint64_t)pre.channel.channel, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostChannelNumber",
                    (uint64_t)post.channel.channel, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPreChannelFlags",
                    (uint64_t)pre.channel.flags, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPostChannelFlags",
                    (uint64_t)post.channel.flags, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessSuperclassUnchanged",
                    unchanged ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessSeedOnlyMatch",
                    controllerGET4EmptySuccessSeedOnlyMatch
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessWouldApply",
                    controllerGET4EmptySuccessWouldApply
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessApplied",
                    controllerGET4EmptySuccessApplied
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessDiagnosticOnly",
                    kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4EmptySuccessFinalReturn",
                    (uint64_t)(uint32_t)finalReturn, 32);
        setProperty("AirportRTW89ControllerGET4EmptySuccessPayloadInvented",
                    kOSBooleanFalse);

        setProperty("AirportRTW89ControllerGET4DiagSeen", kOSBooleanTrue);
        setProperty("AirportRTW89ControllerGET4DiagCandidateCount",
                    (uint64_t)candidateCount, 32);
        setProperty("AirportRTW89ControllerGET4DiagEntryMS",
                    (uint64_t)entryMS, 64);
        setProperty("AirportRTW89ControllerGET4DiagExitMS",
                    (uint64_t)exitMS, 64);
        setProperty("AirportRTW89ControllerGET4DiagInterfacePresent",
                    _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4DiagInterfaceMatchesPrimary",
                    interface == _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4DiagVirtualInterfacePresent",
                    virtualInterface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4DiagReqLen",
                    (uint64_t)outerReq->req_len, 32);
        setProperty("AirportRTW89ControllerGET4DiagReqVal",
                    (uint64_t)(uint32_t)outerReq->req_val, 32);
        setProperty("AirportRTW89ControllerGET4DiagBaseReturn",
                    (uint64_t)(uint32_t)baseReturn, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreCopyinReturn",
                    (uint64_t)(uint32_t)preCopyin, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostCopyinReturn",
                    (uint64_t)(uint32_t)postCopyin, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreNonZeroBytes",
                    (uint64_t)preNonZeroBytes, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreFirstNonZeroOffset",
                    (uint64_t)preFirstNonZeroOffset, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreFirstNonZeroValue",
                    (uint64_t)preFirstNonZeroValue, 8);
        setProperty("AirportRTW89ControllerGET4DiagPostNonZeroBytes",
                    (uint64_t)postNonZeroBytes, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostFirstNonZeroOffset",
                    (uint64_t)postFirstNonZeroOffset, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostFirstNonZeroValue",
                    (uint64_t)postFirstNonZeroValue, 8);
        setProperty("AirportRTW89ControllerGET4DiagPreHash",
                    (uint64_t)preHash, 64);
        setProperty("AirportRTW89ControllerGET4DiagPostHash",
                    (uint64_t)postHash, 64);
        setProperty("AirportRTW89ControllerGET4DiagSuperclassUnchanged",
                    unchanged ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4DiagPreVersion",
                    (uint64_t)pre.version, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreChannelVersion",
                    (uint64_t)pre.channel.version, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreChannelNumber",
                    (uint64_t)pre.channel.channel, 32);
        setProperty("AirportRTW89ControllerGET4DiagPreChannelFlags",
                    (uint64_t)pre.channel.flags, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostVersion",
                    (uint64_t)post.version, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostChannelVersion",
                    (uint64_t)post.channel.version, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostChannelNumber",
                    (uint64_t)post.channel.channel, 32);
        setProperty("AirportRTW89ControllerGET4DiagPostChannelFlags",
                    (uint64_t)post.channel.flags, 32);
        setProperty("AirportRTW89ControllerGET4DiagDiagnosticOnly",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ControllerGET4DiagPayloadModified",
                    kOSBooleanFalse);
        setProperty("AirportRTW89ControllerGET4DiagReturnNormalized",
                    controllerGET4EmptySuccessApplied
                        ? kOSBooleanTrue : kOSBooleanFalse);
        return finalReturn;
    }

    /* 0.2.208: first-real-result primary GET11 controller-marshaller hook.
     *
     * This virtual is declared by the restored IO80211Controller ABI and sits
     * between the legacy interface ioctl wrapper and apple80211Request().
     * IO80211Reference normally reaches its pointer-return GET SCAN_RESULT callback
     * through this controller-owned path.  Keep this override inert except
     * while AirportRTW89Interface::performCommand() explicitly arms the one-shot
     * GET11 experiment on the same thread. */
    const bool probeActive =
        _airportGet11ControllerIoctlGetProbeActive &&
        _airportGet11ControllerIoctlGetProbeThread == current_thread() &&
        interface == _iface && virtualInterface == nullptr && data != nullptr;

    if (!probeActive)
        return IO80211Controller::apple80211_ioctl_get(
            interface, virtualInterface, net, data);

    apple80211req *req = outerReq;
    setProperty("AirportRTW89Get11ControllerIoctlGetEntered",
                kOSBooleanTrue);
    setProperty("AirportRTW89Get11ControllerIoctlGetReqType",
                (uint64_t)(uint32_t)req->req_type, 32);
    setProperty("AirportRTW89Get11ControllerIoctlGetReqVal",
                (uint64_t)(uint32_t)req->req_val, 32);
    setProperty("AirportRTW89Get11ControllerIoctlGetReqLen",
                (uint64_t)req->req_len, 32);
    setProperty("AirportRTW89Get11ControllerIoctlGetReqDataPresent",
                req->req_data ? kOSBooleanTrue : kOSBooleanFalse);

    if (req->req_type != APPLE80211_IOC_SCAN_RESULT ||
        req->req_data == nullptr ||
        req->req_len < sizeof(apple80211_scan_result)) {
        setProperty("AirportRTW89Get11ControllerIoctlGetShapeAccepted",
                    kOSBooleanFalse);
        return IO80211Controller::apple80211_ioctl_get(
            interface, virtualInterface, net, data);
    }

    setProperty("AirportRTW89Get11ControllerIoctlGetShapeAccepted",
                kOSBooleanTrue);
    __sync_add_and_fetch(&_airportGet11ControllerIoctlGetEntryCount, 1);
    setProperty("AirportRTW89Get11ControllerIoctlGetEntryCount",
                (uint64_t)_airportGet11ControllerIoctlGetEntryCount, 32);

    apple80211_scan_result *scanResult = nullptr;
    const SInt32 innerReturn = apple80211Request(
        (unsigned int)SIOCGA80211, APPLE80211_IOC_SCAN_RESULT,
        interface, &scanResult);

    setProperty("AirportRTW89Get11ControllerIoctlGetInnerReturn",
                (uint64_t)(uint32_t)innerReturn, 32);
    setProperty("AirportRTW89Get11ControllerIoctlGetPointerPresent",
                scanResult ? kOSBooleanTrue : kOSBooleanFalse);

    if (innerReturn != kIOReturnSuccess || !scanResult)
        return innerReturn == kIOReturnSuccess ? kIOReturnNotReady
                                               : innerReturn;

    const SInt16 originalRSSI = scanResult->asr_rssi;
    const UInt32 originalAge = scanResult->asr_age;
    scanResult->asr_rssi = -44;
    scanResult->asr_age = 44;

    const int copyoutReturn = copyout(
        scanResult, (user_addr_t)req->req_data,
        sizeof(apple80211_scan_result));

    scanResult->asr_rssi = originalRSSI;
    scanResult->asr_age = originalAge;

    setProperty("AirportRTW89Get11ControllerIoctlGetMarkerRSSI",
                (uint64_t)(SInt64)-44, 64);
    setProperty("AirportRTW89Get11ControllerIoctlGetMarkerAgeMS",
                (uint64_t)44, 32);
    setProperty("AirportRTW89Get11ControllerIoctlGetCopyoutReturn",
                (uint64_t)(uint32_t)copyoutReturn, 32);

    return copyoutReturn == 0 ? kIOReturnSuccess : copyoutReturn;
}

SInt32 RTW88PCIDevice::apple80211SkywalkRequest(
    UInt requestType, int requestNumber, IO80211SkywalkInterface *interface,
    void *data)
{
    /* 0.2.239: diagnostic-only request-number history on the already-proven
     * Skywalk request hook.  0.2.237 and 0.2.238 added new IO80211 virtual
     * overrides and both regressed boot on Tahoe's IO80211FamilyLegacy ABI.
     * This build is based directly on the known-bootable 0.2.236 tree and
     * changes only this existing method body: no vtable slot is added or
     * moved, no request payload is dereferenced, and the historical
     * kIOReturnUnsupported return is preserved exactly.
     *
     * The 0.2.236 runtime's last requestNumber was 37, which matches
     * APPLE80211_IOC_TX_ANTENNA and the boot-time transmit-antenna activity.
     * Therefore retain a timestamped requestNumber ring so a native join can
     * prove or falsify whether APPLE80211_IOC_ASSOCIATE/20 enters this hook
     * immediately before airportd reports the association failure. */
    struct SkywalkRequestDiagEntry {
        UInt32 sequence;
        UInt32 requestNumber;
        UInt32 requestTypeLow32;
        UInt32 flags;
        UInt64 entryMS;
    };
    static_assert(sizeof(SkywalkRequestDiagEntry) == 24,
                  "Skywalk request diagnostic entry size mismatch");
    static SkywalkRequestDiagEntry requestRing[64] = {};
    static volatile UInt32 requestCount = 0;
    static volatile UInt32 associate20Count = 0;

    uint64_t nowNs = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
    const UInt64 entryMS = nowNs / 1000000ULL;
    const UInt32 sequence = __sync_add_and_fetch(&requestCount, 1U);
    const UInt32 number = (UInt32)requestNumber;
    const UInt32 rawType = (UInt32)requestType;
    const bool associationActive =
        _ieee80211 && _ieee80211->hasActiveAssociation();

    UInt32 flags = 0;
    if (interface)
        flags |= 1U << 0;
    if (data)
        flags |= 1U << 1;
    if (associationActive)
        flags |= 1U << 2;
    if (number == APPLE80211_IOC_ASSOCIATE)
        flags |= 1U << 3;

    SkywalkRequestDiagEntry &entry = requestRing[(sequence - 1U) & 63U];
    entry.sequence = sequence;
    entry.requestNumber = number;
    entry.requestTypeLow32 = rawType;
    entry.flags = flags;
    entry.entryMS = entryMS;

    setProperty("AirportRTW89SkywalkRequestSeen", kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkRequestType", (uint64_t)requestType, 32);
    setProperty("AirportRTW89SkywalkRequestNumber",
                (uint64_t)number, 32);
    setProperty("AirportRTW89SkywalkRequestReturnedUnsupported",
                kOSBooleanTrue);

    setProperty("AirportRTW89SkywalkRequestDiagSeen", kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkRequestDiagCount",
                (uint64_t)sequence, 32);
    setProperty("AirportRTW89SkywalkRequestDiagEntrySize",
                (uint64_t)sizeof(SkywalkRequestDiagEntry), 32);
    setProperty("AirportRTW89SkywalkRequestDiagLastEntryMS",
                (uint64_t)entryMS, 64);
    setProperty("AirportRTW89SkywalkRequestDiagLastRequestNumber",
                (uint64_t)number, 32);
    setProperty("AirportRTW89SkywalkRequestDiagLastRequestTypeLow32",
                (uint64_t)rawType, 32);
    setProperty("AirportRTW89SkywalkRequestDiagLastInterfacePresent",
                _iface ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRequestDiagLastDataPresent",
                data ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRequestDiagLastAssociationActive",
                associationActive ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRequestDiagPayloadInspected",
                kOSBooleanFalse);
    setProperty("AirportRTW89SkywalkRequestDiagDiagnosticOnly",
                kOSBooleanTrue);
    setProperty("AirportRTW89SkywalkRequestDiagReturnNormalized",
                kOSBooleanFalse);

    if (number == APPLE80211_IOC_ASSOCIATE) {
        const UInt32 candidate =
            __sync_add_and_fetch(&associate20Count, 1U);
        setProperty("AirportRTW89SkywalkRequest20DiagSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkRequest20DiagCandidateCount",
                    (uint64_t)candidate, 32);
        setProperty("AirportRTW89SkywalkRequest20DiagEntryMS",
                    (uint64_t)entryMS, 64);
        setProperty("AirportRTW89SkywalkRequest20DiagRawTypeLow32",
                    (uint64_t)rawType, 32);
        setProperty("AirportRTW89SkywalkRequest20DiagInterfacePresent",
                    _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkRequest20DiagDataPresent",
                    data ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkRequest20DiagAssociationActive",
                    associationActive ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkRequest20DiagWouldReturnUnsupported",
                    kOSBooleanTrue);
    }

    /* Keep boot-time overhead bounded: scalar telemetry already updates on
     * every call.  Publish the 1536-byte ring only for request 20, the first
     * four calls, or every 16th call thereafter. */
    const bool publishRing =
        number == APPLE80211_IOC_ASSOCIATE || sequence <= 4U ||
        (sequence & 15U) == 0U;
    if (publishRing) {
        if (OSData *ringData = OSData::withBytes(
                requestRing, sizeof(requestRing))) {
            setProperty("AirportRTW89SkywalkRequestDiagRing", ringData);
            ringData->release();
            setProperty("AirportRTW89SkywalkRequestDiagRingPublishSequence",
                        (uint64_t)sequence, 32);
        }
    }

    /* 0.2.241: characterize the only three non-association control requests
     * proven by 0.2.239 to enter this already-boot-safe hook.
     *
     * Runtime established that CARD_CAPABILITIES arrives as SIOCGA80211
     * (GET), while ANTENNA_DIVERSITY and TX_ANTENNA arrive as SIOCSA80211
     * (SET).  IO80211Reference's legacy dispatcher declares all three GET-only,
     * so do not accidentally treat the observed antenna SETs as getters.
     *
     * The buffer ownership for this Skywalk hook is not yet characterized.
     * Use copyin() only: it safely tells us whether data is a user-address
     * buffer and, on success, captures the harmless fixed-size seed.  Never
     * dereference data directly, never copy out, never call airportGet/Set,
     * and preserve kIOReturnUnsupported exactly. */
    const bool cardCapsGetCandidate =
        rawType == (UInt32)SIOCGA80211 &&
        number == APPLE80211_IOC_CARD_CAPABILITIES && data != nullptr;
    const bool txAntennaSetCandidate =
        rawType == (UInt32)SIOCSA80211 &&
        number == APPLE80211_IOC_TX_ANTENNA && data != nullptr;
    const bool antennaDiversitySetCandidate =
        rawType == (UInt32)SIOCSA80211 &&
        number == APPLE80211_IOC_ANTENNA_DIVERSITY && data != nullptr;
    const bool controlShapeCandidate =
        cardCapsGetCandidate || txAntennaSetCandidate ||
        antennaDiversitySetCandidate;

    if (controlShapeCandidate) {
        static_assert(sizeof(apple80211_capability_data) == 16,
                      "apple80211_capability_data ABI size mismatch");
        static_assert(sizeof(apple80211_antenna_data) == 24,
                      "apple80211_antenna_data ABI size mismatch");
        static volatile UInt32 controlShapeCount = 0;
        static volatile UInt32 cardCapsGetCount = 0;
        static volatile UInt32 txAntennaSetCount = 0;
        static volatile UInt32 antennaDiversitySetCount = 0;

        const UInt32 shapeSequence =
            __sync_add_and_fetch(&controlShapeCount, 1U);
        union SkywalkControlSeed {
            apple80211_capability_data capability;
            apple80211_antenna_data antenna;
            UInt8 bytes[sizeof(apple80211_antenna_data)];
        } seed = {};
        static_assert(sizeof(SkywalkControlSeed) ==
                          sizeof(apple80211_antenna_data),
                      "Skywalk control seed union size mismatch");
        const size_t expectedSize = cardCapsGetCandidate
            ? sizeof(apple80211_capability_data)
            : sizeof(apple80211_antenna_data);
        const int copyinReturn =
            copyin((user_addr_t)data, seed.bytes, expectedSize);

        UInt32 nonZeroBytes = 0;
        UInt32 firstNonZeroOffset = 0xffffffffU;
        UInt8 firstNonZeroValue = 0;
        if (copyinReturn == 0) {
            for (size_t i = 0; i < expectedSize; ++i) {
                if (seed.bytes[i] == 0)
                    continue;
                ++nonZeroBytes;
                if (firstNonZeroOffset == 0xffffffffU) {
                    firstNonZeroOffset = (UInt32)i;
                    firstNonZeroValue = seed.bytes[i];
                }
            }
        }
        const UInt64 seedHash = copyinReturn == 0
            ? airportStatusDiagHash(seed.bytes, expectedSize)
            : 0;
        const UInt32 seedVersion = copyinReturn == 0
            ? (cardCapsGetCandidate ? seed.capability.version
                                    : seed.antenna.version)
            : 0;

        setProperty("AirportRTW89SkywalkControlShapeSeen", kOSBooleanTrue);
        setProperty("AirportRTW89SkywalkControlShapeCount",
                    (uint64_t)shapeSequence, 32);
        setProperty("AirportRTW89SkywalkControlShapeRequestNumber",
                    (uint64_t)number, 32);
        setProperty("AirportRTW89SkywalkControlShapeRequestTypeLow32",
                    (uint64_t)rawType, 32);
        setProperty("AirportRTW89SkywalkControlShapeIsGet",
                    rawType == (UInt32)SIOCGA80211
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkControlShapeIsSet",
                    rawType == (UInt32)SIOCSA80211
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkControlShapeExpectedSize",
                    (uint64_t)expectedSize, 32);
        setProperty("AirportRTW89SkywalkControlShapeCopyinReturn",
                    (uint64_t)(uint32_t)copyinReturn, 32);
        setProperty("AirportRTW89SkywalkControlShapeNonZeroBytes",
                    (uint64_t)nonZeroBytes, 32);
        setProperty("AirportRTW89SkywalkControlShapeFirstNonZeroOffset",
                    (uint64_t)firstNonZeroOffset, 32);
        setProperty("AirportRTW89SkywalkControlShapeFirstNonZeroValue",
                    (uint64_t)firstNonZeroValue, 8);
        setProperty("AirportRTW89SkywalkControlShapeHash",
                    (uint64_t)seedHash, 64);
        setProperty("AirportRTW89SkywalkControlShapeVersion",
                    (uint64_t)seedVersion, 32);
        setProperty("AirportRTW89SkywalkControlShapePayloadModified",
                    kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkControlShapeReturnNormalized",
                    kOSBooleanFalse);
        setProperty("AirportRTW89SkywalkControlShapeDiagnosticOnly",
                    kOSBooleanTrue);

        if (cardCapsGetCandidate) {
            const UInt32 count =
                __sync_add_and_fetch(&cardCapsGetCount, 1U);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagSeen",
                        kOSBooleanTrue);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagCount",
                        (uint64_t)count, 32);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagEntryMS",
                        (uint64_t)entryMS, 64);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagCopyinReturn",
                        (uint64_t)(uint32_t)copyinReturn, 32);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagVersion",
                        (uint64_t)seedVersion, 32);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagSeedHash",
                        (uint64_t)seedHash, 64);
            setProperty("AirportRTW89SkywalkCardCapsGetDiagWouldDispatchGet",
                        copyinReturn == 0
                            ? kOSBooleanTrue : kOSBooleanFalse);
        } else {
            const apple80211_antenna_data *antenna = &seed.antenna;
            const UInt32 antennaVersion = copyinReturn == 0
                ? antenna->version : 0;
            const UInt32 antennaNumRadios = copyinReturn == 0
                ? antenna->num_radios : 0;

            if (txAntennaSetCandidate) {
                const UInt32 count =
                    __sync_add_and_fetch(&txAntennaSetCount, 1U);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagSeen",
                            kOSBooleanTrue);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagCount",
                            (uint64_t)count, 32);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagEntryMS",
                            (uint64_t)entryMS, 64);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagCopyinReturn",
                            (uint64_t)(uint32_t)copyinReturn, 32);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagVersion",
                            (uint64_t)antennaVersion, 32);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagNumRadios",
                            (uint64_t)antennaNumRadios, 32);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagIndex0",
                            (uint64_t)(uint32_t)(copyinReturn == 0
                                ? antenna->antenna_index[0] : 0), 32);
                setProperty("AirportRTW89SkywalkTXAntennaSetDiagIO80211ReferenceGETOnly",
                            kOSBooleanTrue);
            }
            if (antennaDiversitySetCandidate) {
                const UInt32 count =
                    __sync_add_and_fetch(&antennaDiversitySetCount, 1U);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagSeen",
                            kOSBooleanTrue);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagCount",
                            (uint64_t)count, 32);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagEntryMS",
                            (uint64_t)entryMS, 64);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagCopyinReturn",
                            (uint64_t)(uint32_t)copyinReturn, 32);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagVersion",
                            (uint64_t)antennaVersion, 32);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagNumRadios",
                            (uint64_t)antennaNumRadios, 32);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagIndex0",
                            (uint64_t)(uint32_t)(copyinReturn == 0
                                ? antenna->antenna_index[0] : 0), 32);
                setProperty("AirportRTW89SkywalkAntennaDiversitySetDiagIO80211ReferenceGETOnly",
                            kOSBooleanTrue);
            }
        }
    }

    /* Preserve the exact 0.2.239 behavior for every request.  This build is
     * shape-only: no GET is serviced yet and the observed antenna SETs are
     * not reinterpreted as GETs. */
    return kIOReturnUnsupported;
}

#ifdef IO80211FAMILY_V2
SInt32 RTW88PCIDevice::apple80211SkywalkRequest(
    UInt requestType, int requestNumber, IO80211SkywalkInterface *interface,
    void *data, void *context)
{
    (void)context;
    return apple80211SkywalkRequest(requestType, requestNumber, interface, data);
}

SInt32 RTW88PCIDevice::handleCardSpecific(
    IO80211SkywalkInterface *interface, unsigned long command, void *data,
    bool isGet)
{
    (void)interface;
    return isGet ? airportGet((unsigned int)command, data)
                 : airportSet((unsigned int)command, data, nullptr);
}
#endif

#ifdef IO80211FAMILY_V2
IOReturn RTW88PCIDevice::getDRIVER_VERSION(
    IO80211SkywalkInterface *, apple80211_version_data *data)
{
    return airportGet(APPLE80211_IOC_DRIVER_VERSION, data);
}

IOReturn RTW88PCIDevice::getHARDWARE_VERSION(
    IO80211SkywalkInterface *, apple80211_version_data *data)
{
    return airportGet(APPLE80211_IOC_HARDWARE_VERSION, data);
}

IOReturn RTW88PCIDevice::getCARD_CAPABILITIES(
    IO80211SkywalkInterface *, apple80211_capability_data *data)
{
    return airportGet(APPLE80211_IOC_CARD_CAPABILITIES, data);
}

IOReturn RTW88PCIDevice::getPOWER(
    IO80211SkywalkInterface *, apple80211_power_data *data)
{
    return airportGet(APPLE80211_IOC_POWER, data);
}

IOReturn RTW88PCIDevice::setPOWER(
    IO80211SkywalkInterface *, apple80211_power_data *data)
{
    return airportSet(APPLE80211_IOC_POWER, data, nullptr);
}

IOReturn RTW88PCIDevice::getCOUNTRY_CODE(
    IO80211SkywalkInterface *, apple80211_country_code_data *data)
{
    return airportGet(APPLE80211_IOC_COUNTRY_CODE, data);
}

IOReturn RTW88PCIDevice::setCOUNTRY_CODE(
    IO80211SkywalkInterface *, apple80211_country_code_data *data)
{
    return airportSet(APPLE80211_IOC_COUNTRY_CODE, data, nullptr);
}

IOReturn RTW88PCIDevice::setGET_DEBUG_INFO(
    IO80211SkywalkInterface *, apple80211_debug_command *)
{
    return kIOReturnUnsupported;
}

UInt32 RTW88PCIDevice::hardwareOutputQueueDepth()
{
    return hardwareOutputQueueDepth(nullptr);
}

SInt32 RTW88PCIDevice::performCountryCodeOperation(IO80211CountryCodeOp operation)
{
    return performCountryCodeOperation(nullptr, operation);
}
#endif

UInt32 RTW88PCIDevice::getFeatures() const
{
    /* IO80211Reference's iwm/iwx/iwn transports publish this exact value. */
    return kIONetworkFeatureMultiPages;
}

bool RTW88PCIDevice::useAppleRSNSupplicant(IO80211VirtualInterface *interface)
{
    const UInt64 queryMS = airportSecurityControlMonotonicMS();
    /* Keep virtual/AWDL policy unchanged.  Current IO80211Reference exposes the
     * Apple supplicant decision on the primary IO80211Interface path; our
     * non-BSD control object is not a second data/RSN owner. */
    (void)interface;
    static UInt32 virtualQueryCount = 0;
    ++virtualQueryCount;
    setProperty("AirportRTW89AppleRSNVirtualSupplicantQueried", kOSBooleanTrue);
    setProperty("AirportRTW89AppleRSNVirtualSupplicantEnabled", kOSBooleanFalse);
    setProperty("AirportRTW89SecurityControlVirtualRSNPolicyCount",
                (uint64_t)virtualQueryCount, 32);
    setProperty("AirportRTW89SecurityControlVirtualRSNPolicyLastMS",
                (uint64_t)queryMS, 64);
    setProperty("AirportRTW89SecurityControlVirtualRSNPolicyReturn",
                kOSBooleanFalse);
    return false;
}

#ifdef IO80211FAMILY_V2
IOReturn RTW88PCIDevice::getHardwareAddressForInterface(
    IOEthernetAddress *address)
{
    return getHardwareAddress(address);
}

SInt32 RTW88PCIDevice::monitorModeSetEnabled(bool enabled, UInt flags)
{
    return monitorModeSetEnabled(nullptr, enabled, flags);
}
#endif

UInt32 RTW88PCIDevice::airportChannelFlags(UInt32 channel) const
{
    UInt32 flags = APPLE80211_C_FLAG_20MHZ | APPLE80211_C_FLAG_ACTIVE;
    flags |= channel <= 14 ? APPLE80211_C_FLAG_2GHZ
                           : APPLE80211_C_FLAG_5GHZ;
    return flags;
}

void RTW88PCIDevice::airportFillChannelsInfo(
    AirportRTW89ChannelsInfoData *value) const
{
    if (!value)
        return;

    bzero(value, sizeof(*value));
    value->version = APPLE80211_VERSION;

    /* Match IO80211Reference's CHANNELS_INFO semantics: chan_num[] is the
     * authoritative primary-channel list; chan_spec[] and private regulatory
     * arrays may remain zero when no richer regulatory database is available.
     * The current RTW89 frontend advertises the same 22 channels through
     * SUPPORTED_CHANNELS/HW_SUPPORTED_CHANNELS. */
    static const UInt8 channels[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        36, 40, 44, 48, 149, 153, 157, 161, 165
    };
    const UInt16 count = (UInt16)(sizeof(channels) / sizeof(channels[0]));
    value->num_chan_specs = count;
    for (UInt16 i = 0; i < count; ++i) {
        const UInt8 channel = channels[i];
        value->chan_num[i] = channel;

        /* RTL8852AE supports HT40 on the advertised 2.4-GHz set and
         * HT/VHT40 on the normal 5-GHz blocks. Channel 165 is 20-MHz-only. */
        value->support_40Mhz[i] = channel == 165 ? 0 : 1;
        value->support_80Mhz[i] =
            (channel >= 36 && channel != 165) ? 1 : 0;
    }
}

UInt32 RTW88PCIDevice::airportStateFromRTW(UInt32 state) const
{
    switch ((RTW88State)state) {
    case RTW88_STATE_SCANNING:
        return APPLE80211_S_SCAN;
    case RTW88_STATE_AUTHENTICATING:
        return APPLE80211_S_AUTH;
    case RTW88_STATE_ASSOCIATING:
    case RTW88_STATE_HANDSHAKING:
        return APPLE80211_S_ASSOC;
    case RTW88_STATE_CONNECTED:
        return APPLE80211_S_RUN;
    case RTW88_STATE_IDLE:
    case RTW88_STATE_DISCONNECTING:
    default:
        return APPLE80211_S_INIT;
    }
}


static bool airportCountryAlpha2Valid(const char alpha2[2])
{
    if (!alpha2)
        return false;
    const char a = alpha2[0];
    const char b = alpha2[1];
    const bool letters =
        ((a >= 'A' && a <= 'Z') || (a >= 'a' && a <= 'z')) &&
        ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'));
    if (!letters)
        return false;
    const char au = (a >= 'a' && a <= 'z') ? (char)(a - ('a' - 'A')) : a;
    const char bu = (b >= 'a' && b <= 'z') ? (char)(b - ('a' - 'A')) : b;
    return !((au == 'Z' && bu == 'Z') ||
             (au == 'X' && bu == 'X'));
}

static void airportCountryUpper(char alpha2[3])
{
    if (alpha2[0] >= 'a' && alpha2[0] <= 'z')
        alpha2[0] -= ('a' - 'A');
    if (alpha2[1] >= 'a' && alpha2[1] <= 'z')
        alpha2[1] -= ('a' - 'A');
    alpha2[2] = '\0';
}

bool RTW88PCIDevice::airportRefreshCountryCode(const char *reason,
                                                bool notifyChange)
{
    if (!_ieee80211)
        return false;

    setProperty("AirportRTW89CountryCodeRefreshSeen", kOSBooleanTrue);
    if (reason)
        setProperty("AirportRTW89CountryCodeRefreshReason", reason);

    /* Tahoe's CWInterface.countryCode() does not traverse legacy GET 51 on
     * this machine.  Resolve and publish the country independently of that
     * request path so IO80211CountryCode is authoritative at all times. */
    char bootCountry[3] = {};
    bool bootArgPresent =
        PE_parse_boot_argn("rtw89_cc", bootCountry, sizeof(bootCountry)) &&
        bootCountry[0] && bootCountry[1] &&
        airportCountryAlpha2Valid(bootCountry);
    if (bootArgPresent)
        airportCountryUpper(bootCountry);

    bool bootArgApplied = false;
    if (bootArgPresent)
        bootArgApplied = _ieee80211->setRegulatoryCountry(bootCountry);

    char driverCountry[3] = {};
    bool driverCountryPresent = _ieee80211->getRegulatoryCountry(driverCountry);
    if (driverCountryPresent)
        airportCountryUpper(driverCountry);

    /* If RTW89 is still in the worldwide/unknown domain, use only the
     * Country Information element (EID 7) from the AP we are actually
     * associated with.  Do not accept arbitrary scan-neighbour hints. */
    char associatedAPCountry[3] = {};
    bool associatedAPHintPresent = false;
    bool associatedAPHintApplied = false;
    if (!driverCountryPresent && !bootArgApplied && _airportLock &&
        _airportBSSCache) {
        RTW88StateResult state = {};
        if (_ieee80211->cmdGetState(&state) == kIOReturnSuccess &&
            state.state == RTW88_STATE_CONNECTED) {
            IOLockLock(_airportLock);
            for (UInt32 i = 0; i < _airportBSSCount && !associatedAPHintPresent;
                 ++i) {
                const RTW88BSS *bss = &_airportBSSCache[i];
                if (memcmp(bss->bssid, state.bssid, 6) != 0)
                    continue;
                for (UInt32 off = 0; off + 2 <= bss->ies_len; ) {
                    const UInt8 id = bss->ies[off];
                    const UInt32 len = bss->ies[off + 1];
                    if (off + 2 + len > bss->ies_len)
                        break;
                    if (id == 7 /* Country Information */ && len >= 3) {
                        associatedAPCountry[0] = (char)bss->ies[off + 2];
                        associatedAPCountry[1] = (char)bss->ies[off + 3];
                        associatedAPCountry[2] = '\0';
                        if (airportCountryAlpha2Valid(associatedAPCountry)) {
                            airportCountryUpper(associatedAPCountry);
                            associatedAPHintPresent = true;
                        }
                        break;
                    }
                    off += 2 + len;
                }
            }
            IOLockUnlock(_airportLock);
        }
    }

    if (!driverCountryPresent && associatedAPHintPresent) {
        associatedAPHintApplied =
            _ieee80211->setRegulatoryCountry(associatedAPCountry);
        driverCountryPresent =
            _ieee80211->getRegulatoryCountry(driverCountry);
        if (driverCountryPresent)
            airportCountryUpper(driverCountry);
    }

    char effective[3] = {'Z', 'Z', '\0'};
    if (driverCountryPresent) {
        effective[0] = driverCountry[0];
        effective[1] = driverCountry[1];
    } else if (airportCountryAlpha2Valid(_airportCountryCode)) {
        effective[0] = _airportCountryCode[0];
        effective[1] = _airportCountryCode[1];
        airportCountryUpper(effective);
    }

    const bool changed =
        _airportCountryCode[0] != effective[0] ||
        _airportCountryCode[1] != effective[1];
    _airportCountryCode[0] = effective[0];
    _airportCountryCode[1] = effective[1];
    _airportCountryCode[2] = '\0';

    setProperty("AirportRTW89CountryCodeSourceBootArg",
                bootArgApplied ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89CountryCodeSourceAssociatedAP",
                associatedAPHintApplied ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89CountryCodeAssociatedAPHintPresent",
                associatedAPHintPresent ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89CountryCodeAssociatedAPHintApplied",
                associatedAPHintApplied ? kOSBooleanTrue : kOSBooleanFalse);
    if (associatedAPHintPresent)
        setProperty("AirportRTW89CountryCodeAssociatedAPHint",
                    associatedAPCountry);
    setProperty("AirportRTW89CountryCodeSourceDriver",
                (driverCountryPresent && !bootArgApplied &&
                 !associatedAPHintApplied)
                    ? kOSBooleanTrue : kOSBooleanFalse);
    if (bootArgPresent && !bootArgApplied && driverCountryPresent &&
        (driverCountry[0] != bootCountry[0] ||
         driverCountry[1] != bootCountry[1]))
        setProperty("AirportRTW89CountryCodeBootArgBlockedByHardware",
                    kOSBooleanTrue);

    setProperty("AirportRTW89CountryCodeEffective", effective);
    setProperty(APPLE80211_REGKEY_COUNTRY_CODE, effective);
    if (_iface)
        _iface->setProperty(APPLE80211_REGKEY_COUNTRY_CODE, effective);

    if (changed) {
        setProperty("AirportRTW89CountryCodeChanged", kOSBooleanTrue);
        if (notifyChange) {
            IO80211Interface *wifi = getNetworkInterface();
            if (wifi) {
                wifi->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED);
                setProperty("AirportRTW89CountryCodeChangedPosted",
                            kOSBooleanTrue);
            }
        }
    }

    return !(effective[0] == 'Z' && effective[1] == 'Z');
}

void RTW88PCIDevice::airportResetScanCache()
{
    if (!_airportLock)
        return;
    IOLockLock(_airportLock);
    if (_airportBSSCache)
        bzero(_airportBSSCache, sizeof(RTW88BSS) * 64);
    _airportBSSCount = 0;
    _airportBSSIndex = 0;
    bzero(_airportScanIterators, sizeof(_airportScanIterators));
    if (++_airportScanIterationSerial == 0U)
        _airportScanIterationSerial = 1U;
    _airportScanCacheHeldPrevious = false;
    _airportScanCacheHeldPreviousCount = 0;
    if (_airportScanResults)
        bzero(_airportScanResults, sizeof(apple80211_scan_result) * 64);
    IOLockUnlock(_airportLock);

    if (_net80211)
        _net80211->clearScanCachePreservingState();

    static UInt32 resetCount = 0;
    ++resetCount;
    setProperty("AirportRTW89AppleScanCacheResetCount",
                (uint64_t)resetCount, 32);
    setProperty("AirportRTW89BSSDiagnosticCount", (uint64_t)0, 32);
    setProperty("AirportRTW89AppleScanCacheEmpty", kOSBooleanTrue);
}

IOReturn RTW88PCIDevice::airportRefreshScanCache()
{
    if (!_ieee80211 || !_airportBSSCache || !_airportLock)
        return kIOReturnNotReady;

    /* 0.2.211: distinguish an actually empty completed scan from the short
     * interval after a new scan starts but before its first beacon/probe
     * response. During that interval copyBSSSnapshot() intentionally reports
     * zero current-generation results. Keep serving the previous Apple
     * snapshot instead of momentarily collapsing the menu to zero networks;
     * the early SCAN_DONE timer still treats this held snapshot as zero-fresh
     * and remains deferred until a current-generation anchor arrives. */
    RTW88StateResult scanState = {};
    const bool haveState =
        _ieee80211->cmdGetState(&scanState) == kIOReturnSuccess;
    const bool scanInProgress =
        haveState && scanState.state == RTW88_STATE_SCANNING;

    UInt32 count = 0;
    IOLockLock(_airportLock);
    const UInt32 previousCount = _airportBSSCount;
    IOReturn result = _ieee80211->copyBSSSnapshot(_airportBSSCache, 64, &count);
    if (result == kIOReturnSuccess) {
        const UInt32 candidateCount = count;
        const bool holdPrevious =
            scanInProgress && candidateCount == 0 && previousCount != 0;

        _airportScanCacheHeldPrevious = holdPrevious;
        if (holdPrevious) {
            _airportScanCacheHeldPreviousCount = previousCount;
            ++_airportScanCacheHeldPreviousEventCount;
            count = previousCount;
            _airportBSSIndex = 0;
            setProperty("AirportRTW89AppleScanCacheHeldPrevious",
                        kOSBooleanTrue);
            setProperty("AirportRTW89AppleScanCacheHeldPreviousCount",
                        (uint64_t)previousCount, 32);
            setProperty("AirportRTW89AppleScanCacheHeldPreviousEventCount",
                        (uint64_t)_airportScanCacheHeldPreviousEventCount, 32);
            setProperty("AirportRTW89AppleScanCacheCandidateCount",
                        (uint64_t)candidateCount, 32);
            /* copyBSSSnapshot() reports the candidate view. Override the two
             * historical Apple-visible count properties to describe what GET11
             * is actually still serving while the new scan warms up. */
            setProperty("AirportRTW89AppleScanSnapshotFreshCount",
                        (uint64_t)count, 32);
            setProperty("AirportRTW89AppleScanSnapshotVisibleCount",
                        (uint64_t)count, 32);
        } else {
            _airportScanCacheHeldPreviousCount = 0;
            _airportBSSCount = count;
            _airportBSSIndex = 0;
            if (_net80211) {
                const bool netConnected = _ieee80211->hasActiveAssociation();
                _net80211->syncFromRTW(_airportBSSCache, count,
                                        scanInProgress, netConnected);
                setProperty("AirportRTW89Net80211AppleRefreshUsed",
                            kOSBooleanTrue);
                setProperty("AirportRTW89Net80211AppleVisibleNodeCount",
                            (uint64_t)_net80211->visibleNodeCount(), 32);
            }
            _airportScanCacheRefreshSerial++;
            if (_airportScanCacheRefreshSerial == 0U)
                _airportScanCacheRefreshSerial = 1U;
            if (++_airportScanIterationSerial == 0U)
                _airportScanIterationSerial = 1U;
            setProperty("AirportRTW89AppleScanCacheRefreshSerial",
                        (uint64_t)_airportScanCacheRefreshSerial, 32);
            setProperty("AirportRTW89AppleScanCacheHeldPrevious",
                        kOSBooleanFalse);
            setProperty("AirportRTW89AppleScanCacheHeldPreviousCount",
                        (uint64_t)0, 32);
            setProperty("AirportRTW89AppleScanCacheCandidateCount",
                        (uint64_t)candidateCount, 32);
        }
        setProperty("AirportRTW89AppleScanCacheEmpty",
                    count == 0 ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.2.122 diagnostic-only: publish the completed RTW89 BSS cache
         * directly in IORegistry so scan names can be inspected even when
         * Tahoe/CoreWLAN filters the user's client-side scan results.  This
         * does not alter GET 11, cache contents, scan timing, or association.
         * SSIDDisplay is printable ASCII for convenient Terminal viewing;
         * SSIDHex preserves the exact SSID bytes for non-ASCII names. */
        setProperty("AirportRTW89BSSDiagnosticsPublished", kOSBooleanTrue);
        setProperty("AirportRTW89BSSDiagnosticCount", (uint64_t)count, 32);
        uint64_t diagnosticNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &diagnosticNowNs);
        for (UInt32 i = 0; i < count && i < 64; ++i) {
            const RTW88BSS *bss = &_airportBSSCache[i];
            char key[96];
            char ssidDisplay[33];
            char ssidHex[65];
            char bssidText[18];
            char rssiText[16];

            const UInt32 ssidLen = bss->ssid_len <= 32 ? bss->ssid_len : 32;
            if (ssidLen == 0) {
                snprintf(ssidDisplay, sizeof(ssidDisplay), "<hidden>");
                ssidHex[0] = '\0';
            } else {
                static const char hex[] = "0123456789abcdef";
                for (UInt32 j = 0; j < ssidLen; ++j) {
                    const UInt8 c = (UInt8)bss->ssid[j];
                    ssidDisplay[j] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
                    ssidHex[j * 2] = hex[(c >> 4) & 0xf];
                    ssidHex[j * 2 + 1] = hex[c & 0xf];
                }
                ssidDisplay[ssidLen] = '\0';
                ssidHex[ssidLen * 2] = '\0';
            }

            snprintf(bssidText, sizeof(bssidText),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     bss->bssid[0], bss->bssid[1], bss->bssid[2],
                     bss->bssid[3], bss->bssid[4], bss->bssid[5]);
            snprintf(rssiText, sizeof(rssiText), "%d", (int)bss->rssi);

            snprintf(key, sizeof(key), "AirportRTW89BSS%02uSSID", i);
            setProperty(key, ssidDisplay);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uSSIDHex", i);
            setProperty(key, ssidHex);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uSSIDLength", i);
            setProperty(key, (uint64_t)ssidLen, 32);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uBSSID", i);
            setProperty(key, bssidText);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uChannel", i);
            setProperty(key, (uint64_t)bss->channel, 32);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uFrequency", i);
            setProperty(key, (uint64_t)bss->freq, 32);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uRSSI", i);
            setProperty(key, rssiText);
            const uint64_t bssAgeMS =
                (bss->last_seen_ns != 0 && diagnosticNowNs >= bss->last_seen_ns) ?
                    (diagnosticNowNs - bss->last_seen_ns) / 1000000ULL :
                    UINT64_MAX;
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uAgeMS", i);
            setProperty(key, bssAgeMS, 64);
            snprintf(key, sizeof(key), "AirportRTW89BSS%02uLastSeenScan", i);
            setProperty(key, (uint64_t)bss->last_seen_scan, 32);
        }
    }
    IOLockUnlock(_airportLock);
    if (result == kIOReturnSuccess)
        airportRefreshCountryCode("scan-cache-refresh", true);
    return result;
}



void RTW88PCIDevice::airportPublishOutputQueueDiagnostics(const char *stage)
{
    if (_skywalkOwnsBSDQueue) {
        setProperty("AirportRTW89LegacyOutputQueueDiagnosticsSuppressed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89OutputQueueStage", stage ? stage : "unknown");
        return;
    }
    IOOutputQueue *queue = _txQueue ? static_cast<IOOutputQueue *>(_txQueue)
                                    : getOutputQueue();
    IOBasicOutputQueue *basic = OSDynamicCast(IOBasicOutputQueue, queue);
    setProperty("AirportRTW89OutputQueuePresent",
                queue ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueGated",
                _txQueue ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueBasic",
                basic ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueStage", stage ? stage : "unknown");
    if (queue) {
        setProperty("AirportRTW89OutputQueueCapacity",
                    (uint64_t)queue->getCapacity(), 32);
        setProperty("AirportRTW89OutputQueueSize",
                    (uint64_t)queue->getSize(), 32);
        const OSMetaClass *meta = queue->getMetaClass();
        if (meta)
            setProperty("AirportRTW89OutputQueueClass", meta->getClassName());
    }
    if (basic) {
        setProperty("AirportRTW89OutputQueueState",
                    (uint64_t)basic->getState(), 32);
        setProperty("AirportRTW89OutputQueueRunning",
                    (basic->getState() & IOBasicOutputQueue::kStateRunning)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89OutputQueueActive",
                    (basic->getState() & IOBasicOutputQueue::kStateOutputActive)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89OutputQueueStalled",
                    (basic->getState() & IOBasicOutputQueue::kStateOutputStalled)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89OutputQueueDropCount",
                    (uint64_t)basic->getDropCount(), 32);
        setProperty("AirportRTW89OutputQueueAcceptedCount",
                    (uint64_t)basic->getOutputCount(), 32);
        setProperty("AirportRTW89OutputQueueRetryCount",
                    (uint64_t)basic->getRetryCount(), 32);
        setProperty("AirportRTW89OutputQueueStallCount",
                    (uint64_t)basic->getStallCount(), 32);
    }
}

void RTW88PCIDevice::airportRepairOutputQueue(const char *stage)
{
    if (_skywalkOwnsBSDQueue) {
        setProperty("AirportRTW89LegacyOutputQueueRepairSuppressed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89OutputQueueRepairStage",
                    stage ? stage : "unknown");
        return;
    }
    /* 0.2.31 output queue capacity/action repair.  IO80211Family may reduce
     * the legacy queue capacity to zero while link is down.  After carrier is
     * published, restore the hardware depth and restart both interface and
     * controller queue paths. */
    IOOutputQueue *queue = _txQueue ? static_cast<IOOutputQueue *>(_txQueue)
                                    : getOutputQueue();
    IOBasicOutputQueue *basic = OSDynamicCast(IOBasicOutputQueue, queue);
    UInt32 before = queue ? queue->getCapacity() : 0;
    UInt32 requested = hardwareOutputQueueDepth(
        OSDynamicCast(IO80211Interface, _iface));
    if (requested == 0)
        requested = 256;
    bool capacityAccepted = false;
    bool startReturned = false;
    bool serviceReturned = false;
    if (queue) {
        capacityAccepted = queue->setCapacity(requested);
        startReturned = queue->start();
    }
    if (queue)
        serviceReturned = queue->service(IOBasicOutputQueue::kServiceAsync);
    _airportOutputQueueRepairCount++;
    setProperty("AirportRTW89OutputQueueRepairStage", stage ? stage : "unknown");
    setProperty("AirportRTW89OutputQueueRepairCount",
                (uint64_t)_airportOutputQueueRepairCount, 32);
    setProperty("AirportRTW89OutputQueueCapacityBeforeRepair",
                (uint64_t)before, 32);
    setProperty("AirportRTW89OutputQueueCapacityRequested",
                (uint64_t)requested, 32);
    setProperty("AirportRTW89OutputQueueCapacitySetAccepted",
                capacityAccepted ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueCapacityAfterRepair",
                (uint64_t)(queue ? queue->getCapacity() : 0), 32);
    setProperty("AirportRTW89OutputQueueRepairStartReturned",
                startReturned ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueRepairServiceReturned",
                serviceReturned ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueInterfaceStartCalled",
                kOSBooleanFalse);
    setProperty("AirportRTW89OutputQueueRepairCompleted", kOSBooleanTrue);
    airportPublishOutputQueueDiagnostics(stage);
}

void RTW88PCIDevice::requestPacketTx(void *request, UInt count)
{
    _airportRequestPacketTxCount++;
    setProperty("AirportRTW89RequestPacketTxCount",
                (uint64_t)_airportRequestPacketTxCount, 32);
    setProperty("AirportRTW89RequestPacketTxArgument",
                (uint64_t)count, 32);
    setProperty("AirportRTW89RequestPacketTxPointerPresent",
                request ? kOSBooleanTrue : kOSBooleanFalse);
    airportPublishOutputQueueDiagnostics("requestPacketTx-before-super");
    RTW88ControllerBase::requestPacketTx(request, count);
    airportPublishOutputQueueDiagnostics("requestPacketTx-after-super");
}

UInt32 RTW88PCIDevice::getDataQueueDepth(OSObject *object)
{
    _airportGetDataQueueDepthCount++;
    UInt32 depth = RTW88ControllerBase::getDataQueueDepth(object);
    setProperty("AirportRTW89GetDataQueueDepthCount",
                (uint64_t)_airportGetDataQueueDepthCount, 32);
    setProperty("AirportRTW89GetDataQueueDepthLast",
                (uint64_t)depth, 32);
    return depth;
}

void RTW88PCIDevice::airportPublishLinkState(bool up, SInt32 rssi,
                                             bool rsnComplete)
{
    /* 0.2.29 direct IO80211 link publication.  The old path depended on
     * airportPollState() observing every CONNECTED/non-CONNECTED edge.  A
     * disconnect, scan and reconnect can all happen between one-second polls,
     * leaving _airportLastState stale at CONNECTED and suppressing link-up. */
    /* The final frontend has one genuine IO80211Interface (en2).  Publish
     * legacy Apple80211 link state/messages there.  The registered Skywalk
     * object is control-only and must not own link/data state. */
    IO80211Interface *wifi = getNetworkInterface();
    setProperty("AirportRTW89LinkPublishAttempted", kOSBooleanTrue);
    setProperty("AirportRTW89LinkPublishRequestedUp",
                up ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89LinkPublishInterfacePresent",
                wifi ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89LinkPublishRSNComplete",
                rsnComplete ? kOSBooleanTrue : kOSBooleanFalse);

    if (up) {
        airportRefreshCountryCode("link-up", true);
        _airportLinkPublishUpCount++;
        _airportOutputPacketCount = 0;
        _airportOutputPacketBytes = 0;
        _airportOutputARPCount = 0;
        _airportOutputIPv4Count = 0;
        _airportOutputDHCPCount = 0;
        setProperty("AirportRTW89OrdinaryDataProbeReset", kOSBooleanTrue);
        setProperty("AirportRTW89OutputPacketCount", (uint64_t)0, 64);
        setProperty("AirportRTW89OutputPacketBytes", (uint64_t)0, 64);
        setProperty("AirportRTW89OutputARPCount", (uint64_t)0, 32);
        setProperty("AirportRTW89OutputIPv4Count", (uint64_t)0, 32);
        setProperty("AirportRTW89OutputDHCPCount", (uint64_t)0, 32);

        setLinkStatus(kIONetworkLinkActive | kIONetworkLinkValid,
                      getCurrentMedium());
        setProperty("AirportRTW89LinkPublishSetLinkStatusCalled",
                    kOSBooleanTrue);
        if (wifi) {
            wifi->setLinkState(kIO80211NetworkLinkUp, 0);
            setProperty("AirportRTW89LinkPublishSetLinkStateCalled",
                        kOSBooleanTrue);
        }

        /* 0.2.158: the Skywalk object is registration/control-only.  Never
         * mirror carrier, running, LQM, reportLinkStatus, or association
         * messages onto it.  Those paths create/arm IO80211 peer/data-path
         * machinery that this non-BSD object deliberately does not own.
         * Also suppress explicit LQM and manual ASSOC/SSID/BSSID/LINK message
         * bursts on the primary interface for this safety build.  The real
         * BSD owner still receives setLinkStatus + setLinkState. */
        setProperty("AirportRTW89ControlLinkStateSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlRunningStateSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlReportLinkStatusSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlLQMSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89PrimaryLQMSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89PrimaryManualAssocMessagesSuppressed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89LinkPublishMessagesPosted", kOSBooleanFalse);
        setProperty("AirportRTW89PeerMonitorSafePublication", kOSBooleanTrue);

        /* 0.2.31: repair zero-capacity legacy output queues and force the
         * IO80211 interface queues to start after link publication. */
        setProperty("AirportRTW89OutputQueueWakeAttempted", kOSBooleanTrue);
        _airportOutputQueueWakeCount++;
        setProperty("AirportRTW89OutputQueueWakeCount",
                    (uint64_t)_airportOutputQueueWakeCount, 32);
        airportRepairOutputQueue("link-up-repair");
        _airportLastState = RTW88_STATE_CONNECTED;
        if (_net80211) {
            RTW88StateResult netState = {};
            const uint8_t *netBSSID = nullptr;
            if (_ieee80211 &&
                _ieee80211->cmdGetState(&netState) == kIOReturnSuccess)
                netBSSID = netState.bssid;
            _net80211->noteState(obsd80211::IEEE80211_S_RUN, netBSSID);
        }
    } else {
        _airportLinkPublishDownCount++;
        setLinkStatus(kIONetworkLinkValid, getCurrentMedium());
        setProperty("AirportRTW89LinkPublishSetLinkStatusCalled",
                    kOSBooleanTrue);
        if (wifi) {
            wifi->setLinkState(kIO80211NetworkLinkDown, 0);
            setProperty("AirportRTW89LinkPublishSetLinkStateCalled",
                        kOSBooleanTrue);
        }
        setProperty("AirportRTW89ControlLinkStateSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlRunningStateSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlReportLinkStatusSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlLQMSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89PrimaryLQMSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89PrimaryManualAssocMessagesSuppressed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89LinkPublishMessagesPosted", kOSBooleanFalse);
        setProperty("AirportRTW89PeerMonitorSafePublication", kOSBooleanTrue);
        _airportLastState = RTW88_STATE_IDLE;
        if (_net80211)
            _net80211->noteState(obsd80211::IEEE80211_S_INIT);
    }

    setProperty("AirportRTW89LinkPublishUpCount",
                (uint64_t)_airportLinkPublishUpCount, 32);
    setProperty("AirportRTW89LinkPublishDownCount",
                (uint64_t)_airportLinkPublishDownCount, 32);
    setProperty("AirportRTW89LinkPublishCachedStateAfter",
                (uint64_t)_airportLastState, 8);
    setProperty("AirportRTW89LinkPublishCompleted", kOSBooleanTrue);
}

void RTW88PCIDevice::airportScanDoneTimerFired(IOTimerEventSource *src)
{
    (void)src;
    _airportScanDoneTimerPending = false;
    setProperty("AirportRTW89IntelScanDoneTimerPending", kOSBooleanFalse);
    ++_airportScanDoneTimerFireCount;
    setProperty("AirportRTW89IntelScanDoneTimerFireCount",
                (uint64_t)_airportScanDoneTimerFireCount, 32);

    /* 0.2.227: a disconnected Apple-originated scan is completed only from
     * airportPollState() after the RTW89 backend has genuinely left SCANNING,
     * refreshed the final snapshot, and rewound the GET11 iterator.  If a
     * leftover/previous 100 ms timer fires, suppress it rather than allowing
     * an early GET11 enumeration to consume the snapshot before real
     * completion. */
    if (_airportDisconnectedScanCompletionPending) {
        setProperty("AirportRTW89DisconnectedEarlyScanDoneSuppressed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89DisconnectedScanCompletionPending",
                    kOSBooleanTrue);
        return;
    }

    /* 0.2.226: do not repeatedly rebuild/publish a partial Apple snapshot
     * every 100 ms while a disconnected full RF scan is still in progress.
     * Wait for backend completion first. This is deliberately before the
     * legacy earlyRefresh path below. */
    RTW88StateResult preRefreshScanState = {};
    const bool havePreRefreshState = _ieee80211 &&
        _ieee80211->cmdGetState(&preRefreshScanState) == kIOReturnSuccess;
    const bool associationActiveNow = _ieee80211 &&
        _ieee80211->hasActiveAssociation();
    if (!associationActiveNow && havePreRefreshState &&
        preRefreshScanState.state == RTW88_STATE_SCANNING &&
        _airportScanDoneTimer) {
        static UInt32 realCompletionDeferralCount = 0;
        ++realCompletionDeferralCount;
        _airportScanDoneTimerPending = true;
        _airportScanDoneTimer->setTimeoutMS(100);
        setProperty("AirportRTW89EarlyScanDoneDeferredUntilRealCompletion",
                    kOSBooleanTrue);
        setProperty("AirportRTW89EarlyScanDoneRealCompletionDeferralCount",
                    (uint64_t)realCompletionDeferralCount, 32);
        setProperty("AirportRTW89IntelScanDoneTimerPending", kOSBooleanTrue);
        return;
    }
    setProperty("AirportRTW89EarlyScanDoneDeferredUntilRealCompletion",
                kOSBooleanFalse);

    /* 0.2.157: IO80211Reference's GET SCAN_RESULT enumerates the live net80211
     * node tree.  AirportRTW89 instead serves a separate Apple-facing snapshot
     * that used to be refreshed only after the multi-second manual scan
     * completed.  The 100 ms SCAN_DONE handoff could therefore expose an empty
     * Apple cache even though RTW89 had already received BSS frames.  Refresh
     * that snapshot immediately before the early handoff. */
    const IOReturn earlyRefresh = airportRefreshScanCache();
    UInt32 earlyBSSCount = 0;
    bool earlySnapshotHeldPrevious = false;
    if (_airportLock) {
        IOLockLock(_airportLock);
        earlyBSSCount = _airportBSSCount;
        earlySnapshotHeldPrevious = _airportScanCacheHeldPrevious;
        IOLockUnlock(_airportLock);
    }
    setProperty("AirportRTW89EarlyScanCacheRefreshReturn",
                (uint64_t)(uint32_t)earlyRefresh, 32);
    setProperty("AirportRTW89EarlyScanCacheBSSCount",
                (uint64_t)earlyBSSCount, 32);
    setProperty("AirportRTW89EarlyScanCacheHeldPrevious",
                earlySnapshotHeldPrevious ? kOSBooleanTrue : kOSBooleanFalse);

    /* If the first 100 ms lands before any beacon/probe response has arrived,
     * do not hand Tahoe an immediate GET-11/no-results (12) failure.  Keep the
     * IO80211Reference-style short handoff, but retry it while the RF scanner is
     * genuinely still running.  Once at least one BSS exists, or the scan has
     * completed with a genuinely empty environment, post SCAN_DONE normally. */
    RTW88StateResult scanState = {};
    const bool haveState = _ieee80211 &&
        _ieee80211->cmdGetState(&scanState) == kIOReturnSuccess;

    /* 0.2.188: after logical OFF, both scan caches are intentionally empty.
     * The normal IO80211Reference-style 100 ms fake SCAN_DONE is useful for
     * steady-state scans, but on the first OFF -> ON scan it advertises a
     * partial snapshot before the 39-channel RF sweep has rebuilt the list.
     * Hold only that one completion edge.  airportPollState() will publish
     * SCAN_CACHE_UPDATED followed by SCAN_DONE after real RF completion. */
    if (_airportPowerOnFullScanNotifyPending) {
        setProperty("AirportRTW89PowerOnFullScanEarlyDoneSuppressed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PowerOnFullScanEarlySnapshotCount",
                    (uint64_t)earlyBSSCount, 32);
        setProperty("AirportRTW89PowerOnFullScanEarlyState",
                    (uint64_t)(haveState ? scanState.state : 0xff), 32);
        return;
    }

    if ((earlyBSSCount == 0 || earlySnapshotHeldPrevious) && haveState &&
        scanState.state == RTW88_STATE_SCANNING && _airportScanDoneTimer) {
        static UInt32 emptyCacheDeferralCount = 0;
        ++emptyCacheDeferralCount;
        _airportScanDoneTimerPending = true;
        _airportScanDoneTimer->setTimeoutMS(100);
        setProperty("AirportRTW89EarlyScanDoneDeferredForEmptyCache",
                    kOSBooleanTrue);
        setProperty("AirportRTW89EarlyScanDoneEmptyCacheDeferralCount",
                    (uint64_t)emptyCacheDeferralCount, 32);
        setProperty("AirportRTW89IntelScanDoneTimerPending", kOSBooleanTrue);
        return;
    }

    setProperty("AirportRTW89EarlyScanDoneDeferredForEmptyCache",
                kOSBooleanFalse);

    /* 0.4.20: exclusive-native mode intentionally removes _iface.  Publish
     * SCAN_DONE on the controller-selected BSD companion instead. */
    IO80211Interface *wifi = getNetworkInterface();
    if (!wifi) {
        setProperty("AirportRTW89IntelScanDonePostSucceeded",
                    kOSBooleanFalse);
        return;
    }

    /* Match IO80211Reference::fakeScanDone(): a single-argument SCAN_DONE post
     * from the genuine network interface, independent of RF completion. */
    wifi->postMessage(APPLE80211_M_SCAN_DONE);
    ++_airportScanDonePostCount;
    setProperty("AirportRTW89IntelScanDonePostCount",
                (uint64_t)_airportScanDonePostCount, 32);
    setProperty("AirportRTW89IntelScanDonePostMessage",
                (uint64_t)APPLE80211_M_SCAN_DONE, 32);
    setProperty("AirportRTW89IntelScanDonePostSucceeded",
                kOSBooleanTrue);
}

void RTW88PCIDevice::airportPollState()
{
    if (!_ieee80211)
        return;

    RTW88StateResult current = {};
    if (_ieee80211->cmdGetState(&current) != kIOReturnSuccess)
        return;

    /* 0.2.159: aggregate hot-path telemetry once per poll instead of writing
     * IORegistry properties for every packet.  This preserves useful counters
     * without putting OSObject allocation/registry locking in TX/RX latency. */
    setProperty("AirportRTW89FastDataPathEnabled", kOSBooleanTrue);
    setProperty("AirportRTW89PerPacketIORegistryDiagnostics",
                kOSBooleanFalse);
    setProperty("AirportRTW89FastPathOutputPacketCount",
                (uint64_t)_airportOutputPacketCount, 64);
    setProperty("AirportRTW89FastPathOutputBytes",
                (uint64_t)_airportOutputPacketBytes, 64);
    setProperty("AirportRTW89FastPathDriverTxBytes",
                (uint64_t)current.tx_byte_count, 64);
    setProperty("AirportRTW89FastPathDriverRxBytes",
                (uint64_t)current.rx_byte_count, 64);

    /* 0.2.162: all RX hot-path counters are memory-only; publish their
     * snapshot here once per Apple state poll. */
    _ieee80211->publishRxSanityTelemetry();

    /* Scan/association completion belongs to the genuine BSD AirPort
     * interface.  Never send active control messages through the passive,
     * non-BSD Skywalk registration service. */
    /* 0.4.20: scan/result completion belongs to whichever IO80211Interface
     * the controller exposes as primary (legacy or exclusive-native). */
    IO80211Interface *wifi = getNetworkInterface();

    /* 0.2.168: publish the actual framework transport latches once per poll.
     * 0.2.167 only published that a re-pin had been attempted, which could
     * hide a later framework callback writing poweredOnByUser(false) again. */
    setProperty("AirportRTW89PrimaryTransportPresentCurrent",
                wifi ? kOSBooleanTrue : kOSBooleanFalse);
    if (wifi) {
        setProperty("AirportRTW89PrimaryTransportUserPowerCurrent",
                    wifi->poweredOnByUser() ? kOSBooleanTrue
                                             : kOSBooleanFalse);
        setProperty("AirportRTW89PrimaryTransportSystemEnableCurrent",
                    wifi->enabledBySystem() ? kOSBooleanTrue
                                             : kOSBooleanFalse);
    }
    setProperty("AirportRTW89LogicalPowerCurrent",
                _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);

    if (_airportScanObserved && current.state != RTW88_STATE_SCANNING) {
        _airportScanObserved = false;
        const bool powerOnFullCompletion = _airportPowerOnFullScanNotifyPending;
        const bool disconnectedAppleCompletion =
            _airportDisconnectedScanCompletionPending;
        _airportDisconnectedScanCompletionPending = false;
        setProperty("AirportRTW89DisconnectedScanCompletionPending",
                    kOSBooleanFalse);

        /* 0.2.199: checkpoint the genuine RF completion in the same monotonic
         * millisecond domain that airportd's logs expose.  The 0.2.198 capture
         * showed CoreWiFi age tracking that domain from a zero origin.  Do not
         * feed this value to Apple yet; first establish whether Tahoe asks for
         * APPLE80211_IOC_LAST_BCAST_SCAN_TIME (GET 110), its request length,
         * and whether the hidden marshaller changes the caller buffer. */
        uint64_t completionNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &completionNowNs);
        _airportLastRealScanCompletionMonotonicMS = completionNowNs / 1000000ULL;
        setProperty("AirportRTW89LastRealScanCompletionMonotonicMS",
                    _airportLastRealScanCompletionMonotonicMS, 64);

        const IOReturn refreshResult = airportRefreshScanCache();
        UInt32 completedBSSCount = 0;
        if (_airportLock) {
            IOLockLock(_airportLock);
            completedBSSCount = _airportBSSCount;
            /* 0.2.227: close the observed 0.2.226 race where an early GET11
             * enumeration consumed all seven results, then the real scan
             * completion triggered a second GET11 before the iterator was
             * rewound.  Rewind immediately at the real-completion boundary,
             * before any SCAN_DONE publication. */
            _airportBSSIndex = 0;
            IOLockUnlock(_airportLock);
        }
        setProperty("AirportRTW89RealCompletionIteratorRewound",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PostScanSnapshotRefreshReturn",
                    (uint64_t)(uint32_t)refreshResult, 32);
        setProperty("AirportRTW89PostScanSnapshotBSSCount",
                    (uint64_t)completedBSSCount, 32);
        setProperty("AirportRTW89PostScanSnapshotGetCountBeforeNotify",
                    (uint64_t)_airportScanResultGetCount, 32);
        setProperty("AirportRTW89PostScanSnapshotSuccessCountBeforeNotify",
                    (uint64_t)_airportScanResultSuccessCount, 32);

        if (wifi) {
            bool disconnectedDonePosted = false;
            if (disconnectedAppleCompletion) {
                /* 0.2.227 single-owner disconnected scan transaction:
                 * final snapshot is already refreshed and the GET11 iterator
                 * is rewound above. Publish SCAN_DONE exactly once from this
                 * genuine RF-completion edge. */
                wifi->postMessage(APPLE80211_M_SCAN_DONE);
                disconnectedDonePosted = true;
                ++_airportDisconnectedRealCompletionPostCount;
                setProperty("AirportRTW89DisconnectedRealCompletionScanDonePostCount",
                            (uint64_t)_airportDisconnectedRealCompletionPostCount,
                            32);
                setProperty("AirportRTW89DisconnectedRealCompletionScanDonePosted",
                            kOSBooleanTrue);
                setProperty("AirportRTW89DisconnectedEarlyScanDoneSuppressed",
                            kOSBooleanTrue);
            }

            /* 0.2.227: the 0.2.226 trace proved that one disconnected live
             * scan could be enumerated twice: the early SCAN_DONE yielded all
             * seven GET11 records, then the later SCAN_CACHE_UPDATED edge
             * triggered another enumeration after the global iterator had
             * already reached end-of-list.  For a disconnected Apple-owned
             * scan, publish exactly one userspace-facing completion edge: the
             * real-completion SCAN_DONE above.  Associated/background paths
             * retain the historical CACHE_UPDATED publication. */
            const bool postCacheUpdated = !disconnectedDonePosted;
            if (postCacheUpdated) {
                wifi->postMessage(APPLE80211_M_SCAN_CACHE_UPDATED, nullptr, 0);
                uint64_t cacheUpdateNowNs = 0;
                absolutetime_to_nanoseconds(mach_absolute_time(),
                                            &cacheUpdateNowNs);
                _airportLastScanCacheUpdatedPostMonotonicMS =
                    cacheUpdateNowNs / 1000000ULL;
                setProperty("AirportRTW89LastScanCacheUpdatedPostMonotonicMS",
                            _airportLastScanCacheUpdatedPostMonotonicMS, 64);
                setProperty(
                    "AirportRTW89LastScanCacheUpdatedDeltaFromCompletionMS",
                    _airportLastScanCacheUpdatedPostMonotonicMS >=
                            _airportLastRealScanCompletionMonotonicMS
                        ? _airportLastScanCacheUpdatedPostMonotonicMS -
                              _airportLastRealScanCompletionMonotonicMS
                        : 0,
                    64);
                setProperty("AirportRTW89ScanCacheUpdatedPostedToLegacy",
                            kOSBooleanTrue);
            } else {
                setProperty("AirportRTW89ScanCacheUpdatedPostedToLegacy",
                            kOSBooleanFalse);
                setProperty(
                    "AirportRTW89DisconnectedCacheUpdatedSuppressed",
                    kOSBooleanTrue);
                setProperty("AirportRTW89DisconnectedSingleEnumerationEdge",
                            kOSBooleanTrue);
            }
            setProperty("AirportRTW89PostScanNotifyOrderCacheUpdatedFirst",
                        postCacheUpdated ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89PostScanNotifyOrderScanDoneFirst",
                        disconnectedDonePosted ? kOSBooleanTrue
                                               : kOSBooleanFalse);

            /* The first scan after OFF -> ON starts from a hard empty cache.
             * Its 100 ms fake SCAN_DONE is intentionally suppressed.  For a
             * disconnected Apple-owned scan, 0.2.227 now completes that first
             * full scan with the same single real-completion SCAN_DONE edge;
             * non-disconnected paths retain the older cache-update behavior. */
            if (powerOnFullCompletion) {
                if (!disconnectedDonePosted)
                    wifi->postMessage(APPLE80211_M_SCAN_DONE);
                _airportPowerOnFullScanNotifyPending = false;
                ++_airportPowerOnFullScanNotifyCount;
                setProperty("AirportRTW89PowerOnFullScanNotifyPending",
                            kOSBooleanFalse);
                setProperty("AirportRTW89PowerOnFullScanNotifyCount",
                            (uint64_t)_airportPowerOnFullScanNotifyCount, 32);
                setProperty("AirportRTW89PowerOnFullScanCacheUpdatedPosted",
                            disconnectedDonePosted ? kOSBooleanFalse
                                                   : kOSBooleanTrue);
                setProperty("AirportRTW89PowerOnFullScanDonePosted",
                            kOSBooleanTrue);
                setProperty("AirportRTW89PowerOnFullScanNotifyOrderValid",
                            kOSBooleanTrue);
                setProperty("AirportRTW89PowerOnFullScanSingleDoneOnly",
                            disconnectedDonePosted ? kOSBooleanTrue
                                                   : kOSBooleanFalse);
                setProperty("AirportRTW89RealCompletionScanDoneSuppressed",
                            kOSBooleanFalse);
                setProperty("AirportRTW89ScanCompleteMessagesPostedToLegacy",
                            kOSBooleanTrue);
            } else if (disconnectedDonePosted) {
                setProperty("AirportRTW89RealCompletionScanDoneSuppressed",
                            kOSBooleanFalse);
                setProperty("AirportRTW89ScanCompleteMessagesPostedToLegacy",
                            kOSBooleanTrue);
            } else {
                setProperty("AirportRTW89RealCompletionScanDoneSuppressed",
                            kOSBooleanTrue);
                setProperty("AirportRTW89ScanCompleteMessagesPostedToLegacy",
                            kOSBooleanFalse);
            }

            /* Observe whether userspace consumes GET SCAN_RESULT after this
             * notification edge.  The controller timer samples one tick later
             * so this is telemetry only and cannot recurse through Apple80211. */
            _airportScanNotifyGetCountAtPost = _airportScanResultGetCount;
            _airportScanNotifyConsumptionProbePending = true;
            _airportScanNotifyConsumptionProbeDelayTicks = 1;
            setProperty("AirportRTW89PostScanNotifyConsumptionProbePending",
                        kOSBooleanTrue);
            setProperty("AirportRTW89PostScanNotifyGetCountAtPost",
                        (uint64_t)_airportScanNotifyGetCountAtPost, 32);
        } else if (powerOnFullCompletion) {
            /* Do not leave future scans permanently suppressing early DONE if
             * the interface vanished unexpectedly. */
            _airportPowerOnFullScanNotifyPending = false;
            setProperty("AirportRTW89PowerOnFullScanNotifyPending",
                        kOSBooleanFalse);
            setProperty("AirportRTW89PowerOnFullScanNotifyInterfaceMissing",
                        kOSBooleanTrue);
        }
    }

    /* 0.2.156: a connected background scan temporarily reports the raw
     * RTW state as SCANNING.  It is not a link-down: cmdScan() saved
     * CONNECTED in _scanReturnState and restores it in scanDone().  Treat
     * that interval as logically connected so the one-second poll cannot
     * publish a false LINK_DOWN while the radio is merely off-channel. */
    const bool connectedScan = _ieee80211->isConnectedScanInProgress();
    const bool wasConnected = _airportLastState == RTW88_STATE_CONNECTED;
    const bool associationActive = _ieee80211->hasActiveAssociation();
    const bool isConnected = associationActive;
    setProperty("AirportRTW89PollAssociationTruth",
                associationActive ? kOSBooleanTrue : kOSBooleanFalse);
    if (current.state == RTW88_STATE_CONNECTED && !associationActive)
        setProperty("AirportRTW89PollStaleConnectedSuppressed",
                    kOSBooleanTrue);
    setProperty("AirportRTW89ConnectedScanEffectiveLink",
                connectedScan ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89ConnectedScanRawState",
                (uint64_t)current.state, 8);
    if (connectedScan) {
        static UInt32 connectedScanPollCount = 0;
        ++connectedScanPollCount;
        setProperty("AirportRTW89ConnectedScanPollCount",
                    (uint64_t)connectedScanPollCount, 32);
        setProperty("AirportRTW89ConnectedScanFalseDownSuppressed",
                    kOSBooleanTrue);
    }

    if (!wasConnected && isConnected) {
        _airportAssocPending = false;
        _airportAssocResult = APPLE80211_RESULT_SUCCESS;
        uint64_t parityConnectedNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(),
                                    &parityConnectedNowNs);
        setProperty("AirportRTW89ParityAssociationReachedConnected",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ParityAssociationReachedConnectedMS",
                    parityConnectedNowNs / 1000000ULL, 64);
        /* airportPublishLinkState() currently suppresses manual ASSOC_DONE/
         * LINK message bursts on the primary interface.  Make that behavior
         * explicit for IO80211Reference event-sequence comparison. */
        setProperty("AirportRTW89ParityAssocDonePostedOnConnectedEdge",
                    kOSBooleanFalse);
        /* Polling is now only a fallback for state changes not published by the
         * direct association/disconnect path. */
        airportPublishLinkState(true, current.rssi, true);
    } else if (wasConnected && !isConnected) {
        uint64_t linkLossNowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &linkLossNowNs);
        gAirportRTW89LinkLossTransitionStartMS = linkLossNowNs / 1000000ULL;
        setProperty("AirportRTW89LinkLossTransitionSeen", kOSBooleanTrue);
        setProperty("AirportRTW89LinkLossTransitionStartMS",
                    gAirportRTW89LinkLossTransitionStartMS, 64);
        airportPublishLinkState(false, current.rssi, false);
    } else if (isConnected) {
        /* 0.2.158 safety: do not enter either legacy or Skywalk LQM/peer
         * monitor path until the mixed legacy+control topology has a fully
         * initialized peer monitor.  Carrier still comes from the sole BSD
         * owner via setLinkStatus/setLinkState. */
        setProperty("AirportRTW89PrimaryLQMSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89ControlLQMSuppressed", kOSBooleanTrue);
        setProperty("AirportRTW89PeerMonitorSafePublication", kOSBooleanTrue);
        if (_skywalkOwnsBSDQueue) {
            setProperty("AirportRTW89SkywalkQueuePollOwnership",
                        kOSBooleanTrue);
        } else {
            IOOutputQueue *queue = _txQueue
                ? static_cast<IOOutputQueue *>(_txQueue) : getOutputQueue();
            if (queue && queue->getCapacity() == 0)
                airportRepairOutputQueue("poll-zero-capacity-repair");
            else
                airportPublishOutputQueueDiagnostics("poll-connected");
        }
    }

    if (_airportAssocPending && current.state == RTW88_STATE_IDLE) {
        _airportAssocPending = false;
        _airportAssocResult = APPLE80211_RESULT_UNSPECIFIED_FAILURE;
        if (wifi) {
            static volatile UInt32 parityAssocDoneFailurePostCount = 0;
            const UInt32 postCount = __sync_add_and_fetch(
                &parityAssocDoneFailurePostCount, 1U);
            uint64_t parityAssocDoneNowNs = 0;
            absolutetime_to_nanoseconds(mach_absolute_time(),
                                        &parityAssocDoneNowNs);
            wifi->postMessage(APPLE80211_M_ASSOC_DONE, nullptr, 0);
            setProperty("AirportRTW89ParityAssocDoneFailurePosted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89ParityAssocDoneFailurePostCount",
                        (uint64_t)postCount, 32);
            setProperty("AirportRTW89ParityAssocDoneFailurePostMS",
                        parityAssocDoneNowNs / 1000000ULL, 64);
        }
    }

    /* Preserve the logical CONNECTED edge across an associated scan.
     * Otherwise the next poll after scan completion looks like a fresh
     * reconnect and generates a spurious LINK_UP to pair with the false
     * LINK_DOWN we just eliminated. */
    _airportLastState = isConnected ? RTW88_STATE_CONNECTED : current.state;
}

SInt32 RTW88PCIDevice::apple80211Request(unsigned int requestType,
                                         int requestNumber,
                                         IO80211Interface *interface,
                                         void *data)
{
    /* Keep persistent diagnostics in IORegistry.  Tahoe may suppress some
     * early IOLog output, but these properties reveal the exact dispatcher
     * calling convention used by the restored IO80211 family. */
    setProperty("AirportRTW89Apple80211RequestSeen", kOSBooleanTrue);
    setProperty("AirportRTW89Apple80211Arg0",
                (uint64_t)requestType, 32);
    setProperty("AirportRTW89Apple80211Arg1",
                (uint64_t)(uint32_t)requestNumber, 32);
    setProperty("AirportRTW89Apple80211DataPresent",
                data ? kOSBooleanTrue : kOSBooleanFalse);

    const UInt32 parityDispatcherSequence = __sync_add_and_fetch(
        &_io80211ReferenceParityDispatcherSequence, 1U);
    setProperty("AirportRTW89ParityDispatcherSeen", kOSBooleanTrue);
    setProperty("AirportRTW89ParityDispatcherSequence",
                (uint64_t)parityDispatcherSequence, 32);
    setProperty("AirportRTW89ParityDispatcherRawRequestType",
                (uint64_t)requestType, 32);
    setProperty("AirportRTW89ParityDispatcherRawRequestNumber",
                (uint64_t)(uint32_t)requestNumber, 32);

    /* 0.2.198: request-scoped acknowledgement for the one native GET11
     * marshaller probe in AirportRTW89Interface::performCommand().  Match the
     * exact interface object and either known IO80211 calling convention;
     * unrelated callbacks that happen while the outer call is active must not
     * be mistaken for ownership of this GET11. */
    AirportRTW89Interface *probeInterface =
        OSDynamicCast(AirportRTW89Interface, interface);

    /* 0.2.217: acknowledge the exact outer performCommand scope on this
     * thread.  Multiple airportd/CoreWiFi workers can be active at once, so
     * search the interface's 16 request-scoped slots instead of using a
     * global last-request marker. */
    AirportRTW89Interface::IO80211ReferenceParityScope *parityScope = nullptr;
    if (probeInterface) {
        UInt32 newestSequence = 0;
        for (UInt32 i = 0; i < 16; ++i) {
            AirportRTW89Interface::IO80211ReferenceParityScope &candidate =
                probeInterface->_io80211ReferenceParityScopes[i];
            if (!candidate.active || candidate.thread != current_thread())
                continue;
            if (!parityScope || candidate.sequence >= newestSequence) {
                parityScope = &candidate;
                newestSequence = candidate.sequence;
            }
        }
    }
    if (parityScope) {
        parityScope->dispatcherEntered = true;
        parityScope->dispatcherRawRequestType = requestType;
        parityScope->dispatcherRawRequestNumber = requestNumber;
        parityScope->dispatcherReturn = kIOReturnNotReady;
        setProperty("AirportRTW89ParityDispatcherScopedEntrySeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ParityDispatcherScopedOuterSequence",
                    (uint64_t)parityScope->sequence, 32);
        setProperty("AirportRTW89ParityDispatcherScopedOuterRequest",
                    (uint64_t)(uint32_t)parityScope->outerRequestType, 32);
        setProperty("AirportRTW89ParityDispatcherInterfaceMatchesPrimary",
                    interface == _iface ? kOSBooleanTrue : kOSBooleanFalse);
    }

    const bool rawLooksLikeGet11 =
        ((requestType == (unsigned int)SIOCGA80211 &&
          requestNumber == APPLE80211_IOC_SCAN_RESULT) ||
         (requestType == APPLE80211_IOC_SCAN_RESULT && requestNumber == 1));
    const bool scopedNativeGet11 =
        probeInterface && probeInterface->_get11NativeProbeActive &&
        probeInterface->_get11NativeProbeThread == current_thread() &&
        rawLooksLikeGet11;

    if (scopedNativeGet11) {
        probeInterface->_get11NativeProbeEnteredInner = true;
        probeInterface->_get11NativeProbeInnerReturn = kIOReturnNotReady;
        probeInterface->_get11NativeProbeResult = nullptr;
        probeInterface->_get11NativeProbeMarkerApplied = false;
        setProperty("AirportRTW89Get11NativeMarshallerInnerSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Get11NativeMarshallerInnerArg0",
                    (uint64_t)requestType, 32);
        setProperty("AirportRTW89Get11NativeMarshallerInnerArg1",
                    (uint64_t)(uint32_t)requestNumber, 32);
        setProperty("AirportRTW89Get11NativeMarshallerInnerDataPresent",
                    data ? kOSBooleanTrue : kOSBooleanFalse);
    }

    /* 0.2.245 IO80211Reference parity: DISASSOCIATE/22 is intentionally
     * payload-less on the legacy controller API.  Do not reject that one
     * lifecycle SET before request normalization; every other null payload
     * remains invalid. */
    const bool payloadlessDisassociate =
        !data &&
        ((requestType == (unsigned int)SIOCSA80211 &&
          requestNumber == APPLE80211_IOC_DISASSOCIATE) ||
         (requestType == APPLE80211_IOC_DISASSOCIATE && requestNumber == 0));

    if (!_ieee80211 || (!data && !payloadlessDisassociate)) {
        if (parityScope)
            parityScope->dispatcherReturn = kIOReturnBadArgument;
        if (scopedNativeGet11) {
            probeInterface->_get11NativeProbeInnerReturn = kIOReturnBadArgument;
            setProperty("AirportRTW89Get11NativeMarshallerInnerReturn",
                        (uint64_t)(uint32_t)kIOReturnBadArgument, 32);
        }
        return kIOReturnBadArgument;
    }

    /* IO80211Family variants use two different argument layouts for this
     * virtual method:
     *
     *   IO80211Reference-style: (SIOCGA80211/SIOCSA80211, request number)
     *   Tahoe legacy:       (request number, 1 for GET / 0 for SET)
     *
     * The attachment-port 0.2.0 build only accepted the first form.  The
     * interface therefore attached, but Tahoe's POWER SET was rejected as an
     * unsupported request and the Wi-Fi switch immediately returned to Off. */
    unsigned int normalizedRequest;
    bool isGet;

    if (requestType == (unsigned int)SIOCGA80211 ||
        requestType == (unsigned int)SIOCSA80211) {
        normalizedRequest = (unsigned int)requestNumber;
        isGet = requestType == (unsigned int)SIOCGA80211;
    } else {
        normalizedRequest = requestType;
        if (requestNumber == 1)
            isGet = true;
        else if (requestNumber == 0)
            isGet = false;
        else {
            if (parityScope)
                parityScope->dispatcherReturn = kIOReturnUnsupported;
            if (scopedNativeGet11) {
                probeInterface->_get11NativeProbeInnerReturn =
                    kIOReturnUnsupported;
                setProperty("AirportRTW89Get11NativeMarshallerInnerReturn",
                            (uint64_t)(uint32_t)kIOReturnUnsupported, 32);
            }
            return kIOReturnUnsupported;
        }
    }

    setProperty("AirportRTW89Apple80211NormalizedRequest",
                (uint64_t)normalizedRequest, 32);
    setProperty("AirportRTW89Apple80211IsGet",
                isGet ? kOSBooleanTrue : kOSBooleanFalse);

    /* 0.3.51 build-fix: the IO80211Interface * exists at this dispatcher
     * boundary, not inside airportGetBody().  Keep the identity audit here and
     * condition it on the exact GET27/HW254 requests under investigation. */
    if (isGet &&
        (normalizedRequest == APPLE80211_IOC_SUPPORTED_CHANNELS ||
         normalizedRequest == APPLE80211_IOC_HW_SUPPORTED_CHANNELS)) {
        setProperty("AirportRTW89Get27InterfacePresent",
                    interface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Get27InterfacePointer",
                    (uint64_t)(uintptr_t)interface, 64);
        if (interface && interface->getMetaClass() &&
            interface->getMetaClass()->getClassName())
            setProperty("AirportRTW89Get27InterfaceClass",
                        interface->getMetaClass()->getClassName());
        setProperty("AirportRTW89Get27InterfaceIsLegacy",
                    OSDynamicCast(AirportRTW89Interface, interface)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Get27InterfaceIsBSDCompanion",
                    OSDynamicCast(AirportRTW89SkywalkBSDInterface, interface)
                        ? kOSBooleanTrue : kOSBooleanFalse);
    }
    if (!isGet && normalizedRequest == APPLE80211_IOC_DISASSOCIATE) {
        uint64_t nowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
        const UInt64 nowMS = nowNs / 1000000ULL;
        const UInt64 priorStartMS = _airportIOUCAssociationCaptureStartMS;
        const UInt64 priorAgeMS =
            priorStartMS != 0 && nowMS >= priorStartMS
                ? nowMS - priorStartMS : UINT64_MAX;
        /* 0.5.40: the first bounded epoch permits Tahoe's disconnected
         * identity preflight to reach "Will associate".  The payload-less
         * SET22 immediately following that decision is a phase boundary, not
         * a reason to re-arm the epoch.  Consume it so later GET1 again has
         * IO80211Reference's native disconnected return (6); otherwise CoreWiFi
         * reports "Already associated, and network transition not permitted"
         * and suppresses SET20. */
        const bool consumePreflightEpoch = priorAgeMS <= 45000ULL;
        _airportIOUCAssociationCaptureStartMS =
            consumePreflightEpoch ? 0ULL : nowMS;
        __sync_synchronize();
        const UInt32 captureSequence = __sync_add_and_fetch(
            &_airportIOUCAssociationCaptureSequence, 1U);
        setProperty("AirportRTW89IOUCAssociationCaptureArmed",
                    kOSBooleanTrue);
        setProperty("AirportRTW89IOUCAssociationCaptureSequence",
                    (uint64_t)captureSequence, 32);
        setProperty("AirportRTW89IOUCAssociationCaptureStartMS",
                    (uint64_t)_airportIOUCAssociationCaptureStartMS, 64);
        setProperty("AirportRTW89IOUCPreflightEpochConsumedAtSET22",
                    consumePreflightEpoch
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89IOUCPreflightEpochAgeAtSET22MS",
                    (uint64_t)priorAgeMS, 64);
    }
    if (payloadlessDisassociate) {
        static volatile UInt32 payloadlessDisassociateCount = 0;
        const UInt32 count = __sync_add_and_fetch(
            &payloadlessDisassociateCount, 1U);
        setProperty("AirportRTW89ExplicitMarshallerPayloadlessDisassociateSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89ExplicitMarshallerPayloadlessDisassociateCount",
                    (uint64_t)count, 32);
    }

    if (parityScope) {
        parityScope->dispatcherNormalizedRequest = normalizedRequest;
        parityScope->dispatcherIsGet = isGet;
        setProperty("AirportRTW89ParityDispatcherScopedNormalizedRequest",
                    (uint64_t)normalizedRequest, 32);
        setProperty("AirportRTW89ParityDispatcherScopedIsGet",
                    isGet ? kOSBooleanTrue : kOSBooleanFalse);
    }

    const UInt32 historySlot = _airportRequestHistoryIndex & 63U;
    _airportRequestHistory[historySlot] =
        (normalizedRequest & 0x7fffffffU) | (isGet ? 0x80000000U : 0U);
    _airportRequestHistoryIndex = (historySlot + 1U) & 63U;
    if (_airportRequestHistoryCount < 64U)
        ++_airportRequestHistoryCount;
    setProperty("AirportRTW89Apple80211RequestHistoryIndex",
                (uint64_t)_airportRequestHistoryIndex, 32);
    setProperty("AirportRTW89Apple80211RequestHistoryCount",
                (uint64_t)_airportRequestHistoryCount, 32);
    OSData *requestHistory = OSData::withBytes(
        _airportRequestHistory, sizeof(_airportRequestHistory));
    if (requestHistory) {
        setProperty("AirportRTW89Apple80211RequestHistory", requestHistory);
        requestHistory->release();
    }

    const SInt32 dispatchResult =
        isGet ? airportGet(normalizedRequest, data)
              : airportSet(normalizedRequest, data, interface);

    if (parityScope) {
        parityScope->dispatcherReturn = dispatchResult;
        setProperty("AirportRTW89ParityDispatcherScopedReturn",
                    (uint64_t)(uint32_t)dispatchResult, 32);
    }

    if (scopedNativeGet11) {
        probeInterface->_get11NativeProbeInnerReturn = dispatchResult;
        setProperty("AirportRTW89Get11NativeMarshallerInnerReturn",
                    (uint64_t)(uint32_t)dispatchResult, 32);

        /* Give the single native-marshaller probe a distinctive, temporary
         * signature in fields CoreWiFi prints in its maxAge diagnostics.  The
         * persistent scan object is restored by performCommand immediately
         * after the superclass returns.  If Tahoe actually marshals this
         * result, airportd should expose rssi=-42 and a small ~42 ms age rather
         * than the uptime-like value seen through the direct bridge. */
        if (dispatchResult == kIOReturnSuccess && isGet &&
            normalizedRequest == APPLE80211_IOC_SCAN_RESULT) {
            apple80211_scan_result **slot =
                static_cast<apple80211_scan_result **>(data);
            apple80211_scan_result *scanResult = slot ? *slot : nullptr;
            probeInterface->_get11NativeProbeResult = scanResult;
            if (scanResult) {
                probeInterface->_get11NativeProbeOriginalRSSI =
                    scanResult->asr_rssi;
                probeInterface->_get11NativeProbeOriginalAge =
                    scanResult->asr_age;
                scanResult->asr_rssi = -42;
                scanResult->asr_age = 42;
                probeInterface->_get11NativeProbeMarkerApplied = true;
                setProperty("AirportRTW89Get11NativeMarshallerMarkerApplied",
                            kOSBooleanTrue);
                setProperty("AirportRTW89Get11NativeMarshallerOriginalRSSI",
                            (uint64_t)(SInt64)
                                probeInterface->_get11NativeProbeOriginalRSSI,
                            64);
                setProperty("AirportRTW89Get11NativeMarshallerOriginalAgeMS",
                            (uint64_t)
                                probeInterface->_get11NativeProbeOriginalAge,
                            32);
            }
        }
    }

    return dispatchResult;
}

SInt32 RTW88PCIDevice::enableVirtualInterface(
    IO80211VirtualInterface *interface)
{
    if (!interface)
        return kIOReturnBadArgument;

    SInt32 result = IO80211Controller::enableVirtualInterface(interface);
    setProperty("AirportRTW89VirtualEnableReturn", (uint64_t)(uint32_t)result, 32);
    if (result == kIOReturnSuccess) {
#if __IO80211_TARGET >= __MAC_13_0
        interface->setEnabledBySystem(true);
#endif
        interface->setLinkState(kIO80211NetworkLinkUp, 0);
        interface->postMessage(APPLE80211_M_LINK_CHANGED);
    }
    return result;
}

SInt32 RTW88PCIDevice::disableVirtualInterface(
    IO80211VirtualInterface *interface)
{
    if (!interface)
        return kIOReturnBadArgument;

    SInt32 result = IO80211Controller::disableVirtualInterface(interface);
    setProperty("AirportRTW89VirtualDisableReturn", (uint64_t)(uint32_t)result, 32);
    if (result == kIOReturnSuccess) {
        interface->setLinkState(kIO80211NetworkLinkDown, 0);
        interface->postMessage(APPLE80211_M_LINK_CHANGED);
    }
    return result;
}

IO80211VirtualInterface *RTW88PCIDevice::createVirtualInterface(
    ether_addr *address, UInt role)
{
    setProperty("AirportRTW89VirtualCreateRole", (uint64_t)role, 32);
    if (!address)
        return nullptr;

    /* This is the same role split used by IO80211Reference: P2P device/client/GO
     * and AWDL receive a generic IO80211VirtualInterface; other roles remain
     * framework-owned. */
    if (role < APPLE80211_VIF_P2P_DEVICE || role > APPLE80211_VIF_AWDL)
        return IO80211Controller::createVirtualInterface(address, role);

    IO80211VirtualInterface *interface = new IO80211VirtualInterface;
    if (!interface)
        return nullptr;
    const char *name = role == APPLE80211_VIF_AWDL ? "awdl" : "p2p";
    if (!interface->init(this, address, role, name)) {
        interface->release();
        return nullptr;
    }
    setProperty("AirportRTW89VirtualCreateSucceeded", kOSBooleanTrue);
    return interface;
}

SInt32 RTW88PCIDevice::apple80211VirtualRequest(
    UInt requestType, int requestNumber, IO80211VirtualInterface *interface,
    void *data)
{
    (void)interface;
    ++_airportVirtualRequestCount;
    setProperty("AirportRTW89Apple80211VirtualRequestCount",
                (uint64_t)_airportVirtualRequestCount, 32);
    setProperty("AirportRTW89Apple80211VirtualArg0", (uint64_t)requestType, 32);
    setProperty("AirportRTW89Apple80211VirtualArg1",
                (uint64_t)(uint32_t)requestNumber, 32);

    if (!data)
        return kIOReturnBadArgument;

    UInt request;
    bool isGet;
    if (requestType == (UInt)SIOCGA80211 || requestType == (UInt)SIOCSA80211) {
        request = (UInt)requestNumber;
        isGet = requestType == (UInt)SIOCGA80211;
    } else {
        request = requestType;
        if (requestNumber == 1)
            isGet = true;
        else if (requestNumber == 0)
            isGet = false;
        else
            return kIOReturnUnsupported;
    }

    setProperty("AirportRTW89Apple80211VirtualNormalizedRequest",
                (uint64_t)request, 32);
    setProperty("AirportRTW89Apple80211VirtualIsGet",
                isGet ? kOSBooleanTrue : kOSBooleanFalse);

    switch (request) {
    case APPLE80211_IOC_AWDL_PEER_TRAFFIC_REGISTRATION: {
        apple80211_awdl_peer_traffic_registration *value =
            (apple80211_awdl_peer_traffic_registration *)data;
        if (isGet) {
            bzero(value, sizeof(*value));
            value->version = APPLE80211_VERSION;
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_AWDL_ELECTION_METRIC: {
        apple80211_awdl_election_metric *value =
            (apple80211_awdl_election_metric *)data;
        if (isGet) {
            value->version = APPLE80211_VERSION;
            value->metric = _airportAwdlElectionMetric;
        } else {
            _airportAwdlElectionMetric = value->metric;
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_AWDL_SYNC_ENABLED: {
        apple80211_awdl_sync_enabled *value =
            (apple80211_awdl_sync_enabled *)data;
        if (isGet) {
            value->version = APPLE80211_VERSION;
            value->enabled = _airportAwdlSyncEnabled ? 1U : 0U;
        } else {
            _airportAwdlSyncEnabled = value->enabled != 0;
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_AWDL_SYNC_FRAME_TEMPLATE:
        /* The hardware AWDL transmitter does not exist yet.  Accept template
         * SETs as IO80211Reference does, but do not retain a userspace pointer. */
        if (!isGet) {
            setProperty("AirportRTW89AwdlSyncFrameTemplateSetSeen", kOSBooleanTrue);
            return kIOReturnSuccess;
        }
        return kIOReturnError;
    case APPLE80211_IOC_AWDL_BSSID: {
        AirportRTW89AwdlBSSIDData *value = (AirportRTW89AwdlBSSIDData *)data;
        if (isGet) {
            bzero(value, sizeof(*value));
            value->version = APPLE80211_VERSION;
            memcpy(value->bssid, _airportAwdlBSSID, sizeof(_airportAwdlBSSID));
        } else {
            memcpy(_airportAwdlBSSID, value->bssid, sizeof(_airportAwdlBSSID));
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_PEER_CACHE_MAXIMUM_SIZE:
    case APPLE80211_IOC_AWDL_ELECTION_ID:
    case APPLE80211_IOC_AWDL_MASTER_CHANNEL:
    case APPLE80211_IOC_AWDL_SECONDARY_MASTER_CHANNEL:
    case APPLE80211_IOC_AWDL_MIN_RATE:
    case APPLE80211_IOC_AWDL_PRESENCE_MODE:
    case APPLE80211_IOC_AWDL_SYNC_STATE:
    case APPLE80211_IOC_AWDL_AF_TX_MODE: {
        AirportRTW89VersionedScalar *value = (AirportRTW89VersionedScalar *)data;
        UInt32 *slot = nullptr;
        switch (request) {
        case APPLE80211_IOC_PEER_CACHE_MAXIMUM_SIZE: slot = &_airportAwdlPeerCacheMaximum; break;
        case APPLE80211_IOC_AWDL_ELECTION_ID: slot = &_airportAwdlElectionId; break;
        case APPLE80211_IOC_AWDL_MASTER_CHANNEL: slot = &_airportAwdlMasterChannel; break;
        case APPLE80211_IOC_AWDL_SECONDARY_MASTER_CHANNEL: slot = &_airportAwdlSecondaryMasterChannel; break;
        case APPLE80211_IOC_AWDL_MIN_RATE: slot = &_airportAwdlMinRate; break;
        case APPLE80211_IOC_AWDL_PRESENCE_MODE: slot = &_airportAwdlPresenceMode; break;
        case APPLE80211_IOC_AWDL_SYNC_STATE: slot = &_airportAwdlSyncState; break;
        case APPLE80211_IOC_AWDL_AF_TX_MODE: slot = &_airportAwdlAfTxMode; break;
        default: break;
        }
        if (!slot)
            return kIOReturnError;
        if (isGet) {
            value->version = APPLE80211_VERSION;
            value->value = *slot;
        } else {
            *slot = value->value;
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_IE:
    case APPLE80211_IOC_ROAM_PROFILE:
    case APPLE80211_IOC_WOW_PARAMETERS:
    case APPLE80211_IOC_P2P_SCAN:
    case APPLE80211_IOC_P2P_LISTEN:
    case APPLE80211_IOC_P2P_GO_CONF:
    case APPLE80211_IOC_BTCOEX_PROFILES:
    case APPLE80211_IOC_BTCOEX_CONFIG:
    case APPLE80211_IOC_BTCOEX_OPTIONS:
    case APPLE80211_IOC_BTCOEX_MODE:
        return isGet ? airportGet(request, data)
                     : airportSet(request, data, nullptr);

    /* Keep the virtual/AWDL CHANNELS_INFO surface using the same canonical
     * builder as the 0.3.8 primary Tahoe compatibility path. */
    case APPLE80211_IOC_CHANNELS_INFO:
        if (!isGet)
            return kIOReturnUnsupported;
        airportFillChannelsInfo(
            reinterpret_cast<AirportRTW89ChannelsInfoData *>(data));
        setProperty("AirportRTW89VirtualChannelsInfoSeen", kOSBooleanTrue);
        return kIOReturnSuccess;

    case APPLE80211_IOC_AWDL_SYNC_PARAMS:
    case APPLE80211_IOC_AWDL_EXTENSION_STATE_MACHINE_PARAMETERS:
    case APPLE80211_IOC_AWDL_ELECTION_RSSI_THRESHOLDS:
    case APPLE80211_IOC_AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE:
    case APPLE80211_IOC_AWDL_DEVICE_CAPABILITIES:
    case APPLE80211_IOC_AWDL_OOB_AUTO_REQUEST:
    case APPLE80211_IOC_HT_CAPABILITY:
    case APPLE80211_IOC_VHT_CAPABILITY:
        if (isGet)
            ((UInt32 *)data)[0] = APPLE80211_VERSION;
        setProperty("AirportRTW89AwdlEmulatedRequest", (uint64_t)request, 32);
        return kIOReturnSuccess;
    default:
        setProperty("AirportRTW89Apple80211LastUnsupportedVirtualRequest",
                    (uint64_t)request, 32);
        return kIOReturnUnsupported;
    }
}

SInt32 RTW88PCIDevice::airportGetAuthTypeAppleControl(void *data)
{
    if (!data)
        return kIOReturnBadArgument;

    /* 0.3.5 IO80211Reference parity: GET2 is a pure read of the Apple-facing
     * current_authtype_* latch.  Do not inspect ic_state, scan nodes, BSS,
     * current association state, or the RTW backend. */
    apple80211_authtype_data *value =
        reinterpret_cast<apple80211_authtype_data *>(data);
    bzero(value, sizeof(*value));
    value->version = APPLE80211_VERSION;
    value->authtype_lower = _airportAppleControl.current_authtype_lower;
    value->authtype_upper = _airportAppleControl.current_authtype_upper;

    /* 0.5.43: Tahoe's secured Join performs GET AUTH_TYPE immediately after
     * its successful SET22/empty-SSID preflight, before it sends the SET2
     * that would normally configure IO80211Reference's Apple-facing latch.  The
     * 0.5.42 trace showed the synchronous association wrapper rejecting the
     * still-zero latch with -3903 before SET20.  Advertise WPA2-PSK only for
     * an unconfigured latch inside the same 25 ms controller-owned SET22
     * transaction.  The real SET20 remains authoritative and validates the
     * selected scan BSS as CCMP+PSK; no password, key, SSID, or BSSID is
     * fabricated here. */
    const UInt64 authNowMS = airportSecurityControlMonotonicMS();
    const UInt64 authEpochStartMS = _airportIOUCAssociationCaptureStartMS;
    const UInt64 authEpochAgeMS =
        authEpochStartMS != 0 && authNowMS >= authEpochStartMS
            ? authNowMS - authEpochStartMS : UINT64_MAX;
    const bool securedJoinAuthSeed =
        !_airportAppleControlAuthConfigured &&
        value->authtype_lower == 0 && value->authtype_upper == 0 &&
        authEpochAgeMS <= 25U;
    if (securedJoinAuthSeed)
        value->authtype_upper = APPLE80211_AUTHTYPE_WPA2_PSK;

    struct AirportWPA2AuthTypeDiagEntry {
        UInt32 sequence;
        UInt32 source;
        UInt32 lower;
        UInt32 upper;
        UInt32 authStateValid;
        UInt32 currentBSSIDNonZero;
        UInt32 currentBSSMatch;
        UInt32 currentBSSSecure;
        UInt32 effectiveConnected;
        UInt32 rawRTWState;
    };
    static_assert(sizeof(AirportWPA2AuthTypeDiagEntry) == 40,
                  "WPA2 AUTH_TYPE diagnostic entry size mismatch");
    static AirportWPA2AuthTypeDiagEntry authDiagRing[64] = {};
    static volatile UInt32 authDiagSequence = 0;
    const UInt32 sequence = __sync_add_and_fetch(&authDiagSequence, 1U);
    const UInt32 slot = (sequence - 1U) & 63U;
    AirportWPA2AuthTypeDiagEntry &diag = authDiagRing[slot];
    diag.sequence = sequence;
    diag.source = 5U; /* IO80211Reference Apple control-state latch */
    diag.lower = value->authtype_lower;
    diag.upper = value->authtype_upper;
    diag.authStateValid = _airportAppleControlAuthConfigured ? 1U : 0U;
    diag.currentBSSIDNonZero = 0U;
    diag.currentBSSMatch = 0U;
    diag.currentBSSSecure = 0U;
    diag.effectiveConnected = 0U;
    diag.rawRTWState = 0U;

    setProperty("AirportRTW89WPA2GetAuthTypeDiagSeen", kOSBooleanTrue);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagDiagnosticOnly",
                securedJoinAuthSeed ? kOSBooleanFalse : kOSBooleanTrue);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagReturnModified",
                securedJoinAuthSeed ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeSET22SeedApplied",
                securedJoinAuthSeed ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeSET22SeedEpochAgeMS",
                (uint64_t)authEpochAgeMS, 64);
    setProperty("AirportRTW89WPA2GetAuthTypeSET22SeedBoundMS",
                (uint64_t)25U, 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagPayloadCaptured",
                kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagCount",
                (uint64_t)sequence, 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagIndex",
                (uint64_t)((slot + 1U) & 63U), 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagEntrySize",
                (uint64_t)sizeof(AirportWPA2AuthTypeDiagEntry), 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastSource",
                (uint64_t)5U, 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastLower",
                (uint64_t)value->authtype_lower, 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastUpper",
                (uint64_t)value->authtype_upper, 32);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastAuthStateValid",
                _airportAppleControlAuthConfigured ? kOSBooleanTrue
                                                   : kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastCurrentBSSIDNonZero",
                kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastCurrentBSSMatch",
                kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastCurrentBSSSecure",
                kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastEffectiveConnected",
                kOSBooleanFalse);
    setProperty("AirportRTW89WPA2GetAuthTypeDiagLastRawRTWState",
                (uint64_t)0U, 32);
    setProperty("AirportRTW89AppleControlGET2IO80211ReferenceLatch",
                kOSBooleanTrue);
    setProperty("AirportRTW89AppleControlGET2ConsultedNet80211",
                kOSBooleanFalse);
    setProperty("AirportRTW89AppleControlGET2ConsultedRTW",
                kOSBooleanFalse);
    if (OSData *authDiagData =
            OSData::withBytes(authDiagRing, sizeof(authDiagRing))) {
        setProperty("AirportRTW89WPA2GetAuthTypeDiagRing", authDiagData);
        authDiagData->release();
    }
    return kIOReturnSuccess;
}

SInt32 RTW88PCIDevice::airportGetStackSafeHotStatus(
    unsigned int requestNumber, void *data)
{
    if (!data)
        return kIOReturnBadArgument;

    obsd80211::ieee80211_current_view netView = {};
    const bool netStateAvailable =
        _net80211 && _net80211->copyCurrentView(netView);
    const bool rtwEffectiveConnected = _ieee80211->hasActiveAssociation();
    const bool effectiveConnected =
        netStateAvailable ? netView.associated : rtwEffectiveConnected;

    switch (requestNumber) {
    case APPLE80211_IOC_OP_MODE: {
        /* airportd polls OP_MODE from inside IO80211's gated ioctl path.
         * Keep this getter allocation-free: entering airportGetBody() below
         * performCommandCompatBody() leaves too little kernel stack for
         * setProperty()/OSSymbol allocation and can double-fault. */
        apple80211_opmode_data *value =
            static_cast<apple80211_opmode_data *>(data);
        value->version = APPLE80211_VERSION;
        value->op_mode = APPLE80211_M_STA;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_CHANNEL: {
        apple80211_channel_data *value =
            static_cast<apple80211_channel_data *>(data);
        if (!effectiveConnected) {
            UInt32 targetChannel = 0;
            const bool targetOverride =
                airportPreRunTargetChannelOverride(&targetChannel);
            /* GET4 telemetry is intentionally retained: unlike the 0.3.9
             * panic path, this helper is reached without the compatibility
             * frame resident, so these registry writes are no longer nested
             * beneath ~9.5 KiB of our own stack. */
            setProperty("AirportRTW89GET4TargetChannelExperimentSeen",
                        kOSBooleanTrue);
            setProperty("AirportRTW89GET4TargetChannelExperimentEnabled",
                        targetOverride ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89GET4TargetChannelConfigured",
                        (uint64_t)targetChannel, 32);
            setProperty("AirportRTW89GET4TargetChannelEffectiveConnected",
                        kOSBooleanFalse);
            setProperty("AirportRTW89StackSafeGET4HotPath", kOSBooleanTrue);
            if (!targetOverride) {
                /* Tahoe performs this direct GET4 immediately after SET22
                 * while preparing a menu association.  Returning 6 is
                 * surfaced by IO80211Old as -3903 and aborts the join before
                 * SET20.  As with disconnected GET SSID/BSSID, return a
                 * versioned empty object: it describes no current channel
                 * and deliberately does not infer/select a scan channel. */
                bzero(value, sizeof(*value));
                value->version = APPLE80211_VERSION;
                setProperty("AirportRTW89GET4TargetChannelSource",
                            (uint64_t)0, 32);
                setProperty("AirportRTW89GET4TargetChannelReturn",
                            (uint64_t)kIOReturnSuccess, 32);
                setProperty("AirportRTW89GET4DisconnectedEmptySuccess",
                            kOSBooleanTrue);
                setProperty("AirportRTW89GET4DisconnectedPayloadInvented",
                            kOSBooleanFalse);
                return kIOReturnSuccess;
            }

            bzero(value, sizeof(*value));
            value->version = APPLE80211_VERSION;
            value->channel.version = APPLE80211_VERSION;
            value->channel.channel = targetChannel;
            value->channel.flags = airportChannelFlags(targetChannel);
            setProperty("AirportRTW89GET4TargetChannelSource",
                        (uint64_t)2, 32);
            setProperty("AirportRTW89GET4TargetChannelReturned",
                        (uint64_t)targetChannel, 32);
            setProperty("AirportRTW89GET4TargetChannelFlags",
                        (uint64_t)value->channel.flags, 32);
            setProperty("AirportRTW89GET4TargetChannelReturn",
                        (uint64_t)kIOReturnSuccess, 32);
            return kIOReturnSuccess;
        }

        UInt32 currentChannel = 0;
        if (netStateAvailable) {
            currentChannel = netView.channel;
        } else {
            RTW88StateResult state = {};
            _ieee80211->cmdGetState(&state);
            currentChannel = state.channel;
        }
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->channel.version = APPLE80211_VERSION;
        value->channel.channel = currentChannel;
        value->channel.flags = airportChannelFlags(currentChannel);
        setProperty("AirportRTW89GET4TargetChannelSource",
                    (uint64_t)1, 32);
        setProperty("AirportRTW89GET4TargetChannelReturned",
                    (uint64_t)currentChannel, 32);
        setProperty("AirportRTW89GET4TargetChannelReturn",
                    (uint64_t)kIOReturnSuccess, 32);
        setProperty("AirportRTW89StackSafeGET4HotPath", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_ASSOCIATE_RESULT: {
        apple80211_assoc_result_data *value =
            static_cast<apple80211_assoc_result_data *>(data);
        value->version = APPLE80211_VERSION;
        value->result = effectiveConnected
                            ? APPLE80211_RESULT_SUCCESS
                            : _airportAssocResult;
        /* Deliberately no setProperty() here.  The 0.3.9 panic faulted while
         * servicing this exact GET inside IORegistry allocation. */
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_ASSOCIATION_STATUS: {
        apple80211_assoc_status_data *value =
            static_cast<apple80211_assoc_status_data *>(data);
        value->version = APPLE80211_VERSION;
        value->status = effectiveConnected
                            ? APPLE80211_STATUS_SUCCESS
                            : APPLE80211_STATUS_UNAVAILABLE;
        /* Same stack rule as ASSOCIATE_RESULT: no synchronous registry work. */
        return kIOReturnSuccess;
    }
    default:
        return kIOReturnUnsupported;
    }
}

SInt32 RTW88PCIDevice::airportGet(unsigned int requestNumber, void *data)
{
    if (requestNumber == APPLE80211_IOC_AUTH_TYPE)
        return airportGetAuthTypeAppleControl(data);
    if (requestNumber == APPLE80211_IOC_OP_MODE ||
        requestNumber == APPLE80211_IOC_CHANNEL ||
        requestNumber == APPLE80211_IOC_ASSOCIATE_RESULT ||
        requestNumber == APPLE80211_IOC_ASSOCIATION_STATUS)
        return airportGetStackSafeHotStatus(requestNumber, data);

    /* 0.3.2 stack-safety repair: keep cmdGetState() out of the historically
     * large Apple getter body.  0.3.1 faulted in cmdGetState while the full
     * airportGet frame was already resident underneath a re-entrant IO80211
     * link-parameter callback.  Gather the exact same RTW snapshot in this
     * small wrapper, then enter the unchanged Stage-2 getter body only after
     * cmdGetState has returned. */
    RTW88StateResult state = {};
    _ieee80211->cmdGetState(&state);
    return airportGetBody(requestNumber, data, state);
}

SInt32 RTW88PCIDevice::airportGetBody(unsigned int requestNumber, void *data,
                                      const RTW88StateResult &state)
{
    /* Keep current-network identity/status queryable while an associated
     * manual/background scan is in progress.  The raw state is SCANNING, but
     * scanDone() will restore CONNECTED. */
    /* 0.3.1 Stage 2: net80211 is now the Apple-visible association-state
     * authority.  The RTW backend remains the hardware/MLME executor and its
     * association bit is retained as observation-only telemetry/fallback if
     * the net80211 core is unavailable.  This prevents stale OPEN state from
     * leaking back into Apple GETs immediately after SET22. */
    const bool rtwEffectiveConnected = _ieee80211->hasActiveAssociation();
    obsd80211::ieee80211_current_view netView = {};
    const bool netStateAvailable =
        _net80211 && _net80211->copyCurrentView(netView);
    const bool effectiveConnected =
        netStateAvailable ? netView.associated : rtwEffectiveConnected;
    setProperty("AirportRTW89Net80211AppleGetterAuthorityUsed",
                netStateAvailable ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89Net80211AppleGetterAssociated",
                effectiveConnected ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89Net80211AppleGetterRTWAssociatedObservation",
                rtwEffectiveConnected ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89Net80211AppleGetterRTWAgreement",
                effectiveConnected == rtwEffectiveConnected ? kOSBooleanTrue
                                                             : kOSBooleanFalse);
    if (effectiveConnected && state.state == RTW88_STATE_SCANNING) {
        static UInt32 connectedScanGetterCount = 0;
        ++connectedScanGetterCount;
        setProperty("AirportRTW89ConnectedScanGetterCount",
                    (uint64_t)connectedScanGetterCount, 32);
        setProperty("AirportRTW89ConnectedScanGettersPreserved",
                    kOSBooleanTrue);
    }

    /* 0.2.176 diagnostic-only: mark the controller-side value generated for
     * the current-network/status getters that feed Control Center and
     * networksetup.  The live interface performCommand() probe records the
     * corresponding userspace buffer after Apple's superclass returns. */
    const bool statusDiagInnerRequest =
        requestNumber == APPLE80211_IOC_SSID ||
        requestNumber == APPLE80211_IOC_BSSID ||
        requestNumber == APPLE80211_IOC_CURRENT_NETWORK ||
        requestNumber == APPLE80211_IOC_STATE ||
        requestNumber == APPLE80211_IOC_RSSI ||
        requestNumber == APPLE80211_IOC_ASSOCIATE_RESULT ||
        requestNumber == APPLE80211_IOC_ASSOCIATION_STATUS;
    if (statusDiagInnerRequest) {
        static UInt32 statusDiagInnerSequence = 0;
        ++statusDiagInnerSequence;
        setProperty("AirportRTW89StatusDiagInnerSeen", kOSBooleanTrue);
        setProperty("AirportRTW89StatusDiagInnerSequence",
                    (uint64_t)statusDiagInnerSequence, 32);
        setProperty("AirportRTW89StatusDiagInnerRequest",
                    (uint64_t)requestNumber, 32);
        setProperty("AirportRTW89StatusDiagInnerRawRTWState",
                    (uint64_t)state.state, 32);
        setProperty("AirportRTW89StatusDiagInnerEffectiveConnected",
                    effectiveConnected ? kOSBooleanTrue : kOSBooleanFalse);
    }

    switch (requestNumber) {
    case APPLE80211_IOC_SSID: {
        if (!effectiveConnected) {
            /* IO80211Reference returns 6 until ieee80211 reaches RUN.  A
             * successful zero-length SSID is not equivalent: Tahoe treats
             * it as an association with an unnamed network and renders the
             * misleading "unknown network" state. */
            setProperty("AirportRTW89DisconnectedSSIDIO80211ReferenceError",
                        kOSBooleanTrue);
            setProperty("AirportRTW89StatusDiagInnerSSIDReturn",
                        (uint64_t)6, 32);
            return 6;
        }
        apple80211_ssid_data *value = (apple80211_ssid_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        if (netStateAvailable) {
            value->ssid_len = netView.essid_len;
            memcpy(value->ssid_bytes, netView.essid, value->ssid_len);
            setProperty("AirportRTW89Net80211SSIDProjectionUsed",
                        kOSBooleanTrue);
        } else {
            value->ssid_len =
                (UInt32)airportBoundedStringLength(state.ssid, 32);
            memcpy(value->ssid_bytes, state.ssid, value->ssid_len);
        }
        setProperty("AirportRTW89StatusDiagInnerSSIDReturn",
                    (uint64_t)kIOReturnSuccess, 32);
        setProperty("AirportRTW89StatusDiagInnerSSIDStructSize",
                    (uint64_t)sizeof(*value), 32);
        setProperty("AirportRTW89StatusDiagInnerSSIDLength",
                    (uint64_t)value->ssid_len, 32);
        setProperty("AirportRTW89StatusDiagInnerSSIDHash",
                    airportStatusDiagHash(value->ssid_bytes, value->ssid_len),
                    64);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_AUTH_TYPE:
        return airportGetAuthTypeAppleControl(data);
    case APPLE80211_IOC_CHANNEL:
        /* 0.3.10: airportGet() routes GET4 through the small stack-safe helper
         * before cmdGetState()/airportGetBody.  Retain a defensive forwarding
         * case for direct internal callers of this body. */
        return airportGetStackSafeHotStatus(requestNumber, data);
    case APPLE80211_IOC_BSSID: {
        if (!effectiveConnected) {
            /* Keep disconnected identity semantics identical to
             * IO80211Reference: no BSSID exists before RUN. */
            setProperty("AirportRTW89DisconnectedBSSIDIO80211ReferenceError",
                        kOSBooleanTrue);
            setProperty("AirportRTW89StatusDiagInnerBSSIDReturn",
                        (uint64_t)6, 32);
            return 6;
        }
        apple80211_bssid_data *value = (apple80211_bssid_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        memcpy(value->bssid.octet,
               netStateAvailable ? netView.bssid : state.bssid, 6);
        if (netStateAvailable)
            setProperty("AirportRTW89Net80211BSSIDProjectionUsed",
                        kOSBooleanTrue);
        setProperty("AirportRTW89StatusDiagInnerBSSIDReturn",
                    (uint64_t)kIOReturnSuccess, 32);
        setProperty("AirportRTW89StatusDiagInnerBSSIDStructSize",
                    (uint64_t)sizeof(*value), 32);
        setProperty("AirportRTW89StatusDiagInnerBSSIDHash",
                    airportStatusDiagHash(value->bssid.octet, 6), 64);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_CURRENT_NETWORK: {
        /* CURRENT_NETWORK is association identity, not a pre-association
         * placeholder.  Returning a successful empty object made airportd
         * mark an idle interface associated to an unnamed network. */
        if (!effectiveConnected || !netStateAvailable || !netView.bss_present) {
            setProperty("AirportRTW89DisconnectedCurrentNetworkError",
                        kOSBooleanTrue);
            return 6;
        }

        apple80211_scan_result *value =
            static_cast<apple80211_scan_result *>(data);
        if (!value)
            return kIOReturnBadArgument;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->asr_channel.version = APPLE80211_VERSION;
        value->asr_channel.channel = netView.channel;
        value->asr_channel.flags = airportChannelFlags(netView.channel);
        value->asr_rssi = netView.rssi;
        value->asr_noise = -95;
        if (value->asr_rssi <= value->asr_noise)
            value->asr_noise = value->asr_rssi > -127
                                   ? (int16_t)(value->asr_rssi - 1)
                                   : (int16_t)-127;
        value->asr_snr = 0;
        value->asr_beacon_int = netView.beacon_interval
                                    ? netView.beacon_interval : 100;
        value->asr_cap = (int16_t)(netView.capinfo & 0xffffU);
        memcpy(value->asr_bssid, netView.bssid, sizeof(netView.bssid));
        value->asr_nrates = netView.nrates < APPLE80211_MAX_RATES
                                ? netView.nrates : APPLE80211_MAX_RATES;
        /* IO80211Reference's converter currently leaves asr_rates[] zeroed while
         * publishing the rate count, so retain that wire behavior. */
        value->asr_ssid_len = netView.essid_len;
        if (value->asr_ssid_len)
            memcpy(value->asr_ssid, netView.essid, value->asr_ssid_len);
        value->asr_age = 0;

#if __IO80211_TARGET < __MAC_12_0
        /* The old ABI carries an external IE pointer.  Do not point it at the
         * request-scoped netView snapshot; identity publication remains valid
         * without an IE on those legacy targets. */
        value->asr_ie_len = 0;
        value->asr_ie_data = nullptr;
#else
        const uint16_t currentIELength = _net80211
            ? _net80211->copyCurrentSecurityIE(
                  value->asr_ie_data, (uint16_t)sizeof(value->asr_ie_data))
            : 0;
        value->asr_ie_len = (int16_t)currentIELength;
#endif
        setProperty("AirportRTW89PostRUNCurrentNetworkInnerSucceeded",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PostRUNCurrentNetworkSSIDLength",
                    (uint64_t)value->asr_ssid_len, 32);
        setProperty("AirportRTW89PostRUNCurrentNetworkChannel",
                    (uint64_t)value->asr_channel.channel, 32);
        setProperty("AirportRTW89PostRUNCurrentNetworkIELength",
                    (uint64_t)(uint16_t)value->asr_ie_len, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_SCAN_RESULT: {
        /* 0.2.208: while the one-shot first-result controller probe is
         * crossing IO80211 on one thread, do not let a concurrent direct
         * GET11 steal index zero. The window is only the inherited
         * performCommand() call; normal traffic is unaffected before/after. */
        if (_airportGet11ControllerIoctlGetProbeActive &&
            _airportGet11ControllerIoctlGetProbeThread != THREAD_NULL &&
            _airportGet11ControllerIoctlGetProbeThread != current_thread()) {
            static volatile UInt32 concurrentBlockedCount = 0;
            const UInt32 blocked = __sync_add_and_fetch(
                &concurrentBlockedCount, 1);
            setProperty(
                "AirportRTW89Get11ControllerFirstResultConcurrentBlocked",
                (uint64_t)blocked, 32);
            return kIOReturnBusy;
        }

        apple80211_scan_result **out = (apple80211_scan_result **)data;
        if (!out)
            return kIOReturnBadArgument;
        /* Never leave a stale pointer visible on the normal 5/12
         * end/no-result returns.  Successful calls publish one of the
         * persistent per-BSS backing objects below. */
        *out = nullptr;
        _airportScanResultGetCount++;
        setProperty("AirportRTW89Apple80211ScanResultGetCount",
                    _airportScanResultGetCount, 32);
        setProperty("AirportRTW89Apple80211ScanResultStructSize",
                    (UInt64)sizeof(apple80211_scan_result), 64);

        if (!_net80211)
            return kIOReturnNotReady;

        IOLockLock(_airportLock);
        const thread_t scanThread = current_thread();
        AirportScanIterator *iterator = nullptr;
        AirportScanIterator *replacement = &_airportScanIterators[0];
        for (UInt32 i = 0; i < 16; ++i) {
            AirportScanIterator *candidate = &_airportScanIterators[i];
            if (candidate->thread == scanThread &&
                candidate->serial == _airportScanIterationSerial) {
                iterator = candidate;
                break;
            }
            if (candidate->thread == THREAD_NULL ||
                candidate->lastUse < replacement->lastUse)
                replacement = candidate;
        }
        if (!iterator) {
            iterator = replacement;
            iterator->thread = scanThread;
            iterator->index = 0;
            iterator->serial = _airportScanIterationSerial;
        }
        iterator->lastUse = ++_airportScanIteratorUseSerial;
        if (_airportScanIteratorUseSerial == 0U) {
            _airportScanIteratorUseSerial = 1U;
            iterator->lastUse = 1U;
        }
        setProperty("AirportRTW89Apple80211ScanResultBSSCount",
                    _airportBSSCount, 32);
        setProperty("AirportRTW89Apple80211ScanResultIndex",
                    iterator->index, 32);
        setProperty("AirportRTW89Apple80211ScanResultIteratorSerial",
                    (uint64_t)_airportScanIterationSerial, 32);
        setProperty("AirportRTW89Apple80211ScanResultPerThreadIterator",
                    kOSBooleanTrue);

        if (_airportBSSCount == 0) {
            _airportScanResultEndCount++;
            setProperty("AirportRTW89Apple80211ScanResultEndCount",
                        _airportScanResultEndCount, 32);
            setProperty("AirportRTW89Apple80211ScanResultLastReturn",
                        (UInt64)12, 32);
            IOLockUnlock(_airportLock);
            return 12; /* mirrors the legacy IO80211 no-results code */
        }
        if (iterator->index >= _airportBSSCount) {
            _airportScanResultEndCount++;
            setProperty("AirportRTW89Apple80211ScanResultEndCount",
                        _airportScanResultEndCount, 32);
            setProperty("AirportRTW89Apple80211ScanResultLastReturn",
                        (UInt64)5, 32);
            IOLockUnlock(_airportLock);
            return 5;  /* end of this scan-result iteration */
        }

        const UInt32 resultSlot = iterator->index++;
        _airportBSSIndex = iterator->index; /* retained diagnostic cursor */
        obsd80211::ieee80211_node *bss =
            _net80211->visibleNodeMutable(resultSlot);
        if (!bss) {
            IOLockUnlock(_airportLock);
            setProperty("AirportRTW89Net80211GET11NodeMissing",
                        kOSBooleanTrue);
            return kIOReturnNotReady;
        }
        /* 0.3.0 Stage 1: make the net80211 node itself own the Apple
         * scan-result backing object, matching IO80211Reference's node-owned
         * projection instead of a detached parallel result array. */
        apple80211_scan_result *result = &bss->verb;
        bzero(result, sizeof(*result));
        setProperty("AirportRTW89Apple80211ScanResultPerBSSStorage", true);
        setProperty("AirportRTW89Apple80211ScanResultStorageSlots", (UInt64)64, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastStorageSlot", (UInt64)resultSlot, 32);
        setProperty("AirportRTW89Net80211GET11NodeVerbUsed", kOSBooleanTrue);
        result->version = APPLE80211_VERSION;
        result->asr_channel.version = APPLE80211_VERSION;
        result->asr_channel.channel = bss->channel;
        result->asr_channel.flags = airportChannelFlags(bss->channel);

        /* RTW89's conversion maps a missing/zero raw RSSI to exactly -110 dBm
         * (MAX_RSSI).  That endpoint has appeared in real scan results and is
         * not a useful Apple80211 signal value.  For this compatibility probe,
         * normalize only that sentinel-like endpoint; preserve all genuine
         * RTW89 dBm values above it.  If this makes networks visible, the
         * permanent fix belongs lower in PPDU/RSSI extraction rather than here. */
        const int16_t rawRSSI = bss->rssi;
        const bool rssiSentinelNormalized = rawRSSI <= -110;
        const int16_t appleRSSI = rssiSentinelNormalized ? -90 : rawRSSI;

        /* Noise was already synthetic in this port. Keep the existing -95 dBm
         * baseline unless a genuine RSSI is even weaker, in which case put the
         * synthetic noise floor 1 dB below the signal so the tuple is coherent. */
        int16_t appleNoise = -95;
        if (!rssiSentinelNormalized && appleRSSI <= appleNoise) {
            const int32_t candidate = (int32_t)appleRSSI - 1;
            appleNoise = (int16_t)(candidate < -127 ? -127 : candidate);
        }
        result->asr_noise = appleNoise;
        /* IO80211Reference leaves the unknown/SNR slot zero in scan results. */
        result->asr_snr = 0;
        result->asr_rssi = appleRSSI;
        result->asr_beacon_int = bss->beacon_interval ? bss->beacon_interval : 100;
        result->asr_cap = (int16_t)(bss->capinfo & 0xffff);
        memcpy(result->asr_bssid, bss->bssid, 6);

        /* Publish one bounded UInt32 entry for every parsed AP rate. */
        const UInt8 rawRateCount =
            bss->nrates < APPLE80211_MAX_RATES ? bss->nrates : APPLE80211_MAX_RATES;
        result->asr_nrates = rawRateCount;
        for (UInt8 rateIndex = 0; rateIndex < rawRateCount; ++rateIndex)
            result->asr_rates[rateIndex] = (UInt32)bss->rates[rateIndex];
        setProperty("AirportRTW89Apple80211ScanResultRatesConsistent", true);
        setProperty("AirportRTW89IO80211ReferenceRateShapeParity", false);
        setProperty("AirportRTW89Apple80211ScanResultRawRateCount",
                    (UInt64)rawRateCount, 32);
        setProperty("AirportRTW89Apple80211ScanResultReturnedRate0",
                    (UInt64)result->asr_rates[0], 32);
        setProperty("AirportRTW89Apple80211ScanResultRatesWidenedToUInt32",
                    kOSBooleanTrue);
        if (rawRateCount != 0) {
            setProperty("AirportRTW89Apple80211ScanResultRawRate0",
                        (UInt64)bss->rates[0], 32);
            if (rawRateCount > 1)
                setProperty("AirportRTW89Apple80211ScanResultRawRate1",
                            (UInt64)bss->rates[1], 32);
            if (rawRateCount > 2)
                setProperty("AirportRTW89Apple80211ScanResultRawRate2",
                            (UInt64)bss->rates[2], 32);
            if (rawRateCount > 3)
                setProperty("AirportRTW89Apple80211ScanResultRawRate3",
                            (UInt64)bss->rates[3], 32);
        }

        const size_t ssidLength =
            bss->essid_len < sizeof(result->asr_ssid)
                ? bss->essid_len : sizeof(result->asr_ssid);
        result->asr_ssid_len = (UInt8)ssidLength;
        if (ssidLength)
            memcpy(result->asr_ssid, bss->essid, ssidLength);

        /* 0.4.21: the legacy Apple80211 ioctl path consumes AirportRTW's
         * absolute monotonic observation stamp, while IO80211Reference V2's
         * Skywalk path publishes elapsed beacon age.  0.4.20 proved the
         * exclusive native companion enumerates every BSS but CoreWiFi shows
         * none: a ~2 s BSS was returned as age ~168000.  Select the encoding
         * by live interface ownership so default legacy behavior is unchanged. */
        const uint64_t observedAgeMs = bss->last_seen_ns / 1000000ULL;
        uint64_t nowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
        uint64_t elapsedAgeMs = 0;
        if (bss->last_seen_ns != 0 && nowNs >= bss->last_seen_ns)
            elapsedAgeMs = (nowNs - bss->last_seen_ns) / 1000000ULL;
        const bool nativeCompanionOwnsInterface =
            _skywalkBSDCompanion && !_iface &&
            getNetworkInterface() == _skywalkBSDCompanion;
        const uint64_t selectedAgeMs = nativeCompanionOwnsInterface
            ? elapsedAgeMs : observedAgeMs;
        const UInt32 encodedAgeMs = selectedAgeMs > UINT32_MAX
            ? UINT32_MAX : (UInt32)selectedAgeMs;
        result->asr_age = encodedAgeMs;

        setProperty("AirportRTW89Apple80211ScanResultAgeFieldAbsoluteMonotonic",
                    nativeCompanionOwnsInterface ? kOSBooleanFalse
                                                 : kOSBooleanTrue);
        setProperty("AirportRTW89Apple80211ScanResultAgeFieldElapsedParity",
                    nativeCompanionOwnsInterface ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211ScanResultAgeNativeTopologySelected",
                    nativeCompanionOwnsInterface ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211ScanResultComputedElapsedAgeMS",
                    elapsedAgeMs, 64);
        setProperty("AirportRTW89Apple80211ScanResultEncodedAgeMS",
                    (UInt64)encodedAgeMs, 32);
        /* IO80211Reference's Ventura-era GET SCAN_RESULT contract exposes only
         * the AP security TLV through asr_ie_data, not the complete beacon IE
         * stream.  Feeding SSID/rates/DS/HT/vendor IEs into this field makes
         * IO80211 successfully enumerate the object but reject the network
         * while parsing it.  Prefer RSN (48).  For legacy WPA, preserve the
         * WPA vendor TLV (00:50:f2:01) as the security IE fallback. */
        const uint8_t *securityIE = nullptr;
        size_t securityIELength = 0;
        bool securityIEIsRSN = false;
        bool securityIEIsWPA = false;

        /* 0.2.180: security is persistent BSS state, not whatever happened to
         * be present in the most recent beacon/probe-response IE stream. */
        if (bss->rsn_ie_len >= 2 &&
            bss->rsn_ie_len <= sizeof(bss->rsn_ie) &&
            bss->rsn_ie[0] == 48 &&
            (size_t)bss->rsn_ie[1] + 2 <= bss->rsn_ie_len) {
            securityIE = bss->rsn_ie;
            securityIELength = (size_t)bss->rsn_ie[1] + 2;
            securityIEIsRSN = true;
        } else if (bss->wpa_ie_len >= 6 &&
                   bss->wpa_ie_len <= sizeof(bss->wpa_ie) &&
                   bss->wpa_ie[0] == 221 &&
                   bss->wpa_ie[2] == 0x00 && bss->wpa_ie[3] == 0x50 &&
                   bss->wpa_ie[4] == 0xf2 && bss->wpa_ie[5] == 0x01 &&
                   (size_t)bss->wpa_ie[1] + 2 <= bss->wpa_ie_len) {
            securityIE = bss->wpa_ie;
            securityIELength = (size_t)bss->wpa_ie[1] + 2;
            securityIEIsWPA = true;
        }
        /* 0.2.165: CoreWiFi still refuses WPA2 candidates before SET20.  For
         * BSSes that the RTW parser has already proven contain CCMP + PSK,
         * expose a minimal station-selected WPA2 RSN IE instead of forwarding
         * optional AP AKMs/capability bits (SAE/PMF/transition extras).  Do not
         * canonicalize enterprise, WPA3-only, malformed, or unknown security. */
        const size_t rawSecurityIELength = securityIELength;
        const UInt8 *rawSecurityIE = securityIE;
        UInt8 canonicalRsnIE[22] = {};
        AirportRTW89RsnSummary rawRsn = {};
        const bool rawRsnParsed = securityIEIsRSN &&
            airportParseRsnSummary(securityIE, securityIELength, &rawRsn);
        const bool rawRsnRequiresPMF = rawRsn.capabilitiesPresent &&
            (rawRsn.capabilities & 0x0040U) != 0; /* MFPR */
        const bool canonicalEligible = securityIEIsRSN && rawRsnParsed &&
            bss->cipher == kAirportRsnCipherCCMP &&
            bss->akm == kAirportRsnAkmPSK && rawRsn.hasCCMP && rawRsn.hasPSK &&
            !rawRsnRequiresPMF;
        bool canonicalApplied = false;
        UInt16 canonicalRsnLength = 0;

#if __IO80211_TARGET >= __MAC_12_0
        /* Tahoe Apple80211Associate2 derives its authentication mask from the
         * selected scan object's security dictionary before it emits SET20.
         * The association trace proved that rewriting this AP's valid
         * 26-byte mixed-mode RSN IE to a synthetic 22-byte CCMP-only form
         * leaves that derived mask at zero and Apple80211Associate2 returns
         * -3903 locally.  Publish the exact validated AP RSN TLV instead.
         * Keep canonicalEligible as diagnostics, but do not alter negotiated
         * cipher/AKM capabilities before the framework selects its auth type. */
        (void)canonicalRsnIE;
        (void)canonicalEligible;
#endif

        static UInt32 canonicalRsnCount = 0;
        if (canonicalApplied)
            ++canonicalRsnCount;
        setProperty("AirportRTW89WPA2CanonicalRSNEligible",
                    canonicalEligible ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2CanonicalRSNApplied",
                    canonicalApplied ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2RawRSNPublishedForAuthDerivation",
                    securityIEIsRSN && rawRsnParsed
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2CanonicalRSNCount",
                    (uint64_t)canonicalRsnCount, 32);
        setProperty("AirportRTW89WPA2RawRSNParsed",
                    rawRsnParsed ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2RawRSNLength",
                    (uint64_t)(securityIEIsRSN ? rawSecurityIELength : 0), 32);
        if (securityIEIsRSN && rawSecurityIE && rawSecurityIELength) {
            size_t snapshotLength = rawSecurityIELength;
            if (snapshotLength > 32)
                snapshotLength = 32;
            if (OSData *rawRsnData = OSData::withBytes(rawSecurityIE, snapshotLength)) {
                setProperty("AirportRTW89WPA2RawRSNPrefix", rawRsnData);
                rawRsnData->release();
            }
        }
        if (rawRsnParsed) {
            setProperty("AirportRTW89WPA2RawRSNVersion",
                        (uint64_t)rawRsn.version, 16);
            setProperty("AirportRTW89WPA2RawRSNGroupCipher",
                        (uint64_t)rawRsn.groupCipher, 32);
            setProperty("AirportRTW89WPA2RawRSNPairwiseCount",
                        (uint64_t)rawRsn.pairwiseCount, 16);
            setProperty("AirportRTW89WPA2RawRSNAKMCount",
                        (uint64_t)rawRsn.akmCount, 16);
            setProperty("AirportRTW89WPA2RawRSNCapabilities",
                        (uint64_t)rawRsn.capabilities, 16);
            setProperty("AirportRTW89WPA2RawRSNHasPSK", rawRsn.hasPSK);
            setProperty("AirportRTW89WPA2RawRSNHasSAE", rawRsn.hasSAE);
            setProperty("AirportRTW89WPA2RawRSNHas8021X", rawRsn.has8021X);
            setProperty("AirportRTW89WPA2RawRSNTransitionMode",
                        rawRsn.hasPSK && rawRsn.hasSAE);
            setProperty("AirportRTW89WPA2RawRSNRequiresPMF",
                        rawRsnRequiresPMF);
        }
        setProperty("AirportRTW89WPA2ParsedPairwiseCipher",
                    (uint64_t)bss->cipher, 32);
        setProperty("AirportRTW89WPA2ParsedGroupCipher",
                    (uint64_t)bss->group_cipher, 32);
        setProperty("AirportRTW89WPA2ParsedAKM", (uint64_t)bss->akm, 32);
        setProperty("AirportRTW89WPA2CanonicalRSNLength",
                    (uint64_t)canonicalRsnLength, 16);

#if __IO80211_TARGET < __MAC_12_0
        result->asr_ie_len = (int16_t)securityIELength;
        result->asr_ie_data = securityIE ? (void *)securityIE : nullptr;
        const size_t ieLength = securityIELength;
#else
        const size_t ieLength =
            securityIELength < sizeof(result->asr_ie_data)
                ? securityIELength : sizeof(result->asr_ie_data);
        result->asr_ie_len = (int16_t)ieLength;
        if (ieLength && securityIE)
            memcpy(result->asr_ie_data, securityIE, ieLength);
#endif
        setProperty("AirportRTW89Apple80211ScanResultSecurityIEOnly", true);
        setProperty("AirportRTW89Apple80211ScanResultSecurityIEIsRSN", securityIEIsRSN);
        setProperty("AirportRTW89Apple80211ScanResultSecurityIEIsWPA", securityIEIsWPA);
        setProperty("AirportRTW89Apple80211ScanResultFullIELength",
                    (UInt64)bss->ies_len, 32);
        setProperty("AirportRTW89Apple80211ScanResultPersistentRSNLength",
                    (UInt64)bss->rsn_ie_len, 16);
        setProperty("AirportRTW89Apple80211ScanResultPersistentWPALength",
                    (UInt64)bss->wpa_ie_len, 16);

        /* 0.2.155: compact IO80211Reference-parity snapshot of the exact BSS
         * metadata CoreWiFi sees before deciding whether to issue SET 20. */
        static UInt32 preJoinScanResultCount = 0;
        static UInt32 preJoinScanRSNCount = 0;
        static UInt32 preJoinScanWPACount = 0;
        static UInt32 preJoinScanOpenCount = 0;
        static UInt32 preJoinScanPrivacyNoIECount = 0;
        ++preJoinScanResultCount;
        UInt32 securityClass = 0; /* 0=open, 1=privacy/no TLV, 2=WPA, 3=RSN */
        if (securityIEIsRSN) {
            securityClass = 3;
            ++preJoinScanRSNCount;
        } else if (securityIEIsWPA) {
            securityClass = 2;
            ++preJoinScanWPACount;
        } else if ((result->asr_cap & 0x0010) != 0) {
            securityClass = 1;
            ++preJoinScanPrivacyNoIECount;
        } else {
            ++preJoinScanOpenCount;
        }
        setProperty("AirportRTW89PreJoinScanResultSeen", kOSBooleanTrue);
        setProperty("AirportRTW89PreJoinScanResultCount",
                    (uint64_t)preJoinScanResultCount, 32);
        setProperty("AirportRTW89PreJoinScanSecurityClass",
                    (uint64_t)securityClass, 32);
        setProperty("AirportRTW89PreJoinScanRSNCount",
                    (uint64_t)preJoinScanRSNCount, 32);
        setProperty("AirportRTW89PreJoinScanWPACount",
                    (uint64_t)preJoinScanWPACount, 32);
        setProperty("AirportRTW89PreJoinScanOpenCount",
                    (uint64_t)preJoinScanOpenCount, 32);
        setProperty("AirportRTW89PreJoinScanPrivacyNoIECount",
                    (uint64_t)preJoinScanPrivacyNoIECount, 32);
        setProperty("AirportRTW89PreJoinScanChannel",
                    (uint64_t)result->asr_channel.channel, 32);
        setProperty("AirportRTW89PreJoinScanChannelFlags",
                    (uint64_t)result->asr_channel.flags, 32);
        setProperty("AirportRTW89PreJoinScanCapability",
                    (uint64_t)(UInt16)result->asr_cap, 32);
        setProperty("AirportRTW89PreJoinScanIELength",
                    (uint64_t)(UInt16)result->asr_ie_len, 32);
        setProperty("AirportRTW89PreJoinScanSSIDLength",
                    (uint64_t)result->asr_ssid_len, 32);

        _airportScanResultSuccessCount++;
        setProperty("AirportRTW89Apple80211ScanResultSuccessCount",
                    _airportScanResultSuccessCount, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastReturn",
                    (UInt64)kIOReturnSuccess, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastChannel",
                    (UInt64)result->asr_channel.channel, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastChannelFlags",
                    (UInt64)result->asr_channel.flags, 32);
        setProperty("AirportRTW89Apple80211ScanResultRawRSSI",
                    (UInt64)(SInt64)rawRSSI, 64);
        setProperty("AirportRTW89Apple80211ScanResultLastRSSI",
                    (UInt64)(SInt64)result->asr_rssi, 64);
        setProperty("AirportRTW89Apple80211ScanResultEffectiveNoise",
                    (UInt64)(SInt64)result->asr_noise, 64);
        setProperty("AirportRTW89Apple80211ScanResultRSSISentinelNormalized",
                    rssiSentinelNormalized);
        setProperty("AirportRTW89Apple80211ScanResultLastAge",
                    (UInt64)result->asr_age, 32);
        setProperty("AirportRTW89Apple80211ScanResultAgeFromTimestamp", true);
        setProperty("AirportRTW89Apple80211ScanResultLastComputedElapsedAgeMS",
                    (uint64_t)0, 64);
        setProperty("AirportRTW89Apple80211ScanResultLastObservedMonotonicMS",
                    observedAgeMs, 64);
        setProperty("AirportRTW89Apple80211ScanResultLastCapability",
                    (UInt64)(UInt16)result->asr_cap, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastBeaconInterval",
                    (UInt64)(UInt16)result->asr_beacon_int, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastSSIDLength",
                    (UInt64)result->asr_ssid_len, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastIELength",
                    (UInt64)(UInt16)result->asr_ie_len, 32);
        setProperty("AirportRTW89Apple80211ScanResultLastRateCount",
                    (UInt64)result->asr_nrates, 32);
        setProperty("AirportRTW89Apple80211ScanResultESS",
                    (result->asr_cap & 0x0001) != 0);
        setProperty("AirportRTW89Apple80211ScanResultPrivacy",
                    (result->asr_cap & 0x0010) != 0);

        *out = result;
        IOLockUnlock(_airportLock);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_CARD_CAPABILITIES: {
        apple80211_capability_data *value = (apple80211_capability_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        /* Match IO80211Reference 2.3.0 (Ventura) byte-for-byte.  The restored
         * Tahoe frameworks use the private high capability bytes to choose
         * their qualification/request path, so approximating these values
         * advertises a materially different driver contract. */
        value->capabilities[0] = 0x0b; /* WEP, TKIP, AES-CCM */
        value->capabilities[1] = 0x76; /* short slot/preamble, TKIPMIC, WPA1/2 */
        value->capabilities[2] = 0xff;
        value->capabilities[3] = 0x2b;
        value->capabilities[4] = 0xad;
        value->capabilities[5] = 0x8c;
        value->capabilities[6] = 0x8c;
        value->capabilities[7] = 0x84;
        /* IO80211Reference's newer IO80211 capability layout publishes the
         * private peer-to-peer/AWDL extension as the little-endian value
         * 0x0201.  Tahoe's CoreWLAN uses these bytes for supportsAirDrop;
         * leaving them zero omits the AirDrop row from System Information. */
        value->capabilities[8] = 0x01;
        value->capabilities[9] = 0x02;
        OSData *capabilityBytes = OSData::withBytes(
            value->capabilities, sizeof(value->capabilities));
        if (capabilityBytes) {
            setProperty("AirportRTW89Apple80211CapabilityBytes",
                        capabilityBytes);
            capabilityBytes->release();
        }
        setProperty("AirportRTW89Apple80211IO80211ReferenceCapabilityBitmap",
                    kOSBooleanTrue);
        static UInt32 preJoinCardCapabilitiesCount = 0;
        ++preJoinCardCapabilitiesCount;
        setProperty("AirportRTW89PreJoinCardCapabilitiesSeen", kOSBooleanTrue);
        setProperty("AirportRTW89PreJoinCardCapabilitiesCount",
                    (uint64_t)preJoinCardCapabilitiesCount, 32);
        setProperty("AirportRTW89PreJoinCardCapabilitiesVersion",
                    (uint64_t)value->version, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_STATE: {
        ++_airportStateGetCount;
        setProperty("AirportRTW89Apple80211StateGetCount",
                    (uint64_t)_airportStateGetCount, 32);
        apple80211_state_data *value = (apple80211_state_data *)data;
        value->version = APPLE80211_VERSION;
        if (netStateAvailable) {
            value->state = (UInt32)netView.state;
            setProperty("AirportRTW89Net80211StateProjectionUsed",
                        kOSBooleanTrue);
        } else {
            value->state = airportStateFromRTW(state.state);
            if (state.state == RTW88_STATE_CONNECTED && !effectiveConnected) {
                value->state = APPLE80211_S_INIT;
                setProperty("AirportRTW89Apple80211StateStaleRunSuppressed",
                            kOSBooleanTrue);
            }
        }
        setProperty("AirportRTW89Apple80211StateAssociationTruth",
                    effectiveConnected ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211StateRawRTW",
                    (uint64_t)state.state, 32);
        setProperty("AirportRTW89Apple80211StateReported",
                    (uint64_t)value->state, 32);
        setProperty("AirportRTW89StatusDiagInnerStateStructSize",
                    (uint64_t)sizeof(*value), 32);
        setProperty("AirportRTW89StatusDiagInnerStateVersion",
                    (uint64_t)value->version, 32);
        setProperty("AirportRTW89StatusDiagInnerStateValue",
                    (uint64_t)value->state, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_PHY_MODE: {
        apple80211_phymode_data *value = (apple80211_phymode_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->phy_mode = APPLE80211_MODE_11A | APPLE80211_MODE_11B |
                          APPLE80211_MODE_11G | APPLE80211_MODE_11N |
                          APPLE80211_MODE_11AC | APPLE80211_MODE_11AX;
        /* IO80211Reference reports IEEE80211_MODE_AUTO before association.  A
         * zero channel means RTW89 has no active BSS; treating that as 2 GHz
         * falsely reports 11n while the interface is still in INIT and can
         * make the legacy CoreWLAN qualification state inconsistent. */
        if (state.state == RTW88_STATE_IDLE || state.channel == 0)
            value->active_phy_mode = APPLE80211_MODE_AUTO;
        else
            value->active_phy_mode = state.channel > 14
                                         ? APPLE80211_MODE_11AC
                                         : APPLE80211_MODE_11N;
        static UInt32 preJoinPhyModeCount = 0;
        ++preJoinPhyModeCount;
        setProperty("AirportRTW89PreJoinPhyModeSeen", kOSBooleanTrue);
        setProperty("AirportRTW89PreJoinPhyModeCount",
                    (uint64_t)preJoinPhyModeCount, 32);
        setProperty("AirportRTW89PreJoinPhyModeMask",
                    (uint64_t)value->phy_mode, 32);
        setProperty("AirportRTW89PreJoinActivePhyMode",
                    (uint64_t)value->active_phy_mode, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_OP_MODE: {
        apple80211_opmode_data *value = (apple80211_opmode_data *)data;
        if (!value)
            return kIOReturnBadArgument;

        setProperty("AirportRTW89NativeDecisionOPModeSeen", kOSBooleanTrue);
        setProperty("AirportRTW89NativeDecisionOPModeInterfacePresent",
                    _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89NativeDecisionOPModeInterfacePointer",
                    (uint64_t)(uintptr_t)_iface, 64);
        if (_iface && _iface->getMetaClass())
            setProperty("AirportRTW89NativeDecisionOPModeInterfaceClass",
                        _iface->getMetaClass()->getClassName());
        setProperty("AirportRTW89NativeDecisionOPModeStructSize",
                    (uint64_t)sizeof(*value), 32);

        OSData *before = OSData::withBytes(value, sizeof(*value));
        if (before) {
            setProperty("AirportRTW89NativeDecisionOPModeRawBefore", before);
            before->release();
        }

        value->version = APPLE80211_VERSION;
        value->op_mode = APPLE80211_M_STA;

        OSData *after = OSData::withBytes(value, sizeof(*value));
        if (after) {
            setProperty("AirportRTW89NativeDecisionOPModeRawAfter", after);
            after->release();
        }
        setProperty("AirportRTW89NativeDecisionOPModeVersion",
                    (uint64_t)value->version, 32);
        setProperty("AirportRTW89NativeDecisionOPModeValue",
                    (uint64_t)value->op_mode, 32);
        setProperty("AirportRTW89NativeDecisionOPModeReturn",
                    (uint64_t)(uint32_t)kIOReturnSuccess, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_RSSI: {
        if (!effectiveConnected) {
            apple80211_rssi_data *value =
                (apple80211_rssi_data *)data;
            if (!value)
                return kIOReturnBadArgument;
            bzero(value, sizeof(*value));
            value->version = APPLE80211_VERSION;
            value->num_radios = 0;
            value->rssi_unit = APPLE80211_UNIT_DBM;
            setProperty("AirportRTW89NativeIOUCDisconnectedRSSIEmptySuccess",
                        kOSBooleanTrue);
            setProperty("AirportRTW89StatusDiagInnerRSSIReturn",
                        (uint64_t)kIOReturnSuccess, 32);
            return kIOReturnSuccess;
        }
        apple80211_rssi_data *value = (apple80211_rssi_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->num_radios = 1;
        value->rssi_unit = APPLE80211_UNIT_DBM;
        value->rssi[0] = state.rssi;
        value->aggregate_rssi = state.rssi;
        value->rssi_ext[0] = state.rssi;
        value->aggregate_rssi_ext = state.rssi;
        setProperty("AirportRTW89StatusDiagInnerRSSIReturn",
                    (uint64_t)kIOReturnSuccess, 32);
        setProperty("AirportRTW89StatusDiagInnerRSSIStructSize",
                    (uint64_t)sizeof(*value), 32);
        setProperty("AirportRTW89StatusDiagInnerRSSINumRadios",
                    (uint64_t)value->num_radios, 32);
        setProperty("AirportRTW89StatusDiagInnerRSSIUnit",
                    (uint64_t)value->rssi_unit, 32);
        setProperty("AirportRTW89StatusDiagInnerRSSI0",
                    (uint64_t)(SInt64)value->rssi[0], 64);
        setProperty("AirportRTW89StatusDiagInnerRSSIAggregate",
                    (uint64_t)(SInt64)value->aggregate_rssi, 64);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_NOISE: {
        apple80211_noise_data *value = (apple80211_noise_data *)data;
        if (!value)
            return kIOReturnBadArgument;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        if (!effectiveConnected) {
            value->num_radios = 0;
            value->noise_unit = APPLE80211_UNIT_DBM;
            setProperty("AirportRTW89NativeIOUCDisconnectedNoiseEmptySuccess",
                        kOSBooleanTrue);
            return kIOReturnSuccess;
        }
        value->num_radios = 1;
        value->noise_unit = APPLE80211_UNIT_DBM;
        value->noise[0] = -95;
        value->aggregate_noise = -95;
        value->noise_ext[0] = -95;
        value->aggregate_noise_ext = -95;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_PROTMODE: {
        if (!effectiveConnected)
            return 6;
        apple80211_protmode_data *value = (apple80211_protmode_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->protmode = APPLE80211_PROTMODE_OFF;
        value->threshold = 0;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_TXPOWER: {
        if (!effectiveConnected)
            return 6;
        apple80211_txpower_data *value = (apple80211_txpower_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->txpower_unit = APPLE80211_UNIT_PERCENT;
        /* RTW89 does not currently export the firmware-selected percentage.
         * Use a stable compatibility value, clearly marked as emulated. */
        value->txpower = 100;
        setProperty("AirportRTW89Apple80211TXPowerEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_RATE: {
        apple80211_rate_data *value = (apple80211_rate_data *)data;
        if (!value)
            return kIOReturnBadArgument;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        if (!effectiveConnected) {
            value->num_radios = 0;
            setProperty("AirportRTW89NativeIOUCDisconnectedRateEmptySuccess",
                        kOSBooleanTrue);
            return kIOReturnSuccess;
        }
        value->num_radios = 1;
        /* Until RTW89 rate-control telemetry is exported, give CoreWLAN a
         * non-zero legacy-compatible baseline rather than inventing MCS data. */
        value->rate[0] = 54;
        setProperty("AirportRTW89Apple80211RateEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_INT_MIT: {
        apple80211_intmit_data *value = (apple80211_intmit_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->int_mit = APPLE80211_INT_MIT_AUTO;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_RATE_SET: {
        if (!effectiveConnected)
            return 6;
        apple80211_rate_set_data *value = (apple80211_rate_set_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        static const UInt32 rates[] = {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108};
        value->num_rates = (UInt16)(sizeof(rates) / sizeof(rates[0]));
        for (UInt16 i = 0; i < value->num_rates; ++i) {
            value->rates[i].version = APPLE80211_VERSION;
            value->rates[i].rate = rates[i];
            value->rates[i].flags = 0;
        }
        setProperty("AirportRTW89Apple80211RateSetEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_MCS_INDEX_SET: {
        if (!effectiveConnected)
            return 6;
        apple80211_mcs_index_set_data *value =
            (apple80211_mcs_index_set_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->mcs_set_map[0] = 0xff; /* conservative one-stream MCS 0..7 */
        setProperty("AirportRTW89Apple80211MCSSetEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_VHT_MCS_INDEX_SET: {
        if (!effectiveConnected)
            return kIOReturnError;
        AirportRTW89VHTMCSIndexSetData *value =
            (AirportRTW89VHTMCSIndexSetData *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        /* VHT MCS map: one stream up to MCS9, remaining streams unsupported. */
        value->mcs_map = 0xfffe;
        setProperty("AirportRTW89Apple80211VHTMCSSetEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_MCS_VHT: {
        if (!effectiveConnected)
            return kIOReturnError;
        AirportRTW89MCSVHTData *value = (AirportRTW89MCSVHTData *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->index = 0;
        value->nss = 1;
        value->bw = 20;
        value->guard_interval = APPLE80211_GI_LONG;
        setProperty("AirportRTW89Apple80211MCSVHTEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_DEAUTH: {
        apple80211_deauth_data *value = (apple80211_deauth_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->deauth_reason = 0;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_TX_ANTENNA: {
        if (!effectiveConnected)
            return kIOReturnError;
        apple80211_antenna_data *value = (apple80211_antenna_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->num_radios = 1;
        value->antenna_index[0] = 1;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_ANTENNA_DIVERSITY: {
        apple80211_antenna_data *value = (apple80211_antenna_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->num_radios = 1;
        value->antenna_index[0] = 1;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_AP_IE_LIST: {
        /* IO80211Reference exposes the selected AP's RSN TLV to Apple's
         * supplicant through this request.  Preserve the caller-owned output
         * pointer/capacity and copy only the RSN IE. */
        apple80211_ap_ie_data *value = (apple80211_ap_ie_data *)data;
        if (!value || !value->ie_data || value->len == 0)
            return kIOReturnBadArgument;
        uint8_t rsn[APPLE80211_MAX_RSN_IE_LEN] = {};
        uint32_t rsnLen = 0;
        if (!_ieee80211->copyAppleRSNIE(rsn, sizeof(rsn), &rsnLen) ||
            rsnLen == 0 || rsnLen > value->len)
            return kIOReturnError;
        memcpy(value->ie_data, rsn, rsnLen);
        value->version = APPLE80211_VERSION;
        value->len = rsnLen;
        setProperty("AirportRTW89AppleRSNAPIEListSeen", kOSBooleanTrue);
        setProperty("AirportRTW89AppleRSNAPIEListLength",
                    (uint64_t)rsnLen, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_LINK_CHANGED_EVENT_DATA: {
        apple80211_link_changed_event_data *value =
            (apple80211_link_changed_event_data *)data;
        bzero(value, sizeof(*value));
        value->isLinkDown = !effectiveConnected;
        if (value->isLinkDown) {
            value->voluntary = false;
            value->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
        } else {
            value->rssi = (UInt32)state.rssi;
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_MCS: {
        apple80211_mcs_data *value = (apple80211_mcs_data *)data;
        if (!value)
            return kIOReturnBadArgument;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->index = 0;
        if (!effectiveConnected) {
            setProperty("AirportRTW89NativeIOUCDisconnectedMCSEmptySuccess",
                        kOSBooleanTrue);
            return kIOReturnSuccess;
        }
        setProperty("AirportRTW89Apple80211MCSEmulated", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_TX_NSS: {
        apple80211_tx_nss_data *value = (apple80211_tx_nss_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->nss = 1;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_NSS: {
        apple80211_nss_data *value = (apple80211_nss_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        value->nss = 1;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_WOW_PARAMETERS:
    case APPLE80211_IOC_IE:
    case APPLE80211_IOC_ROAM_PROFILE:
    case APPLE80211_IOC_BTCOEX_PROFILES:
        return kIOReturnError;
    case APPLE80211_IOC_BTCOEX_CONFIG: {
        UInt32 *words = (UInt32 *)data;
        for (UInt32 i = 0; i < 5; ++i)
            words[i] = _airportBtcConfigWords[i];
        words[0] = APPLE80211_VERSION;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_BTCOEX_MODE: {
        AirportRTW89VersionedScalar *value = (AirportRTW89VersionedScalar *)data;
        value->version = APPLE80211_VERSION;
        value->value = _airportBtcMode;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_BTCOEX_OPTIONS: {
        AirportRTW89VersionedScalar *value = (AirportRTW89VersionedScalar *)data;
        value->version = APPLE80211_VERSION;
        value->value = _airportBtcOptions;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_POWER: {
        apple80211_power_data *value = (apple80211_power_data *)data;
        UInt32 *words = (UInt32 *)data;
        if (!value)
            return kIOReturnBadArgument;

        setProperty("AirportRTW89NativeDecisionPowerSeen", kOSBooleanTrue);
        setProperty("AirportRTW89NativeDecisionPowerInterfacePresent",
                    _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89NativeDecisionPowerInterfacePointer",
                    (uint64_t)(uintptr_t)_iface, 64);
        if (_iface && _iface->getMetaClass())
            setProperty("AirportRTW89NativeDecisionPowerInterfaceClass",
                        _iface->getMetaClass()->getClassName());
        setProperty("AirportRTW89NativeDecisionPowerStructSize",
                    (uint64_t)sizeof(*value), 32);

        /* 0.3.49: raw POWER inner-buffer ABI audit.  The live Tahoe path
         * reaches this exact APPLE80211_IOC_POWER getter while bypassing both
         * AirportRTW performCommand() bridges.  Record the buffer exactly as
         * Apple supplied it, but do not alter behavior or returned layout. */
        setProperty("AirportRTW89PowerInnerStructSize",
                    (uint64_t)sizeof(*value), 32);
        setProperty("AirportRTW89PowerInnerPointer",
                    (uint64_t)(uintptr_t)data, 64);
        setProperty("AirportRTW89PowerInnerPointerAlignment",
                    (uint64_t)((uintptr_t)data & 0x0fU), 32);
        OSData *powerInnerBefore = OSData::withBytes(value, sizeof(*value));
        if (powerInnerBefore) {
            setProperty("AirportRTW89PowerInnerRawBefore", powerInnerBefore);
            powerInnerBefore->release();
        }

        OSData *powerBefore = OSData::withBytes(value, sizeof(*value));
        if (powerBefore) {
            setProperty("AirportRTW89NativeDecisionPowerRawBefore", powerBefore);
            powerBefore->release();
        }

        ++_airportPowerGetCount;
        setProperty("AirportRTW89Apple80211PowerGetCount",
                    (uint64_t)_airportPowerGetCount, 32);
        bzero(value, sizeof(*value));

        /* 0.2.165: report the user-visible logical Wi-Fi state.  RTW89
         * hardware intentionally remains initialized while logically OFF so
         * OFF -> ON can recover without a firmware restart. */
        const UInt32 reportedPower = _airportLogicalPowerOn
            ? APPLE80211_POWER_ON : APPLE80211_POWER_OFF;

        /* 0.2.101: now that IO80211Old's Apple80211 IOCTL transport reaches
         * this controller correctly, report the native legacy POWER structure
         * used by IO80211Reference: version 1, four radios, and the same logical
         * power state in every radio slot.  The old one-radio value was a
         * Tahoe compact-reader workaround from before the transport bridge. */
        value->version = APPLE80211_VERSION;
        value->num_radios = APPLE80211_MAX_RADIO;
        setProperty("AirportRTW89Apple80211PowerGetOneRadio",
                    kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211PowerGetFourRadios",
                    kOSBooleanTrue);
        for (UInt32 i = 0; i < APPLE80211_MAX_RADIO; ++i)
            value->power_state[i] = reportedPower;

        setProperty("AirportRTW89Apple80211ReportedPower",
                    (uint64_t)reportedPower, 8);
        setProperty("AirportRTW89Apple80211ReportedRadios",
                    (uint64_t)value->num_radios, 8);
        setProperty("AirportRTW89Apple80211GetPowerWord0",
                    (uint64_t)words[0], 32);
        setProperty("AirportRTW89Apple80211GetPowerWord1",
                    (uint64_t)words[1], 32);
        setProperty("AirportRTW89Apple80211GetPowerWord2",
                    (uint64_t)words[2], 32);

        /* 0.3.49: publish all six 32-bit words of the 24-byte native POWER
         * payload plus an independent raw-after snapshot. */
        setProperty("AirportRTW89PowerInnerWord0", (uint64_t)words[0], 32);
        setProperty("AirportRTW89PowerInnerWord1", (uint64_t)words[1], 32);
        setProperty("AirportRTW89PowerInnerWord2", (uint64_t)words[2], 32);
        setProperty("AirportRTW89PowerInnerWord3", (uint64_t)words[3], 32);
        setProperty("AirportRTW89PowerInnerWord4", (uint64_t)words[4], 32);
        setProperty("AirportRTW89PowerInnerWord5", (uint64_t)words[5], 32);
        OSData *powerInnerAfter = OSData::withBytes(value, sizeof(*value));
        if (powerInnerAfter) {
            setProperty("AirportRTW89PowerInnerRawAfter", powerInnerAfter);
            powerInnerAfter->release();
        }

        setProperty("AirportRTW89Apple80211GetPowerCompatLayout",
                    kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211GetPowerIO80211ReferenceLayout",
                    kOSBooleanTrue);

        OSData *powerAfter = OSData::withBytes(value, sizeof(*value));
        if (powerAfter) {
            setProperty("AirportRTW89NativeDecisionPowerRawAfter", powerAfter);
            powerAfter->release();
        }
        setProperty("AirportRTW89NativeDecisionPowerVersion",
                    (uint64_t)value->version, 32);
        setProperty("AirportRTW89NativeDecisionPowerNumRadios",
                    (uint64_t)value->num_radios, 32);
        setProperty("AirportRTW89NativeDecisionPowerState0",
                    (uint64_t)value->power_state[0], 32);
        setProperty("AirportRTW89NativeDecisionPowerState1",
                    (uint64_t)value->power_state[1], 32);
        setProperty("AirportRTW89NativeDecisionPowerState2",
                    (uint64_t)value->power_state[2], 32);
        setProperty("AirportRTW89NativeDecisionPowerState3",
                    (uint64_t)value->power_state[3], 32);
        setProperty("AirportRTW89NativeDecisionPowerReturn",
                    (uint64_t)(uint32_t)kIOReturnSuccess, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_ASSOCIATE_RESULT:
    case APPLE80211_IOC_ASSOCIATION_STATUS:
        /* 0.3.10 stack-safety: these hot association polling getters must not
         * allocate/publish IORegistry properties from airportGetBody. */
        return airportGetStackSafeHotStatus(requestNumber, data);
    case APPLE80211_IOC_AP_MODE: {
        apple80211_apmode_data *value = (apple80211_apmode_data *)data;
        value->version = APPLE80211_VERSION;
        value->apmode = APPLE80211_AP_MODE_INFRA;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_CHANNELS_INFO: {
        /* 0.3.8 Tahoe scan-list stability: the restored legacy stack issues
         * CHANNELS_INFO/207 on the primary en2 interface.  Reuse the same
         * canonical payload builder already used by the virtual/AWDL surface
         * instead of letting the request fall through to IO80211Old as -3903.
         * This is channel-capability publication only; it does not trigger a
         * scan, alter BSS retention, or change association/security state. */
        AirportRTW89ChannelsInfoData *value =
            reinterpret_cast<AirportRTW89ChannelsInfoData *>(data);
        if (!value)
            return kIOReturnBadArgument;
        airportFillChannelsInfo(value);
        static volatile UInt32 primaryChannelsInfoInnerCount = 0;
        const UInt32 count = __sync_add_and_fetch(
            &primaryChannelsInfoInnerCount, 1U);
        setProperty("AirportRTW89PrimaryChannelsInfoInnerSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PrimaryChannelsInfoInnerCount",
                    (uint64_t)count, 32);
        setProperty("AirportRTW89PrimaryChannelsInfoInnerNumChannels",
                    (uint64_t)value->num_chan_specs, 32);
        setProperty("AirportRTW89PrimaryChannelsInfoInnerReturn",
                    (uint64_t)kIOReturnSuccess, 32);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_SUPPORTED_CHANNELS:
    case APPLE80211_IOC_HW_SUPPORTED_CHANNELS: {
        apple80211_sup_channel_data *value = (apple80211_sup_channel_data *)data;
        if (!value)
            return kIOReturnBadArgument;

        /* 0.3.51: audit the exact controller-boundary buffer used by Apple's
         * live GET27/HW254 marshaller.  Interface identity is recorded one layer
         * above in apple80211Request(), where the IO80211Interface * argument is
         * actually in scope.  This remains telemetry-only. */
        setProperty("AirportRTW89Get27DataPointer",
                    (uint64_t)(uintptr_t)data, 64);
        setProperty("AirportRTW89Get27DataAlignment",
                    (uint64_t)((uintptr_t)data & 0x0fU), 32);
        setProperty("AirportRTW89Get27ControllerStructSize",
                    (uint64_t)sizeof(*value), 32);
        if (OSData *rawBefore = OSData::withBytes(value, sizeof(*value))) {
            setProperty("AirportRTW89Get27RawBefore", rawBefore);
            rawBefore->release();
        }

        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        static const UInt32 channels[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            36, 40, 44, 48, 149, 153, 157, 161, 165
        };
        value->num_channels = (UInt32)(sizeof(channels) / sizeof(channels[0]));
        for (UInt32 i = 0; i < value->num_channels; i++) {
            value->supported_channels[i].version = APPLE80211_VERSION;
            value->supported_channels[i].channel = channels[i];
            value->supported_channels[i].flags = airportChannelFlags(channels[i]);
        }

        /* 0.2.129 diagnostic-only: CoreWLAN currently reports an empty
         * supportedWLANChannels() set even though request history proves GET
         * APPLE80211_IOC_SUPPORTED_CHANNELS reaches this handler.  Record the
         * exact inner structure produced here; the live interface
         * performCommand() probe records whether Apple's superclass then
         * copies the same structure to the userspace ioctl buffer. */
        static UInt32 supportedChannelsInnerSequence = 0;
        ++supportedChannelsInnerSequence;
        setProperty("AirportRTW89PreJoinSupportedChannelsSeen", kOSBooleanTrue);
        setProperty("AirportRTW89PreJoinSupportedChannelsCount",
                    (uint64_t)supportedChannelsInnerSequence, 32);
        setProperty("AirportRTW89PreJoinSupportedChannelsRequest",
                    (uint64_t)(UInt32)requestNumber, 32);
        setProperty("AirportRTW89PreJoinSupportedChannelsNumChannels",
                    (uint64_t)value->num_channels, 32);
        setProperty("AirportRTW89Get27InnerSeen", kOSBooleanTrue);
        setProperty("AirportRTW89Get27InnerSequence",
                    (uint64_t)supportedChannelsInnerSequence, 32);
        setProperty("AirportRTW89Get27InnerRequest",
                    (uint64_t)(UInt32)requestNumber, 32);
        setProperty("AirportRTW89Get27InnerStructSize",
                    (uint64_t)sizeof(*value), 32);
        setProperty("AirportRTW89Get27InnerVersion",
                    (uint64_t)value->version, 32);
        setProperty("AirportRTW89Get27InnerNumChannels",
                    (uint64_t)value->num_channels, 32);
        if (value->num_channels != 0) {
            const UInt32 last = value->num_channels - 1;
            setProperty("AirportRTW89Get27InnerFirstChannel",
                        (uint64_t)value->supported_channels[0].channel, 32);
            setProperty("AirportRTW89Get27InnerFirstFlags",
                        (uint64_t)value->supported_channels[0].flags, 32);
            setProperty("AirportRTW89Get27InnerLastChannel",
                        (uint64_t)value->supported_channels[last].channel, 32);
            setProperty("AirportRTW89Get27InnerLastFlags",
                        (uint64_t)value->supported_channels[last].flags, 32);
        }

        if (OSData *rawAfter = OSData::withBytes(value, sizeof(*value))) {
            setProperty("AirportRTW89Get27RawAfter", rawAfter);
            rawAfter->release();
        }
        static const UInt32 auditEntries[] = {0, 1, 2, 13, 14, 21};
        for (UInt32 j = 0; j < sizeof(auditEntries) / sizeof(auditEntries[0]); ++j) {
            const UInt32 idx = auditEntries[j];
            if (idx >= value->num_channels)
                continue;
            char key[64] = {};
            snprintf(key, sizeof(key), "AirportRTW89Get27Entry%02uRaw", idx);
            if (OSData *entry = OSData::withBytes(&value->supported_channels[idx],
                                                  sizeof(apple80211_channel))) {
                setProperty(key, entry);
                entry->release();
            }
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_LOCALE: {
        apple80211_locale_data *value = (apple80211_locale_data *)data;
        value->version = APPLE80211_VERSION;
        value->locale = APPLE80211_LOCALE_FCC;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_DRIVER_VERSION:
    case APPLE80211_IOC_HARDWARE_VERSION: {
        apple80211_version_data *value = (apple80211_version_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        char firmwareText[sizeof(value->string)] = {};
        const char *text = state.chip_name;
        if (requestNumber == APPLE80211_IOC_DRIVER_VERSION) {
            /* System Information labels this Apple80211 response as the
             * firmware version.  Report the version parsed from the active
             * Realtek firmware header instead of an AirportRTW89 experiment
             * or driver-build label. */
            const UInt32 firmwareMajor = state.fw_version >> 8;
            const UInt32 firmwareMinor = state.fw_version & 0xff;
            const UInt32 firmwareSub = state.fw_sub_version;
            snprintf(firmwareText, sizeof(firmwareText),
                     "%u.%u.%u", firmwareMajor, firmwareMinor, firmwareSub);
            text = firmwareText;
        }
        strlcpy(value->string, text, sizeof(value->string));
        value->string_len = (UInt16)airportBoundedStringLength(
            value->string, sizeof(value->string));
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_RSN_IE: {
        apple80211_rsn_ie_data *value = (apple80211_rsn_ie_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;
        uint32_t rsnLen = 0;
        if (!_ieee80211->copyAppleRSNIE(value->ie, sizeof(value->ie),
                                         &rsnLen))
            return kIOReturnError;
        value->len = (UInt16)rsnLen;
        setProperty("AirportRTW89AppleRSNIEGetSeen", kOSBooleanTrue);
        setProperty("AirportRTW89AppleRSNIEGetLength",
                    (uint64_t)rsnLen, 16);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_COUNTRY_CODE: {
        apple80211_country_code_data *value =
            (apple80211_country_code_data *)data;
        bzero(value, sizeof(*value));
        value->version = APPLE80211_VERSION;

        /* 0.2.131: country publication no longer depends on this legacy GET.
         * Keep GET 51 correct for older framework paths, but share the same
         * resolver used at startup/link/scan-cache updates on Tahoe. */
        airportRefreshCountryCode("legacy-get51", false);
        value->cc[0] = (u_int8_t)_airportCountryCode[0];
        value->cc[1] = (u_int8_t)_airportCountryCode[1];
        static UInt32 preJoinCountryCodeCount = 0;
        ++preJoinCountryCodeCount;
        char preJoinCountry[3] = { (char)value->cc[0], (char)value->cc[1], '\0' };
        setProperty("AirportRTW89PreJoinCountryCodeSeen", kOSBooleanTrue);
        setProperty("AirportRTW89PreJoinCountryCodeCount",
                    (uint64_t)preJoinCountryCodeCount, 32);
        setProperty("AirportRTW89PreJoinCountryCode", preJoinCountry);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_POWERSAVE: {
        apple80211_powersave_data *value = (apple80211_powersave_data *)data;
        value->version = APPLE80211_VERSION;
        value->powersave_level = APPLE80211_POWERSAVE_MODE_DISABLED;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_RADIO_INFO: {
        apple80211_radio_info_data *value = (apple80211_radio_info_data *)data;
        value->version = APPLE80211_VERSION;
        value->count = 1;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_MAX_NSS_FOR_AP:
        /* 0.2.104 diagnostic only. Tahoe/CoreWLAN probes request 259 on this
         * machine, but the bundled headers expose only the request number and
         * not a trustworthy payload structure. Keep the existing unsupported
         * behavior while making the probe explicit; do not touch unknown
         * caller memory until its ABI is established. */
        setProperty("AirportRTW89Apple80211MaxNSSForAPGetSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Apple80211MaxNSSForAPDataPresent",
                    data ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211LastUnsupportedGetRequest",
                    (uint64_t)requestNumber, 32);
        return kIOReturnUnsupported;
    case APPLE80211_IOC_LAST_BCAST_SCAN_TIME: {
        /* 0.2.199 diagnostic only.  The public/private header surface names
         * request 110 but does not expose a trustworthy payload structure.
         * Record whether Apple's superclass actually dispatches it to the
         * controller and its timing relative to the most recent real scan,
         * but preserve the pre-existing unsupported return and never write to
         * unknown caller memory. */
        uint64_t nowNs = 0;
        absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
        const UInt64 nowMS = nowNs / 1000000ULL;
        static UInt32 inner110Count = 0;
        ++inner110Count;
        setProperty("AirportRTW89LastBcastScanTimeInnerSeen", kOSBooleanTrue);
        setProperty("AirportRTW89LastBcastScanTimeInnerCount",
                    (uint64_t)inner110Count, 32);
        setProperty("AirportRTW89LastBcastScanTimeInnerDataPresent",
                    data ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89LastBcastScanTimeInnerNowMonotonicMS",
                    nowMS, 64);
        setProperty("AirportRTW89LastBcastScanTimeInnerLastCompletionMS",
                    _airportLastRealScanCompletionMonotonicMS, 64);
        setProperty("AirportRTW89LastBcastScanTimeInnerDeltaFromCompletionMS",
                    nowMS >= _airportLastRealScanCompletionMonotonicMS
                        ? nowMS - _airportLastRealScanCompletionMonotonicMS
                        : 0,
                    64);
        setProperty("AirportRTW89LastBcastScanTimePayloadUnknown",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Apple80211LastUnsupportedGetRequest",
                    (uint64_t)requestNumber, 32);
        return kIOReturnUnsupported;
    }
    case APPLE80211_IOC_ROAM_THRESH: {
        /* 0.2.97: airportd/CoreWLAN probes ROAM_THRESH during interface
         * qualification.  0.2.96 recorded request 80 as the final GET and
         * returned kIOReturnUnsupported, after which CoreWLAN exposed no
         * interfaces.  Match IO80211Reference's known-compatible response for
         * this ABI: threshold=100, count=0.  This request carries no version
         * field in apple80211_roam_threshold_data. */
        apple80211_roam_threshold_data *value =
            (apple80211_roam_threshold_data *)data;
        bzero(value, sizeof(*value));
        value->threshold = 100;
        value->count = 0;
        setProperty("AirportRTW89Apple80211RoamThreshGetSeen",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Apple80211RoamThreshThreshold",
                    (uint64_t)value->threshold, 32);
        setProperty("AirportRTW89Apple80211RoamThreshCount",
                    (uint64_t)value->count, 32);
        /* Clear the checkpoint here; a later unsupported GET in the same
         * airportd qualification pass will repopulate it. */
        setProperty("AirportRTW89Apple80211LastUnsupportedGetRequest",
                    (uint64_t)0, 32);
        return kIOReturnSuccess;
    }
    default:
        /* Keep the next qualification blocker visible if airportd advances
         * beyond ROAM_THRESH and encounters another unsupported GET. */
        setProperty("AirportRTW89Apple80211LastUnsupportedGetRequest",
                    (uint64_t)requestNumber, 32);
        return kIOReturnUnsupported;
    }
}

IOReturn RTW88PCIDevice::airportSyntheticAssociateDiagnostic(
    const RTW88SyntheticAssociateArgs &args)
{
    /* This selector is intentionally explicit and one-shot.  It exists to
     * answer a single diagnostic question: once we cross the missing SET20
     * boundary, can the existing RTW89 + Apple-RSN path advance to EAPOL?
     * Never infer an SSID from the scan list and never accept a password/PMK. */
    size_t ssidLength = 0;
    while (ssidLength < sizeof(args.ssid) && args.ssid[ssidLength] != '\0')
        ++ssidLength;
    if (ssidLength == 0 || ssidLength > APPLE80211_MAX_SSID_LEN)
        return kIOReturnBadArgument;

    if (args.use_bssid > 1)
        return kIOReturnBadArgument;
    if (args.use_bssid) {
        static const UInt8 zeroBSSID[6] = {};
        if (memcmp(args.bssid, zeroBSSID, sizeof(zeroBSSID)) == 0)
            return kIOReturnBadArgument;
    }

    apple80211_assoc_data assoc = {};
    assoc.version = APPLE80211_VERSION;
    assoc.ad_mode = APPLE80211_AP_MODE_INFRA;
    assoc.ad_auth_lower = APPLE80211_AUTHTYPE_OPEN;
    assoc.ad_auth_upper = APPLE80211_AUTHTYPE_WPA2_PSK;
    assoc.ad_ssid_len = (u_int32_t)ssidLength;
    bcopy(args.ssid, assoc.ad_ssid, ssidLength);
    if (args.use_bssid)
        bcopy(args.bssid, assoc.ad_bssid.octet, sizeof(args.bssid));

    const UInt32 sequence =
        __sync_add_and_fetch(&_airportSyntheticAssociateCount, 1U);
    setProperty("AirportRTW89SyntheticSET20Experiment", kOSBooleanTrue);
    setProperty("AirportRTW89SyntheticSET20Count", (uint64_t)sequence, 32);
    setProperty("AirportRTW89SyntheticSET20SSIDLength",
                (uint64_t)ssidLength, 32);
    setProperty("AirportRTW89SyntheticSET20BSSIDPresent",
                args.use_bssid ? kOSBooleanTrue : kOSBooleanFalse);
    setProperty("AirportRTW89SyntheticSET20AuthLower",
                (uint64_t)assoc.ad_auth_lower, 16);
    setProperty("AirportRTW89SyntheticSET20AuthUpper",
                (uint64_t)assoc.ad_auth_upper, 16);
    setProperty("AirportRTW89SyntheticSET20CredentialBytes", (uint64_t)0, 32);
    setProperty("AirportRTW89SyntheticSET20AppleRSNExpected", kOSBooleanTrue);
    /* Apple OSS EAPOLControl state/mode is userspace control state.  The
     * current driver trace does not establish a kernel selector carrying
     * those values, so this experiment deliberately does not fabricate an
     * 802.1X state.  It crosses only the missing SET20 boundary and observes
     * the real Apple-RSN/EAPOL behavior that follows. */
    setProperty("AirportRTW89Userspace8021XStateSpoofed", kOSBooleanFalse);
    setProperty("AirportRTW89AppleRSNBoundaryDiagnostic", kOSBooleanTrue);
    setProperty("AirportRTW89SyntheticSET20Dispatching", kOSBooleanTrue);

    /* Tag only this synchronous thread.  A real Apple SET20 arriving on
     * another thread remains classified as real. */
    _airportSyntheticAssociateThread = current_thread();
    const IOReturn result = airportSet(APPLE80211_IOC_ASSOCIATE, &assoc, _iface);
    _airportSyntheticAssociateThread = THREAD_NULL;

    setProperty("AirportRTW89SyntheticSET20Dispatching", kOSBooleanFalse);
    setProperty("AirportRTW89SyntheticSET20DispatchReturn",
                (uint64_t)(uint32_t)result, 32);
    setProperty("AirportRTW89SyntheticSET20EnteredCommonBody", kOSBooleanTrue);
    return result;
}

SInt32 RTW88PCIDevice::airportSet(unsigned int requestNumber, void *data,
                                  IO80211Interface *interface)
{
    const bool securityControlRequest =
        requestNumber == APPLE80211_IOC_AUTH_TYPE ||
        requestNumber == APPLE80211_IOC_CIPHER_KEY ||
        requestNumber == APPLE80211_IOC_ASSOCIATE ||
        requestNumber == APPLE80211_IOC_DISASSOCIATE ||
        requestNumber == APPLE80211_IOC_RSN_IE;
    if (securityControlRequest) {
        const UInt64 nowMS = airportSecurityControlMonotonicMS();
        setProperty("AirportRTW89SecurityControlLastSetRequest",
                    (uint64_t)requestNumber, 32);
        setProperty("AirportRTW89SecurityControlLastSetMS",
                    (uint64_t)nowMS, 64);
        switch (requestNumber) {
        case APPLE80211_IOC_AUTH_TYPE: {
            static volatile UInt32 count = 0;
            const UInt32 sequence = __sync_add_and_fetch(&count, 1U);
            setProperty("AirportRTW89SecurityControlSET2Count",
                        (uint64_t)sequence, 32);
            setProperty("AirportRTW89SecurityControlSET2LastMS",
                        (uint64_t)nowMS, 64);
            break;
        }
        case APPLE80211_IOC_CIPHER_KEY: {
            static volatile UInt32 count = 0;
            const UInt32 sequence = __sync_add_and_fetch(&count, 1U);
            setProperty("AirportRTW89SecurityControlSET3Count",
                        (uint64_t)sequence, 32);
            setProperty("AirportRTW89SecurityControlSET3LastMS",
                        (uint64_t)nowMS, 64);
            break;
        }
        case APPLE80211_IOC_ASSOCIATE: {
            static volatile UInt32 count = 0;
            const UInt32 sequence = __sync_add_and_fetch(&count, 1U);
            setProperty("AirportRTW89SecurityControlSET20Count",
                        (uint64_t)sequence, 32);
            if (sequence == 1U)
                setProperty("AirportRTW89SecurityControlSET20FirstMS",
                            (uint64_t)nowMS, 64);
            setProperty("AirportRTW89SecurityControlSET20LastMS",
                        (uint64_t)nowMS, 64);
            break;
        }
        case APPLE80211_IOC_DISASSOCIATE: {
            static volatile UInt32 count = 0;
            const UInt32 sequence = __sync_add_and_fetch(&count, 1U);
            setProperty("AirportRTW89SecurityControlSET22Count",
                        (uint64_t)sequence, 32);
            if (sequence == 1U)
                setProperty("AirportRTW89SecurityControlSET22FirstMS",
                            (uint64_t)nowMS, 64);
            setProperty("AirportRTW89SecurityControlSET22LastMS",
                        (uint64_t)nowMS, 64);
            break;
        }
        case APPLE80211_IOC_RSN_IE: {
            static volatile UInt32 count = 0;
            const UInt32 sequence = __sync_add_and_fetch(&count, 1U);
            setProperty("AirportRTW89SecurityControlSET46Count",
                        (uint64_t)sequence, 32);
            setProperty("AirportRTW89SecurityControlSET46LastMS",
                        (uint64_t)nowMS, 64);
            break;
        }
        default:
            break;
        }
    }

    switch (requestNumber) {
    case APPLE80211_IOC_SCAN_REQ:
    case APPLE80211_IOC_SCAN_REQ_MULTIPLE: {
        if (!_airportLogicalPowerOn) {
            setProperty("AirportRTW89ScanRejectedWhileUserPowerOff",
                        kOSBooleanTrue);
            return kIOReturnNotReady;
        }
        ++_airportScanSetCount;
        setProperty("AirportRTW89Apple80211ScanSetCount",
                    (uint64_t)_airportScanSetCount, 32);
        setProperty("AirportRTW89Apple80211ScanSetRequest",
                    (uint64_t)requestNumber, 32);

        /* Diagnostics only: capture the bounded target fields Tahoe supplied
         * with a legacy single scan.  Do not retain them in controller state
         * and do not alter scan/result behavior. */
        if (requestNumber == APPLE80211_IOC_SCAN_REQ && data) {
            const apple80211_scan_data *scan =
                static_cast<const apple80211_scan_data *>(data);
            const UInt32 ssidLength = scan->ssid_len;
            setProperty("AirportRTW89ScanRequestSSIDLength",
                        (uint64_t)ssidLength, 32);
            if (ssidLength > 0 && ssidLength <= APPLE80211_MAX_SSID_LEN)
                setProperty("AirportRTW89ScanRequestSSID",
                            const_cast<u_int8_t *>(scan->ssid), ssidLength);
            setProperty("AirportRTW89ScanRequestBSSID",
                        const_cast<u_char *>(scan->bssid.octet),
                        APPLE80211_ADDR_LEN);
            setProperty("AirportRTW89ScanRequestType",
                        (uint64_t)scan->scan_type, 32);
            setProperty("AirportRTW89ScanRequestChannelCount",
                        (uint64_t)scan->num_channels, 32);
        }

        /* 0.2.118: keep the last completed Apple-facing scan cache while a
         * new asynchronous RTW89 scan is in progress. IO80211Reference starts a
         * cache background scan without freeing its existing node tree; its
         * GET SCAN_RESULT path can therefore continue serving the previous
         * completed results until fresh nodes arrive. AirportRTW89 used to
         * call airportResetScanCache() here, creating a multi-second empty
         * window because the manual 39-channel scan finishes asynchronously.
         * Tahoe airportd often completes its high-level scan request during
         * exactly that window. Rewind only the iterator; airportRefreshScanCache()
         * atomically replaces the cache when the real scan completes. */
        UInt32 retainedBSSCount = 0;
        if (_airportLock) {
            IOLockLock(_airportLock);
            retainedBSSCount = _airportBSSCount;
            _airportBSSIndex = 0;
            if (++_airportScanIterationSerial == 0U)
                _airportScanIterationSerial = 1U;
            IOLockUnlock(_airportLock);
        }
        setProperty("AirportRTW89Apple80211ScanRequestCacheRetained", true);
        setProperty("AirportRTW89Apple80211ScanRequestRetainedBSSCount",
                    (uint64_t)retainedBSSCount, 32);
        setProperty("AirportRTW89Apple80211ScanRequestCacheIndexRewound", true);
        setProperty("AirportRTW89Apple80211ScanRequestIntelCacheParity", true);

        RTW88StateResult scanRequestState = {};
        const bool haveScanRequestState =
            _ieee80211->cmdGetState(&scanRequestState) == kIOReturnSuccess;

        /* 0.2.186: permanent cache-only associated scans made the network
         * list inevitably stale.  Start a bounded rotating RF slice instead.
         * RTW88IEEE80211 limits Apple-originated connected scans to six
         * channels and returns home between channels, while private cmdScan()
         * callers retain the full-scan default. */
        const bool associationActive =
            _ieee80211->hasActiveAssociation();
        const bool boundedAssociatedScan =
            haveScanRequestState && associationActive &&
            scanRequestState.state == RTW88_STATE_CONNECTED;
        setProperty("AirportRTW89AssociatedScanAssociationTruth",
                    associationActive ? kOSBooleanTrue : kOSBooleanFalse);
        if (haveScanRequestState &&
            scanRequestState.state == RTW88_STATE_CONNECTED &&
            !associationActive) {
            static UInt32 staleAssociatedScanCount = 0;
            ++staleAssociatedScanCount;
            setProperty("AirportRTW89AssociatedScanStaleConnectedSuppressed",
                        kOSBooleanTrue);
            setProperty("AirportRTW89AssociatedScanStaleConnectedCount",
                        (uint64_t)staleAssociatedScanCount, 32);
        }

        setProperty("AirportRTW89AssociatedScanCacheOnly",
                    kOSBooleanFalse);
        setProperty("AirportRTW89AssociatedScanRFStartSuppressed",
                    kOSBooleanFalse);
        setProperty("AirportRTW89AssociatedScanBoundedRFRequested",
                    boundedAssociatedScan ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89AssociatedScanRetainedBSSCount",
                    (uint64_t)retainedBSSCount, 32);

        /* 0.2.227: disconnected scans no longer use the historical 100 ms
         * fake completion edge.  Mark the transaction before cmdScan() so a
         * stale timer cannot race the new scan.  Associated bounded scans keep
         * the old short handoff unchanged. */
        _airportDisconnectedScanCompletionPending = !associationActive;
        setProperty("AirportRTW89DisconnectedScanCompletionPending",
                    _airportDisconnectedScanCompletionPending
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89DisconnectedScanSingleCompletionOwner",
                    kOSBooleanTrue);
        if (_airportDisconnectedScanCompletionPending &&
            _airportScanDoneTimer) {
            _airportScanDoneTimer->cancelTimeout();
            _airportScanDoneTimerPending = false;
            setProperty("AirportRTW89IntelScanDoneTimerPending",
                        kOSBooleanFalse);
            setProperty("AirportRTW89IntelScanDoneTimerArmed",
                        kOSBooleanFalse);
            setProperty("AirportRTW89DisconnectedEarlyScanDoneSuppressed",
                        kOSBooleanTrue);
        }

        _airportScanObserved = true;
        IOReturn backendResult =
            _ieee80211->cmdScan(boundedAssociatedScan);

        const bool coalescedBusyScan =
            backendResult == kIOReturnBusy && haveScanRequestState &&
            scanRequestState.state == RTW88_STATE_SCANNING;
        const IOReturn result =
            coalescedBusyScan ? kIOReturnSuccess : backendResult;

        setProperty("AirportRTW89Apple80211ScanSetBackendReturn",
                    (uint64_t)(uint32_t)backendResult, 32);
        setProperty("AirportRTW89Apple80211ScanSetReturn",
                    (uint64_t)(uint32_t)result, 32);
        setProperty("AirportRTW89ScanBusyCoalesced",
                    coalescedBusyScan ? kOSBooleanTrue : kOSBooleanFalse);
        if (coalescedBusyScan) {
            static UInt32 busyCoalescedCount = 0;
            ++busyCoalescedCount;
            setProperty("AirportRTW89ScanBusyCoalescedCount",
                        (uint64_t)busyCoalescedCount, 32);
            setProperty("AirportRTW89ScanObservedPreservedOnBusy",
                        kOSBooleanTrue);
        }

        if (result == kIOReturnSuccess && _airportScanDoneTimer &&
            !_airportDisconnectedScanCompletionPending) {
            /* Associated bounded scans retain the historical short SCAN_DONE
             * handoff.  Disconnected scans are completed only at genuine RF
             * completion by airportPollState(). */
            _airportScanDoneTimer->cancelTimeout();
            _airportScanDoneTimerPending = true;
            _airportScanDoneTimer->setTimeoutMS(100);
            setProperty("AirportRTW89IntelScanDoneTimerArmed", kOSBooleanTrue);
            setProperty("AirportRTW89IntelScanDoneTimerPending", kOSBooleanTrue);
            setProperty("AirportRTW89IntelScanDoneTimerDelayMS",
                        (uint64_t)100, 32);
        } else if (result == kIOReturnSuccess &&
                   _airportDisconnectedScanCompletionPending) {
            setProperty("AirportRTW89IntelScanDoneTimerArmed",
                        kOSBooleanFalse);
            setProperty("AirportRTW89IntelScanDoneTimerPending",
                        kOSBooleanFalse);
            setProperty("AirportRTW89DisconnectedRealCompletionRequired",
                        kOSBooleanTrue);
        } else if (result != kIOReturnSuccess) {
            if (_airportPowerOnFullScanNotifyPending) {
                _airportPowerOnFullScanNotifyPending = false;
                setProperty("AirportRTW89PowerOnFullScanNotifyPending",
                            kOSBooleanFalse);
                setProperty("AirportRTW89PowerOnFullScanStartFailed",
                            kOSBooleanTrue);
            }
            /* Only a real start failure clears completion tracking.  A Busy
             * return from an already-running scan was converted to success
             * above and deliberately preserves _airportScanObserved so the
             * real completion can refresh the final Apple-facing cache. */
            _airportScanObserved = false;
            _airportDisconnectedScanCompletionPending = false;
            setProperty("AirportRTW89DisconnectedScanCompletionPending",
                        kOSBooleanFalse);
            if (_airportScanDoneTimer)
                _airportScanDoneTimer->cancelTimeout();
            _airportScanDoneTimerPending = false;
            setProperty("AirportRTW89IntelScanDoneTimerArmed", kOSBooleanFalse);
            setProperty("AirportRTW89IntelScanDoneTimerPending", kOSBooleanFalse);
        }
        return result;
    }
    case APPLE80211_IOC_POWER: {
        const UInt32 powerEventSequence = ++_airportPowerEventSequence;
        setProperty("AirportRTW89PowerEventSequence",
                    (uint64_t)_airportPowerEventSequence, 32);
        setProperty("AirportRTW89Apple80211InnerPowerEventSequence",
                    (uint64_t)powerEventSequence, 32);
        setProperty("AirportRTW89Apple80211InnerPowerLogicalAtEntry",
                    _airportLogicalPowerOn ? kOSBooleanTrue : kOSBooleanFalse);

        ++_airportPowerSetCount;
        setProperty("AirportRTW89Apple80211PowerSetCount",
                    (uint64_t)_airportPowerSetCount, 32);

        apple80211_power_data *value = (apple80211_power_data *)data;
        if (!value)
            return kIOReturnBadArgument;

        const UInt32 *rawPowerWords = (const UInt32 *)data;
        const UInt32 firstWord = rawPowerWords[0];
        for (UInt32 i = 0; i < 6; ++i) {
            char property[64] = {};
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211SetRawWord%u", (unsigned)i);
            setProperty(property, (uint64_t)rawPowerWords[i], 32);
        }

        /* 0.2.170: use IO80211Reference's POWER-state model.  The persistent
         * logical state is changed only when Apple supplies at least one
         * radio entry.  num_radios == 0 is a successful no-op; it is not a
         * scalar OFF value, not a toggle, and not a reason to consult the
         * always-live transport latches.
         *
         * Upstream IO80211Reference does exactly the same structural check in
         * setPOWER(): if (pd->num_radios > 0) { ... power_state =
         * pd->power_state[0]; }.  GET POWER reports the stored state in four
         * radio slots.  RTW89 keeps its firmware/Apple transport alive as a
         * Tahoe-specific restart-safety adaptation, but that transport state
         * never becomes user-power authority. */
        IO80211Interface *powerInterface = interface ? interface : _iface;
        const bool interfaceUserPower = powerInterface
            ? powerInterface->poweredOnByUser() : false;
        const bool interfaceSystemEnable = powerInterface
            ? powerInterface->enabledBySystem() : false;
        const bool hasRadioState = value->num_radios > 0;
        const bool zeroRadioNoOp = !hasRadioState;

        /* 0.3.54: Tahoe's user-OFF transition reaches this hidden inner POWER
         * callback with a completely zeroed apple80211_power_data object after
         * IO80211 has already moved the live interface's poweredOnByUser()
         * latch to false.  System-enable and controller-enable remain true
         * because AirportRTW deliberately keeps the Apple control transport
         * alive so a later ON request can still arrive.
         *
         * 0.3.53 telemetry proved the exact signature on a real OFF request:
         *   num_radios == 0, userPower == false, systemEnable == true,
         *   controller enabled == true.
         *
         * Preserve IO80211Reference's zero-radio no-op semantics for every other
         * shape.  Only this independently corroborated Tahoe OFF signature is
         * promoted to logical user-power authority.  In particular, never use
         * userPower == true as a zero-radio ON signal: the driver itself pins
         * the base IO80211 transport latch true for restart safety. */
        const bool zeroRadioFrameworkOff =
            zeroRadioNoOp && !interfaceUserPower && interfaceSystemEnable &&
            _enabled;
        const UInt32 requestedPower = hasRadioState
            ? (value->power_state[0] == 0
                   ? APPLE80211_POWER_OFF
                   : APPLE80211_POWER_ON)
            : (zeroRadioFrameworkOff
                   ? APPLE80211_POWER_OFF
                   : (_airportLogicalPowerOn
                          ? APPLE80211_POWER_ON
                          : APPLE80211_POWER_OFF));

        setProperty("AirportRTW89PowerStateModelIO80211Reference",
                    kOSBooleanTrue);
        setProperty("AirportRTW89PowerStateStored",
                    _airportLogicalPowerOn ? (uint64_t)APPLE80211_POWER_ON
                                           : (uint64_t)APPLE80211_POWER_OFF,
                    8);
        setProperty("AirportRTW89Apple80211SetPowerExplicit",
                    hasRadioState ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerAmbiguous",
                    (zeroRadioNoOp && !zeroRadioFrameworkOff)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerIO80211ReferenceNoOp",
                    (zeroRadioNoOp && !zeroRadioFrameworkOff)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerZeroRadioIgnored",
                    (zeroRadioNoOp && !zeroRadioFrameworkOff)
                        ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ZeroRadioFrameworkOffSeen",
                    zeroRadioFrameworkOff ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89ZeroRadioFrameworkOffAccepted",
                    kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerBufferNormalized",
                    kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211InnerPowerDecodedRequested",
                    (uint64_t)requestedPower, 32);

        const UInt32 entryFlags =
            (interfaceUserPower ? 2U : 0U) |
            (interfaceSystemEnable ? 4U : 0U) |
            (_enabled ? 8U : 0U) |
            (zeroRadioNoOp ? 32U : 0U) |
            (hasRadioState ? 64U : 0U) |
            128U | /* IO80211Reference state-model marker. */
            (zeroRadioFrameworkOff ? 256U : 0U);

        const UInt32 innerPowerSlot = (_airportPowerSetCount - 1U) & 3U;
        setProperty("AirportRTW89Apple80211InnerPowerSequence",
                    (uint64_t)_airportPowerSetCount, 32);
        setProperty("AirportRTW89Apple80211InnerPowerLastSlot",
                    (uint64_t)innerPowerSlot, 32);
        for (UInt32 i = 0; i < 6; ++i) {
            char property[80] = {};
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211InnerPowerSlot%uRawWord%u",
                     (unsigned)innerPowerSlot, (unsigned)i);
            setProperty(property, (uint64_t)rawPowerWords[i], 32);
        }
        {
            char property[80] = {};
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211InnerPowerSlot%uRequested",
                     (unsigned)innerPowerSlot);
            setProperty(property, (uint64_t)requestedPower, 32);
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211InnerPowerSlot%uFlags",
                     (unsigned)innerPowerSlot);
            setProperty(property, (uint64_t)entryFlags, 32);
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211InnerPowerSlot%uUserPower",
                     (unsigned)innerPowerSlot);
            setProperty(property, interfaceUserPower ? kOSBooleanTrue
                                                     : kOSBooleanFalse);
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211InnerPowerSlot%uSystemEnable",
                     (unsigned)innerPowerSlot);
            setProperty(property, interfaceSystemEnable ? kOSBooleanTrue
                                                        : kOSBooleanFalse);
            snprintf(property, sizeof(property),
                     "AirportRTW89Apple80211InnerPowerSlot%uControllerEnabled",
                     (unsigned)innerPowerSlot);
            setProperty(property, _enabled ? kOSBooleanTrue : kOSBooleanFalse);
        }

        if (_airportPowerSetCount <= 8) {
            UInt32 *entry = _airportPowerSetHistory[_airportPowerSetCount - 1];
            for (UInt32 i = 0; i < 6; ++i)
                entry[i] = rawPowerWords[i];
            entry[6] = requestedPower;
            entry[7] = entryFlags;
        }
        OSData *powerHistory = OSData::withBytes(
            _airportPowerSetHistory, sizeof(_airportPowerSetHistory));
        if (powerHistory) {
            setProperty("AirportRTW89Apple80211PowerSetHistory", powerHistory);
            powerHistory->release();
        }

        setProperty("AirportRTW89Apple80211SetInterfacePresent",
                    _iface ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetInterfaceUserPower",
                    interfaceUserPower ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetInterfaceSystemEnable",
                    interfaceSystemEnable ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetControllerEnabledAtEntry",
                    _enabled ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerSeen", kOSBooleanTrue);
        setProperty("AirportRTW89Apple80211SetPowerWord0",
                    (uint64_t)firstWord, 32);
        setProperty("AirportRTW89Apple80211SetPowerRadios",
                    (uint64_t)value->num_radios, 8);
        setProperty("AirportRTW89Apple80211SetPowerLegacyValue",
                    (uint64_t)value->power_state[0], 8);
        setProperty("AirportRTW89Apple80211SetPowerValue",
                    (uint64_t)requestedPower, 8);
        setProperty("AirportRTW89Apple80211SetPowerScalarLayout",
                    kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerInterfaceFallback",
                    kOSBooleanFalse);

        IOLog("rtw88: 0.3.54 POWER SET #%u radios=%u raw=%u,%u,%u,%u,%u,%u state=%u io80211reference_noop=%u zero_radio_framework_off=%u\n",
              (unsigned)_airportPowerSetCount,
              (unsigned)value->num_radios,
              (unsigned)rawPowerWords[0], (unsigned)rawPowerWords[1],
              (unsigned)rawPowerWords[2], (unsigned)rawPowerWords[3],
              (unsigned)rawPowerWords[4], (unsigned)rawPowerWords[5],
              (unsigned)requestedPower,
              (zeroRadioNoOp && !zeroRadioFrameworkOff) ? 1U : 0U,
              zeroRadioFrameworkOff ? 1U : 0U);

        /* 0.3.54 Tahoe zero-radio OFF bridge.  The radio payload itself is
         * ambiguous, but the framework user-power latch is already false while
         * system/controller enable stay true.  Commit that one corroborated OFF
         * edge through the normal logical-power backend, then let the existing
         * OFF path re-pin only the transport latches needed for restart safety. */
        if (zeroRadioFrameworkOff) {
            setProperty("AirportRTW89ZeroRadioFrameworkOffAccepted",
                        kOSBooleanTrue);
            setProperty("AirportRTW89Apple80211SetPowerPreservedLogicalState",
                        kOSBooleanFalse);
            setProperty("AirportRTW89Apple80211SetPowerAmbiguousNoOp",
                        kOSBooleanFalse);

            const IOReturn result = applyAirportUserPowerState(
                false, kAirportLogicalPowerApple80211);

            setProperty("AirportRTW89ZeroRadioFrameworkOffApplyReturn",
                        (uint64_t)(uint32_t)result, 32);
            setProperty("AirportRTW89Apple80211InnerPowerLogicalAfterApply",
                        _airportLogicalPowerOn ? kOSBooleanTrue
                                               : kOSBooleanFalse);
            setProperty("AirportRTW89Apple80211SetPowerReturn",
                        (uint64_t)(uint32_t)result, 32);
            return result;
        }

        /* IO80211Reference semantics remain unchanged for every other zero-radio
         * SET: succeed without changing power_state or rewriting the buffer. */
        if (zeroRadioNoOp) {
            setProperty("AirportRTW89ZeroRadioFrameworkOffAccepted",
                        kOSBooleanFalse);
            setProperty("AirportRTW89Apple80211SetPowerPreservedLogicalState",
                        _airportLogicalPowerOn ? kOSBooleanTrue
                                               : kOSBooleanFalse);
            setProperty("AirportRTW89Apple80211SetPowerAmbiguousNoOp",
                        kOSBooleanTrue);
            setProperty("AirportRTW89Apple80211InnerPowerLogicalAfterApply",
                        _airportLogicalPowerOn ? kOSBooleanTrue
                                               : kOSBooleanFalse);
            setProperty("AirportRTW89Apple80211SetPowerReturn",
                        (uint64_t)0, 32);
            return kIOReturnSuccess;
        }

        setProperty("AirportRTW89Apple80211SetPowerAmbiguousNoOp",
                    kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerPreservedLogicalState",
                    kOSBooleanFalse);

        const bool turnOn = requestedPower != APPLE80211_POWER_OFF;
        const IOReturn result = applyAirportUserPowerState(
            turnOn, kAirportLogicalPowerApple80211);
        setProperty("AirportRTW89Apple80211InnerPowerLogicalAfterApply",
                    _airportLogicalPowerOn ? kOSBooleanTrue
                                           : kOSBooleanFalse);
        setProperty("AirportRTW89Apple80211SetPowerReturn",
                    (uint64_t)(uint32_t)result, 32);
        return result;
    }
    case APPLE80211_IOC_ASSOCIATE: {
        const bool syntheticOrigin =
            _airportSyntheticAssociateThread != THREAD_NULL &&
            _airportSyntheticAssociateThread == current_thread();
        if (syntheticOrigin) {
            setProperty("AirportRTW89AssocOrigin", (uint64_t)2, 8);
            setProperty("AirportRTW89SyntheticSET20CommonBodySeen",
                        kOSBooleanTrue);
        } else {
            const UInt32 realSequence =
                __sync_add_and_fetch(&_airportRealAssociateCount, 1U);
            setProperty("AirportRTW89AssocOrigin", (uint64_t)1, 8);
            setProperty("AirportRTW89RealSET20Count",
                        (uint64_t)realSequence, 32);
            setProperty("AirportRTW89RealSET20Seen", kOSBooleanTrue);
        }
        /* 0.3.7: a new association starts with RSN incomplete.  This does not
         * claim WPA2 capability or handshake success; it only keeps the live
         * IO80211 security-state property truthful. */
        setProperty("IO80211RSNDone", kOSBooleanFalse);
        if (_iface)
            _iface->setProperty("IO80211RSNDone", kOSBooleanFalse);
        setProperty("AirportRTW89NativeSecuredControlRSNDoneResetBySET20",
                    kOSBooleanTrue);
        if (!_airportLogicalPowerOn) {
            setProperty("AirportRTW89AssociateRejectedWhileUserPowerOff",
                        kOSBooleanTrue);
            return kIOReturnNotReady;
        }
        apple80211_assoc_data outerAssoc = {};
        apple80211_assoc_data *assoc = (apple80211_assoc_data *)data;
        bool outerAssocConsumed = false;
        if (_airportLock) IOLockLock(_airportLock);
        /* A real Apple SET20 may have an outer Tahoe wire-shape cached by the
         * explicit marshaller.  The synthetic diagnostic must never consume
         * or replace itself with that cache: otherwise a stale real payload
         * would make the experiment non-deterministic.  Leave the cache intact
         * for the next genuine Apple request. */
        if (!syntheticOrigin && _airportOuterAssocCacheValid) {
            outerAssoc = _airportOuterAssocCache;
            bzero(&_airportOuterAssocCache, sizeof(_airportOuterAssocCache));
            _airportOuterAssocCacheValid = false;
            outerAssocConsumed = true;
        }
        if (_airportLock) IOLockUnlock(_airportLock);
        if (outerAssocConsumed) {
            assoc = &outerAssoc;
            setProperty("AirportRTW89WPA2OuterAssociateConsumed", kOSBooleanTrue);
        } else {
            setProperty("AirportRTW89WPA2OuterAssociateConsumed", kOSBooleanFalse);
        }
        if (syntheticOrigin)
            setProperty("AirportRTW89SyntheticSET20OuterCacheBypassed",
                        kOSBooleanTrue);
        if (!assoc)
            return kIOReturnBadArgument;

        static UInt32 preJoinAssociateSetCount = 0;
        ++preJoinAssociateSetCount;
        setProperty("AirportRTW89PreJoinAssociateSet20Seen", kOSBooleanTrue);
        setProperty("AirportRTW89PreJoinAssociateSet20Count",
                    (uint64_t)preJoinAssociateSetCount, 32);
        setProperty("AirportRTW89Apple80211AssociateSeen", kOSBooleanTrue);
        setProperty("AirportRTW89Apple80211AssociateVersion",
                    (uint64_t)assoc->version, 32);
        setProperty("AirportRTW89Apple80211AssociateMode",
                    (uint64_t)assoc->ad_mode, 16);
        setProperty("AirportRTW89Apple80211AssociateAuthLower",
                    (uint64_t)assoc->ad_auth_lower, 16);
        setProperty("AirportRTW89Apple80211AssociateAuthUpperRequested",
                    (uint64_t)assoc->ad_auth_upper, 16);
        setProperty("AirportRTW89Apple80211AssociateSSIDLength",
                    (uint64_t)assoc->ad_ssid_len, 32);
        setProperty("AirportRTW89Apple80211AssociateKeyLength",
                    (uint64_t)assoc->ad_key.key_len, 32);
        setProperty("AirportRTW89Apple80211AssociateKeyCipherType",
                    (uint64_t)assoc->ad_key.key_cipher_type, 32);
        setProperty("AirportRTW89Apple80211AssociateKeyFlags",
                    (uint64_t)assoc->ad_key.key_flags, 16);
        setProperty("AirportRTW89Apple80211AssociateFlags",
                    (uint64_t)assoc->ad_flags, 32);

        if (assoc->ad_ssid_len == 0 || assoc->ad_ssid_len > 32) {
            setProperty("AirportRTW89Apple80211AssociateRejectedSSID",
                        kOSBooleanTrue);
            return kIOReturnBadArgument;
        }

        const UInt32 nativePSKAuth = APPLE80211_AUTHTYPE_WPA_PSK |
                                     APPLE80211_AUTHTYPE_WPA2_PSK |
                                     APPLE80211_AUTHTYPE_SHA256_PSK;
        const UInt32 knownAuth = nativePSKAuth | APPLE80211_AUTHTYPE_WPA3_SAE;
        const UInt32 unknownAuth = assoc->ad_auth_upper & ~knownAuth;
        const bool requestedSAE =
            (assoc->ad_auth_upper & APPLE80211_AUTHTYPE_WPA3_SAE) != 0;
        const bool requestedPSK = (assoc->ad_auth_upper & nativePSKAuth) != 0;

        if (unknownAuth) {
            setProperty("AirportRTW89Apple80211AssociateUnsupportedAuthMask",
                        (uint64_t)unknownAuth, 32);
            return kIOReturnUnsupported;
        }

        /* The internal Senmiko supplicant implements WPA/WPA2 PSK, not SAE.
         * Tahoe may select SAE even on a WPA2/WPA3 transition BSS.  Mark a
         * provisional WPA2 fallback here, but RTW88IEEE80211 must verify that
         * the exact scanned target BSS advertises PSK before it is applied.
         * WPA3-only BSSes are therefore still rejected. */
        UInt32 effectiveAuth = assoc->ad_auth_upper & nativePSKAuth;
        if (requestedSAE) {
            if (!requestedPSK)
                effectiveAuth |= APPLE80211_AUTHTYPE_WPA2_PSK;
            setProperty("AirportRTW89Apple80211AssociateTransitionFallbackRequested",
                        kOSBooleanTrue);
        }
        char ssid[33] = {};
        memcpy(ssid, assoc->ad_ssid, assoc->ad_ssid_len);

        static const uint8_t zeroBSSID[6] = {};
        const uint8_t *preferredBSSID =
            memcmp(assoc->ad_bssid.octet, zeroBSSID, 6) == 0
                ? nullptr : assoc->ad_bssid.octet;
        setProperty("AirportRTW89Apple80211AssociatePreferredBSSIDPresent",
                    preferredBSSID ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.2.179: Tahoe omits ad_auth_upper and the SET20 RSN IE for the
         * WPA2 hotspot we observed, while the live scan BSS already carries
         * the parsed CCMP+PSK security.  Resolve security from the exact same
         * _bssList that cmdConnect() will use instead of the separate Airport
         * mirror.  In the ambiguous upper-auth==0 case, prefer a live WPA2-PSK
         * candidate for this SSID over an open/unknown duplicate. */
        RTW88ConnectTargetInfo liveTarget = {};
        uint32_t liveMatchCount = 0;
        uint32_t livePSKCount = 0;
        const bool liveTargetFound = _ieee80211->copyBestConnectTarget(
            ssid, preferredBSSID, true, &liveTarget,
            &liveMatchCount, &livePSKCount);
        const bool liveTargetWPA2PSK = liveTargetFound &&
            (liveTarget.capabilities & 0x0010U) != 0 &&
            liveTarget.rsn_ie_len >= 2 &&
            liveTarget.cipher == kAirportRsnCipherCCMP &&
            liveTarget.akm == kAirportRsnAkmPSK;

        const bool preferredBSSIDRecoveredSSID =
            preferredBSSID && liveTargetFound && liveTarget.ssid_len > 0 &&
            liveTarget.ssid_len <= 32 &&
            (liveTarget.ssid_len != assoc->ad_ssid_len ||
             memcmp(liveTarget.ssid, assoc->ad_ssid,
                    liveTarget.ssid_len) != 0);
        const char *connectSSID = preferredBSSIDRecoveredSSID
            ? liveTarget.ssid : ssid;
        const uint8_t connectSSIDLength = preferredBSSIDRecoveredSSID
            ? liveTarget.ssid_len : (uint8_t)assoc->ad_ssid_len;
        setProperty("AirportRTW89PreferredBSSIDRecoveredSSID",
                    preferredBSSIDRecoveredSSID ? kOSBooleanTrue
                                                 : kOSBooleanFalse);
        if (preferredBSSIDRecoveredSSID) {
            setProperty("AirportRTW89PreferredBSSIDRecoveredSSIDLength",
                        (uint64_t)connectSSIDLength, 8);
        }

        setProperty("AirportRTW89WPA2LiveLookupFound",
                    liveTargetFound ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2LiveLookupMatchCount",
                    (uint64_t)liveMatchCount, 32);
        setProperty("AirportRTW89WPA2LiveLookupPSKCount",
                    (uint64_t)livePSKCount, 32);
        setProperty("AirportRTW89WPA2LiveLookupSelectedPSK",
                    liveTargetWPA2PSK ? kOSBooleanTrue : kOSBooleanFalse);
        if (liveTargetFound) {
            setProperty("AirportRTW89WPA2LiveLookupCipher",
                        (uint64_t)liveTarget.cipher, 32);
            setProperty("AirportRTW89WPA2LiveLookupGroupCipher",
                        (uint64_t)liveTarget.group_cipher, 32);
            setProperty("AirportRTW89WPA2LiveLookupAKM",
                        (uint64_t)liveTarget.akm, 32);
            setProperty("AirportRTW89WPA2LiveLookupChannel",
                        (uint64_t)liveTarget.channel, 8);
            setProperty("AirportRTW89WPA2LiveLookupPrivacy",
                        (liveTarget.capabilities & 0x0010U)
                            ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89WPA2LiveLookupPersistentRSN",
                        liveTarget.rsn_ie_len >= 2
                            ? kOSBooleanTrue : kOSBooleanFalse);
            setProperty("AirportRTW89WPA2LiveLookupPersistentRSNLength",
                        (uint64_t)liveTarget.rsn_ie_len, 16);
            setProperty("AirportRTW89WPA2LiveLookupRSNObservationCount",
                        (uint64_t)liveTarget.rsn_observation_count, 32);
            setProperty("AirportRTW89WPA2LiveLookupSecurityUpdateCount",
                        (uint64_t)liveTarget.security_update_count, 32);
            setProperty("AirportRTW89WPA2LiveLookupSecurityPreserveCount",
                        (uint64_t)liveTarget.security_preserve_count, 32);
            setProperty("AirportRTW89WPA2LiveLookupSecurityOpenCandidateCount",
                        (uint64_t)liveTarget.security_open_candidate_count, 32);
            setProperty("AirportRTW89WPA2LiveLookupSecurityOpenClearCount",
                        (uint64_t)liveTarget.security_open_clear_count, 32);
            setProperty("AirportRTW89WPA2LiveLookupLastSecurityScanGeneration",
                        (uint64_t)liveTarget.last_security_scan_generation, 32);
            setProperty("AirportRTW89WPA2LiveLookupOpenCandidateScanGeneration",
                        (uint64_t)liveTarget.open_candidate_scan_generation, 32);
        }

        /* Keep the historical marker for test-script compatibility, but its
         * source of truth is now the live connect list rather than the Airport
         * snapshot cache. */
        const bool scannedWPA2PSK = liveTargetWPA2PSK;
        setProperty("AirportRTW89WPA2ScannedTargetPSK",
                    scannedWPA2PSK ? kOSBooleanTrue : kOSBooleanFalse);

        /* Tahoe can submit SET20 with ad_auth_upper==0 after selecting a WPA2
         * network in the menu.  In only that ambiguous case, allow the exact
         * persistent BSSID record to select backend WPA2-PSK when it carries
         * a parsed RSN IE, Privacy, CCMP and PSK.  Do not change the
         * Apple-facing auth latch below: this is join-backend adaptation, not
         * fabricated Apple control state. */
        const bool liveAuthFallback =
            assoc->ad_auth_upper == APPLE80211_AUTHTYPE_NONE &&
            liveTargetWPA2PSK;
        if (liveAuthFallback)
            effectiveAuth |= APPLE80211_AUTHTYPE_WPA2_PSK;
        setProperty("AirportRTW89WPA2LiveLookupUsedForAuth",
                    liveAuthFallback ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89AppleControlScanAuthInferenceDisabled",
                    liveAuthFallback ? kOSBooleanFalse : kOSBooleanTrue);

        /* Pin the actual connect call to the BSSID selected by the live
         * security lookup.  This prevents a second strongest-RSSI search from
         * choosing an open/unknown duplicate after we classified WPA2. */
        const uint8_t *connectBSSID = preferredBSSID;
        if (!connectBSSID && liveTargetFound)
            connectBSSID = liveTarget.bssid;
        setProperty("AirportRTW89WPA2LiveLookupBSSIDPinned",
                    (!preferredBSSID && liveTargetFound)
                        ? kOSBooleanTrue : kOSBooleanFalse);

        setProperty("AirportRTW89Apple80211AssociateAuthUpperEffective",
                    (uint64_t)effectiveAuth, 16);

        /* 0.3.5 IO80211Reference parity: SET20 internally refreshes the same
         * Apple-facing AUTH_TYPE latch from the association request before
         * handing the join to net80211/RTW.  Keep backend-only auth adaptation
         * out of GET2 ownership. */
        _airportAppleControl.current_authtype_lower = assoc->ad_auth_lower;
        _airportAppleControl.current_authtype_upper = assoc->ad_auth_upper;
        _airportAppleControlAuthConfigured = true;
        setProperty("AirportRTW89AppleControlSET20RefreshedAuthLatch",
                    kOSBooleanTrue);
        if (_net80211) {
            _net80211->noteDesired((const uint8_t *)connectSSID,
                                    connectSSIDLength,
                                    connectBSSID, assoc->ad_auth_lower,
                                    effectiveAuth, true);
            _net80211->noteState(obsd80211::IEEE80211_S_AUTH);
            setProperty("AirportRTW89Net80211SET20DesiredStateUsed",
                        kOSBooleanTrue);
            setProperty("AirportRTW89Net80211LegacyAuthMirrorValid",
                        kOSBooleanTrue);
            setProperty("AirportRTW89Net80211LegacyAuthMirrorMatches",
                        kOSBooleanTrue);
        }

        IOReturn result;
        const bool secured =
            effectiveAuth != APPLE80211_AUTHTYPE_NONE;
        const bool keyIsPMK = secured &&
            assoc->ad_key.key_cipher_type == APPLE80211_CIPHER_PMK &&
            assoc->ad_key.key_len == 32;
        setProperty("AirportRTW89Apple80211AssociateKeyInterpretedAsPMK",
                    keyIsPMK ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.2.177: if SET20 already carries usable credential material, avoid
         * depending on Tahoe's later Apple-supplicant key marshalling and run
         * the existing in-driver WPA2 handshake instead.  PMK is ideal; the
         * legacy passphrase path is retained for 8..32-byte non-PMK material.
         * When SET20 has no credential bytes, keep the Apple RSN supplicant as
         * the fallback and accept PTK/GTK through CIPHER_KEY. */
        const bool usablePassphrase = secured && !keyIsPMK &&
            assoc->ad_key.key_len >= 8 &&
            assoc->ad_key.key_len <= APPLE80211_KEY_BUFF_LEN;
        const bool internalWPA2 = secured && (keyIsPMK || usablePassphrase);
        const bool appleRSNFallback = secured && !internalWPA2;
        _ieee80211->setAppleRSNMode(appleRSNFallback);
        setProperty("AirportRTW89WPA2InternalSupplicantSelected",
                    internalWPA2 ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2AppleSupplicantFallback",
                    appleRSNFallback ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89WPA2CredentialMaterialPresent",
                    (keyIsPMK || usablePassphrase) ? kOSBooleanTrue
                                                   : kOSBooleanFalse);
        if (secured && assoc->ad_rsn_ie[0] == 48 /* RSN */ &&
            assoc->ad_rsn_ie[1] > 0) {
            const uint16_t assocRsnLen = (uint16_t)assoc->ad_rsn_ie[1] + 2;
            if (assocRsnLen <= APPLE80211_MAX_RSN_IE_LEN) {
                const bool rsnStored =
                    _ieee80211->setAppleRSNIE(assoc->ad_rsn_ie, assocRsnLen);
                setProperty("AirportRTW89AppleRSNAssocIEStored",
                            rsnStored ? kOSBooleanTrue : kOSBooleanFalse);
                setProperty("AirportRTW89AppleRSNAssocIELength",
                            (uint64_t)assocRsnLen, 16);
            }
        }

        const bool requireScannedPSK = requestedPSK || requestedSAE;
        setProperty("AirportRTW89WPA2RequireScannedPSK",
                    requireScannedPSK ? kOSBooleanTrue : kOSBooleanFalse);

        if (keyIsPMK) {
            result = _ieee80211->cmdConnectWithPMK(
                connectSSID, assoc->ad_key.key, assoc->ad_key.key_len,
                connectBSSID, requireScannedPSK);
        } else {
            /* apple80211_key carries at most 32 bytes.  For the internal PSK
             * path, non-PMK material is therefore a passphrase fragment and
             * must satisfy the WPA minimum; importantly, a 32-character
             * passphrase is not automatically a PMK. */
            if (secured && assoc->ad_key.key_len != 0 &&
                (assoc->ad_key.key_len < 8 ||
                 assoc->ad_key.key_len > APPLE80211_KEY_BUFF_LEN)) {
                setProperty("AirportRTW89Apple80211AssociateRejectedKeyLength",
                            kOSBooleanTrue);
                return kIOReturnBadArgument;
            }
            char password[APPLE80211_KEY_BUFF_LEN + 1] = {};
            memcpy(password, assoc->ad_key.key, assoc->ad_key.key_len);
            result = _ieee80211->cmdConnect(connectSSID, password, connectBSSID,
                                             requireScannedPSK);
        }

        setProperty("AirportRTW89Apple80211AssociateDispatchReturn",
                    (uint64_t)(uint32_t)result, 32);
        if (result == kIOReturnSuccess) {
            _airportAssocPending = true;
            _airportAssocResult = APPLE80211_RESULT_UNAVAILABLE;
        }
        return result;
    }
    case APPLE80211_IOC_DISASSOCIATE: {
        /* 0.3.7: DISASSOCIATE always invalidates completed-RSN publication,
         * even when IO80211Reference state semantics make the hardware action a
         * disconnected no-op.  The Apple AUTH latch remains preserved. */
        setProperty("IO80211RSNDone", kOSBooleanFalse);
        if (_iface)
            _iface->setProperty("IO80211RSNDone", kOSBooleanFalse);
        setProperty("AirportRTW89NativeSecuredControlRSNDoneResetBySET22",
                    kOSBooleanTrue);
        obsd80211::ieee80211_current_view preDisassocView = {};
        const bool preDisassocViewValid =
            _net80211 && _net80211->copyCurrentView(preDisassocView);
        const bool io80211ReferenceStateNoOp = preDisassocViewValid &&
            (preDisassocView.state < obsd80211::IEEE80211_S_SCAN ||
             preDisassocView.state == obsd80211::IEEE80211_S_AUTH ||
             preDisassocView.state == obsd80211::IEEE80211_S_ASSOC);
        setProperty("AirportRTW89AppleControlSET22PreState",
                    preDisassocViewValid ? (uint64_t)preDisassocView.state : 0U,
                    32);
        setProperty("AirportRTW89AppleControlSET22StateNoOp",
                    io80211ReferenceStateNoOp ? kOSBooleanTrue : kOSBooleanFalse);

        /* 0.3.5 IO80211Reference parity: SET22 is state-sensitive.  The net80211
         * core now mirrors IO80211Reference's early-state no-op / SCAN transition
         * semantics, and the Apple-facing current_authtype_* latch is never
         * cleared here. */
        if (_net80211) {
            _net80211->noteDisassociate();
            setProperty("AirportRTW89Net80211SET22ResetSeen",
                        kOSBooleanTrue);
            setProperty("AirportRTW89Net80211SET22ClearedSingleState",
                        kOSBooleanFalse);
        }
        setProperty("AirportRTW89AppleControlSET22PreservedAuthLatch",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Net80211LegacyAuthMirrorValid",
                    _airportAppleControlAuthConfigured ? kOSBooleanTrue
                                                       : kOSBooleanFalse);
        _airportAssocPending = false;
        _airportAssocResult = APPLE80211_RESULT_UNAVAILABLE;

        /* 0.2.251: IO80211Reference-style idle DISASSOCIATE semantics.
         *
         * The 0.2.249/0.2.250 SET-only traces prove that Tahoe emits a
         * payload-less SET22 roughly 2 ms before every real "Will associate"
         * edge, while ASSOCIATE/20 is never emitted.  The same runtime also
         * proves that every one of those SET22 calls arrives while the Realtek
         * backend already reports isIdle()==true.
         *
         * IO80211Reference does not tear the hardware down for a redundant
         * disconnected DISASSOCIATE.  In its early/disconnected states it
         * acknowledges the request and preserves the scan-state machine for
         * the following association.  Our historical cmdDisconnect() path, by
         * contrast, reaches doDisconnect()/hw_scan_abort() even when already
         * idle and also clears Apple RSN mode.
         *
         * Make exactly that one semantic change here: when already idle,
         * acknowledge SET22 without cmdDisconnect() and without clearing the
         * Apple RSN mode.  Non-idle DISASSOCIATE retains the existing backend
         * teardown unchanged. */
        const bool alreadyIdle = _ieee80211 && _ieee80211->isIdle();
        static volatile UInt32 idleNoOpCount = 0;
        setProperty("AirportRTW89IO80211ReferenceDisassociateAlreadyIdle",
                    alreadyIdle ? kOSBooleanTrue : kOSBooleanFalse);
        if (io80211ReferenceStateNoOp || alreadyIdle) {
            const UInt32 seq = __sync_add_and_fetch(&idleNoOpCount, 1U);
            setProperty("AirportRTW89IO80211ReferenceIdleDisassociateNoOpSeen",
                        kOSBooleanTrue);
            setProperty("AirportRTW89IO80211ReferenceIdleDisassociateNoOpCount",
                        (uint64_t)seq, 32);
            setProperty("AirportRTW89IO80211ReferenceIdleDisassociateCmdDisconnectCalled",
                        kOSBooleanFalse);
            setProperty("AirportRTW89IO80211ReferenceIdleDisassociateRSNModeCleared",
                        kOSBooleanFalse);
            setProperty("AirportRTW89IO80211ReferenceIdleDisassociateScanStatePreserved",
                        kOSBooleanTrue);
            setProperty("AirportRTW89IO80211ReferenceDisassociateStateNoOpApplied",
                        io80211ReferenceStateNoOp ? kOSBooleanTrue : kOSBooleanFalse);
            return kIOReturnSuccess;
        }

        setProperty("AirportRTW89IO80211ReferenceIdleDisassociateCmdDisconnectCalled",
                    kOSBooleanTrue);
        IOReturn ret = _ieee80211->cmdDisconnect();
        _ieee80211->setAppleRSNMode(false);
        setProperty("AirportRTW89IO80211ReferenceIdleDisassociateRSNModeCleared",
                    kOSBooleanTrue);
        return ret;
    }
    case APPLE80211_IOC_DEAUTH:
        /* IO80211Reference's SET DEAUTH is an acknowledgement/no-op.  Keep the
         * actual disconnect on DISASSOCIATE so the framework owns sequencing. */
        setProperty("AirportRTW89Apple80211DeauthSetNoOp", kOSBooleanTrue);
        return kIOReturnSuccess;
    case APPLE80211_IOC_SCANCACHE_CLEAR:
        airportResetScanCache();
        return kIOReturnSuccess;
    case APPLE80211_IOC_AUTH_TYPE: {
        apple80211_authtype_data outerAuth = {};
        apple80211_authtype_data *value = (apple80211_authtype_data *)data;
        bool outerConsumed = false;
        if (_airportLock) IOLockLock(_airportLock);
        if (_airportOuterAuthCacheValid) {
            outerAuth = _airportOuterAuthCache;
            bzero(&_airportOuterAuthCache, sizeof(_airportOuterAuthCache));
            _airportOuterAuthCacheValid = false;
            outerConsumed = true;
        }
        if (_airportLock) IOLockUnlock(_airportLock);
        if (outerConsumed)
            value = &outerAuth;
        setProperty("AirportRTW89WPA2OuterAuthConsumed",
                    outerConsumed ? kOSBooleanTrue : kOSBooleanFalse);
        if (!value)
            return kIOReturnBadArgument;
        /* 0.3.5 IO80211Reference parity: SET2 owns only the Apple control-state
         * latch.  net80211 association policy is populated by SET20. */
        _airportAppleControl.current_authtype_lower = value->authtype_lower;
        _airportAppleControl.current_authtype_upper = value->authtype_upper;
        _airportAppleControlAuthConfigured = true;
        setProperty("AirportRTW89Net80211SET2AuthAuthorityUpdated",
                    kOSBooleanFalse);
        setProperty("AirportRTW89AppleControlSET2LatchUpdated",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Net80211LegacyAuthMirrorValid",
                    kOSBooleanTrue);
        setProperty("AirportRTW89Net80211LegacyAuthMirrorMatches",
                    kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_COUNTRY_CODE: {
        apple80211_country_code_data *value =
            (apple80211_country_code_data *)data;
        setProperty("AirportRTW89CountryCodeSetSeen", kOSBooleanTrue);

        char requested[3] = { (char)value->cc[0], (char)value->cc[1], '\0' };
        if (requested[0] >= 'a' && requested[0] <= 'z')
            requested[0] -= ('a' - 'A');
        if (requested[1] >= 'a' && requested[1] <= 'z')
            requested[1] -= ('a' - 'A');
        const bool valid =
            requested[0] >= 'A' && requested[0] <= 'Z' &&
            requested[1] >= 'A' && requested[1] <= 'Z' &&
            requested[0] != 'X';

        if (!valid) {
            setProperty("AirportRTW89CountryCodeSetIgnoredSentinel",
                        kOSBooleanTrue);
            return kIOReturnSuccess;
        }

        const bool applied =
            _ieee80211 && _ieee80211->setRegulatoryCountry(requested);
        char effective[3] = {};
        const bool effectivePresent =
            _ieee80211 && _ieee80211->getRegulatoryCountry(effective);

        if (applied || !effectivePresent) {
            _airportCountryCode[0] = requested[0];
            _airportCountryCode[1] = requested[1];
            _airportCountryCode[2] = '\0';
        } else {
            /* Hardware-programmed country differs: keep the hardware domain. */
            _airportCountryCode[0] = effective[0];
            _airportCountryCode[1] = effective[1];
            _airportCountryCode[2] = '\0';
            setProperty("AirportRTW89CountryCodeSetBlockedByHardware",
                        kOSBooleanTrue);
        }

        char published[3] = { _airportCountryCode[0],
                              _airportCountryCode[1], '\0' };
        setProperty("AirportRTW89CountryCodeSourceAirport",
                    applied ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89CountryCodeAppliedToDriver",
                    applied ? kOSBooleanTrue : kOSBooleanFalse);
        setProperty("AirportRTW89CountryCodeEffective", published);
        setProperty(APPLE80211_REGKEY_COUNTRY_CODE, published);
        if (_iface)
            _iface->setProperty(APPLE80211_REGKEY_COUNTRY_CODE, published);

        IO80211Interface *notifyInterface = interface;
        if (!notifyInterface)
            notifyInterface = OSDynamicCast(IO80211Interface, _iface);
        if (notifyInterface) {
            notifyInterface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED);
            setProperty("AirportRTW89CountryCodeChangedPosted", kOSBooleanTrue);
        } else {
            setProperty("AirportRTW89CountryCodeChangedPosted", kOSBooleanFalse);
        }
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_SSID:
    case APPLE80211_IOC_BSSID:
        return kIOReturnSuccess;
    case APPLE80211_IOC_CHANNEL:
    case APPLE80211_IOC_PROTMODE:
    case APPLE80211_IOC_MCS_VHT:
    case APPLE80211_IOC_TX_NSS:
    case APPLE80211_IOC_ROAM:
    case APPLE80211_IOC_WOW_PARAMETERS:
        return kIOReturnError;
    case APPLE80211_IOC_RSN_IE: {
        apple80211_rsn_ie_data outerRSN = {};
        apple80211_rsn_ie_data *value = (apple80211_rsn_ie_data *)data;
        bool outerConsumed = false;
        if (_airportLock) IOLockLock(_airportLock);
        if (_airportOuterRSNIECacheValid) {
            outerRSN = _airportOuterRSNIECache;
            bzero(&_airportOuterRSNIECache, sizeof(_airportOuterRSNIECache));
            _airportOuterRSNIECacheValid = false;
            outerConsumed = true;
        }
        if (_airportLock) IOLockUnlock(_airportLock);
        if (outerConsumed)
            value = &outerRSN;
        setProperty("AirportRTW89WPA2OuterRSNIEConsumed",
                    outerConsumed ? kOSBooleanTrue : kOSBooleanFalse);
        if (!value || value->len < 2 || value->len > sizeof(value->ie))
            return kIOReturnBadArgument;
        const bool stored = _ieee80211->setAppleRSNIE(value->ie, value->len);
        setProperty("AirportRTW89AppleRSNIESetRequestSeen", kOSBooleanTrue);
        setProperty("AirportRTW89AppleRSNIESetRequestLength",
                    (uint64_t)value->len, 16);
        return stored ? kIOReturnSuccess : kIOReturnBadArgument;
    }
    case APPLE80211_IOC_POWERSAVE:
        return kIOReturnError;
    case APPLE80211_IOC_IE:
        /* IO80211Reference accepts SET IE but its GET path is an error. */
        setProperty("AirportRTW89Apple80211IESetSeen", kOSBooleanTrue);
        return kIOReturnSuccess;
    case APPLE80211_IOC_P2P_LISTEN:
    case APPLE80211_IOC_P2P_SCAN:
    case APPLE80211_IOC_P2P_GO_CONF:
        setProperty("AirportRTW89Apple80211P2PControlSeen",
                    (uint64_t)requestNumber, 32);
        return kIOReturnSuccess;
    case APPLE80211_IOC_VIRTUAL_IF_CREATE:
        /* Match current IO80211Reference on Ventura/Sonoma+: the old primary-path
         * virtual-interface creation sequence is intentionally disabled. */
        return kIOReturnUnsupported;
    case APPLE80211_IOC_VIRTUAL_IF_DELETE:
        return kIOReturnUnsupported;
    case APPLE80211_IOC_ROAM_PROFILE:
        /* The private roam-profile structure is newer than this SDK.  Accept
         * the SET contract and diagnose it; do not dereference unknown size. */
        setProperty("AirportRTW89Apple80211RoamProfileSetSeen", kOSBooleanTrue);
        return kIOReturnSuccess;
    case APPLE80211_IOC_BTCOEX_PROFILES:
        setProperty("AirportRTW89Apple80211BTCoexProfilesSetSeen", kOSBooleanTrue);
        return kIOReturnSuccess;
    case APPLE80211_IOC_BTCOEX_CONFIG: {
        const UInt32 *words = (const UInt32 *)data;
        for (UInt32 i = 0; i < 5; ++i)
            _airportBtcConfigWords[i] = words[i];
        setProperty("AirportRTW89Apple80211BTCoexConfigSetSeen", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_BTCOEX_MODE: {
        const AirportRTW89VersionedScalar *value =
            (const AirportRTW89VersionedScalar *)data;
        _airportBtcMode = value->value;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_BTCOEX_OPTIONS: {
        const AirportRTW89VersionedScalar *value =
            (const AirportRTW89VersionedScalar *)data;
        _airportBtcOptions = value->value;
        return kIOReturnSuccess;
    }
    case APPLE80211_IOC_CIPHER_KEY: {
        apple80211_key outerKey = {};
        apple80211_key *key = (apple80211_key *)data;
        bool outerConsumed = false;
        if (_airportLock) IOLockLock(_airportLock);
        if (_airportOuterCipherKeyCacheValid) {
            outerKey = _airportOuterCipherKeyCache;
            bzero(&_airportOuterCipherKeyCache,
                  sizeof(_airportOuterCipherKeyCache));
            _airportOuterCipherKeyCacheValid = false;
            outerConsumed = true;
        }
        if (_airportLock) IOLockUnlock(_airportLock);
        if (outerConsumed)
            key = &outerKey;
        setProperty("AirportRTW89WPA2OuterCipherKeyConsumed",
                    outerConsumed ? kOSBooleanTrue : kOSBooleanFalse);
        if (!key || key->key_len > APPLE80211_KEY_BUFF_LEN)
            return kIOReturnBadArgument;

        setProperty("AirportRTW89AppleRSNCipherKeySeen", kOSBooleanTrue);
        setProperty("AirportRTW89AppleRSNCipherKeyLength",
                    (uint64_t)key->key_len, 32);
        setProperty("AirportRTW89AppleRSNCipherKeyType",
                    (uint64_t)key->key_cipher_type, 32);
        setProperty("AirportRTW89AppleRSNCipherKeyFlags",
                    (uint64_t)key->key_flags, 16);
        setProperty("AirportRTW89AppleRSNCipherKeyIndex",
                    (uint64_t)key->key_index, 16);

        /* Match IO80211Reference's observed Apple-supplicant convention: flags=4
         * is the PTK and flags=0 is a GTK.  Also accept the named unicast/
         * multicast bits if Tahoe uses the header-defined form. */
        const bool pairwise =
            key->key_flags == APPLE80211_KEY_FLAG_TX ||
            (key->key_flags & APPLE80211_KEY_FLAG_UNICAST) != 0;
        const bool group =
            key->key_flags == 0 ||
            (key->key_flags & APPLE80211_KEY_FLAG_MULTICAST) != 0;
        if (!pairwise && !group) {
            setProperty("AirportRTW89AppleRSNCipherKeyUnclassified",
                        kOSBooleanTrue);
            return kIOReturnUnsupported;
        }

        /* IO80211Reference acknowledges NONE/PMK/PMKSA requests even though its
         * Apple-supplicant path does not install those through setCIPHER_KEY.
         * Preserve that control-plane contract; actual PTK/GTK installs are
         * handled below for TKIP/CCMP. */
        if (key->key_cipher_type == APPLE80211_CIPHER_NONE ||
            key->key_cipher_type == APPLE80211_CIPHER_PMK ||
            key->key_cipher_type == APPLE80211_CIPHER_PMKSA) {
            setProperty("AirportRTW89AppleRSNCipherKeyAcknowledgedOnly",
                        kOSBooleanTrue);
            return kIOReturnSuccess;
        }

        IOReturn ret = _ieee80211->installAppleRSNKey(
            pairwise, (uint8_t)key->key_index, key->key_cipher_type,
            key->key, (uint8_t)key->key_len);
        setProperty("AirportRTW89AppleRSNCipherKeyInstallReturn",
                    (uint64_t)(uint32_t)ret, 32);
        setProperty("AirportRTW89AppleRSNCipherKeyPairwise",
                    pairwise ? kOSBooleanTrue : kOSBooleanFalse);

        if (ret == kIOReturnSuccess) {
            const bool rsnComplete = _ieee80211->appleRSNHandshakeComplete();
            setProperty("AirportRTW89AppleRSNHandshakeComplete",
                        rsnComplete ? kOSBooleanTrue : kOSBooleanFalse);
            if (!rsnComplete) {
                /* 0.3.15: a successful SET3 means one temporal key was
                 * programmed, not that the WPA2 controlled port is complete.
                 * Apple can deliver PTK and GTK as separate CIPHER_KEY calls.
                 * Publishing RSN_HANDSHAKE_DONE after the first key races the
                 * second install and can make airportd advance the secured
                 * state machine prematurely. */
                setProperty("AirportRTW89AppleRSNHandshakeDoneDeferredForSecondKey",
                            kOSBooleanTrue);
            } else {
                IO80211Interface *notify = interface;
                if (!notify)
                    notify = OSDynamicCast(IO80211Interface, _iface);
                if (notify) {
                    static volatile UInt32 parityRSNHandshakePostCount = 0;
                    const UInt32 postCount = __sync_add_and_fetch(
                        &parityRSNHandshakePostCount, 1U);
                    uint64_t parityRSNNowNs = 0;
                    absolutetime_to_nanoseconds(mach_absolute_time(),
                                                &parityRSNNowNs);
                    /* Publish the secured-port completion edge only after the
                     * pairwise and group temporal keys are both installed. */
                    setProperty("IO80211RSNDone", kOSBooleanTrue);
                    notify->setProperty("IO80211RSNDone", kOSBooleanTrue);
                    setProperty("AirportRTW89NativeSecuredControlRSNDoneSetByRealKeyInstall",
                                kOSBooleanTrue);
                    notify->postMessage(APPLE80211_M_RSN_HANDSHAKE_DONE, nullptr, 0);
                    setProperty("AirportRTW89AppleRSNHandshakeDonePosted",
                                kOSBooleanTrue);
                    setProperty("AirportRTW89ParityRSNHandshakeDonePostCount",
                                (uint64_t)postCount, 32);
                    setProperty("AirportRTW89ParityRSNHandshakeDonePostMS",
                                parityRSNNowNs / 1000000ULL, 64);
                }
            }
        }
        return ret;
    }
    default:
        setProperty("AirportRTW89Apple80211LastUnsupportedSetRequest",
                    (uint64_t)requestNumber, 32);
        return kIOReturnUnsupported;
    }
}

#endif /* RTW_AIRPORT */
