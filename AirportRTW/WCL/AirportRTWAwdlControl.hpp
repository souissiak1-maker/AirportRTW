/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_CONTROL_HPP
#define AIRPORTRTW_AWDL_CONTROL_HPP
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <IOKit/IOReturn.h>
#include <stdint.h>
#include <stddef.h>
struct IO80211VirtualInterface;
namespace AirportRTWAwdl {
enum class Request : uint8_t {
    SSID,
    CHANNEL,
    BSSID,
    STATE,
    AWDL_SYNC_PARAMS,
    AWDL_SYNC_ENABLED,
    AWDL_EXTENSION_STATE_MACHINE_PARAMETERS,
    AWDL_ELECTION_ID,
    AWDL_ELECTION_METRIC,
    AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE,
    PEER_CACHE_MAXIMUM_SIZE,
    AWDL_MASTER_CHANNEL,
    AWDL_SYNC_STATE,
    AWDL_ELECTION_RSSI_THRESHOLDS,
    AWDL_PRESENCE_MODE,
    AWDL_ELECTION_PARAMS,
    AWDL_DEVICE_CAPABILITIES,
    AWDL_SECONDARY_MASTER_CHANNEL,
    AWDL_AF_TX_MODE,
    AWDL_MIN_RATE,
    AWDL_ENCRYPTION_TYPE,
    AWDL_TXCAL_PERIOD,
    AWDL_DEV_STATS,
    AWDL_DFSP_CONFIG,
    AWDL_CCA,
    AWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES,
    LLW_PARAMS,
    AWDL_BSSID,
    PEER_CACHE_CONTROL,
    AWDL_OOB_REQUEST,
    AWDL_SYNC_FRAME_TEMPLATE,
    AWDL_PEER_TRAFFIC_REGISTRATION,
    AWDL_ENCRYPTION_KEYS,
    AWDL_OOB_AUTO_REQUEST,
    AWDL_AWDL_ADVERTISERS,
    AWDL_DFSP_UCSA_CONFIG,
    COMPANION_SKYWALK_IF_CREATE,
    AWDL_OOB_SEC_PAYLOAD_REQUEST,
    TX_RATE,
    P2P_COEX_PROTECTION,
    PSF_DWELL,
    AWDL_CONFIG,
    AWDL_RTG_PEER_STATS_CONFIG,
};
// Native protocol/runtime contract, not a hardware-specific HAL interface.
// The controller owns this provider and stops the interface before destroying it.
// Runtime supplies validated native controls; publication additionally requires
// its concrete radio/protocol backend to supply every capability gate.
class Control {
public:
    enum Capability : uint32_t {
        ActionTxRx = 1U << 0, DataTxRx = 1U << 1,
        ClockAndSynchronization = 1U << 2, RadioScheduling = 1U << 3,
        RegulatoryEnforcement = 1U << 4, PeerState = 1U << 5,
        QuiescentShutdown = 1U << 6
    };
    static constexpr uint32_t requiredCapabilities = ActionTxRx | DataTxRx |
        ClockAndSynchronization | RadioScheduling | RegulatoryEnforcement |
        PeerState | QuiescentShutdown;
    virtual ~Control() = default;
    virtual uint32_t capabilities() const = 0;
    virtual bool ready() const = 0;
    // Prepare runs before native base start: do not access its workqueue yet.
    // It may bind the interface but must not invoke callbacks until enable.
    // shutdown must handle partial prepare and synchronously quiesce producers.
    virtual IOReturn prepare(IO80211VirtualInterface *, const uint8_t mac[6]) = 0;
    virtual IOReturn enable(bool) = 0;
    virtual void shutdown() = 0;
    // Native payloads retain their family-defined types/layouts. A provider must
    // validate each supported request and return Unsupported for unknown ones.
    // Request payloads are borrowed only for the duration of this synchronous call.
    virtual IOReturn request(Request, bool set, void *payload) = 0;
    virtual IOReturn setAddress(const uint8_t mac[6]) = 0;
    // Copy before true; false is backpressure. Do not tear down reentrantly.
    virtual bool transmitEthernet(const uint8_t *, size_t) = 0;
};
}
#endif
#endif
