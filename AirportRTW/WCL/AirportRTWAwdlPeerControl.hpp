/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_PEER_CONTROL_HPP
#define AIRPORTRTW_AWDL_PEER_CONTROL_HPP
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <IOKit/IOReturn.h>
#include <stdint.h>
struct IO80211VirtualInterface;
struct apple80211_awdl_peer_traffic_registration;
namespace AirportRTWAwdl {
// Native runtime peer transaction owner. Lives through every in-flight request;
// destruction is outside callbacks. Calls run on the native workloop.
class PeerControl {
public:
    virtual ~PeerControl() = default;
    virtual bool ready() const = 0;
    virtual IOReturn bind(IO80211VirtualInterface *, const uint8_t[6]) = 0;
    virtual IOReturn enable(bool) = 0;
    // Immediate authorization gate only, safe during a reentrant native event.
    virtual void revoke() = 0;
    // Caller has stopped data producers. Hardware failures remain HAL-owned.
    virtual void shutdown() = 0;
    // Forget native references without deleting hardware peers. Backend close
    // takes ownership and quiesces the whole VIF, including retained failures.
    virtual void abandon() = 0;
    virtual IOReturn cache(uint32_t operation, const uint8_t[6]) = 0;
    virtual IOReturn traffic(const apple80211_awdl_peer_traffic_registration &) = 0;
    virtual uint32_t capacity() const = 0;
    // Serialized native RX admission. Default rejects incomplete providers.
    virtual bool authorized(const uint8_t[6]) const {return false;}
    virtual bool acceptData(const uint8_t[6],unsigned,uint16_t,uint64_t) {return false;}
};
}
#endif
#endif
