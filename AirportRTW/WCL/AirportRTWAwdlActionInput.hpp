/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_ACTION_INPUT_HPP
#define AIRPORTRTW_AWDL_ACTION_INPUT_HPP
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <stddef.h>
#include <stdint.h>
struct IO80211VirtualInterface;
namespace AirportRTWAwdlActionInput {
// Called on the native AWDL workqueue with a live, initialized role-6 interface.
// Header is the calibrated native action metadata, not the 802.11 frame header.
// True means buffer ownership was handed to the family, not peer acceptance.
// Radio timestamps must already be translated into the family's clock domain.
bool deliver(IO80211VirtualInterface *, const uint8_t *frame, size_t length,
             const uint8_t *metadata, size_t metadataLength);
}
#endif
#endif
