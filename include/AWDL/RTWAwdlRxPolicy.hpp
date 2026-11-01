/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_RX_POLICY_HPP
#define RTW_AWDL_RX_POLICY_HPP
namespace RTWAwdl {
// Linux filter bit values are supplied by the HAL to avoid coupling shared
// protocol code to either driver's compatibility headers.
inline unsigned receiveFlags(bool scanning, bool discovery, bool allMulticast,
                             unsigned otherBss, unsigned beaconPromiscuous,
                             unsigned multicast) {
    return ((scanning || discovery) ? otherBss | beaconPromiscuous : 0) |
           ((allMulticast || discovery) ? multicast : 0);
}
}
#endif
