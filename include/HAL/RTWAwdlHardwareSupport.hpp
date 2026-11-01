/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_HARDWARE_SUPPORT_HPP
#define RTW_AWDL_HARDWARE_SUPPORT_HPP
#include <stdint.h>
namespace RTWAwdl {
enum HardwareSupport : uint32_t {
    FrameTransport=1U<<0, ManualVisits=1U<<1, PeerStations=1U<<2,
    // Full producer/lifetime barrier, not merely a successful firmware delete.
    QuiescentRemoval=1U<<3
};
}
#endif
