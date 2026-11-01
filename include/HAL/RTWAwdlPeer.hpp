/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_PEER_HPP
#define RTW_AWDL_PEER_HPP
#include <stdint.h>
namespace RTWAwdl {
enum class PeerResult : uint8_t {
    Success, Unsupported, Invalid, NotReady, NoMemory, NoResources,
    HardwareError, RecoveryRequired
};
}
#endif
