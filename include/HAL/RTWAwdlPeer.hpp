/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_PEER_HPP
#define RTW_AWDL_PEER_HPP
#include <stdint.h>
namespace RTWAwdl {
enum class PeerResult : uint8_t {
    Success, Unsupported, Invalid, NotReady, NoMemory, NoResources,
    HardwareError, RecoveryRequired
};
// Shared hardware contract. Stop peer TX producers before removing a peer.
// RecoveryRequired keeps the HAL allocation alive until cleanup/device fencing.
class PeerHardware {
public:
    virtual ~PeerHardware() = default;
    virtual uint32_t awdlPeerCapacity() const { return 0; }
    virtual PeerResult setAwdlPeer(const uint8_t[6], bool) { return PeerResult::Unsupported; }
};
}
#endif
