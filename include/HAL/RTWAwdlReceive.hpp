/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_RECEIVE_HPP
#define RTW_AWDL_RECEIVE_HPP
#include <stddef.h>
#include <stdint.h>
class OSObject;
namespace RTWAwdl {
struct ReceiveRegistration;
enum class FrameKind : uint8_t { Action, IPv6 };
struct ReceiveMetadata {
    FrameKind kind;
    int32_t rssi;
    uint16_t frequency;
    uint32_t radioTimestamp;
    bool radioTimestampValid;
};
// Runs on the HAL RX worker with a registration lock held. Copy/enqueue only:
// never call the HAL, change this registration, block on a workloop, or retain
// packet pointers. Timestamp is the raw device clock, not a native-family clock.
using ReceiveHandler = void (*)(OSObject *, const uint8_t *, size_t,
                               const ReceiveMetadata &);
}
#endif
