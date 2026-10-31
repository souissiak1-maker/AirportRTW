/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_PACKET_FLOW_HPP
#define RTW_AWDL_PACKET_FLOW_HPP
#include <stddef.h>
#include <stdint.h>
#include "RTWAwdlData.hpp"
namespace RTWAwdl {
// Adapter contract: view borrows packet bytes until completion; send must copy
// them before returning true. A false send means backpressure, without ownership
// transfer. complete transfers the batch only on success; release handles failure.
// All methods run under the native interface workqueue gate.
struct PacketFlow {
    static bool validView(uint32_t buffers, uint64_t base, uint32_t capacity,
                          uint16_t offset, size_t length) {
        return buffers == 1 && base && offset <= capacity &&
            length <= capacity - offset && length >= 14 &&
            length <= 14 + DataCodec::mtu && base <= UINT64_MAX - offset &&
            length <= UINT64_MAX - (base + offset);
    }

    template<class Adapter>
    static uint32_t transmit(Adapter &adapter, void *const *packets, uint32_t count) {
        if (!packets || !count || !adapter.enabled()) return 0;
        void *completed[64];
        uint32_t batch = 0, consumed = 0;
        for (; consumed < count; ++consumed) {
            const uint8_t *bytes = nullptr;
            size_t length = 0;
            if (!packets[consumed]) { adapter.invalid(); continue; }
            if (adapter.view(packets[consumed], bytes, length)) {
                if (!adapter.send(bytes, length)) break;
            } else {
                adapter.invalid();
            }
            completed[batch++] = packets[consumed];
            if (batch == 64) { finish(adapter, completed, batch); batch = 0; }
        }
        if (batch) finish(adapter, completed, batch);
        return consumed;
    }
private:
    template<class Adapter>
    static void finish(Adapter &adapter, void *const *packets, uint32_t count) {
        if (!adapter.complete(packets, count))
            for (uint32_t i = 0; i < count; ++i) adapter.release(packets[i]);
    }
};
}
#endif
