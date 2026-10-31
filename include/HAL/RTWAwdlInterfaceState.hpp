/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_INTERFACE_STATE_HPP
#define RTW_AWDL_INTERFACE_STATE_HPP
#include <stddef.h>
namespace RTWAwdl {
// Owned by the HAL context. All operations require its hardware serialization
// and quiesced producers before removal; this record owns no protocol state.
struct InterfaceState {
    void *vif;
    size_t allocationSize;
    size_t txqAllocationSize;
    bool hardwareAdded;
    bool registered;
};
}
#endif
