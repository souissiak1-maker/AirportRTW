/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_SHARED_RTWCORE_HPP
#define AIRPORTRTW_SHARED_RTWCORE_HPP

#include <HAL/ItlHalService.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlDriverController.hpp>

constexpr int RTW_MIN_DBM = -100;

/* Hardware-independent Realtek HAL contract and common frontend defaults.
 * Chip state, firmware loading, transport and hardware callbacks belong in
 * RTWCore88 or RTWCore89. net80211 remains the shared owner of MLME state. */
class RTWCore : public ItlHalService,
                public ItlDriverInfo,
                public ItlDriverController {
    OSDeclareAbstractStructors(RTWCore)
public:
    ItlDriverInfo *getDriverInfo() override { return this; }
    ItlDriverController *getDriverController() override { return this; }
    const char *getFirmwareVersion() override;
    int16_t getBSSNoise() override;
    bool is5GBandSupport() override { return true; }
    UInt32 supportedFeatures() override;
};
#endif
