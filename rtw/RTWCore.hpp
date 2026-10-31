/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_SHARED_RTWCORE_HPP
#define AIRPORTRTW_SHARED_RTWCORE_HPP

#include <HAL/ItlHalService.hpp>
#include <HAL/RTWAwdlReceive.hpp>
#include <HAL/RTWAwdlRadio.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlDriverController.hpp>

constexpr int RTW_MIN_DBM = -100;

/* Hardware-independent Realtek HAL contract and common frontend defaults.
 * Chip state, firmware loading, transport and hardware callbacks belong in
 * RTWCore88 or RTWCore89. net80211 remains the shared owner of MLME state. */
class RTWCore : public ItlHalService,
                public ItlDriverInfo,
                public ItlDriverController,
                public RTWAwdl::Radio {
    OSDeclareAbstractStructors(RTWCore)
public:
    ItlDriverInfo *getDriverInfo() override { return this; }
    ItlDriverController *getDriverController() override { return this; }
    const char *getFirmwareVersion() override;
    int16_t getBSSNoise() override;
    bool is5GBandSupport() override { return true; }
    UInt32 supportedFeatures() override;
    // Native protocol code uses this hardware-independent contract. Control
    // operations run on the controller workloop; RX callbacks only copy/enqueue.
    virtual bool addAwdlInterface(const uint8_t mac[6]) = 0;
    virtual void removeAwdlInterface() = 0;
    virtual bool setAwdlReceiver(OSObject *, RTWAwdl::ReceiveHandler) = 0;
    virtual bool transmitAwdlAction(const uint8_t *, size_t, uint16_t) = 0;
};
#endif
