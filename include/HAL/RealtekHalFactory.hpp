/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_REALTEK_HAL_FACTORY_HPP
#define AIRPORTRTW_REALTEK_HAL_FACTORY_HPP
#include "RealtekPciIds.hpp"
#include "../../rtw/hal_rtw89/RTWCore89.hpp"
#include "../../rtw/hal_rtw88/RTWCore88.hpp"

inline ItlHalService *createRealtekHal(IOPCIDevice *device)
{
    if (!device) return nullptr;
    const auto family = RealtekHal::family(
        device->configRead16(kIOPCIConfigVendorID),
        device->configRead16(kIOPCIConfigDeviceID));
    switch (family) {
    case RealtekHal::Family::RTW88:
        device->setProperty("RTWHALFamily", "RTW88");
        return new RTWCore88;
    case RealtekHal::Family::RTW89:
        device->setProperty("RTWHALFamily", "RTW89");
        return new RTWCore89;
    default: return nullptr;
    }
}
#endif
