/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "RTWCore.hpp"

OSDefineMetaClassAndAbstractStructors(RTWCore, ItlHalService)

const char *RTWCore::getFirmwareVersion()
{
    return "AirportRTW2.2.0";
}

int16_t RTWCore::getBSSNoise()
{
    /* The Apple80211 result path negates this magnitude to -95 dBm. */
    return 95;
}

UInt32 RTWCore::supportedFeatures()
{
    return kIONetworkFeatureMultiPages;
}
