/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_RADIO_STATUS_H
#define RTW_AWDL_RADIO_STATUS_H
/* Hardware-neutral diagnostic bits shared with C HAL adapters. They explain a
 * snapshot, never grant a capability or authorize transmit/retune operations. */
enum RtwAwdlRadioBlocker {
    RTW_AWDL_RADIO_UNAVAILABLE       = 1U << 0,
    RTW_AWDL_RADIO_STOPPED           = 1U << 1,
    RTW_AWDL_RADIO_PRIMARY_MISSING   = 1U << 2,
    RTW_AWDL_RADIO_SCANNING          = 1U << 3,
    RTW_AWDL_RADIO_RECOVERY          = 1U << 4,
    RTW_AWDL_RADIO_SECONDARY_MISSING = 1U << 5,
    RTW_AWDL_RADIO_SECONDARY_NOT_ADDED = 1U << 6,
    RTW_AWDL_RADIO_SECONDARY_NOT_REGISTERED = 1U << 7,
    RTW_AWDL_RADIO_PRIMARY_NOT_AUTHORIZED = 1U << 8,
    RTW_AWDL_RADIO_TX_PAUSED         = 1U << 9,
    RTW_AWDL_RADIO_CHANNEL_MISSING   = 1U << 10,
    RTW_AWDL_RADIO_SECONDARY_ROC_NOT_MANUAL = 1U << 11,
    RTW_AWDL_RADIO_SECONDARY_ROC_NOT_ON_CHANNEL = 1U << 12,
    RTW_AWDL_RADIO_OTHER_ROC_ACTIVE  = 1U << 13,
    RTW_AWDL_RADIO_HOME_CHANNEL_MISSING = 1U << 14,
    RTW_AWDL_RADIO_SECONDARY_INVALID = 1U << 15
};
#endif
