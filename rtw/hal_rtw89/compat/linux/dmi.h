/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_DMI_H
#define _RTW88_COMPAT_DMI_H

#include "types.h"

/*
 * DMI stub for the rtw89 macOS port.  The driver's DMI quirk tables target
 * specific Linux laptops (e.g. PCI BER workarounds); none apply to a Mac,
 * and macOS offers no SMBIOS matching from a kext this shallow.  Matching
 * always fails, so no quirk is ever applied.
 */

enum dmi_field {
    DMI_NONE,
    DMI_BIOS_VENDOR,
    DMI_BIOS_VERSION,
    DMI_SYS_VENDOR,
    DMI_PRODUCT_NAME,
    DMI_PRODUCT_VERSION,
    DMI_PRODUCT_SERIAL,
    DMI_PRODUCT_SKU,
    DMI_PRODUCT_FAMILY,
    DMI_BOARD_VENDOR,
    DMI_BOARD_NAME,
    DMI_BOARD_VERSION,
    DMI_STRING_MAX,
};

struct dmi_strmatch {
    unsigned char slot:7;
    unsigned char exact_match:1;
    char substr[79];
};

struct dmi_system_id {
    int (*callback)(const struct dmi_system_id *);
    const char *ident;
    struct dmi_strmatch matches[4];
    void *driver_data;
};

#define DMI_MATCH(a, b)       { .slot = a, .substr = b }
#define DMI_EXACT_MATCH(a, b) { .slot = a, .substr = b, .exact_match = 1 }

static inline const struct dmi_system_id *
dmi_first_match(const struct dmi_system_id *list)
{
    return NULL;
}

static inline int dmi_check_system(const struct dmi_system_id *list)
{
    return 0;
}

#endif /* _RTW88_COMPAT_DMI_H */
