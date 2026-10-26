/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_REALTEK_PCI_IDS_HPP
#define AIRPORTRTW_REALTEK_PCI_IDS_HPP
#include <stdint.h>
namespace RealtekHal {
enum class Family { None, RTW88, RTW89 };
constexpr Family family(uint16_t vendor, uint16_t device)
{
    if (vendor != 0x10ec) return Family::None;
    switch (device) {
    case 0xd723: case 0x8813:
    case 0xc822: case 0xc82f: case 0xb822: case 0xc821: case 0xb821:
        return Family::RTW88;
    case 0x8852: case 0xa85a: case 0xb852: case 0xb85b: case 0xb851:
    case 0xb520: case 0xc852: case 0x8922: case 0x892b:
        return Family::RTW89;
    default: return Family::None;
    }
}
}
#endif
