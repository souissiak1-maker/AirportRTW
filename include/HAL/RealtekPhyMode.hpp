/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef REALTEK_PHY_MODE_HPP
#define REALTEK_PHY_MODE_HPP
namespace RealtekPhy {
enum class Mode { Auto, Legacy, HT, VHT, HE };
inline Mode active(bool connected, bool he, bool vht, bool ht)
{
    if (!connected) return Mode::Auto;
    if (he) return Mode::HE;
    if (vht) return Mode::VHT;
    if (ht) return Mode::HT;
    return Mode::Legacy;
}
}
#endif
