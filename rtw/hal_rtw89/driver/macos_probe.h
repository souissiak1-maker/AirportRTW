/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW89_MACOS_PROBE_H
#define RTW89_MACOS_PROBE_H
#ifdef RTW89_MACOS
extern void rtw89_macos_chip_stage(const char *stage);
extern void rtw89_macos_poll_failure(unsigned int reg, unsigned int value,
                                     unsigned int mask, unsigned int expected);
#define RTW89_CHIP_STAGE(stage) rtw89_macos_chip_stage(stage)
#define RTW89_POLL_FAILURE(reg, value, mask, expected) \
    rtw89_macos_poll_failure(reg, value, mask, expected)
#else
#define RTW89_CHIP_STAGE(stage) do { } while (0)
#define RTW89_POLL_FAILURE(reg, value, mask, expected) do { } while (0)
#endif
#endif
