/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_DIAGNOSTICS_H
#define AIRPORTRTW_DIAGNOSTICS_H
#if defined(DEBUG) && DEBUG
#define RTW_DIAGNOSTICS 1
#define RTW_LOG(...) IOLog(__VA_ARGS__)
#define RTW_DIAGNOSTIC(...) do { __VA_ARGS__; } while (0)
#else
#define RTW_DIAGNOSTICS 0
#define RTW_LOG(...) do {} while (0)
#define RTW_DIAGNOSTIC(...) do {} while (0)
#endif
#endif
