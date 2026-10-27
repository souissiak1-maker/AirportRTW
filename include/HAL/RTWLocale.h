/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_LOCALE_H
#define RTW_LOCALE_H
/* Apple regulatory locale ABI; independent of operating-system language. */
enum RTWLocale {
    RTW_LOCALE_UNKNOWN = 0, RTW_LOCALE_FCC = 1, RTW_LOCALE_ETSI = 2,
    RTW_LOCALE_JAPAN = 3, RTW_LOCALE_KOREA = 4, RTW_LOCALE_APAC = 5,
    RTW_LOCALE_ROW = 6, RTW_LOCALE_INDONESIA = 7
};
static inline const char *rtw_locale_name(unsigned int locale)
{
    switch (locale) {
    case RTW_LOCALE_FCC: return "FCC";
    case RTW_LOCALE_ETSI: return "ETSI";
    case RTW_LOCALE_JAPAN: return "Japan";
    case RTW_LOCALE_KOREA: return "Korea";
    case RTW_LOCALE_APAC: return "APAC";
    case RTW_LOCALE_ROW: return "ROW";
    case RTW_LOCALE_INDONESIA: return "Indonesia";
    default: return "Unknown";
    }
}
#endif
