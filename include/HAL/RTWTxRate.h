/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_TX_RATE_H
#define AIRPORTRTW_TX_RATE_H
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

enum RTWRateMode { RTW_RATE_LEGACY, RTW_RATE_HT, RTW_RATE_VHT, RTW_RATE_HE };
/* A firmware TX-rate sample, not the maximum supported link rate. */
struct RTWTxRate {
    uint32_t bitrate100Kbps;
    uint16_t widthMHz;
    uint8_t mcs; /* HT: combined 0..31; VHT: per-stream 0..9; HE: per-stream 0..11. */
    uint8_t nss;
    uint8_t mode;
    bool shortGI;
    bool valid;
    uint16_t guardIntervalNs; /* HE: 800, 1600 or 3200; HT/VHT: 400 or 800. */
    bool dcm; /* HE dual-carrier modulation, when supplied by firmware. */
};

/* HT/VHT/HE PHY rates in 100 kbps, with cfg80211-compatible units.
 * HT/VHT rounding follows cfg80211; HE uses modulation and symbol timing.
 * Modulation rates are numeric protocol data; the HAL supplies actual NSS,
 * width and guard interval rather than substituting advertised capabilities.
 */
static inline uint32_t rtw_tx_rate_calculate(const struct RTWTxRate *rate)
{
    uint64_t bits;
    if (!rate) return 0;
    if (rate->mode == RTW_RATE_LEGACY) return rate->bitrate100Kbps;
    if (rate->mode == RTW_RATE_HE) {
        /* HE has a 12.8 us useful symbol. Full-channel data subcarriers:
         * 234/468/980/1960 for 20/40/80/160 MHz, respectively.
         */
        static const uint8_t numerators[12] = {1,1,3,2,3,4,9,5,6,20,15,25};
        static const uint8_t denominators[12] = {2,1,2,1,1,1,2,1,1,3,2,3};
        uint32_t carriers;
        uint64_t denominator, numerator;
        if (rate->mcs > 11 || rate->nss < 1 || rate->nss > 8) return 0;
        if (rate->guardIntervalNs != 800 && rate->guardIntervalNs != 1600 &&
            rate->guardIntervalNs != 3200) return 0;
        if (rate->dcm && (rate->nss > 2 || (rate->mcs != 0 && rate->mcs != 1 &&
            rate->mcs != 3 && rate->mcs != 4))) return 0;
        switch (rate->widthMHz) {
        case 20: carriers=234; break;
        case 40: carriers=468; break;
        case 80: carriers=980; break;
        case 160: carriers=1960; break;
        default: return 0;
        }
        numerator = (uint64_t)carriers * numerators[rate->mcs] * rate->nss * 10000;
        denominator = (12800 + rate->guardIntervalNs) * denominators[rate->mcs];
        if (rate->dcm) denominator *= 2;
        return (uint32_t)((numerator + denominator / 2) / denominator);
    }
    if (rate->mode == RTW_RATE_HT) {
        static const uint8_t factors[8] = {1, 2, 3, 4, 6, 8, 9, 10};
        if (rate->mcs > 31 || (rate->widthMHz != 20 && rate->widthMHz != 40)) return 0;
        bits = (rate->widthMHz == 40 ? 13500000ULL : 6500000ULL) *
            factors[rate->mcs & 7] * (rate->mcs / 8 + 1);
    } else if (rate->mode == RTW_RATE_VHT) {
        static const uint32_t base[4][10] = {
            {6500000,13000000,19500000,26000000,39000000,52000000,58500000,65000000,78000000,86700000},
            {13500000,27000000,40500000,54000000,81000000,108000000,121500000,135000000,162000000,180000000},
            {29300000,58500000,87800000,117000000,175500000,234000000,263300000,292500000,351000000,390000000},
            {58500000,117000000,175500000,234000000,351000000,468000000,526500000,585000000,702000000,780000000}
        };
        unsigned index;
        if (rate->mcs > 9 || rate->nss < 1 || rate->nss > 4) return 0;
        switch (rate->widthMHz) {
        case 20: index=0; break;
        case 40: index=1; break;
        case 80: index=2; break;
        case 160: index=3; break;
        default: return 0;
        }
        bits = (uint64_t)base[index][rate->mcs] * rate->nss;
    } else return 0;
    if (rate->shortGI) bits = (bits / 9) * 10;
    return (uint32_t)((bits + 50000) / 100000);
}
#endif
