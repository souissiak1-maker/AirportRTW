/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _IF_RTW89VAR_H_
#define _IF_RTW89VAR_H_

#include <compat.h>

#include <net80211/ieee80211_var.h>

/*
 * Native OpenBSD net80211 ownership for the rtw89 port.
 *
 * Keep ieee80211com embedded, as iwn/iwm/iwx do.  In particular, this
 * structure must not grow a second scan cache, association state machine, or
 * key store.  Linux-derived rtw89 objects below this boundary represent
 * hardware/firmware state only.
 */
struct rtw89_dev;
struct ieee80211_hw;
struct ieee80211_vif;
struct ieee80211_sta;

struct rtw89_softc {
	struct device sc_dev;
	struct ieee80211com sc_ic;

	/* Original net80211 transition handler wrapped by rtw89_newstate(). */
	int (*sc_newstate)(struct ieee80211com *, enum ieee80211_state, int);

	/* Linux-derived hardware objects; they do not own MLME state. */
	struct rtw89_dev *sc_rtwdev;
	struct ieee80211_hw *sc_hw;
	struct ieee80211_vif *sc_vif;
	struct ieee80211_sta *sc_sta;

	unsigned int sc_flags;
#define RTW89_FLAG_ATTACHED       (1U << 0)
#define RTW89_FLAG_ENABLED        (1U << 1)
#define RTW89_FLAG_SCANNING       (1U << 2)
#define RTW89_FLAG_FW_RUNNING     (1U << 3)
#define RTW89_FLAG_INTERFACE      (1U << 4)

	size_t sc_vif_size;

	int sc_noise;
	char sc_fwver[32];
	char sc_fwname[64];
	char sc_country[3];
};

#endif /* _IF_RTW89VAR_H_ */
