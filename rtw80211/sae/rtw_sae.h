/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared net80211 interface to hostap SAE (WPA3-Personal, group 19).
 * Plain types keep hostap's compatibility headers out of both HALs.
 *
 * Message bodies are what follows the Authentication frame's algorithm,
 * sequence number and status code fields.
 */
#ifndef _RTW_SAE_SAE_H
#define _RTW_SAE_SAE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rtw_sae;

/* Password element and own commit for this station and access point. NULL
 * if there is no memory or the password makes no element. */
struct rtw_sae *rtw_sae_begin(const uint8_t own[6], const uint8_t peer[6],
                                  const uint8_t *password, size_t password_len,
                                  const uint8_t *ssid, size_t ssid_len, int h2e);
void rtw_sae_end(struct rtw_sae *sae);

/* Own commit, with the anti-clogging token the AP asked for (or none).
 * Returns the body length, or negative. */
int rtw_sae_write_commit(struct rtw_sae *sae, const uint8_t *token, size_t token_len,
                           uint8_t *out, size_t max);
/* The AP's commit (status 0 or H2E status 126): checked, and the keys derived. Returns 0, or the
 * 802.11 status code to give up with. */
int rtw_sae_rx_commit(struct rtw_sae *sae, const uint8_t *body, size_t len);
/* Own confirm. Returns the body length, or negative. */
int rtw_sae_write_confirm(struct rtw_sae *sae, uint8_t *out, size_t max);
/* The AP's confirm: 0 if it proves the AP has the same password. */
int rtw_sae_rx_confirm(struct rtw_sae *sae, const uint8_t *body, size_t len);
/* After a good confirm: the 32-byte PMK and the 16-byte PMKID. */
void rtw_sae_keys(const struct rtw_sae *sae, uint8_t pmk[32], uint8_t pmkid[16]);

#ifdef __cplusplus
}
#endif

#endif /* _RTW_SAE_SAE_H */
