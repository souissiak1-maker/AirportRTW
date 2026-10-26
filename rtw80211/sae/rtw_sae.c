// SPDX-License-Identifier: GPL-2.0
/* See rtw_sae.h: hostap's sae_data behind a plain interface. */
#include "includes.h"
#include "common.h"
#include "common/defs.h"
#include "ieee802_11_defs.h"
#include "sae.h"

#include "rtw_sae.h"

struct rtw_sae {
    struct sae_data data;
};

struct rtw_sae *rtw_sae_begin(const uint8_t own[6], const uint8_t peer[6],
                                  const uint8_t *password, size_t password_len,
                                  const uint8_t *ssid, size_t ssid_len, int h2e)
{
    if (!own || !peer || !password || !password_len || password_len > 63 ||
        !ssid || !ssid_len || ssid_len > 32 || !memcmp(own, peer, 6)) return NULL;
    struct rtw_sae *sae = os_zalloc(sizeof(*sae));

    if (!sae)
        return NULL;
    if (sae_set_group(&sae->data, 19)) {
        os_free(sae);
        return NULL;
    }
    sae->data.akmp = WPA_KEY_MGMT_SAE;
    int error;
    if (h2e) {
        const int groups[] = {19, 0};
        struct sae_pt *pt = sae_derive_pt(groups, ssid, ssid_len, password, password_len, NULL, 0);
        error = !pt || sae_prepare_commit_pt(&sae->data, pt, own, peer, NULL, NULL);
        sae_deinit_pt(pt);
    } else {
        error = sae_prepare_commit(own, peer, password, password_len, &sae->data);
    }
    if (error) {
        rtw_sae_end(sae);
        return NULL;
    }
    sae->data.state = SAE_COMMITTED;
    return sae;
}

void rtw_sae_end(struct rtw_sae *sae)
{
    if (!sae)
        return;
    sae_clear_data(&sae->data);
    bin_clear_free(sae, sizeof(*sae));
}

static int copy_out(struct wpabuf *buf, uint8_t *out, size_t max)
{
    size_t len = wpabuf_len(buf);

    if (len > max) {
        wpabuf_clear_free(buf);
        return -1;
    }
    memcpy(out, wpabuf_head(buf), len);
    wpabuf_clear_free(buf);
    return (int)len;
}

int rtw_sae_write_commit(struct rtw_sae *sae, const uint8_t *token, size_t token_len,
                           uint8_t *out, size_t max)
{
    if (!sae || !out || (!token && token_len) || token_len > 256) return -1;
    struct wpabuf *buf = wpabuf_alloc(512), *tok = NULL;
    int ret;

    if (!buf)
        return -1;
    if (token && token_len) {
        tok = wpabuf_alloc_copy(token, token_len);
        if (!tok) {
            wpabuf_free(buf);
            return -1;
        }
    }
    ret = sae_write_commit(&sae->data, buf, tok, NULL, 0);
    wpabuf_free(tok);
    if (ret) {
        wpabuf_free(buf);
        return -1;
    }
    return copy_out(buf, out, max);
}

int rtw_sae_rx_commit(struct rtw_sae *sae, const uint8_t *body, size_t len)
{
    if (!sae || !body || len < 98 || len > 512) return -1;
    static int groups[] = { 19, 0 };
    const u8 *token = NULL;
    size_t token_len = 0;
    u16 status;

    status = sae_parse_commit(&sae->data, body, len, &token, &token_len, groups, sae->data.h2e, NULL);
    if (status != WLAN_STATUS_SUCCESS)
        return status;
    if (sae_process_commit(&sae->data))
        return WLAN_STATUS_UNSPECIFIED_FAILURE;
    return 0;
}

int rtw_sae_write_confirm(struct rtw_sae *sae, uint8_t *out, size_t max)
{
    if (!sae || !out || max < 34) return -1;
    struct wpabuf *buf = wpabuf_alloc(64);

    if (!buf)
        return -1;
    /* sae_write_confirm() counts send-confirm itself */
    if (sae_write_confirm(&sae->data, buf)) {
        wpabuf_free(buf);
        return -1;
    }
    sae->data.state = SAE_CONFIRMED;
    return copy_out(buf, out, max);
}

int rtw_sae_rx_confirm(struct rtw_sae *sae, const uint8_t *body, size_t len)
{
    if (!sae || !body || len != 34) return -1;
    if (sae_check_confirm(&sae->data, body, len, NULL))
        return -1;
    sae->data.state = SAE_ACCEPTED;
    return 0;
}

void rtw_sae_keys(const struct rtw_sae *sae, uint8_t pmk[32], uint8_t pmkid[16])
{
    if (!sae || !pmk || !pmkid || sae->data.state != SAE_ACCEPTED) return;
    memcpy(pmk, sae->data.pmk, 32);
    memcpy(pmkid, sae->data.pmkid, 16);
}
