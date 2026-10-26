/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <sys/param.h>
#include <sys/mbuf.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_proto.h>
#include "../../sae/rtw_sae.h"

mbuf_t ieee80211_getmgmt(int, int, u_int);

struct net80211_sae_session {
    struct rtw_sae *crypto;
    uint8_t peer[6], own[6];
    uint8_t token[256], confirm[34];
    size_t tokenLength;
    unsigned tokenRequests;
    bool h2e, committed, confirmed;
};

void ieee80211_sae_clear(struct ieee80211com *ic, bool credentials)
{
    auto *s = static_cast<net80211_sae_session *>(ic->ic_sae);
    if (s) {
        rtw_sae_end(s->crypto);
        explicit_bzero(s, sizeof(*s));
        ::free(s);
    }
    ic->ic_sae = NULL;
    if (credentials) {
        explicit_bzero(ic->ic_sae_password, sizeof(ic->ic_sae_password));
        ic->ic_sae_password_len = 0;
        ic->ic_sae_enabled = false;
        ic->ic_flags &= ~IEEE80211_F_MFPR;
    }
}

mbuf_t ieee80211_sae_auth(struct ieee80211com *ic, struct ieee80211_node *ni, unsigned seq)
{
    if (!ic->ic_sae_enabled || ni->ni_rsnakms != IEEE80211_AKM_SAE) return NULL;
    auto *s = static_cast<net80211_sae_session *>(ic->ic_sae);
    if (s && (memcmp(s->peer, ni->ni_bssid, 6) || memcmp(s->own, ic->ic_myaddr, 6))) {
        ieee80211_sae_clear(ic, false); s = NULL;
    }
    if (!s) {
        if (seq != 1 || !ic->ic_sae_password_len) return NULL;
        s = static_cast<net80211_sae_session *>(::malloc(sizeof(*s), 0, 0));
        if (!s) return NULL;
        bzero(s, sizeof(*s));
        s->h2e = ni->ni_sae_h2e;
        memcpy(s->peer, ni->ni_bssid, 6); memcpy(s->own, ic->ic_myaddr, 6);
        s->crypto = rtw_sae_begin(s->own, s->peer, ic->ic_sae_password,
            ic->ic_sae_password_len, ni->ni_essid, ni->ni_esslen, s->h2e);
        if (!s->crypto) { explicit_bzero(s, sizeof(*s)); ::free(s); return NULL; }
        ic->ic_sae = s;
        ic->ic_sae_stage = 2;
        RTW_LOG("AirportRTW SAE: authentication started (group=19 h2e=%u)\n", unsigned(s->h2e));
    }
    uint8_t body[512];
    int length = -1;
    if (seq == 1) length = rtw_sae_write_commit(s->crypto, s->token, s->tokenLength, body, sizeof(body));
    else if (seq == 2 && s->committed) {
        if (!s->confirmed) {
            if (rtw_sae_write_confirm(s->crypto, s->confirm, sizeof(s->confirm)) != 34) return NULL;
            s->confirmed = true;
        }
        memcpy(body, s->confirm, 34); length = 34;
    }
    if (length <= 0 || length > int(sizeof(body))) return NULL;
    mbuf_t m = ieee80211_getmgmt(MBUF_DONTWAIT, MT_DATA, length + 6);
    if (!m) { explicit_bzero(body, sizeof(body)); return NULL; }
    auto *p = mtod(m, uint8_t *);
    p[0] = 3; p[1] = 0; p[2] = seq; p[3] = 0;
    p[4] = seq == 1 && s->h2e ? 126 : 0; p[5] = 0;
    memcpy(p + 6, body, length);
    explicit_bzero(body, sizeof(body));
    mbuf_setlen(m, length + 6); mbuf_pkthdr_setlen(m, length + 6);
    return m;
}

void ieee80211_sae_receive(struct ieee80211com *ic, struct ieee80211_node *ni,
    const struct ieee80211_frame *wh, unsigned seq, unsigned status,
    const uint8_t *body, size_t length)
{
    auto *s = static_cast<net80211_sae_session *>(ic->ic_sae);
    if (!s || !ic->ic_sae_enabled || ic->ic_state != IEEE80211_S_AUTH ||
        !IEEE80211_ADDR_EQ(wh->i_addr2, s->peer) ||
        !IEEE80211_ADDR_EQ(wh->i_addr3, s->peer) ||
        !IEEE80211_ADDR_EQ(wh->i_addr1, s->own)) return;
    if (seq == 1 && status == 76 && !s->committed) {
        if (length < 3 || (body[0] | (unsigned(body[1]) << 8)) != 19 || ++s->tokenRequests > 3) return;
        // H2E carries its anti-clogging token in extension element 93.
        const uint8_t *token = body + 2;
        size_t n = length - 2;
        if (s->h2e) {
            if (n < 3 || token[0] != 255 || token[1] < 2 || token[1] > n - 2 || token[2] != 93) return;
            n = token[1] - 1; token += 3;
        }
        if (!n || n > sizeof(s->token)) return;
        memcpy(s->token, token, n); s->tokenLength = n;
        IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_AUTH, 1);
        return;
    }
    if (seq == 1 && status == (s->h2e ? 126u : 0u)) {
        if (!s->committed) {
            int error = rtw_sae_rx_commit(s->crypto, body, length);
            if (error) { ic->ic_sae_error = 0x10000u | unsigned(error); RTW_LOG("AirportRTW SAE: commit rejected (%d)\n", error); return; }
            s->committed = true; ic->ic_sae_stage = 3;
        }
        IEEE80211_SEND_MGMT(ic, ni, IEEE80211_FC0_SUBTYPE_AUTH, 2);
    } else if (seq == 2 && status == 0 && s->confirmed) {
        if (length != 34 || rtw_sae_rx_confirm(s->crypto, body, length)) { ic->ic_sae_error = 0x20000; return; }
        ic->ic_sae_stage = 4; ic->ic_sae_error = 0;
        RTW_LOG("AirportRTW SAE: peer confirmed, starting association\n");
        rtw_sae_keys(s->crypto, ic->ic_psk, ni->ni_pmkid);
        ic->ic_flags |= IEEE80211_F_PSK;
        ni->ni_flags |= IEEE80211_NODE_PMKID;
        ni->ni_port_valid = 0; ni->ni_replaycnt_ok = 0;
        ic->ic_mgt_timer = 0;
        ic->ic_assoc_status = 0xffff;
        ieee80211_new_state(ic, IEEE80211_S_ASSOC, IEEE80211_FC0_SUBTYPE_AUTH);
    }
}
