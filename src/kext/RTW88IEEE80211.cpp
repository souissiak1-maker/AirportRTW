/* 0.2.226: persistent BSSID refresh experiment. Keep the 0.2.217/0.2.225
 * in-place BSSID cache, extend backend retention, and prioritize channels for
 * already-known APs so real beacon/probe observations refresh truthful age
 * before Tahoe consumes scan results. No SSID is special-cased. */
/* 0.2.209: stabilize disconnected Apple scan snapshots with a bounded
 * recent-BSS window anchored by current-generation RF evidence; retain true
 * observation ages and add scan-completion RSSI transition diagnostics. */
/* 0.2.182: resolve contradictory open/security scan observations at a
 * completed scan-generation boundary so one Privacy=0 sample cannot erase
 * persistent RSN state seen elsewhere in the same scan. */
/* 0.2.180: make each live BSS own persistent RSN/WPA security state and
 * merge beacon/probe refreshes so incomplete frames cannot downgrade a known
 * secure BSSID to cipher/AKM zero. */
/* 0.2.179: expose a locked live-BSS connect-target snapshot so Apple80211
 * security classification and the backend association select the same BSS. */
/* 0.2.163: add an IO80211Reference-style Apple RSN supplicant bridge for WPA2 joins. */
/* 0.2.161: decline RX ADDBA while the A-MPDU datapath is disabled. */
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// RTW88IEEE80211.cpp — 802.11 state machine

#include "RTW88IEEE80211.hpp"

/* 0.2.159: IORegistry publication is intentionally disabled on the packet
 * hot path. setProperty() allocates/locks and was being called many times per
 * TX/RX packet, collapsing throughput. Keep counters in memory and publish
 * aggregate snapshots from the one-second controller poll instead. */
#define RTW89_PER_PACKET_IOREG_DIAGNOSTICS 0
#include "RTW88PCIDevice.hpp"
#include "RTW88UserClient.hpp"

#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <sys/mbuf.h>
#include <string.h>
#include <sys/random.h>

/* Debug stage checkpoint — logs message only (no sleep). */
#define RTW88_STAGE(fmt, ...) IOLog("rtw88: ---- STAGE: " fmt " ----\n", ##__VA_ARGS__)

/* Chain-safe packet mbuf builder (defined below). */
static mbuf_t rtw88_make_packet_mbuf(const void *src, uint32_t len);

static size_t rtw88_bounded_string_length(const char *text, size_t maximum)
{
    size_t length = 0;
    if (!text)
        return 0;
    while (length < maximum && text[length] != '\0')
        ++length;
    return length;
}

/* 0.2.226 scan/cache stability policy. Backend identity retention and Apple
 * snapshot visibility are deliberately separate from observation freshness.
 * A BSSID can live for five minutes without being deleted, but its last_seen_ns
 * advances only when processScanResult() receives a real beacon/probe response.
 * Apple therefore still receives truthful age and may impose its own maxAge.
 * The longer window prevents our own generation/timeout policy from deleting a
 * physically persistent AP before a later channel visit can refresh it. */
static const uint32_t kRTW88ConnectedScanSliceChannels = 6;
static const uint64_t kRTW88ConnectedScanVisibleNs = 300000000000ULL; /* 5 min */
static const uint64_t kRTW88DisconnectedScanVisibleNs = 300000000000ULL; /* 5 min */
static const uint64_t kRTW88PersistentBSSExpireNs = 300000000000ULL; /* 5 min */
static const uint64_t kRTW88RSSISentinelHoldNs = 30000000000ULL; /* 30 s */
static const uint32_t kRTW88PriorityFrequencyCapacity = 32;

static uint64_t rtw88_now_ns()
{
    uint64_t nowNs = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nowNs);
    return nowNs;
}

extern "C" {
#include "../compat/rtw88_compat.h"

/* Linux driver public API */
int  rtw_core_init(struct rtw_dev *rtwdev);
void rtw_core_deinit(struct rtw_dev *rtwdev);
int  rtw_core_start(struct rtw_dev *rtwdev);
void rtw_core_stop(struct rtw_dev *rtwdev);
void rtw_tx(struct rtw_dev *rtwdev, struct ieee80211_tx_control *control,
            struct sk_buff *skb);

/* PCI probe shim declared in pci.c */
int  rtw_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void rtw_pci_remove(struct pci_dev *pdev);

/* Exported from the compat layer for hooking */
void rtw88_set_hw_callbacks(struct rtw88_hw_callbacks *cbs, void *kext_hw);

/* chip hw_spec structs — driver_data for rtw_pci_probe */
#ifndef RTW89_MACOS
extern const struct rtw_chip_info rtw8822b_hw_spec;
extern const struct rtw_chip_info rtw8822c_hw_spec;
extern const struct rtw_chip_info rtw8821c_hw_spec;
extern const struct rtw_chip_info rtw8821a_hw_spec;
extern const struct rtw_chip_info rtw8812a_hw_spec;
extern const struct rtw_chip_info rtw8814a_hw_spec;
#endif

} /* extern "C" */

/* 0.3.4: mac80211 normally serializes configuration callbacks with the
 * wiphy mutex. AirportRTW89 invokes several callbacks directly, so restore
 * that caller contract for the rtw89 build only. */
class RTW89CompatWiphyGuard {
public:
    explicit RTW89CompatWiphyGuard(struct ieee80211_hw *hw) : _hw(hw)
    {
#ifdef RTW89_MACOS
        if (_hw && _hw->wiphy && _hw->wiphy->serialize_lock.m) {
            if (!mutex_trylock(&_hw->wiphy->serialize_lock)) {
                __sync_fetch_and_add(&_hw->wiphy->serialize_lock_contention_count, 1);
                mutex_lock(&_hw->wiphy->serialize_lock);
            }
            __sync_fetch_and_add(&_hw->wiphy->serialize_lock_acquire_count, 1);
            _locked = true;
        }
#endif
    }
    ~RTW89CompatWiphyGuard()
    {
#ifdef RTW89_MACOS
        if (_locked) mutex_unlock(&_hw->wiphy->serialize_lock);
#endif
    }
private:
    struct ieee80211_hw *_hw = nullptr;
    bool _locked = false;
};

/* ------------------------------------------------------------------ */
/*  WPA2 cryptographic functions (SHA1, HMAC-SHA1, PBKDF2, PRF)      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} KERN_SHA1_CTX;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | (rol(block->l[i], 8) & 0x00FF00FF))
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

#define r0(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30);
#define r1(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30);
#define r2(v,w,x,y,z,i) z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define r3(v,w,x,y,z,i) z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); w = rol(w, 30);
#define r4(v,w,x,y,z,i) z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); w = rol(w, 30);

static void kern_sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union {
        uint8_t c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16 block[1];
    memcpy(block, buffer, 64);
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    r0(a,b,c,d,e,0);  r0(e,a,b,c,d,1);  r0(d,e,a,b,c,2);  r0(c,d,e,a,b,3);
    r0(b,c,d,e,a,4);  r0(a,b,c,d,e,5);  r0(e,a,b,c,d,6);  r0(d,e,a,b,c,7);
    r0(c,d,e,a,b,8);  r0(b,c,d,e,a,9);  r0(a,b,c,d,e,10); r0(e,a,b,c,d,11);
    r0(d,e,a,b,c,12); r0(c,d,e,a,b,13); r0(b,c,d,e,a,14); r0(a,b,c,d,e,15);
    r1(e,a,b,c,d,16); r1(d,e,a,b,c,17); r1(c,d,e,a,b,18); r1(b,c,d,e,a,19);
    r2(a,b,c,d,e,20); r2(e,a,b,c,d,21); r2(d,e,a,b,c,22); r2(c,d,e,a,b,23);
    r2(b,c,d,e,a,24); r2(a,b,c,d,e,25); r2(e,a,b,c,d,26); r2(d,e,a,b,c,27);
    r2(c,d,e,a,b,28); r2(b,c,d,e,a,29); r2(a,b,c,d,e,30); r2(e,a,b,c,d,31);
    r2(d,e,a,b,c,32); r2(c,d,e,a,b,33); r2(b,c,d,e,a,34); r2(a,b,c,d,e,35);
    r2(e,a,b,c,d,36); r2(d,e,a,b,c,37); r2(c,d,e,a,b,38); r2(b,c,d,e,a,39);
    r3(a,b,c,d,e,40); r3(e,a,b,c,d,41); r3(d,e,a,b,c,42); r3(c,d,e,a,b,43);
    r3(b,c,d,e,a,44); r3(a,b,c,d,e,45); r3(e,a,b,c,d,46); r3(d,e,a,b,c,47);
    r3(c,d,e,a,b,48); r3(b,c,d,e,a,49); r3(a,b,c,d,e,50); r3(e,a,b,c,d,51);
    r3(d,e,a,b,c,52); r3(c,d,e,a,b,53); r3(b,c,d,e,a,54); r3(a,b,c,d,e,55);
    r3(e,a,b,c,d,56); r3(d,e,a,b,c,57); r3(c,d,e,a,b,58); r3(b,c,d,e,a,59);
    r4(a,b,c,d,e,60); r4(e,a,b,c,d,61); r4(d,e,a,b,c,62); r4(c,d,e,a,b,63);
    r4(b,c,d,e,a,64); r4(a,b,c,d,e,65); r4(e,a,b,c,d,66); r4(d,e,a,b,c,67);
    r4(c,d,e,a,b,68); r4(b,c,d,e,a,69); r4(a,b,c,d,e,70); r4(e,a,b,c,d,71);
    r4(d,e,a,b,c,72); r4(c,d,e,a,b,73); r4(b,c,d,e,a,74); r4(a,b,c,d,e,75);
    r4(e,a,b,c,d,76); r4(d,e,a,b,c,77); r4(c,d,e,a,b,78); r4(b,c,d,e,a,79);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void kern_sha1_init(KERN_SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

static void kern_sha1_update(KERN_SHA1_CTX *context, const uint8_t *data, uint32_t len) {
    uint32_t i, j;
    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        kern_sha1_transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            kern_sha1_transform(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

static void kern_sha1_final(uint8_t digest[20], KERN_SHA1_CTX *context) {
    unsigned char finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    unsigned char c = 0200;
    kern_sha1_update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0;
        kern_sha1_update(context, &c, 1);
    }
    kern_sha1_update(context, finalcount, 8);
    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

static void kern_hmac_sha1(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t mac[20])
{
    KERN_SHA1_CTX ctx;
    uint8_t k_ipad[64] = {};
    uint8_t k_opad[64] = {};
    uint8_t tmp_key[20];

    if (key_len > 64) {
        kern_sha1_init(&ctx);
        kern_sha1_update(&ctx, key, (uint32_t)key_len);
        kern_sha1_final(tmp_key, &ctx);
        key = tmp_key;
        key_len = 20;
    }

    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    kern_sha1_init(&ctx);
    kern_sha1_update(&ctx, k_ipad, 64);
    kern_sha1_update(&ctx, data, (uint32_t)data_len);
    kern_sha1_final(mac, &ctx);

    kern_sha1_init(&ctx);
    kern_sha1_update(&ctx, k_opad, 64);
    kern_sha1_update(&ctx, mac, 20);
    kern_sha1_final(mac, &ctx);
}

static void derivePMK(const uint8_t *passphrase, const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32])
{
    size_t pass_len = strlen((const char *)passphrase);
    uint8_t salt[128];
    if (ssid_len > 120) ssid_len = 120;
    memcpy(salt, ssid, ssid_len);

    for (int block = 1; block <= 2; block++) {
        salt[ssid_len]     = (uint8_t)((block >> 24) & 0xff);
        salt[ssid_len + 1] = (uint8_t)((block >> 16) & 0xff);
        salt[ssid_len + 2] = (uint8_t)((block >> 8) & 0xff);
        salt[ssid_len + 3] = (uint8_t)(block & 0xff);

        uint8_t u[20];
        uint8_t t[20];
        kern_hmac_sha1(passphrase, pass_len, salt, ssid_len + 4, u);
        memcpy(t, u, 20);

        for (int iter = 1; iter < 4096; iter++) {
            kern_hmac_sha1(passphrase, pass_len, u, 20, u);
            for (int i = 0; i < 20; i++) {
                t[i] ^= u[i];
            }
        }

        if (block == 1) {
            memcpy(pmk, t, 20);
        } else {
            memcpy(pmk + 20, t, 12);
        }
    }
}

static void derivePTK(const uint8_t pmk[32], const uint8_t anonce[32], const uint8_t snonce[32],
                      const uint8_t spa[6], const uint8_t aa[6], uint8_t ptk[64])
{
    uint8_t min_mac[6], max_mac[6];
    if (memcmp(spa, aa, 6) < 0) {
        memcpy(min_mac, spa, 6);
        memcpy(max_mac, aa, 6);
    } else {
        memcpy(min_mac, aa, 6);
        memcpy(max_mac, spa, 6);
    }

    uint8_t min_nonce[32], max_nonce[32];
    if (memcmp(snonce, anonce, 32) < 0) {
        memcpy(min_nonce, snonce, 32);
        memcpy(max_nonce, anonce, 32);
    } else {
        memcpy(min_nonce, anonce, 32);
        memcpy(max_nonce, snonce, 32);
    }

    uint8_t data[100];
    const char *label = "Pairwise key expansion";
    memcpy(data, label, 22);
    data[22] = 0;
    memcpy(data + 23, min_mac, 6);
    memcpy(data + 29, max_mac, 6);
    memcpy(data + 35, min_nonce, 32);
    memcpy(data + 67, max_nonce, 32);
    size_t data_len = 23 + 6 + 6 + 32 + 32;

    uint8_t hash[20];
    for (int i = 0; i < 4; i++) {
        data[data_len] = (uint8_t)i;
        kern_hmac_sha1(pmk, 32, data, data_len + 1, hash);
        if (i < 3) {
            memcpy(ptk + i * 20, hash, 20);
        } else {
            memcpy(ptk + i * 20, hash, 4);
        }
    }
}

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static uint8_t aes_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static uint8_t aes_mul(uint8_t x, uint8_t y)
{
    uint8_t r = 0;
    while (y) {
        if (y & 1) r ^= x;
        x = aes_xtime(x);
        y >>= 1;
    }
    return r;
}

static void aes128_key_expand(const uint8_t key[16], uint8_t round_key[176])
{
    static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    memcpy(round_key, key, 16);
    for (int bytes = 16, r = 0; bytes < 176; bytes += 4) {
        uint8_t t[4];
        memcpy(t, round_key + bytes - 4, 4);
        if ((bytes & 15) == 0) {
            uint8_t tmp = t[0];
            t[0] = aes_sbox[t[1]] ^ rcon[r++];
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[tmp];
        }
        for (int i = 0; i < 4; i++)
            round_key[bytes + i] = round_key[bytes - 16 + i] ^ t[i];
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *rk)
{
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void aes_inv_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void aes_inv_sub_bytes(uint8_t s[16])
{
    for (int i = 0; i < 16; i++) s[i] = aes_rsbox[s[i]];
}

static void aes_inv_mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t *p = s + c * 4;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = aes_mul(a0, 0x0e) ^ aes_mul(a1, 0x0b) ^ aes_mul(a2, 0x0d) ^ aes_mul(a3, 0x09);
        p[1] = aes_mul(a0, 0x09) ^ aes_mul(a1, 0x0e) ^ aes_mul(a2, 0x0b) ^ aes_mul(a3, 0x0d);
        p[2] = aes_mul(a0, 0x0d) ^ aes_mul(a1, 0x09) ^ aes_mul(a2, 0x0e) ^ aes_mul(a3, 0x0b);
        p[3] = aes_mul(a0, 0x0b) ^ aes_mul(a1, 0x0d) ^ aes_mul(a2, 0x09) ^ aes_mul(a3, 0x0e);
    }
}

static void aes128_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[176];
    uint8_t s[16];
    aes128_key_expand(key, rk);
    memcpy(s, in, 16);
    aes_add_round_key(s, rk + 160);
    for (int round = 9; round >= 1; round--) {
        aes_inv_shift_rows(s);
        aes_inv_sub_bytes(s);
        aes_add_round_key(s, rk + round * 16);
        aes_inv_mix_columns(s);
    }
    aes_inv_shift_rows(s);
    aes_inv_sub_bytes(s);
    aes_add_round_key(s, rk);
    memcpy(out, s, 16);
}

static bool aes_unwrap_128(const uint8_t kek[16], const uint8_t *in,
                           uint16_t in_len, uint8_t *out, uint16_t *out_len)
{
    if (in_len < 16 || (in_len & 7))
        return false;

    uint8_t a[8];
    uint8_t r[32][8];
    int n = in_len / 8 - 1;
    if (n <= 0 || n > 32)
        return false;

    memcpy(a, in, 8);
    for (int i = 0; i < n; i++)
        memcpy(r[i], in + 8 + i * 8, 8);

    for (int j = 5; j >= 0; j--) {
        for (int i = n - 1; i >= 0; i--) {
            uint8_t block[16], plain[16];
            uint64_t t = (uint64_t)(n * j + i + 1);
            memcpy(block, a, 8);
            for (int k = 7; k >= 0 && t; k--, t >>= 8)
                block[k] ^= (uint8_t)(t & 0xff);
            memcpy(block + 8, r[i], 8);
            aes128_decrypt_block(kek, block, plain);
            memcpy(a, plain, 8);
            memcpy(r[i], plain + 8, 8);
        }
    }

    static const uint8_t iv[8] = {0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6};
    if (memcmp(a, iv, 8) != 0)
        return false;

    for (int i = 0; i < n; i++)
        memcpy(out + i * 8, r[i], 8);
    *out_len = (uint16_t)(n * 8);
    return true;
}

static bool eapol_mic_ok(const uint8_t kck[16], const uint8_t *eapol,
                         uint32_t eapol_len)
{
    if (eapol_len < 99)
        return false;

    uint8_t *tmp = (uint8_t *)IOMalloc(eapol_len);
    if (!tmp)
        return false;

    memcpy(tmp, eapol, eapol_len);
    uint8_t rx_mic[16];
    memcpy(rx_mic, tmp + 81, sizeof(rx_mic));
    memset(tmp + 81, 0, sizeof(rx_mic));

    uint8_t mic[20];
    kern_hmac_sha1(kck, 16, tmp, eapol_len, mic);
    IOFree(tmp, eapol_len);
    return memcmp(rx_mic, mic, sizeof(rx_mic)) == 0;
}

static bool extract_gtk_from_kde(const uint8_t *key_data, uint16_t key_data_len,
                                 uint8_t gtk[32], uint8_t *gtk_len,
                                 uint8_t *gtk_idx)
{
    const uint8_t rsn_gtk_oui[4] = {0x00, 0x0f, 0xac, 0x01};

    for (uint16_t pos = 0; pos + 2 <= key_data_len; ) {
        uint8_t id = key_data[pos];
        uint8_t len = key_data[pos + 1];
        const uint8_t *body = key_data + pos + 2;
        if (pos + 2 + len > key_data_len)
            break;

        if (id == 0xdd && len >= 6 && memcmp(body, rsn_gtk_oui, 4) == 0) {
            uint8_t key_len = (uint8_t)(len - 6);
            if (key_len > 32)
                return false;
            *gtk_idx = body[4] & 0x3;
            *gtk_len = key_len;
            memcpy(gtk, body + 6, key_len);
            return true;
        }
        pos += 2 + len;
    }

    return false;
}

#undef rol
#undef blk0
#undef blk
#undef r0
#undef r1
#undef r2
#undef r3
#undef r4

/* PCI device-ID → chip_info lookup (PCIe chips only) */
struct rtw88_pci_id_entry {
    uint16_t device;
    const struct rtw_chip_info *chip;
};

#ifdef RTW89_MACOS
/* rtw89: chip lookup happens inside the driver bridge (Senmiko.c),
 * which matches the real per-chip id tables; this kext-side table only
 * gates known PCI device ids, so the chip pointer is a dummy tag. */
#define RTW89_CHIP_TAG ((const struct rtw_chip_info *)1)
static const struct rtw88_pci_id_entry rtw88_pci_chip_table[] = {
    { 0xB851, RTW89_CHIP_TAG },  /* RTL8851BE */
    { 0x8852, RTW89_CHIP_TAG },  /* RTL8852AE */
    { 0xA85A, RTW89_CHIP_TAG },  /* RTL8852AE variant */
    { 0xB852, RTW89_CHIP_TAG },  /* RTL8852BE */
    { 0xB85B, RTW89_CHIP_TAG },  /* RTL8852BE variant */
    { 0xB520, RTW89_CHIP_TAG },  /* RTL8852BTE */
    { 0xC852, RTW89_CHIP_TAG },  /* RTL8852CE */
    { 0x8922, RTW89_CHIP_TAG },  /* RTL8922AE */
    { 0x892B, RTW89_CHIP_TAG },  /* RTL8922AE variant */
    { 0, nullptr }
};
#else
static const struct rtw88_pci_id_entry rtw88_pci_chip_table[] = {
    { 0xB822, &rtw8822b_hw_spec },  /* RTL8822BE */
    { 0xC822, &rtw8822c_hw_spec },  /* RTL8822CE */
    { 0xC82F, &rtw8822c_hw_spec },  /* RTL8822CE variant */
    { 0xC821, &rtw8821c_hw_spec },  /* RTL8821CE */
    { 0xB821, &rtw8821c_hw_spec },  /* RTL8821CE variant */
    { 0x8821, &rtw8821a_hw_spec },  /* RTL8821AE */
    { 0x8812, &rtw8812a_hw_spec },  /* RTL8812AE */
    { 0x8813, &rtw8814a_hw_spec },  /* RTL8814AE */
    { 0, nullptr }
};
#endif

/* Forward declaration of hw_callbacks struct from compat.c */
struct rtw88_hw_callbacks {
    void (*rx_frame)(void *kext_hw, struct sk_buff *skb);
    void (*tx_status)(void *kext_hw, struct sk_buff *skb);
    void (*scan_done)(void *kext_hw, bool aborted);
};

#define super OSObject
/* One extra macro-expansion level so a -DRTW88Foo=RTW89Foo class rename
 * (rtw89 kext build) also renames the OSMetaClass name string:
 * arguments used plainly in a macro body are expanded before being
 * passed to OSDefineMetaClassAndStructors' internal stringify. */
#define RTW_DEFINE_METACLASS(cls, super) OSDefineMetaClassAndStructors(cls, super)
RTW_DEFINE_METACLASS(RTW88IEEE80211, OSObject)

/* 0.2.43: peer-NSS bootstrap + RA payload audit bridge.  There is one active
 * RTW88IEEE80211 instance for this PCI device. */
static RTW88IEEE80211 *g_assoc_probe_instance = nullptr;

/* ------------------------------------------------------------------ */
/*  Static compat callbacks                                             */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::compat_rx_frame(void *kext_hw, struct sk_buff *skb)
{
    RTW88IEEE80211 *self = (RTW88IEEE80211 *)kext_hw;
    if (self) self->rxFrame(skb);
}

void RTW88IEEE80211::compat_tx_status(void *kext_hw, struct sk_buff *skb)
{
    RTW88IEEE80211 *self = (RTW88IEEE80211 *)kext_hw;
    if (self) self->txStatus(skb);
    kfree_skb(skb);
}

void RTW88IEEE80211::compat_scan_done(void *kext_hw, bool aborted)
{
    RTW88IEEE80211 *self = (RTW88IEEE80211 *)kext_hw;
    if (self) self->scanDone(aborted);
}

/* ------------------------------------------------------------------ */
/*  Factory / init / free                                               */
/* ------------------------------------------------------------------ */

RTW88IEEE80211 *RTW88IEEE80211::create(RTW88PCIDevice *dev, struct pci_dev *pci)
{
    RTW88IEEE80211 *obj = new RTW88IEEE80211;
    if (obj && !obj->init(dev, pci)) {
        obj->release();
        return nullptr;
    }
    return obj;
}

bool RTW88IEEE80211::init(RTW88PCIDevice *dev, struct pci_dev *pci)
{
    if (!super::init()) return false;
    _parent = dev;
    _pcidev = pci;

    _lock    = IOLockAlloc();
    _bssLock = IOLockAlloc();
    if (!_lock || !_bssLock) return false;

    _connectTC = thread_call_allocate((thread_call_func_t)RTW88IEEE80211::connectTCFn,
                                       (thread_call_param_t)this);
    _manualScanTC = thread_call_allocate((thread_call_func_t)RTW88IEEE80211::manualScanTCFn,
                                          (thread_call_param_t)this);

    /* Install callbacks into compat layer */
    static struct rtw88_hw_callbacks cbs = {
        .rx_frame  = RTW88IEEE80211::compat_rx_frame,
        .tx_status = RTW88IEEE80211::compat_tx_status,
        .scan_done = RTW88IEEE80211::compat_scan_done,
    };
    rtw88_set_hw_callbacks(&cbs, this);

    /* Set up workloop / timer for state machine */
    _wl = IOWorkLoop::workLoop();
    if (!_wl) return false;

    _gate = IOCommandGate::commandGate(this);
    if (!_gate) return false;
    _wl->addEventSource(_gate);

    _timer = IOTimerEventSource::timerEventSource(this,
        &RTW88IEEE80211::timerFired);
    if (!_timer) return false;
    _wl->addEventSource(_timer);

    /* RX A-MPDU reorder: lock + hole-flush timer.  The timer lives on the
     * RX/interrupt workloop (not _wl) so reorder-released frames and normal RX
     * frames are delivered from the same thread — injectRxFrame's queue+flush
     * is not safe against concurrent callers. */
    _rxBaLock = IOLockAlloc();
    if (!_rxBaLock) return false;
    IOWorkLoop *rxwl = _parent ? _parent->getRxWorkLoop() : nullptr;
    if (!rxwl) return false;
    _reorderTimer = IOTimerEventSource::timerEventSource(this,
        &RTW88IEEE80211::reorderTimerFired);
    if (!_reorderTimer) return false;
    rxwl->addEventSource(_reorderTimer);

    g_assoc_probe_instance = this;
    IOLog("rtw88: RTW88IEEE80211 initialized\n");
    return true;
}

void RTW88IEEE80211::free()
{
    if (g_assoc_probe_instance == this)
        g_assoc_probe_instance = nullptr;
    clearKeys();
    releaseSta();
    rxBaTeardownAll();
    if (_reorderTimer) {
        IOWorkLoop *rxwl = _parent ? _parent->getRxWorkLoop() : nullptr;
        if (rxwl) rxwl->removeEventSource(_reorderTimer);
        _reorderTimer->release();
        _reorderTimer = nullptr;
    }
    if (_rxBaLock) { IOLockFree(_rxBaLock); _rxBaLock = nullptr; }
    _manualScanAbort = true;
    if (_manualScanTC) { thread_call_cancel(_manualScanTC); thread_call_free(_manualScanTC); _manualScanTC = nullptr; }
    if (_connectTC) { thread_call_cancel(_connectTC); thread_call_free(_connectTC); _connectTC = nullptr; }
    if (_timer)  { _wl->removeEventSource(_timer); _timer->release();  _timer = nullptr; }
    if (_gate)   { _wl->removeEventSource(_gate);  _gate->release();   _gate = nullptr; }
    if (_wl)     { _wl->release();   _wl = nullptr; }
    if (_lock)   { IOLockFree(_lock);    _lock = nullptr; }
    if (_bssLock){ IOLockFree(_bssLock); _bssLock = nullptr; }

    /* Free BSS list */
    RTW88BSS *b = _bssList;
    while (b) {
        RTW88BSS *n = b->next;
        IOFree(b, sizeof(*b));
        b = n;
    }
    _bssList = nullptr;
    super::free();
}

void RTW88IEEE80211::clearKeys()
{
    if (_powered && _hw && _hw->ops && _hw->ops->set_key) {
        if (_ptkConf)
            _hw->ops->set_key(_hw, DISABLE_KEY, _vif, _sta, _ptkConf);
        if (_gtkConf)
            _hw->ops->set_key(_hw, DISABLE_KEY, _vif, nullptr, _gtkConf);
    }

    if (_ptkConf) {
        IOFree(_ptkConf, sizeof(*_ptkConf));
        _ptkConf = nullptr;
    }
    if (_gtkConf) {
        IOFree(_gtkConf, sizeof(*_gtkConf));
        _gtkConf = nullptr;
    }
    memset(_ptk, 0, sizeof(_ptk));
    memset(_gtk, 0, sizeof(_gtk));
    memset(_ccmpTxPn, 0, sizeof(_ccmpTxPn));
    _rxCcmpIvSkipLogged = false;
    _appleRSNPTKInstalled = false;
    _appleRSNGTKInstalled = false;
}

void RTW88IEEE80211::releaseSta()
{
    if (!_sta)
        return;

    rtw88_unregister_sta();
    if (_hw && _hw->ops && _vif) {
        RTW89CompatWiphyGuard cfgGuard(_hw);
        if (_hw->ops->sta_state) {
            /* Reverse of the assoc-time transitions (rtw89). */
            _hw->ops->sta_state(_hw, _vif, _sta,
                IEEE80211_STA_ASSOC, IEEE80211_STA_AUTH);
            _hw->ops->sta_state(_hw, _vif, _sta,
                IEEE80211_STA_AUTH, IEEE80211_STA_NONE);
            _hw->ops->sta_state(_hw, _vif, _sta,
                IEEE80211_STA_NONE, IEEE80211_STA_NOTEXIST);
        } else if (_hw->ops->sta_remove) {
            _hw->ops->sta_remove(_hw, _vif, _sta);
        }
    }

    IOFree(_sta, _staAllocSize ? _staAllocSize : sizeof(struct ieee80211_sta));
    _sta = nullptr;
    _staAllocSize = 0;
    _txBaActive = false;
    _dataSeq = 0;
    rxBaTeardownAll();
}

static const char *rtw88CipherName(uint32_t cipher)
{
    switch (cipher) {
    case WLAN_CIPHER_SUITE_CCMP:
        return "CCMP";
    case WLAN_CIPHER_SUITE_TKIP:
        return "TKIP";
    default:
        return "unknown";
    }
}

bool RTW88IEEE80211::installKey(struct ieee80211_key_conf **slot, bool pairwise,
                                uint8_t keyidx, uint32_t cipher,
                                const uint8_t *tk, uint8_t tk_len)
{
    if (!_hw || !_hw->ops || !_hw->ops->set_key || !slot || !tk || tk_len == 0 || tk_len > 32)
        return false;
    if (cipher != WLAN_CIPHER_SUITE_CCMP && cipher != WLAN_CIPHER_SUITE_TKIP)
        return false;
    if (cipher == WLAN_CIPHER_SUITE_CCMP && tk_len != 16)
        return false;
    if (cipher == WLAN_CIPHER_SUITE_TKIP && tk_len != 32)
        return false;

    if (*slot) {
        _hw->ops->set_key(_hw, DISABLE_KEY, _vif, pairwise ? _sta : nullptr, *slot);
        IOFree(*slot, sizeof(**slot));
        *slot = nullptr;
    }

    struct ieee80211_key_conf *key =
        (struct ieee80211_key_conf *)IOMallocZero(sizeof(*key));
    if (!key)
        return false;

    key->cipher = cipher;
    key->keyidx = (s8)keyidx;
    key->flags = pairwise ? IEEE80211_KEY_FLAG_PAIRWISE : 0;
    key->keylen = tk_len;
    key->iv_len = 8;
    key->icv_len = (cipher == WLAN_CIPHER_SUITE_TKIP) ? 4 : 8;
    memcpy(key->key, tk, tk_len);

    int ret = _hw->ops->set_key(_hw, SET_KEY, _vif, pairwise ? _sta : nullptr, key);
    if (ret) {
        IOLog("rtw88: failed to install %s %s key ret=%d\n",
              pairwise ? "pairwise" : "group", rtw88CipherName(cipher), ret);
        IOFree(key, sizeof(*key));
        return false;
    }

    *slot = key;
    if (pairwise)
        memset(_ccmpTxPn, 0, sizeof(_ccmpTxPn));
    IOLog("rtw88: installed %s %s key idx=%u hw_idx=%u\n",
          pairwise ? "pairwise" : "group", rtw88CipherName(cipher),
          keyidx, key->hw_key_idx);
    return true;
}

void RTW88IEEE80211::setAppleRSNMode(bool enabled)
{
    _appleRSNMode = enabled;
    _appleRSNPTKInstalled = false;
    _appleRSNGTKInstalled = false;
    _appleRSNEAPOLRxCount = 0;
    _appleRSNEAPOLTxCount = 0;
    if (!enabled) {
        _appleRSNIELen = 0;
        memset(_appleRSNIE, 0, sizeof(_appleRSNIE));
    }
    if (_parent) {
        _parent->setProperty("AirportRTW89AppleRSNMode",
                             enabled ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleRSNPTKInstalled", kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleRSNGTKInstalled", kOSBooleanFalse);
    }
}

bool RTW88IEEE80211::setAppleRSNIE(const uint8_t *ie, uint16_t len)
{
    if (!ie || len < 2 || len > sizeof(_appleRSNIE) ||
        ie[0] != WLAN_EID_RSN || (uint16_t)(ie[1] + 2) > len)
        return false;
    const uint16_t exact = (uint16_t)(ie[1] + 2);
    memset(_appleRSNIE, 0, sizeof(_appleRSNIE));
    memcpy(_appleRSNIE, ie, exact);
    _appleRSNIELen = exact;
    if (_parent) {
        _parent->setProperty("AirportRTW89AppleRSNIESet", kOSBooleanTrue);
        _parent->setProperty("AirportRTW89AppleRSNIELength",
                             (uint64_t)_appleRSNIELen, 16);
    }
    return true;
}

bool RTW88IEEE80211::copyAppleRSNIE(uint8_t *out, uint32_t capacity,
                                      uint32_t *outLen) const
{
    if (outLen)
        *outLen = 0;
    const uint8_t *src = nullptr;
    uint32_t len = 0;
    if (_appleRSNIELen >= 2) {
        src = _appleRSNIE;
        len = _appleRSNIELen;
    } else if (_targetBSS.rsn_ie_len >= 2 &&
               _targetBSS.rsn_ie_len <= sizeof(_targetBSS.rsn_ie)) {
        /* 0.2.180: the selected BSS owns the authoritative AP RSN TLV. */
        src = _targetBSS.rsn_ie;
        len = _targetBSS.rsn_ie_len;
    }
    if (!src || !len || !out || capacity < len)
        return false;
    memcpy(out, src, len);
    if (outLen)
        *outLen = len;
    return true;
}

IOReturn RTW88IEEE80211::installAppleRSNKey(bool pairwise, uint8_t keyidx,
                                              uint32_t cipher,
                                              const uint8_t *key,
                                              uint8_t keyLen)
{
    if (!_appleRSNMode || !_wpa2 || !_sta || !key || keyLen == 0)
        return kIOReturnNotReady;

    uint32_t linuxCipher = 0;
    switch (cipher) {
    case 3: /* APPLE80211_CIPHER_TKIP */
        linuxCipher = WLAN_CIPHER_SUITE_TKIP;
        break;
    case 4: /* APPLE80211_CIPHER_AES_OCB: use the CCMP engine like IO80211Reference */
    case 5: /* APPLE80211_CIPHER_AES_CCM */
        linuxCipher = WLAN_CIPHER_SUITE_CCMP;
        break;
    default:
        return kIOReturnUnsupported;
    }

    struct ieee80211_key_conf **slot = pairwise ? &_ptkConf : &_gtkConf;
    if (!installKey(slot, pairwise, keyidx, linuxCipher, key, keyLen))
        return kIOReturnError;

    if (pairwise)
        _appleRSNPTKInstalled = true;
    else
        _appleRSNGTKInstalled = true;

    if (_parent) {
        _parent->setProperty("AirportRTW89AppleRSNPTKInstalled",
                             _appleRSNPTKInstalled ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleRSNGTKInstalled",
                             _appleRSNGTKInstalled ? kOSBooleanTrue : kOSBooleanFalse);
    }

    /* Key ordering is not guaranteed by the Apple supplicant.  Complete the
     * controlled port as soon as both pairwise and group temporal keys exist,
     * regardless of which CIPHER_KEY request arrived last. */
    if (_appleRSNPTKInstalled && _appleRSNGTKInstalled) {
        setHandshakeRxFilter(false);
        _state = RTW88_STATE_CONNECTED;
        _timer->cancelTimeout();
#ifdef RTW_AIRPORT
        if (_parent)
            _parent->airportPublishLinkState(true, _targetBSS.rssi, true);
#endif
        startTxAggregation();
    }
    return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ */
/*  start / stop                                                        */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::start()
{
    RTW88_STAGE("IEEE80211::start entered");
    if (_parent) _parent->setBringupStage("ieee-start-enter");

    /* Look up chip info from PCI device ID */
    const struct rtw_chip_info *chip = nullptr;
    for (int i = 0; rtw88_pci_chip_table[i].device != 0; i++) {
        if (rtw88_pci_chip_table[i].device == _pcidev->device) {
            chip = rtw88_pci_chip_table[i].chip;
            break;
        }
    }
    if (!chip) {
        IOLog("rtw88: unknown PCI device %04x — cannot probe\n", _pcidev->device);
        if (_parent) _parent->setBringupStage("chip-unsupported", kIOReturnUnsupported);
        return kIOReturnUnsupported;
    }
    RTW88_STAGE("chip matched: device=%04x", _pcidev->device);

    const struct pci_device_id fake_id = {
        .vendor      = _pcidev->vendor,
        .device      = _pcidev->device,
        .subvendor   = PCI_ANY_ID,
        .subdevice   = PCI_ANY_ID,
        .driver_data = (unsigned long)chip,
    };

    RTW88_STAGE("calling rtw_pci_probe");
    if (_parent) _parent->setBringupStage("rtw-pci-probe-running");
    int ret = rtw_pci_probe(_pcidev, &fake_id);
    RTW88_STAGE("rtw_pci_probe returned %d", ret);
    if (ret != 0) {
        IOLog("rtw88: rtw_pci_probe failed: %d\n", ret);
        if (_parent) _parent->setBringupStage("rtw-pci-probe-failed", ret);
        return kIOReturnError;
    }
    if (_parent) _parent->setBringupStage("rtw-pci-probe-complete");

    /* Use the hw pointer that ieee80211_alloc_hw() registered in the compat
     * layer via rtw88_register_hw().  rtw88_get_hw() is the external-linkage
     * accessor for the static g_rtw88_hw variable — avoids both the fragile
     * *(ieee80211_hw **)rtwdev double-dereference and the UB of declaring
     * 'extern' on a static variable from another TU. */
    _hw = rtw88_get_hw();

    /* rtwdev is hw->priv (allocated contiguously after ieee80211_hw in alloc_hw).
     * Note: rtw_pci_probe stores hw (not rtwdev) in pdev->driver_data via pci_set_drvdata(). */
    if (_hw) {
        _rtwdev = (struct rtw_dev *)_hw->priv;
    } else {
        _rtwdev = nullptr;
    }

    RTW88_STAGE("rtwdev=%p hw=%p", (void *)_rtwdev, (void *)_hw);

    /* Read MAC address — SET_IEEE80211_PERM_ADDR() copies EFuse MAC into
     * hw->wiphy->perm_addr during rtw_register_hw(); read it from there. */
    if (_hw && _hw->wiphy) {
        memcpy(_macAddr, _hw->wiphy->perm_addr, 6);
        IOLog("rtw88: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
              _macAddr[0], _macAddr[1], _macAddr[2],
              _macAddr[3], _macAddr[4], _macAddr[5]);
    }

    /* Create virtual interface in the driver.
     * NOTE: _rtwdev must NOT be reassigned here. It has been correctly set from
     * _hw->priv above. */
    if (_hw) {
        /* mac80211 order is drv_start THEN drv_add_interface.  rtw89's
         * add_interface sends H2C commands to firmware that ops->start
         * only just downloads (rtw88 tolerated the reversed order because
         * its add_interface is pure register writes).  With the order
         * flipped, add_interface fails, silently unsets the vif's link,
         * and every later scan/tx dies with "find no designated link". */
        RTW88_STAGE("calling hw->ops->start");
        if (_parent) _parent->setBringupStage("hardware-start-running");
        if (_hw->ops && _hw->ops->start) {
            RTW89CompatWiphyGuard cfgGuard(_hw);
            int sret = _hw->ops->start(_hw);
            RTW88_STAGE("hw->ops->start returned %d", sret);
            if (_parent)
                _parent->setProperty("AirportRTW89HardwareStartReturn",
                                     (uint64_t)(uint32_t)sret, 32);
            if (sret != 0) {
                IOLog("rtw88: hw->ops->start failed: %d\n", sret);
                if (_parent) {
                    _parent->setProperty("AirportRTW89HardwarePowered", kOSBooleanFalse);
                    _parent->setBringupStage("hardware-start-failed", sret);
                }
            } else {
                _powered = true;
                if (_parent) {
                    _parent->setProperty("AirportRTW89HardwarePowered", kOSBooleanTrue);
                    _parent->setBringupStage("hardware-start-complete");
                }
            }
        }

        if (_powered) {
            RTW88_STAGE("adding STA interface");
            /* drv_priv must hold the driver's per-vif struct: rtw_vif for rtw88,
             * rtw89_vif (multi-KB, links_inst[] array) for rtw89.  Both drivers
             * publish the exact size in hw->vif_data_size before this point —
             * a fixed size here under-allocates and the driver writes past the
             * buffer (heap corruption, panics later in unrelated paths). */
            _vifAllocSize = sizeof(struct ieee80211_vif) + _hw->vif_data_size;
            _vif = (struct ieee80211_vif *)IOMallocZero(_vifAllocSize);
            if (_vif) {
                _vif->type = NL80211_IFTYPE_STATION;
                memcpy(_vif->addr, _macAddr, 6);
                /* rtw89's add-iface path snapshots the per-link MAC from
                 * bss_conf.addr (not vif->addr) into the firmware role and
                 * address CAM.  Leaving it zeroed makes the hardware filter
                 * drop every unicast frame addressed to our real MAC —
                 * broadcast (beacons/scan) still works, auth replies don't. */
                memcpy(_vif->bss_conf.addr, _macAddr, 6);
                /* bss_conf.bssid must never be NULL — iterators dereference it
                 * for every RX frame even before association. */
                _vif->bss_conf.bssid = _vif->bss_conf.bssid_buf;
                /* Non-MLO contract mac80211 normally provides: link 0's conf is
                 * the vif's own bss_conf, valid_links stays 0.  rtw89 derefs
                 * vif->link_conf[0] on every H2C/CAM update; leaving it NULL
                 * forces its nolink fallback path (error spam / stale conf). */
                _vif->link_conf[0] = &_vif->bss_conf;
                int aret = -1;
                if (_hw->ops && _hw->ops->add_interface) {
                    RTW89CompatWiphyGuard cfgGuard(_hw);
                    aret = _hw->ops->add_interface(_hw, _vif);
                }
                if (aret == 0) {
                    _ifaceAdded = true;
                    rtw88_register_vif(_vif);
                    if (_parent) {
                        _parent->setProperty("AirportRTW89DriverInterfaceAdded", kOSBooleanTrue);
                        _parent->setBringupStage("driver-add-interface-complete");
                    }
                } else {
                    IOLog("rtw88: add_interface failed: %d\n", aret);
                    if (_parent) {
                        _parent->setProperty("AirportRTW89DriverInterfaceAdded", kOSBooleanFalse);
                        _parent->setProperty("AirportRTW89DriverAddInterfaceReturn",
                                             (uint64_t)(uint32_t)aret, 32);
                        _parent->setBringupStage("driver-add-interface-failed", aret);
                    }
                    IOFree(_vif, _vifAllocSize);
                    _vif = nullptr;
                    _vifAllocSize = 0;
                }
            }
            RTW88_STAGE("add_interface done");
        }
    }

    _state = RTW88_STATE_IDLE;
    _scanReturnState = RTW88_STATE_IDLE;
    RTW88_STAGE("IEEE80211::start complete — SUCCESS");
    if (_parent) _parent->setBringupStage("ieee-start-complete");
    return kIOReturnSuccess;
}

void RTW88IEEE80211::stop()
{
    IOLog("rtw88: IEEE80211 stop\n");
    _timer->cancelTimeout();

    if (_state == RTW88_STATE_SCANNING) {
        if (_parent)
            _parent->setProperty("AirportRTW89ManualScanTeardownAbortRequested",
                                 kOSBooleanTrue);
        bool scanIdle = abortActiveScan(true);
        if (_parent)
            _parent->setProperty("AirportRTW89ManualScanTeardownAbortCompleted",
                                 scanIdle ? kOSBooleanTrue : kOSBooleanFalse);
    }

    if ((_state == RTW88_STATE_CONNECTED ||
         (_state == RTW88_STATE_SCANNING &&
          _scanReturnState == RTW88_STATE_CONNECTED)) && _powered)
        doDisconnect();
    else {
        clearKeys();
        releaseSta();
    }

    if (_vif && _hw && _hw->ops) {
        /* mac80211 removes interfaces BEFORE drv_stop — rtw89's remove
         * path sends H2C teardown to the firmware that ops->stop kills. */
        if (_ifaceAdded) {
            rtw88_unregister_vif();
            if (_hw->ops->remove_interface) {
                RTW89CompatWiphyGuard cfgGuard(_hw);
                _hw->ops->remove_interface(_hw, _vif);
            }
            _ifaceAdded = false;
        }
        IOFree(_vif, _vifAllocSize ? _vifAllocSize : sizeof(*_vif));
        _vif = nullptr;
        _vifAllocSize = 0;
    }
    if (_hw && _hw->ops && _powered && _hw->ops->stop) {
        RTW89CompatWiphyGuard cfgGuard(_hw);
        _hw->ops->stop(_hw, false);
        _powered = false;
    }

    if (_pcidev) rtw_pci_remove(_pcidev);
    _rtwdev = nullptr;
    _hw     = nullptr;
    _state  = RTW88_STATE_IDLE;
    _scanReturnState = RTW88_STATE_IDLE;
}

/* ------------------------------------------------------------------ */
/*  Power on/off (called from enable/disable)                          */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::powerOn()
{
    IOLog("rtw88: IEEE80211 powerOn\n");
    if (_powered) return kIOReturnSuccess;
    if (!_hw || !_hw->ops || !_hw->ops->start) return kIOReturnNotReady;
    int ret = 0;
    {
        RTW89CompatWiphyGuard cfgGuardStart(_hw);
        ret = _hw->ops->start(_hw);
    }
    if (ret) {
        IOLog("rtw88: rtw_core_start failed: %d\n", ret);
        return kIOReturnError;
    }
    _powered = true;
    /* ops->start re-downloads firmware, so the interface's firmware role
     * is gone — re-create it, same as mac80211's resume reconfig which
     * replays drv_add_interface after drv_start. */
    if (_vif && !_ifaceAdded && _hw->ops->add_interface) {
        RTW89CompatWiphyGuard cfgGuardAdd(_hw);
        int aret = _hw->ops->add_interface(_hw, _vif);
        if (aret == 0) {
            _ifaceAdded = true;
            rtw88_register_vif(_vif);
        } else {
            IOLog("rtw88: add_interface failed after powerOn: %d\n", aret);
        }
    }
    return kIOReturnSuccess;
}

void RTW88IEEE80211::powerOff()
{
    IOLog("rtw88: IEEE80211 powerOff\n");
    if (!_powered) return;
    if (_state == RTW88_STATE_SCANNING) {
        if (_parent)
            _parent->setProperty("AirportRTW89ManualScanTeardownAbortRequested",
                                 kOSBooleanTrue);
        bool scanIdle = abortActiveScan(true);
        if (_parent)
            _parent->setProperty("AirportRTW89ManualScanTeardownAbortCompleted",
                                 scanIdle ? kOSBooleanTrue : kOSBooleanFalse);
    }
    /* Remove the interface first (mac80211 order); its firmware role dies
     * with ops->stop anyway, and powerOn re-adds it cleanly. */
    if (_hw && _hw->ops && _vif && _ifaceAdded) {
        rtw88_unregister_vif();
        if (_hw->ops->remove_interface) {
            RTW89CompatWiphyGuard cfgGuardRemove(_hw);
            _hw->ops->remove_interface(_hw, _vif);
        }
        _ifaceAdded = false;
    }
    if (_hw && _hw->ops && _hw->ops->stop) {
        RTW89CompatWiphyGuard cfgGuardStop(_hw);
        _hw->ops->stop(_hw, false);
    }
    _powered = false;
}

/* ------------------------------------------------------------------ */
/*  Interrupt dispatch                                                  */
/* ------------------------------------------------------------------ */

extern "C" void rtw88_trigger_interrupt(void);

void RTW88IEEE80211::handleInterrupt()
{
    static int intr_cnt = 0;
    IOLog("rtw88: handling interrupt (count=%d) ENTER\n", intr_cnt);
    intr_cnt++;

    rtw88_trigger_interrupt();

    IOLog("rtw88: handling interrupt (count=%d) LEAVE\n", intr_cnt - 1);
}

/* ------------------------------------------------------------------ */
/*  TX path: Ethernet → 802.11 data frame                              */
/* ------------------------------------------------------------------ */


static bool rtw88_is_dhcp_mbuf(mbuf_t m, uint16_t *ethertypeOut)
{
    uint8_t hdr[64] = {};
    size_t total = mbuf_pkthdr_len(m);
    size_t inspect = total < sizeof(hdr) ? total : sizeof(hdr);
    if (inspect < 14 || mbuf_copydata(m, 0, inspect, hdr) != 0)
        return false;
    uint16_t ethertype = (uint16_t)((hdr[12] << 8) | hdr[13]);
    if (ethertypeOut)
        *ethertypeOut = ethertype;
    if (ethertype != 0x0800 || inspect < 34 || hdr[23] != 17)
        return false;
    size_t ihl = (size_t)(hdr[14] & 0x0f) * 4;
    size_t udp = 14 + ihl;
    if (ihl < 20 || inspect < udp + 4)
        return false;
    uint16_t sport = (uint16_t)((hdr[udp] << 8) | hdr[udp + 1]);
    uint16_t dport = (uint16_t)((hdr[udp + 2] << 8) | hdr[udp + 3]);
    return (sport == 67 || sport == 68) && (dport == 67 || dport == 68);
}

UInt32 RTW88IEEE80211::outputPacket(mbuf_t m)
{
    /* 0.2.30 ordinary output path entry. */
    _ordinaryOutputPacketCount++;
#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
    uint16_t ordinaryEthertype = 0;
    bool ordinaryDHCP = rtw88_is_dhcp_mbuf(m, &ordinaryEthertype);
    if (_parent) {
        _parent->setProperty("AirportRTW89IEEEOutputPacketCount",
                             (uint64_t)_ordinaryOutputPacketCount, 64);
        _parent->setProperty("AirportRTW89IEEEOutputLastEthertype",
                             (uint64_t)ordinaryEthertype, 16);
        _parent->setProperty("AirportRTW89IEEEOutputLastDHCP",
                             ordinaryDHCP ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89IEEEOutputState",
                             (uint64_t)_state, 8);
        _parent->setProperty("AirportRTW89IEEEOutputVifPresent",
                             _vif ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89IEEEOutputStaPresent",
                             _sta ? kOSBooleanTrue : kOSBooleanFalse);
    }
#endif

    /* Need an associated STA before ordinary data frames can be sent.
     * Apple's RSN supplicant is the one exception: its EAPOL frames must be
     * transmitted while the 802.11 peer is associated but the controlled port
     * is still in HANDSHAKING state. */
    uint16_t txEthertype = 0;
    (void)rtw88_is_dhcp_mbuf(m, &txEthertype);
    const bool appleRSNEAPOL =
        _appleRSNMode && _state == RTW88_STATE_HANDSHAKING &&
        txEthertype == ETH_P_PAE;
    bool connected = (_state == RTW88_STATE_CONNECTED) ||
                     (_state == RTW88_STATE_SCANNING &&
                      _scanReturnState == RTW88_STATE_CONNECTED &&
                      (_manualScanChannelCount == 0 ||
                       _manualScanOnHomeChannel));
    if ((!connected && !appleRSNEAPOL) || !_rtwdev || !_hw || !_vif || !_sta) {
        if (_parent)
            _parent->setProperty("AirportRTW89IEEEOutputDroppedPrerequisite",
                                 kOSBooleanTrue);
        mbuf_freem(m);
        return kIOReturnOutputDropped;
    }

    if (appleRSNEAPOL) {
        ++_appleRSNEAPOLTxCount;
        if (_parent) {
            const UInt64 nowMS = rtw88_now_ns() / 1000000ULL;
            _parent->setProperty("AirportRTW89AppleRSNEAPOLTxSeen",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89AppleRSNEAPOLTxCount",
                                 (uint64_t)_appleRSNEAPOLTxCount, 32);
            if (_appleRSNEAPOLTxCount == 1U)
                _parent->setProperty("AirportRTW89SecurityControlEAPOLTxFirstMS",
                                     (uint64_t)nowMS, 64);
            _parent->setProperty("AirportRTW89SecurityControlEAPOLTxLastMS",
                                 (uint64_t)nowMS, 64);
            _parent->setProperty("AirportRTW89SecurityControlEAPOLTxState",
                                 (uint64_t)_state, 8);
        }
    }

    /* txDataFrame() encapsulates the Ethernet frame as an 802.11 data frame
     * and consumes (frees) the mbuf in all paths. */
    return txDataFrame(m) ? kIOReturnOutputSuccess : kIOReturnOutputDropped;
}

/* ------------------------------------------------------------------ */
/*  RX path: sk_buff from driver → mbuf to macOS                       */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::rxFrame(struct sk_buff *skb)
{
    if (!skb) return;

    struct ieee80211_rx_status *rxs = IEEE80211_SKB_RXCB(skb);
    _rssi = rxs->signal;

    /* 0.2.162: our ieee80211_rx_napi() compatibility bridge bypasses the
     * real mac80211 RX pipeline.  rtw89 still annotates bad frames in the
     * normal ieee80211_rx_status flags, so honor those flags before parsing
     * or injecting the frame.  Passing CRC/PLCP-corrupt payloads to TCP makes
     * them look like ordinary packet loss and destroys downlink throughput. */
    if (rxs->flag & RX_FLAG_FAILED_FCS_CRC) {
        ++_rxFailedFcsDropCount;
        kfree_skb(skb);
        return;
    }
    if (rxs->flag & RX_FLAG_FAILED_PLCP_CRC) {
        ++_rxFailedPlcpDropCount;
        kfree_skb(skb);
        return;
    }

    if (skb->len < sizeof(struct ieee80211_hdr_3addr)) {
        kfree_skb(skb);
        return;
    }

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    __le16 fc = hdr->frame_control;

    _rxFrameCount++;
    if (_state == RTW88_STATE_HANDSHAKING) {
        _handshakeRxFrames++;
        if (_parent)
            _parent->setProperty("AirportRTW89HandshakeRXFrames",
                                 (uint64_t)_handshakeRxFrames, 32);
    }

    if (ieee80211_is_mgmt(fc)) {
        processRxMgmt(skb);
    } else if (ieee80211_is_data(fc)) {
        /* Record raw PHY metadata in memory only.  Publication is done by the
         * one-second AirPort poll, never from the RX hot path. */
        ++_rxDataFrameCount;
        _rxDataByteCount += skb->len;
        _rxLastStatusFlags = rxs->flag;
        _rxLastEncFlags = rxs->enc_flags;
        _rxLastFrameLength = (uint16_t)(skb->len > 0xffff ? 0xffff : skb->len);
        _rxLastEncoding = rxs->encoding;
        _rxLastRateIndex = rxs->rate_idx;
        _rxLastNSS = rxs->nss;
        _rxLastBandwidth = rxs->bw;
        _rxLastSignal = rxs->signal;
        if (rxs->encoding < 5)
            ++_rxEncodingCount[rxs->encoding];

        /* mac80211 normally suppresses retransmitted duplicates.  Our direct
         * bridge must do the minimal equivalent itself, otherwise a retry of
         * the same MPDU is delivered to the BSD stack a second time.  Track
         * one sequence/fragment tuple for each QoS TID plus one non-QoS slot.
         * Update the tuple for every accepted frame; only a frame carrying the
         * Retry bit and matching the previous tuple is discarded. */
        uint16_t fcCpu = le16_to_cpu(fc);
        uint16_t sc = le16_to_cpu(hdr->seq_ctrl);
        uint16_t seq = (uint16_t)((sc >> 4) & 0x0fff);
        uint8_t frag = (uint8_t)(sc & 0x0f);
        uint8_t dupSlot = 16;
        if (ieee80211_is_data_qos(fc)) {
            uint16_t hdrlen = ieee80211_get_hdrlen_from_skb(skb);
            if (hdrlen >= 2 && skb->len >= hdrlen)
                dupSlot = (uint8_t)(skb->data[hdrlen - 2] & 0x0f);
            if (dupSlot > 15)
                dupSlot = 16;
        }
        const bool retry = (fcCpu & IEEE80211_FCTL_RETRY) != 0;
        if (retry)
            ++_rxRetryFrameCount;
        if (retry && _rxDuplicateValid[dupSlot] &&
            _rxDuplicateSeq[dupSlot] == seq &&
            _rxDuplicateFrag[dupSlot] == frag) {
            ++_rxRetryDuplicateDropCount;
            kfree_skb(skb);
            return;
        }
        _rxDuplicateSeq[dupSlot] = seq;
        _rxDuplicateFrag[dupSlot] = frag;
        _rxDuplicateValid[dupSlot] = true;

        processRxData(skb);
    } else {
        kfree_skb(skb);
    }
}

void RTW88IEEE80211::processRxMgmt(struct sk_buff *skb)
{
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    __le16 fc = hdr->frame_control;
    uint16_t stype = le16_to_cpu(fc) & 0x00f0;

    switch (stype) {
    case 0x0080: /* beacon */
    case 0x0050: /* probe response */
        if (_state == RTW88_STATE_SCANNING)
            processScanResult(skb);
        else
            kfree_skb(skb);
        break;

    case 0x00B0: /* auth */
        if (_state == RTW88_STATE_AUTHENTICATING) {
            /* Only accept an auth response actually sent by our target AP.
             * Without this we'd treat any stray/stale auth frame as success,
             * falsely "associating" while the AP never admitted us. */
            struct ieee80211_hdr_3addr *h3 =
                (struct ieee80211_hdr_3addr *)skb->data;
            if (memcmp(h3->addr3, _targetBSS.bssid, 6) != 0) {
                IOLog("rtw88: auth resp from %02x:%02x:%02x:%02x:%02x:%02x "
                      "!= target BSSID — ignoring\n",
                      h3->addr3[0], h3->addr3[1], h3->addr3[2],
                      h3->addr3[3], h3->addr3[4], h3->addr3[5]);
                kfree_skb(skb);
                break;
            }
            uint8_t *body = skb->data + sizeof(struct ieee80211_hdr_3addr);
            uint32_t body_len = skb->len - sizeof(struct ieee80211_hdr_3addr);
            /* auth body: algo(2), seq(2), status(2) */
            if (body_len >= 6) {
                uint16_t status = (uint16_t)(body[4] | (body[5] << 8));
                if (_parent) {
                    _parent->setProperty("AirportRTW89AuthResponseSeen",
                                         kOSBooleanTrue);
                    _parent->setProperty("AirportRTW89AuthResponseStatus",
                                         (uint64_t)status, 16);
                }
                if (status == 0) {
                    IOLog("rtw88: auth success, sending assoc\n");
                    doAssociate();
                } else {
                    IOLog("rtw88: auth failed status=%u, retrying\n", status);
                    _state = RTW88_STATE_IDLE;
                }
            } else {
                doAssociate(); /* assume success */
            }
        }
        kfree_skb(skb);
        break;

    case 0x0010: /* assoc response */
        if (_state == RTW88_STATE_ASSOCIATING)
            processAssocResponse(skb);
        else
            kfree_skb(skb);
        break;

    case 0x0030: /* reassoc response */
        if (_state == RTW88_STATE_ASSOCIATING)
            processAssocResponse(skb);
        else
            kfree_skb(skb);
        break;

    case 0x00A0: /* disassoc */
    case 0x00C0: /* deauth */
        if (_state == RTW88_STATE_CONNECTED ||
            _state == RTW88_STATE_HANDSHAKING ||
            (_state == RTW88_STATE_SCANNING &&
             _scanReturnState == RTW88_STATE_CONNECTED)) {
            struct ieee80211_hdr_3addr *h3 =
                (struct ieee80211_hdr_3addr *)skb->data;
            bool fromTarget = memcmp(h3->addr3, _targetBSS.bssid, 6) == 0 ||
                              memcmp(h3->addr2, _targetBSS.bssid, 6) == 0;
            bool addressedToUs = memcmp(h3->addr1, _macAddr, 6) == 0 ||
                                 is_broadcast_ether_addr(h3->addr1);
            if (!fromTarget || !addressedToUs) {
                kfree_skb(skb);
                break;
            }
            /* Log which frame and the reason code — the AP's reason for
             * dropping us a few seconds after connect (e.g. excessive retries
             * vs. class-3 violation) is the key diagnostic. */
            {
                const uint8_t *rb = skb->data + sizeof(*h3);
                uint16_t reason = (skb->len >= sizeof(*h3) + 2) ?
                                  (uint16_t)(rb[0] | (rb[1] << 8)) : 0;
                IOLog("rtw88: %s from AP, reason=%u — disconnecting\n",
                      (stype == 0x00C0) ? "deauth" : "disassoc", reason);
                if (_state == RTW88_STATE_HANDSHAKING) {
                    _handshakeDisconnectCount++;
                    _handshakeLastDisconnectReason = reason;
                    _handshakeLastDisconnectSubtype =
                        (stype == 0x00C0) ? 12 : 10;
                    if (_parent) {
                        _parent->setProperty("AirportRTW89HandshakeDisconnectCount",
                                             (uint64_t)_handshakeDisconnectCount, 32);
                        _parent->setProperty("AirportRTW89HandshakeLastDisconnectReason",
                                             (uint64_t)reason, 16);
                        _parent->setProperty("AirportRTW89HandshakeLastDisconnectSubtype",
                                             (uint64_t)_handshakeLastDisconnectSubtype, 8);
                    }
                }
            }
            setHandshakeRxFilter(false);
            clearKeys();
            _txBaActive = false;
            rxBaTeardownAll();
            _state = RTW88_STATE_IDLE;
            _scanReturnState = RTW88_STATE_IDLE;
#ifdef RTW_AIRPORT
            if (_parent)
                _parent->airportPublishLinkState(false, _targetBSS.rssi, false);
#endif
        }
        kfree_skb(skb);
        break;

    case 0x00D0: /* action */
        if (_state == RTW88_STATE_CONNECTED) {
            struct ieee80211_hdr_3addr *h3 =
                (struct ieee80211_hdr_3addr *)skb->data;
            const uint8_t *b = skb->data + sizeof(*h3);
            uint32_t blen = (skb->len > sizeof(*h3)) ?
                            skb->len - (uint32_t)sizeof(*h3) : 0;
            /* BlockAck (ADDBA/DELBA) action frames from our AP only. */
            if (blen >= 2 && b[0] == WLAN_CATEGORY_BACK &&
                memcmp(h3->addr3, _targetBSS.bssid, 6) == 0)
                handleBackAction(b, blen);
        }
        kfree_skb(skb);
        break;

    default:
        kfree_skb(skb);
        break;
    }
}

static uint32_t rtw88ReadSuite(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void rtw88WriteSuite(uint8_t *p, uint32_t suite)
{
    p[0] = (uint8_t)(suite >> 24);
    p[1] = (uint8_t)(suite >> 16);
    p[2] = (uint8_t)(suite >> 8);
    p[3] = (uint8_t)suite;
}

static bool rtw88RsnSelectCcmpPsk(const uint8_t *rsn, uint8_t len,
                                  uint32_t *pairwise_cipher,
                                  uint32_t *group_cipher)
{
    const uint8_t *p = rsn;
    const uint8_t *end = rsn + len;

    if (p + 8 > end)
        return false;

    p += 2; /* version */
    uint32_t group = rtw88ReadSuite(p);
    p += 4;

    if (p + 2 > end)
        return false;
    uint16_t pairwiseCount = (uint16_t)(p[0] | (p[1] << 8));
    p += 2;
    if (p + pairwiseCount * 4 > end)
        return false;

    bool hasCcmp = false;
    for (uint16_t i = 0; i < pairwiseCount; i++, p += 4) {
        if (rtw88ReadSuite(p) == WLAN_CIPHER_SUITE_CCMP)
            hasCcmp = true;
    }

    if (p + 2 > end)
        return false;
    uint16_t akmCount = (uint16_t)(p[0] | (p[1] << 8));
    p += 2;
    if (p + akmCount * 4 > end)
        return false;

    bool hasPsk = false;
    for (uint16_t i = 0; i < akmCount; i++, p += 4) {
        if (rtw88ReadSuite(p) == 0x000FAC02) /* 00-0f-ac:2 PSK */
            hasPsk = true;
    }

    if (!hasCcmp || !hasPsk)
        return false;

    if (group != WLAN_CIPHER_SUITE_CCMP &&
        group != WLAN_CIPHER_SUITE_TKIP)
        group = WLAN_CIPHER_SUITE_CCMP;

    if (pairwise_cipher)
        *pairwise_cipher = WLAN_CIPHER_SUITE_CCMP;
    if (group_cipher)
        *group_cipher = group;
    return true;
}

static uint16_t rtw88BuildSelectedRsnIe(uint8_t *out, uint32_t group_cipher)
{
    if (group_cipher != WLAN_CIPHER_SUITE_TKIP)
        group_cipher = WLAN_CIPHER_SUITE_CCMP;

    uint8_t *p = out;
    *p++ = WLAN_EID_RSN;
    *p++ = 20;           /* body length */
    *p++ = 1; *p++ = 0;  /* version */
    rtw88WriteSuite(p, group_cipher); p += 4;
    *p++ = 1; *p++ = 0;  /* one pairwise cipher */
    rtw88WriteSuite(p, WLAN_CIPHER_SUITE_CCMP); p += 4;
    *p++ = 1; *p++ = 0;  /* one AKM */
    rtw88WriteSuite(p, 0x000FAC02); p += 4; /* PSK */
    *p++ = 0; *p++ = 0;  /* RSN capabilities */
    return (uint16_t)(p - out);
}

/*
 * mac80211 normally parses the AP's WMM Parameter element and invokes
 * ieee80211_ops::conf_tx for every access category.  This native port bypasses
 * mac80211 MLME, so do the small, deterministic part here before notifying
 * rtw89 that association is complete.
 */
static void rtw88DefaultEdca(struct ieee80211_tx_queue_params params[IEEE80211_NUM_ACS])
{
    memset(params, 0, sizeof(struct ieee80211_tx_queue_params) * IEEE80211_NUM_ACS);

    /* Wi-Fi Alliance / 802.11e station defaults, TXOP in 32-us units. */
    params[IEEE80211_AC_VO].aifs   = 2;
    params[IEEE80211_AC_VO].cw_min = 3;
    params[IEEE80211_AC_VO].cw_max = 7;
    params[IEEE80211_AC_VO].txop   = 47;

    params[IEEE80211_AC_VI].aifs   = 2;
    params[IEEE80211_AC_VI].cw_min = 7;
    params[IEEE80211_AC_VI].cw_max = 15;
    params[IEEE80211_AC_VI].txop   = 94;

    params[IEEE80211_AC_BE].aifs   = 3;
    params[IEEE80211_AC_BE].cw_min = 15;
    params[IEEE80211_AC_BE].cw_max = 1023;
    params[IEEE80211_AC_BE].txop   = 0;

    params[IEEE80211_AC_BK].aifs   = 7;
    params[IEEE80211_AC_BK].cw_min = 15;
    params[IEEE80211_AC_BK].cw_max = 1023;
    params[IEEE80211_AC_BK].txop   = 0;
}

static int rtw88WmmAciToAc(uint8_t aci)
{
    switch (aci & 0x3) {
    case 0: return IEEE80211_AC_BE;
    case 1: return IEEE80211_AC_BK;
    case 2: return IEEE80211_AC_VI;
    case 3: return IEEE80211_AC_VO;
    default: return -1;
    }
}

static bool rtw88ParseWmmParameters(const uint8_t *ies, uint32_t iesLen,
                                    struct ieee80211_tx_queue_params params[IEEE80211_NUM_ACS],
                                    uint8_t *qosInfo, uint8_t *parameterSetCount,
                                    uint8_t *acmMask)
{
    if (!ies || iesLen < 2)
        return false;

    for (uint32_t off = 0; off + 2 <= iesLen; ) {
        const uint8_t id = ies[off];
        const uint8_t len = ies[off + 1];
        if (off + 2U + len > iesLen)
            break;

        const uint8_t *ie = ies + off;
        if (id == WLAN_EID_VENDOR_SPECIFIC && len >= 24 &&
            ie[2] == 0x00 && ie[3] == 0x50 && ie[4] == 0xf2 &&
            ie[5] == 0x02 && /* WMM OUI type */
            ie[6] == 0x01 && /* Parameter subtype */
            ie[7] == 0x01) { /* version */
            bool seen[IEEE80211_NUM_ACS] = {};
            uint8_t localAcm = 0;

            for (uint32_t n = 0; n < 4; n++) {
                const uint8_t *rec = ie + 10 + n * 4;
                const uint8_t aciAifsn = rec[0];
                const uint8_t ecw = rec[1];
                const int ac = rtw88WmmAciToAc((aciAifsn >> 5) & 0x3);
                if (ac < 0)
                    continue;

                const uint8_t ecwMin = ecw & 0x0f;
                const uint8_t ecwMax = (ecw >> 4) & 0x0f;
                params[ac].aifs = aciAifsn & 0x0f;
                params[ac].cw_min = (uint16_t)((1U << ecwMin) - 1U);
                params[ac].cw_max = (uint16_t)((1U << ecwMax) - 1U);
                params[ac].txop = (uint16_t)(rec[2] | ((uint16_t)rec[3] << 8));
                if (aciAifsn & 0x10)
                    localAcm |= (uint8_t)(1U << ac);
                seen[ac] = true;
            }

            bool complete = true;
            for (int ac = 0; ac < IEEE80211_NUM_ACS; ac++)
                complete = complete && seen[ac];
            if (!complete)
                return false;

            if (qosInfo)
                *qosInfo = ie[8];
            if (parameterSetCount)
                *parameterSetCount = ie[8] & 0x0f;
            if (acmMask)
                *acmMask = localAcm;
            return true;
        }

        off += 2U + len;
    }

    return false;
}

void RTW88IEEE80211::processScanResult(struct sk_buff *skb)
{
    if (!skb || skb->len < sizeof(struct ieee80211_hdr) + 12) {
        kfree_skb(skb);
        return;
    }

    /* Parse beacon/probe-response fixed fields before walking IEs.
     * The fixed 12-byte body is timestamp(8), beacon interval(2), and
     * capability information(2), all little-endian on the air.  These
     * values are part of Apple's scan-result contract; in particular the
     * ESS/privacy capability bits must not be silently reported as zero. */
    const uint8_t *body = skb->data + sizeof(struct ieee80211_hdr_3addr);
    const uint8_t *end  = skb->data + skb->len;

    RTW88BSS *bss = (RTW88BSS *)IOMallocZero(sizeof(RTW88BSS));
    if (!bss) { kfree_skb(skb); return; }

    bss->beacon_interval = (uint16_t)body[8] | ((uint16_t)body[9] << 8);
    bss->capabilities = (uint16_t)body[10] | ((uint16_t)body[11] << 8);
    body += 12;

    /* BSSID is addr3 in a beacon from AP */
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    memcpy(bss->bssid, hdr->addr3, 6);

    /* Walk IEs */
    while (body + 2 <= end) {
        uint8_t id = body[0];
        uint8_t len = body[1];
        if (body + 2 + len > end) break;

        if (id == WLAN_EID_SSID && len > 0 && len <= 32) {
            memcpy(bss->ssid, body + 2, len);
            bss->ssid_len = len;
        } else if (id == WLAN_EID_SUPP_RATES ||
                   id == WLAN_EID_EXT_SUPP_RATES) {
            for (uint8_t i = 0; i < len && bss->nrates < sizeof(bss->rates); i++)
                bss->rates[bss->nrates++] = body[2 + i];
        } else if (id == WLAN_EID_DS_PARAMS && len >= 1) {
            bss->channel = body[2];
        } else if (id == WLAN_EID_HT_OPERATION && len >= 1 && bss->channel == 0) {
            bss->channel = body[2];
        } else if (id == WLAN_EID_RSN) {
            const uint16_t tlvLen = (uint16_t)(2U + len);
            if (tlvLen <= sizeof(bss->rsn_ie)) {
                memcpy(bss->rsn_ie, body, tlvLen);
                bss->rsn_ie_len = tlvLen;
            }

            uint32_t pairwise = 0;
            uint32_t group = 0;
            if (rtw88RsnSelectCcmpPsk(body + 2, len, &pairwise, &group)) {
                bss->cipher = pairwise;
                bss->group_cipher = group;
                bss->akm = 0x000FAC02; /* PSK */
            }
        } else if (id == WLAN_EID_VENDOR_SPECIFIC &&
                   len >= 8 && body[2] == 0x00 && body[3] == 0x50 &&
                   body[4] == 0xf2 && body[5] == 0x01 &&
                   bss->rsn_ie_len == 0) {
            const uint16_t tlvLen = (uint16_t)(2U + len);
            if (tlvLen <= sizeof(bss->wpa_ie)) {
                memcpy(bss->wpa_ie, body, tlvLen);
                bss->wpa_ie_len = tlvLen;
            }

            /* Legacy WPA IE. Keep this as scan metadata only; association
             * still prefers RSN/WPA2 when the AP advertises it. */
            if (bss->cipher == 0) {
                bss->cipher = WLAN_CIPHER_SUITE_TKIP;
                bss->group_cipher = WLAN_CIPHER_SUITE_TKIP;
                bss->akm    = 0x000FAC02; /* PSK */
            }
        }

        /* Copy all IEs */
        uint16_t copy = (uint16_t)(2 + len);
        if (bss->ies_len + copy < sizeof(bss->ies)) {
            memcpy(bss->ies + bss->ies_len, body, copy);
            bss->ies_len += copy;
        }
        body += 2 + len;
    }

    struct ieee80211_rx_status *rxs = IEEE80211_SKB_RXCB(skb);
    bss->rssi = rxs->signal;
    bss->freq = rxs->freq;
    bss->last_seen_scan = _scanGeneration;
    /* Keep a real monotonic age source for Apple80211 GET SCAN_RESULT.
     * IO80211Reference reports node age rather than pinning every result to age 0. */
    bss->last_seen_ns = rtw88_now_ns();
    if (bss->rssi > -110 && bss->rssi <= 0)
        bss->last_valid_rssi_ns = bss->last_seen_ns;

    /* 0.2.226: memory-only observation telemetry. A counter increment here is
     * proof that the RF path really heard this BSSID during the current scan;
     * Apple cache reads never touch these fields or last_seen_ns. */
    ++_scanBSSObservationCount;
    _scanBSSLastObservationSource = ieee80211_is_beacon(hdr->frame_control) ? 1U :
        (ieee80211_is_probe_resp(hdr->frame_control) ? 2U : 0U);
    
    if (bss->channel == 0 && bss->freq) {
        int f = bss->freq;
        if (f == 2484)
            bss->channel = 14;
        else if (f >= 2412 && f <= 2472)
            bss->channel = (f - 2407) / 5;
        else if (f >= 5000 && f <= 5900)
            bss->channel = (f - 5000) / 5;
    }

    /* 0.2.182: do not erase persistent security from an individual
     * Privacy=0 observation.  Real-world scan streams can contain a
     * contradictory beacon/probe sample for the same BSSID.  Security is
     * authoritative immediately when an RSN/WPA TLV is present; an open
     * observation is only a pending downgrade until scanDone() can evaluate
     * the whole generation. */

    /* Add to BSS list (deduplicate by BSSID). */
    IOLockLock(_bssLock);
    for (RTW88BSS *e = _bssList; e; e = e->next) {
        if (memcmp(e->bssid, bss->bssid, 6) == 0) {
            const bool incomingPrivacy = (bss->capabilities & 0x0010U) != 0;
            const bool incomingSecurityIE =
                bss->rsn_ie_len >= 2 || bss->wpa_ie_len >= 2;
            const bool existingSecurityIE =
                e->rsn_ie_len >= 2 || e->wpa_ie_len >= 2;
            const bool openCandidate =
                !incomingPrivacy && !incomingSecurityIE && existingSecurityIE;
            const bool preserveSecurity =
                !incomingSecurityIE && existingSecurityIE;
            const bool securityUpgrade =
                incomingSecurityIE && !existingSecurityIE;

            const int16_t previousRSSI = e->rssi;
            const uint64_t previousSeenNs = e->last_seen_ns;
            const int32_t rssiDelta =
                (int32_t)bss->rssi - (int32_t)previousRSSI;
            const uint32_t rssiAbsDelta =
                (uint32_t)(rssiDelta < 0 ? -rssiDelta : rssiDelta);
            const uint64_t observationGapNs =
                (previousSeenNs != 0 && bss->last_seen_ns >= previousSeenNs) ?
                    (bss->last_seen_ns - previousSeenNs) : 0;
            ++_scanBSSExistingRefreshCount;
            memcpy(_scanBSSLastRefreshBSSID, bss->bssid,
                   sizeof(_scanBSSLastRefreshBSSID));
            _scanBSSLastRefreshPreviousAgeMS = observationGapNs / 1000000ULL;
            _scanBSSLastRefreshChannel = bss->channel;
            _scanBSSLastRefreshFrequency = bss->freq;
            _scanBSSLastRefreshGeneration = _scanGeneration;
            _scanBSSLastRefreshSource = _scanBSSLastObservationSource;
            /* 0.2.211: rxs->signal reaches -110 when the compatibility RX
             * path has no usable signal measurement. The management frame is
             * still a real observation, so refresh age/generation/security,
             * but never let that sentinel overwrite a recent valid RSSI. */
            const bool previousRSSIValid = previousRSSI > -110 && previousRSSI <= 0;
            const bool incomingRSSISentinel = bss->rssi <= -110;
            const uint64_t validRSSIAgeNs =
                (e->last_valid_rssi_ns != 0 &&
                 bss->last_seen_ns >= e->last_valid_rssi_ns) ?
                    (bss->last_seen_ns - e->last_valid_rssi_ns) : UINT64_MAX;
            const bool previousRSSIRecent =
                validRSSIAgeNs != UINT64_MAX &&
                validRSSIAgeNs <= kRTW88RSSISentinelHoldNs;
            const bool preserveRSSI =
                incomingRSSISentinel && previousRSSIValid && previousRSSIRecent;
            const int16_t appliedRSSI = preserveRSSI ? previousRSSI : bss->rssi;

            if (bss->ssid_len != 0) {
                e->ssid_len = bss->ssid_len;
                memcpy(e->ssid, bss->ssid, sizeof(e->ssid));
            }
            e->rssi = appliedRSSI;
            if (!incomingRSSISentinel)
                e->last_valid_rssi_ns = bss->last_seen_ns;
            e->freq = bss->freq;
            e->channel = bss->channel;
            /* Persistent security owns the Privacy bit while a downgrade is
             * only pending.  Other capability bits still refresh normally. */
            e->capabilities = (preserveSecurity || incomingSecurityIE) ?
                (bss->capabilities | 0x0010U) : bss->capabilities;
            e->beacon_interval = bss->beacon_interval;
            e->nrates = bss->nrates;
            memcpy(e->rates, bss->rates, sizeof(e->rates));
            e->last_seen_scan = bss->last_seen_scan;
            e->last_seen_ns = bss->last_seen_ns;

            if (incomingSecurityIE) {
                e->cipher = bss->cipher;
                e->group_cipher = bss->group_cipher;
                e->akm = bss->akm;
                e->rsn_ie_len = bss->rsn_ie_len;
                e->wpa_ie_len = bss->wpa_ie_len;
                memset(e->rsn_ie, 0, sizeof(e->rsn_ie));
                memset(e->wpa_ie, 0, sizeof(e->wpa_ie));
                if (bss->rsn_ie_len)
                    memcpy(e->rsn_ie, bss->rsn_ie, bss->rsn_ie_len);
                if (bss->wpa_ie_len)
                    memcpy(e->wpa_ie, bss->wpa_ie, bss->wpa_ie_len);
                e->ies_len = bss->ies_len;
                memset(e->ies, 0, sizeof(e->ies));
                if (bss->ies_len)
                    memcpy(e->ies, bss->ies, bss->ies_len);
                e->last_security_scan_generation = _scanGeneration;
                /* Keep any same-generation open candidate marked until
                 * scanDone(); the generation boundary can then record that
                 * RSN/WPA evidence defeated the contradictory open sample. */
            } else if (openCandidate) {
                /* Do not touch cipher/AKM/RSN/association IEs here.  Mark the
                 * downgrade and let scanDone() commit it only if no security
                 * evidence was observed anywhere in this complete scan. */
                e->open_candidate_scan_generation = _scanGeneration;
            } else if (!preserveSecurity) {
                e->cipher = bss->cipher;
                e->group_cipher = bss->group_cipher;
                e->akm = bss->akm;
                e->ies_len = bss->ies_len;
                memset(e->ies, 0, sizeof(e->ies));
                if (bss->ies_len)
                    memcpy(e->ies, bss->ies, bss->ies_len);
            }

            e->rsn_observation_count += (bss->rsn_ie_len >= 2 ? 1U : 0U);
            e->security_update_count += (incomingSecurityIE ? 1U : 0U);
            e->security_preserve_count += (preserveSecurity ? 1U : 0U);
            e->security_open_candidate_count += (openCandidate ? 1U : 0U);

            if (_parent) {
                static uint32_t securityPreserveCount = 0;
                static uint32_t securityUpgradeCount = 0;
                static uint32_t securityOpenCandidateCount = 0;
                if (preserveSecurity) ++securityPreserveCount;
                if (securityUpgrade) ++securityUpgradeCount;
                if (openCandidate) ++securityOpenCandidateCount;
                _parent->setProperty("AirportRTW89BSSSecurityPreserveCount",
                                     (uint64_t)securityPreserveCount, 32);
                _parent->setProperty("AirportRTW89BSSSecurityUpgradeCount",
                                     (uint64_t)securityUpgradeCount, 32);
                _parent->setProperty("AirportRTW89BSSSecurityOpenCandidateCount",
                                     (uint64_t)securityOpenCandidateCount, 32);
                _parent->setProperty("AirportRTW89BSSLastUpdatePreservedSecurity",
                                     preserveSecurity ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89BSSLastUpdateOpenDeferred",
                                     openCandidate ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89BSSLastPersistentRSNLength",
                                     (uint64_t)e->rsn_ie_len, 16);
                _parent->setProperty("AirportRTW89BSSLastPersistentCipher",
                                     (uint64_t)e->cipher, 32);
                _parent->setProperty("AirportRTW89BSSLastPersistentAKM",
                                     (uint64_t)e->akm, 32);
                _parent->setProperty("AirportRTW89BSSLastRSNObservationCount",
                                     (uint64_t)e->rsn_observation_count, 32);
                _parent->setProperty("AirportRTW89BSSLastSecurityUpdateCount",
                                     (uint64_t)e->security_update_count, 32);
                _parent->setProperty("AirportRTW89BSSLastSecurityPreserveCount",
                                     (uint64_t)e->security_preserve_count, 32);
                _parent->setProperty("AirportRTW89BSSLastSecurityOpenCandidateCount",
                                     (uint64_t)e->security_open_candidate_count, 32);
                _parent->setProperty("AirportRTW89BSSLastSecurityOpenClearCount",
                                     (uint64_t)e->security_open_clear_count, 32);
                _parent->setProperty("AirportRTW89BSSLastSecurityScanGeneration",
                                     (uint64_t)e->last_security_scan_generation, 32);
                _parent->setProperty("AirportRTW89BSSLastOpenCandidateScanGeneration",
                                     (uint64_t)e->open_candidate_scan_generation, 32);

                /* 0.2.209: keep RSSI transition diagnostics memory-only on
                 * the scan RX path.  scanDone() publishes the aggregate once
                 * the sweep is complete so diagnostics cannot perturb beacon
                 * processing with IORegistry allocation/locking. */
                memcpy(_scanRSSILastBSSID, e->bssid, sizeof(_scanRSSILastBSSID));
                _scanRSSILastPrevious = previousRSSI;
                _scanRSSILastIncoming = bss->rssi;
                _scanRSSILastDelta = rssiDelta;
                _scanRSSILastAbsDelta = rssiAbsDelta;
                _scanRSSILastObservationGapMS = observationGapNs / 1000000ULL;
                _scanRSSILastGeneration = _scanGeneration;
                _scanRSSILastLargeJump = rssiAbsDelta >= 30U;
                _scanRSSILastIncomingWasMinus90 = bss->rssi == -90;
                _scanRSSILastIncomingWasMinus110 = incomingRSSISentinel;
                _scanRSSILastSentinelRejected = preserveRSSI;
                _scanRSSILastApplied = appliedRSSI;
                if (preserveRSSI)
                    ++_scanRSSISentinelRejectCount;
                if (_scanRSSILastLargeJump)
                    ++_scanRSSILargeJumpCount;
            }

            IOFree(bss, sizeof(*bss));
            IOLockUnlock(_bssLock);
            kfree_skb(skb);
            return;
        }
    }

    ++_scanBSSNewCount;

    /* First observation of a BSSID.  A security TLV is authoritative even if
     * one capability sample is contradictory; normalize Privacy to match the
     * persistent security state. */
    const bool firstSecurityIE =
        bss->rsn_ie_len >= 2 || bss->wpa_ie_len >= 2;
    if (firstSecurityIE) {
        bss->capabilities |= 0x0010U;
        bss->last_security_scan_generation = _scanGeneration;
    }
    bss->rsn_observation_count = bss->rsn_ie_len >= 2 ? 1U : 0U;
    bss->security_update_count = firstSecurityIE ? 1U : 0U;
    bss->security_preserve_count = 0;
    bss->security_open_candidate_count = 0;
    bss->security_open_clear_count = 0;
    bss->open_candidate_scan_generation = 0;
    bss->next = _bssList;
    _bssList  = bss;
    _bssCount++;
    if (_parent) {
        _parent->setProperty("AirportRTW89BSSLastPersistentRSNLength",
                             (uint64_t)bss->rsn_ie_len, 16);
        _parent->setProperty("AirportRTW89BSSLastPersistentCipher",
                             (uint64_t)bss->cipher, 32);
        _parent->setProperty("AirportRTW89BSSLastPersistentAKM",
                             (uint64_t)bss->akm, 32);
        _parent->setProperty("AirportRTW89BSSLastRSNObservationCount",
                             (uint64_t)bss->rsn_observation_count, 32);
        _parent->setProperty("AirportRTW89BSSLastSecurityUpdateCount",
                             (uint64_t)bss->security_update_count, 32);
        _parent->setProperty("AirportRTW89BSSLastSecurityPreserveCount",
                             (uint64_t)bss->security_preserve_count, 32);
        _parent->setProperty("AirportRTW89BSSLastSecurityOpenCandidateCount",
                             (uint64_t)bss->security_open_candidate_count, 32);
        _parent->setProperty("AirportRTW89BSSLastSecurityOpenClearCount",
                             (uint64_t)bss->security_open_clear_count, 32);
        _parent->setProperty("AirportRTW89BSSLastSecurityScanGeneration",
                             (uint64_t)bss->last_security_scan_generation, 32);
    }

    IOLockUnlock(_bssLock);

    kfree_skb(skb);
}

void RTW88IEEE80211::processRxData(struct sk_buff *skb)
{
    bool connected = (_state == RTW88_STATE_CONNECTED) ||
                     (_state == RTW88_STATE_HANDSHAKING) ||
                     (_state == RTW88_STATE_SCANNING &&
                      _scanReturnState == RTW88_STATE_CONNECTED);
    if (!connected) {
        kfree_skb(skb);
        return;
    }

    if (_state == RTW88_STATE_HANDSHAKING) {
        _handshakeDataFrames++;
        if (_parent)
            _parent->setProperty("AirportRTW89HandshakeDataFrames",
                                 (uint64_t)_handshakeDataFrames, 32);
    }

    /* If this TID has an active downlink BlockAck agreement, run the frame
     * through the per-TID reorder buffer so A-MPDU subframes (and frames
     * retransmitted in a later A-MPDU) reach the stack in order.  Delivering
     * out of order collapses TCP and trips CCMP replay drops — that is the RX
     * regression aggregation otherwise causes. */
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    if (ieee80211_is_data_qos(hdr->frame_control)) {
        uint16_t hdrlen = ieee80211_get_hdrlen_from_skb(skb);
        if (skb->len >= hdrlen) {
            uint8_t tid = (uint8_t)(skb->data[hdrlen - 2] & 0x0f);
            if (tid < kRxBaNumTid && _rxBa[tid] && _rxBa[tid]->active) {
                uint16_t sn = (uint16_t)
                    ((le16_to_cpu(hdr->seq_ctrl) & 0xFFF0) >> 4);
                rxReorderInput(tid, skb, sn);   /* takes ownership of skb */
                return;
            }
        }
    }

    deliverDataFrame(skb);   /* no active RX BA — deliver immediately */
}

/* Strip the 802.11 header (+ optional CCMP IV), de-aggregate A-MSDU if present,
 * and hand each MSDU to the network stack as Ethernet.  Takes ownership of skb. */
void RTW88IEEE80211::deliverDataFrame(struct sk_buff *skb)
{
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    uint16_t hdrlen = ieee80211_get_hdrlen_from_skb(skb);
    if (skb->len < hdrlen) { kfree_skb(skb); return; }

    bool amsdu = false;
    if (ieee80211_is_data_qos(hdr->frame_control))
        amsdu = (skb->data[hdrlen - 2] & 0x80) != 0;  /* QoS-ctl A-MSDU bit */

    if (amsdu) {
        ++_rxAmsduFrameCount;
        /* QoS A-MSDU: header [+ CCMP IV] then a chain of subframes.  rtw88
         * leaves the CCMP IV in the frame (mac80211 would normally strip it). */
        uint32_t off = hdrlen;
        if (ieee80211_has_protected(hdr->frame_control)) {
            if (skb->len < off + 8) { kfree_skb(skb); return; }
            off += 8;
        }
        deAmsdu(skb->data + off, skb->len - off);
        kfree_skb(skb);
        return;
    }

    /* Single MSDU.  Decrypted CCMP frames may still carry the 8-byte CCMP
     * header before the plaintext LLC/SNAP bytes. */
    uint32_t payload_off = hdrlen;
    if (skb->len < payload_off + 8) { kfree_skb(skb); return; }
    const uint8_t *llc = skb->data + payload_off;
    if ((llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) &&
        ieee80211_has_protected(hdr->frame_control) &&
        skb->len >= payload_off + 8 + 8) {
        const uint8_t *ccmp_llc = skb->data + payload_off + 8;
        if (ccmp_llc[0] == 0xAA && ccmp_llc[1] == 0xAA && ccmp_llc[2] == 0x03) {
            payload_off += 8;
            llc = ccmp_llc;
            if (!_rxCcmpIvSkipLogged) {
                IOLog("rtw88: rx protected data includes CCMP IV, skipping it\n");
                _rxCcmpIvSkipLogged = true;
            }
        }
    }

    /* LLC SNAP: AA AA 03 00 00 00 ETHERTYPE */
    uint16_t ethertype = 0;
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
        ethertype = (uint16_t)((llc[6] << 8) | llc[7]);
        /* Check for EAPOL during handshake (never aggregated). */
        if (ethertype == ETH_P_PAE && _state == RTW88_STATE_HANDSHAKING) {
            _handshakeEapolFrames++;
            if (_parent) {
                _parent->setProperty("AirportRTW89HandshakeEAPOLFrames",
                                     (uint64_t)_handshakeEapolFrames, 32);
                if (_assocNotifyInProgress)
                    _parent->setProperty(
                        "AirportRTW89HandshakeEAPOLBeforeAssocNotifyComplete",
                        kOSBooleanTrue);
            }
            if (!_appleRSNMode) {
                handleEAPOL(llc + 8, skb->len - payload_off - 8);
                kfree_skb(skb);
                return;
            }
            /* Apple RSN owns the 4-way handshake in 0.2.163.  Do not consume
             * EAPOL in the internal supplicant; let the normal Ethernet
             * decapsulation below inject it onto en2 for IO80211Family. */
            ++_appleRSNEAPOLRxCount;
            if (_parent) {
                const UInt64 nowMS = rtw88_now_ns() / 1000000ULL;
                _parent->setProperty("AirportRTW89AppleRSNEAPOLRxSeen",
                                     kOSBooleanTrue);
                _parent->setProperty("AirportRTW89AppleRSNEAPOLRxCount",
                                     (uint64_t)_appleRSNEAPOLRxCount, 32);
                if (_appleRSNEAPOLRxCount == 1U)
                    _parent->setProperty("AirportRTW89SecurityControlEAPOLRxFirstMS",
                                         (uint64_t)nowMS, 64);
                _parent->setProperty("AirportRTW89SecurityControlEAPOLRxLastMS",
                                     (uint64_t)nowMS, 64);
                _parent->setProperty("AirportRTW89SecurityControlEAPOLRxState",
                                     (uint64_t)_state, 8);
            }
        }
    }

    /* DA = addr1 (recipient = us), SA = addr3 (original source via DS) */
    uint32_t paylen = skb->len - payload_off - 8; /* strip 802.11/CCMP/LLC */

    /* 0.2.48: record the exact 802.11 -> LLC boundary for DHCP replies. */
    bool rxParitySingleDHCP = false;
    if (ethertype == 0x0800 && paylen >= 28) {
        const uint8_t *rxParityIP = llc + 8;
        size_t rxParityIHL = (size_t)(rxParityIP[0] & 0x0f) * 4;
        if ((rxParityIP[0] >> 4) == 4 && rxParityIHL >= 20 &&
            paylen >= rxParityIHL + 8 && rxParityIP[9] == 17) {
            uint16_t rxParitySport =
                (uint16_t)((rxParityIP[rxParityIHL] << 8) |
                           rxParityIP[rxParityIHL + 1]);
            uint16_t rxParityDport =
                (uint16_t)((rxParityIP[rxParityIHL + 2] << 8) |
                           rxParityIP[rxParityIHL + 3]);
            rxParitySingleDHCP = (rxParitySport == 67 && rxParityDport == 68);
        }
    }
    if (rxParitySingleDHCP && _parent) {
        static uint32_t rxParity80211Count = 0;
        rxParity80211Count++;
        _parent->setProperty("AirportRTW89RxParity80211Count",
                             (uint64_t)rxParity80211Count, 32);
        _parent->setProperty("AirportRTW89RxParity80211Protected",
                             ieee80211_has_protected(hdr->frame_control)
                                 ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89RxParity80211HdrLen",
                             (uint64_t)hdrlen, 16);
        _parent->setProperty("AirportRTW89RxParity80211PayloadOffset",
                             (uint64_t)payload_off, 16);
        _parent->setProperty("AirportRTW89RxParity80211CcmpBytesSkipped",
                             (uint64_t)(payload_off - hdrlen), 16);
        _parent->setProperty("AirportRTW89RxParity80211SKBLen",
                             (uint64_t)skb->len, 32);
        _parent->setProperty("AirportRTW89RxParity80211LLCOffset",
                             (uint64_t)payload_off, 16);
        _parent->setProperty("AirportRTW89RxParity80211EtherPayloadLen",
                             (uint64_t)paylen, 32);
        _parent->setProperty("AirportRTW89RxParity80211AMSDU",
                             amsdu ? kOSBooleanTrue : kOSBooleanFalse);
    }

    deliverEthernet(hdr->addr1, hdr->addr3, ethertype, llc + 8, paylen);
    kfree_skb(skb);
}

/* 0.2.48: passive RX parity helpers.  These intentionally do not mutate
 * the received packet.  They let us compare our hand-decapsulated DHCP frame
 * with the Ethernet/IP/UDP shape that Intel's net80211 path would hand to
 * IOEthernetInterface. */
static uint32_t rtw89_rx_parity_sum16(const uint8_t *p, size_t len, uint32_t sum)
{
    while (len >= 2) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return sum;
}

static uint16_t rtw89_rx_parity_finish_sum16(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)(~sum & 0xffffU);
}

static uint64_t rtw89_rx_parity_mac48(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned int i = 0; i < 6; i++)
        v = (v << 8) | p[i];
    return v;
}

/* Build one Ethernet frame [da][sa][ethertype][payload] and inject it. */
void RTW88IEEE80211::deliverEthernet(const uint8_t *da, const uint8_t *sa,
                                     uint16_t ethertype,
                                     const uint8_t *payload, uint32_t paylen)
{
    /* 0.2.48 Intel/net80211 RX parity audit.  Read-only diagnostics for
     * DHCP server -> client frames after our 802.11/LLC decapsulation. */
    if (_parent && ethertype == 0x0800 && paylen >= 28) {
        uint8_t ipVersion = (uint8_t)(payload[0] >> 4);
        size_t ipIHL = (size_t)(payload[0] & 0x0f) * 4;
        if (ipVersion == 4 && ipIHL >= 20 && paylen >= ipIHL + 8 &&
            payload[9] == 17) {
            const uint8_t *udp = payload + ipIHL;
            uint16_t sport = (uint16_t)((udp[0] << 8) | udp[1]);
            uint16_t dport = (uint16_t)((udp[2] << 8) | udp[3]);
            if (sport == 67 && dport == 68) {
                static uint32_t parityDHCPCount = 0;
                parityDHCPCount++;

                uint16_t ipTotalLen =
                    (uint16_t)((payload[2] << 8) | payload[3]);
                uint16_t ipHeaderChecksum =
                    (uint16_t)((payload[10] << 8) | payload[11]);
                uint16_t udpLen = (uint16_t)((udp[4] << 8) | udp[5]);
                uint16_t udpChecksum = (uint16_t)((udp[6] << 8) | udp[7]);

                bool ipLengthValid = ipTotalLen >= ipIHL &&
                                     ipTotalLen <= paylen;
                bool udpLengthValid = udpLen >= 8 && ipLengthValid &&
                                      (size_t)udpLen <= ipTotalLen - ipIHL &&
                                      ipIHL + (size_t)udpLen <= paylen;

                uint32_t ipSum = rtw89_rx_parity_sum16(payload, ipIHL, 0);
                bool ipChecksumValid =
                    rtw89_rx_parity_finish_sum16(ipSum) == 0;

                bool udpChecksumValid = (udpChecksum == 0);
                if (udpChecksum != 0 && udpLengthValid) {
                    uint32_t udpSum = 0;
                    udpSum = rtw89_rx_parity_sum16(payload + 12, 8, udpSum);
                    udpSum += 17;       /* IPPROTO_UDP */
                    udpSum += udpLen;
                    udpSum = rtw89_rx_parity_sum16(udp, udpLen, udpSum);
                    udpChecksumValid =
                        rtw89_rx_parity_finish_sum16(udpSum) == 0;
                }

                uint32_t srcIPv4 = ((uint32_t)payload[12] << 24) |
                                   ((uint32_t)payload[13] << 16) |
                                   ((uint32_t)payload[14] << 8) |
                                   payload[15];
                uint32_t dstIPv4 = ((uint32_t)payload[16] << 24) |
                                   ((uint32_t)payload[17] << 16) |
                                   ((uint32_t)payload[18] << 8) |
                                   payload[19];

                _parent->setProperty("AirportRTW89RxParityDHCPCount",
                                     (uint64_t)parityDHCPCount, 32);
                _parent->setProperty("AirportRTW89RxParityDA48",
                                     rtw89_rx_parity_mac48(da), 64);
                _parent->setProperty("AirportRTW89RxParitySA48",
                                     rtw89_rx_parity_mac48(sa), 64);
                _parent->setProperty("AirportRTW89RxParityEtherType",
                                     (uint64_t)ethertype, 16);
                _parent->setProperty("AirportRTW89RxParityEtherPayloadLen",
                                     (uint64_t)paylen, 32);
                _parent->setProperty("AirportRTW89RxParityEtherFrameLen",
                                     (uint64_t)(14 + paylen), 32);
                _parent->setProperty("AirportRTW89RxParityIPVersion",
                                     (uint64_t)ipVersion, 8);
                _parent->setProperty("AirportRTW89RxParityIPIHL",
                                     (uint64_t)ipIHL, 16);
                _parent->setProperty("AirportRTW89RxParityIPTotalLen",
                                     (uint64_t)ipTotalLen, 16);
                _parent->setProperty("AirportRTW89RxParityIPLengthValid",
                                     ipLengthValid ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89RxParityIPTrailingBytes",
                                     (uint64_t)(ipLengthValid ? paylen - ipTotalLen : 0),
                                     32);
                _parent->setProperty("AirportRTW89RxParityIPHeaderChecksum",
                                     (uint64_t)ipHeaderChecksum, 16);
                _parent->setProperty("AirportRTW89RxParityIPChecksumValid",
                                     ipChecksumValid ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89RxParitySrcIPv4BE",
                                     (uint64_t)srcIPv4, 32);
                _parent->setProperty("AirportRTW89RxParityDstIPv4BE",
                                     (uint64_t)dstIPv4, 32);
                _parent->setProperty("AirportRTW89RxParityUDPSport",
                                     (uint64_t)sport, 16);
                _parent->setProperty("AirportRTW89RxParityUDPDport",
                                     (uint64_t)dport, 16);
                _parent->setProperty("AirportRTW89RxParityUDPLen",
                                     (uint64_t)udpLen, 16);
                _parent->setProperty("AirportRTW89RxParityUDPLengthValid",
                                     udpLengthValid ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89RxParityUDPTrailingBytes",
                                     (uint64_t)(udpLengthValid
                                         ? (ipTotalLen - ipIHL - udpLen) : 0), 32);
                _parent->setProperty("AirportRTW89RxParityUDPChecksum",
                                     (uint64_t)udpChecksum, 16);
                _parent->setProperty("AirportRTW89RxParityUDPChecksumValid",
                                     udpChecksumValid ? kOSBooleanTrue : kOSBooleanFalse);

                if (udpLengthValid && udpLen >= 8 + 240) {
                    const uint8_t *bootp = udp + 8;
                    size_t bootpLen = udpLen - 8;
                    uint32_t xid = ((uint32_t)bootp[4] << 24) |
                                   ((uint32_t)bootp[5] << 16) |
                                   ((uint32_t)bootp[6] << 8) |
                                   bootp[7];
                    uint16_t bootpFlags =
                        (uint16_t)((bootp[10] << 8) | bootp[11]);
                    uint32_t yiaddr = ((uint32_t)bootp[16] << 24) |
                                      ((uint32_t)bootp[17] << 16) |
                                      ((uint32_t)bootp[18] << 8) |
                                      bootp[19];
                    uint32_t cookie = ((uint32_t)bootp[236] << 24) |
                                      ((uint32_t)bootp[237] << 16) |
                                      ((uint32_t)bootp[238] << 8) |
                                      bootp[239];
                    uint8_t dhcpType = 0;
                    size_t opt = 240;
                    while (opt < bootpLen) {
                        uint8_t code = bootp[opt++];
                        if (code == 0)
                            continue;
                        if (code == 255)
                            break;
                        if (opt >= bootpLen)
                            break;
                        uint8_t olen = bootp[opt++];
                        if (opt + olen > bootpLen)
                            break;
                        if (code == 53 && olen == 1)
                            dhcpType = bootp[opt];
                        opt += olen;
                    }

                    _parent->setProperty("AirportRTW89RxParityBOOTPOp",
                                         (uint64_t)bootp[0], 8);
                    _parent->setProperty("AirportRTW89RxParityBOOTPHTYPE",
                                         (uint64_t)bootp[1], 8);
                    _parent->setProperty("AirportRTW89RxParityBOOTPHLEN",
                                         (uint64_t)bootp[2], 8);
                    _parent->setProperty("AirportRTW89RxParityBOOTPFlags",
                                         (uint64_t)bootpFlags, 16);
                    _parent->setProperty("AirportRTW89RxParityBOOTPTransactionID",
                                         (uint64_t)xid, 32);
                    _parent->setProperty("AirportRTW89RxParityBOOTPYourIPv4BE",
                                         (uint64_t)yiaddr, 32);
                    _parent->setProperty("AirportRTW89RxParityBOOTPClientMAC48",
                                         rtw89_rx_parity_mac48(bootp + 28), 64);
                    _parent->setProperty("AirportRTW89RxParityDHCPMagicCookie",
                                         (uint64_t)cookie, 32);
                    _parent->setProperty("AirportRTW89RxParityDHCPMagicCookieValid",
                                         cookie == 0x63825363U
                                             ? kOSBooleanTrue : kOSBooleanFalse);
                    _parent->setProperty("AirportRTW89RxParityDHCPMessageType",
                                         (uint64_t)dhcpType, 8);
                }
            }
        }
    }
    /* 0.2.44: passive RX-delivery audit for DHCP Offers. */
    bool rxDeliveryOffer = false;
    uint16_t rxDeliverySport = 0;
    uint16_t rxDeliveryDport = 0;
    uint16_t rxDeliveryIPTotalLen = 0;
    uint16_t rxDeliveryUDPLen = 0;
    size_t rxDeliveryIHL = 0;
    /* 0.2.30 RX-side ordinary data classification before injection. */
    if (ethertype == 0x0806) {
        _ordinaryRxARPCount++;
        _parent->setProperty("AirportRTW89OrdinaryRxARPCount",
                             (uint64_t)_ordinaryRxARPCount, 32);
    } else if (ethertype == 0x0800 && paylen >= 28 && payload[9] == 17) {
        size_t ihl = (size_t)(payload[0] & 0x0f) * 4;
        if (ihl >= 20 && paylen >= ihl + 8) {
            uint16_t sport = (uint16_t)((payload[ihl] << 8) | payload[ihl + 1]);
            uint16_t dport = (uint16_t)((payload[ihl + 2] << 8) | payload[ihl + 3]);
            if (sport == 67 && dport == 68) {
                _ordinaryRxDHCPOfferCount++;
                _parent->setProperty("AirportRTW89OrdinaryRxDHCPOfferCount",
                                     (uint64_t)_ordinaryRxDHCPOfferCount, 32);
                rxDeliveryOffer = true;
                rxDeliverySport = sport;
                rxDeliveryDport = dport;
                rxDeliveryIHL = ihl;
                if (paylen >= 4)
                    rxDeliveryIPTotalLen =
                        (uint16_t)((payload[2] << 8) | payload[3]);
                if (paylen >= ihl + 6)
                    rxDeliveryUDPLen =
                        (uint16_t)((payload[ihl + 4] << 8) | payload[ihl + 5]);

                static uint32_t offerDetectedCount = 0;
                offerDetectedCount++;
                _parent->setProperty("AirportRTW89RxDeliveryOfferDetectedCount",
                                     (uint64_t)offerDetectedCount, 32);
                _parent->setProperty("AirportRTW89RxDeliveryEthertype",
                                     (uint64_t)ethertype, 16);
                _parent->setProperty("AirportRTW89RxDeliveryPayLen",
                                     (uint64_t)paylen, 32);
                _parent->setProperty("AirportRTW89RxDeliveryEthernetLen",
                                     (uint64_t)(14 + paylen), 32);
                _parent->setProperty("AirportRTW89RxDeliveryIHL",
                                     (uint64_t)rxDeliveryIHL, 16);
                _parent->setProperty("AirportRTW89RxDeliveryIPTotalLen",
                                     (uint64_t)rxDeliveryIPTotalLen, 16);
                _parent->setProperty("AirportRTW89RxDeliveryUDPLen",
                                     (uint64_t)rxDeliveryUDPLen, 16);
                _parent->setProperty("AirportRTW89RxDeliverySport",
                                     (uint64_t)rxDeliverySport, 16);
                _parent->setProperty("AirportRTW89RxDeliveryDport",
                                     (uint64_t)rxDeliveryDport, 16);
            }
        }
    }

    /* Allocate via IONetworkController::allocatePacket (through the parent) —
     * NOT mbuf_allocpacket.  allocatePacket sets m_len/pkthdr.len consistently
     * for every segment, which the dlil input validator requires.
     * mbuf_copyback fills the data and is chain-safe. */
    if (!_parent) return;
    if (rxDeliveryOffer) {
        static uint32_t allocAttemptCount = 0;
        allocAttemptCount++;
        _parent->setProperty("AirportRTW89RxDeliveryParentPresent",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89RxDeliveryAllocAttemptCount",
                             (uint64_t)allocAttemptCount, 32);
    }
    mbuf_t m = _parent->allocateInputPacket(14 + paylen);
    if (!m) {
        if (rxDeliveryOffer) {
            static uint32_t allocFailCount = 0;
            allocFailCount++;
            _parent->setProperty("AirportRTW89RxDeliveryAllocSuccess",
                                 kOSBooleanFalse);
            _parent->setProperty("AirportRTW89RxDeliveryAllocFailCount",
                                 (uint64_t)allocFailCount, 32);
        }
        return;
    }
    if (rxDeliveryOffer) {
        static uint32_t allocSuccessCount = 0;
        allocSuccessCount++;
        _parent->setProperty("AirportRTW89RxDeliveryAllocSuccess",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89RxDeliveryAllocSuccessCount",
                             (uint64_t)allocSuccessCount, 32);
        _parent->setProperty("AirportRTW89RxDeliveryAllocatedPkthdrLen",
                             (uint64_t)mbuf_pkthdr_len(m), 32);
        _parent->setProperty("AirportRTW89RxDeliveryAllocatedMLen",
                             (uint64_t)mbuf_len(m), 32);
    }

    uint8_t ehdr[14];
    memcpy(ehdr,     da, 6);
    memcpy(ehdr + 6, sa, 6);
    ehdr[12] = (uint8_t)(ethertype >> 8);
    ehdr[13] = (uint8_t)(ethertype & 0xff);

    int headerCopyResult = mbuf_copyback(m, 0, 14, ehdr, MBUF_WAITOK);
    int payloadCopyResult = 0;
    if (headerCopyResult == 0 && paylen)
        payloadCopyResult = mbuf_copyback(m, 14, paylen, payload, MBUF_WAITOK);

    if (rxDeliveryOffer) {
        _parent->setProperty("AirportRTW89RxDeliveryHeaderCopyResult",
                             (uint64_t)(uint32_t)headerCopyResult, 32);
        _parent->setProperty("AirportRTW89RxDeliveryPayloadCopyResult",
                             (uint64_t)(uint32_t)payloadCopyResult, 32);
        _parent->setProperty("AirportRTW89RxDeliveryHeaderCopySuccess",
                             headerCopyResult == 0 ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89RxDeliveryPayloadCopySuccess",
                             payloadCopyResult == 0 ? kOSBooleanTrue : kOSBooleanFalse);
    }

    if (headerCopyResult != 0 || payloadCopyResult != 0) {
        if (rxDeliveryOffer) {
            static uint32_t copyFailCount = 0;
            copyFailCount++;
            _parent->setProperty("AirportRTW89RxDeliveryCopyFailCount",
                                 (uint64_t)copyFailCount, 32);
        }
        mbuf_freem(m);
        return;
    }
    if (rxDeliveryOffer) {
        static uint32_t injectCallCount = 0;
        injectCallCount++;
        _parent->setProperty("AirportRTW89RxDeliveryInjectCallCount",
                             (uint64_t)injectCallCount, 32);
        _parent->setProperty("AirportRTW89RxDeliveryPreInjectPkthdrLen",
                             (uint64_t)mbuf_pkthdr_len(m), 32);
        _parent->setProperty("AirportRTW89RxDeliveryPreInjectMLen",
                             (uint64_t)mbuf_len(m), 32);
    }
    _parent->injectRxFrame(m);
}

/* Split an A-MSDU payload into its constituent MSDUs and deliver each. */
void RTW88IEEE80211::deAmsdu(const uint8_t *data, uint32_t len)
{
    uint32_t pos = 0;
    /* Subframe: DA(6) SA(6) Length(2, big-endian) | MSDU(Length) | pad to a
     * 4-byte boundary (the last subframe is not padded). */
    while (pos + 14 <= len) {
        const uint8_t *sf = data + pos;
        uint16_t sublen = (uint16_t)((sf[12] << 8) | sf[13]);
        if (sublen < 8 || pos + 14 + sublen > len) {
            ++_rxAmsduMalformedCount;
            break;   /* truncated / malformed */
        }
        const uint8_t *msdu = sf + 14;
        if (msdu[0] == 0xAA && msdu[1] == 0xAA && msdu[2] == 0x03) {
            uint16_t ethertype = (uint16_t)((msdu[6] << 8) | msdu[7]);
            ++_rxAmsduSubframeCount;
            deliverEthernet(sf, sf + 6, ethertype, msdu + 8, sublen - 8);
        } else {
            ++_rxAmsduMalformedCount;
        }
        pos += (14u + sublen + 3u) & ~3u;   /* next subframe (4-byte aligned) */
    }
}

/* ------------------------------------------------------------------ */
/*  RX A-MPDU reorder buffer                                            */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::rxBaSetup(uint8_t tid, uint16_t ssn, uint16_t bufsize)
{
    if (tid >= kRxBaNumTid) return;
    if (bufsize == 0 || bufsize > kRxBaMaxBuf) bufsize = kRxBaMaxBuf;

    IOLockLock(_rxBaLock);
    RxReorder *r = _rxBa[tid];
    if (!r) {
        r = (RxReorder *)IOMallocZero(sizeof(RxReorder));
        _rxBa[tid] = r;
    } else {
        for (uint32_t i = 0; i < kRxBaMaxBuf; i++)
            if (r->buf[i]) { kfree_skb(r->buf[i]); r->buf[i] = nullptr; }
    }
    if (r) {
        r->active  = true;
        r->headSn  = (uint16_t)(ssn & 0xFFF);
        r->bufSize = bufsize;
        r->stored  = 0;
    }
    IOLockUnlock(_rxBaLock);
}

void RTW88IEEE80211::rxBaTeardown(uint8_t tid)
{
    if (tid >= kRxBaNumTid) return;
    struct sk_buff *freelist[kRxBaMaxBuf];
    uint32_t nf = 0;

    IOLockLock(_rxBaLock);
    RxReorder *r = _rxBa[tid];
    if (r) {
        for (uint32_t i = 0; i < kRxBaMaxBuf; i++)
            if (r->buf[i]) { freelist[nf++] = r->buf[i]; r->buf[i] = nullptr; }
        _rxBa[tid] = nullptr;
    }
    IOLockUnlock(_rxBaLock);

    if (r) {
        IOFree(r, sizeof(RxReorder));
        for (uint32_t i = 0; i < nf; i++)
            kfree_skb(freelist[i]);
    }
}

void RTW88IEEE80211::rxBaTeardownAll()
{
    for (uint8_t tid = 0; tid < kRxBaNumTid; tid++)
        rxBaTeardown(tid);
    /* Deliberately do NOT cancel _reorderTimer here: teardown can run on a
     * different workloop than the timer, and a stray fire is harmless (it finds
     * every TID inactive/empty and does nothing). */
}

void RTW88IEEE80211::rxReorderInput(uint8_t tid, struct sk_buff *skb, uint16_t sn)
{
    struct sk_buff *out[kRxBaMaxBuf];
    uint32_t nout = 0;
    bool needTimer = false;

    IOLockLock(_rxBaLock);
    RxReorder *r = _rxBa[tid];
    if (!r || !r->active) {            /* torn down between dispatch and here */
        IOLockUnlock(_rxBaLock);
        deliverDataFrame(skb);
        return;
    }

    uint16_t rel = (uint16_t)((sn - r->headSn) & 0xFFF);
    if (rel >= 2048) {                 /* before the window: stale / duplicate */
        IOLockUnlock(_rxBaLock);
        kfree_skb(skb);
        return;
    }

    if (rel >= r->bufSize) {
        /* sn is ahead of the window — slide the window up, releasing buffered
         * frames that fall out the bottom (in order; missing ones are lost). */
        uint16_t newHead = (uint16_t)((sn + 1 - r->bufSize) & 0xFFF);
        while (((newHead - r->headSn) & 0xFFF) != 0 &&
               ((newHead - r->headSn) & 0xFFF) < 2048 && nout < kRxBaMaxBuf) {
            uint16_t hidx = r->headSn % kRxBaMaxBuf;
            if (r->buf[hidx]) {
                out[nout++] = r->buf[hidx];
                r->buf[hidx] = nullptr;
                r->stored--;
            }
            r->headSn = (uint16_t)((r->headSn + 1) & 0xFFF);
        }
    }

    uint16_t idx = sn % kRxBaMaxBuf;
    if (r->buf[idx]) {                 /* duplicate within the window */
        kfree_skb(skb);
    } else {
        r->buf[idx] = skb;
        r->stored++;
    }

    /* Release the in-order run starting at head. */
    while (r->stored > 0 && nout < kRxBaMaxBuf) {
        uint16_t hidx = r->headSn % kRxBaMaxBuf;
        if (!r->buf[hidx]) break;
        out[nout++] = r->buf[hidx];
        r->buf[hidx] = nullptr;
        r->stored--;
        r->headSn = (uint16_t)((r->headSn + 1) & 0xFFF);
    }
    needTimer = (r->stored > 0);
    IOLockUnlock(_rxBaLock);

    for (uint32_t i = 0; i < nout; i++)
        deliverDataFrame(out[i]);

    if (needTimer)
        rxReorderArmTimer();
}

void RTW88IEEE80211::rxReorderArmTimer()
{
    if (_reorderTimer)
        _reorderTimer->setTimeoutMS(kReorderTimeoutMs);
}

/* Timer: a hole has persisted past the reorder timeout (the missing frame is
 * not coming).  Force progress by releasing past the first hole on each TID. */
void RTW88IEEE80211::rxReorderFlushStale()
{
    struct sk_buff *out[kRxBaMaxBuf];
    uint32_t nout = 0;
    bool again = false;

    IOLockLock(_rxBaLock);
    for (uint8_t tid = 0; tid < kRxBaNumTid; tid++) {
        RxReorder *r = _rxBa[tid];
        if (!r || !r->active || r->stored == 0) continue;

        /* Skip leading holes (lost frames), then release the next run. */
        uint32_t guard = 0;
        while (r->stored > 0 && guard < 4096) {
            uint16_t hidx = r->headSn % kRxBaMaxBuf;
            if (r->buf[hidx]) break;
            r->headSn = (uint16_t)((r->headSn + 1) & 0xFFF);
            guard++;
        }
        while (r->stored > 0 && nout < kRxBaMaxBuf) {
            uint16_t hidx = r->headSn % kRxBaMaxBuf;
            if (!r->buf[hidx]) break;
            out[nout++] = r->buf[hidx];
            r->buf[hidx] = nullptr;
            r->stored--;
            r->headSn = (uint16_t)((r->headSn + 1) & 0xFFF);
        }
        if (r->stored > 0) again = true;
    }
    IOLockUnlock(_rxBaLock);

    for (uint32_t i = 0; i < nout; i++)
        deliverDataFrame(out[i]);

    if (again)
        rxReorderArmTimer();
}

void RTW88IEEE80211::reorderTimerFired(OSObject *owner, IOTimerEventSource *)
{
    RTW88IEEE80211 *self = OSDynamicCast(RTW88IEEE80211, owner);
    if (self) self->rxReorderFlushStale();
}

/* ------------------------------------------------------------------ */
/*  TX status                                                           */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::txStatus(struct sk_buff *skb)
{
    if (!skb) return;

    /* EAPOL M2/M4 frames request an explicit rtw89 PCI TX report.  The
     * previous "Transmitted" property only meant that ops->tx accepted the
     * skb; it did not prove that the AP acknowledged the over-the-air frame. */
    if (skb->protocol == cpu_to_be16(ETH_P_PAE)) {
        struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
        uint32_t flags = info ? info->flags : 0;
        bool acked = (flags & IEEE80211_TX_STAT_ACK) != 0;
        uint8_t step = skb->pkt_type ? skb->pkt_type : _pendingEapolTxStep;

        IOLog("rtw88: EAPOL M%u TX status flags=0x%08x ack=%d\n",
              step, flags, acked);

        if (_parent) {
            _parent->setProperty("AirportRTW89HandshakeLastEAPOLTxStep",
                                 (uint64_t)step, 8);
            _parent->setProperty("AirportRTW89HandshakeLastEAPOLTxFlags",
                                 (uint64_t)flags, 32);
            _parent->setProperty("AirportRTW89HandshakeLastEAPOLTxAcked",
                                 acked ? kOSBooleanTrue : kOSBooleanFalse);
            if (step == 2) {
                _handshakeM2TxStatusCount++;
                _parent->setProperty("AirportRTW89HandshakeM2TxStatusSeen",
                                     kOSBooleanTrue);
                _parent->setProperty("AirportRTW89HandshakeM2TxStatusCount",
                                     (uint64_t)_handshakeM2TxStatusCount, 32);
                _parent->setProperty("AirportRTW89HandshakeM2TxFlags",
                                     (uint64_t)flags, 32);
                _parent->setProperty("AirportRTW89HandshakeM2TxAcked",
                                     acked ? kOSBooleanTrue : kOSBooleanFalse);
            } else if (step == 4) {
                _handshakeM4TxStatusCount++;
                _parent->setProperty("AirportRTW89HandshakeM4TxStatusSeen",
                                     kOSBooleanTrue);
                _parent->setProperty("AirportRTW89HandshakeM4TxStatusCount",
                                     (uint64_t)_handshakeM4TxStatusCount, 32);
                _parent->setProperty("AirportRTW89HandshakeM4TxFlags",
                                     (uint64_t)flags, 32);
                _parent->setProperty("AirportRTW89HandshakeM4TxAcked",
                                     acked ? kOSBooleanTrue : kOSBooleanFalse);
            }
        }
        _pendingEapolTxStep = 0;
    } else if (skb->pkt_type >= 0xB1 && skb->pkt_type <= 0xB4) {
        static const char *const seenKey[] = {
            "AirportRTW89NullAB_A_StatusSeen", "AirportRTW89NullAB_B_StatusSeen",
            "AirportRTW89NullAB_C_StatusSeen", "AirportRTW89NullAB_D_StatusSeen"};
        static const char *const flagsKey[] = {
            "AirportRTW89NullAB_A_StatusFlags", "AirportRTW89NullAB_B_StatusFlags",
            "AirportRTW89NullAB_C_StatusFlags", "AirportRTW89NullAB_D_StatusFlags"};
        static const char *const ackedKey[] = {
            "AirportRTW89NullAB_A_Acked", "AirportRTW89NullAB_B_Acked",
            "AirportRTW89NullAB_C_Acked", "AirportRTW89NullAB_D_Acked"};
        static const char *const statusCountKey[] = {
            "AirportRTW89NullAB_A_StatusCount", "AirportRTW89NullAB_B_StatusCount",
            "AirportRTW89NullAB_C_StatusCount", "AirportRTW89NullAB_D_StatusCount"};
        static const char *const ackCountKey[] = {
            "AirportRTW89NullAB_A_AckCount", "AirportRTW89NullAB_B_AckCount",
            "AirportRTW89NullAB_C_AckCount", "AirportRTW89NullAB_D_AckCount"};
        unsigned int v = skb->pkt_type - 0xB1;
        struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
        uint32_t flags = info ? info->flags : 0;
        bool acked = (flags & IEEE80211_TX_STAT_ACK) != 0;
        _nullABTxStatusCount[v]++;
        if (acked) _nullABTxAckCount[v]++;
        IOLog("rtw88: 0.2.43 NSSRA-%c TX status flags=0x%08x ack=%d\n",
              'A' + v, flags, acked);
        if (_parent) {
            _parent->setProperty(seenKey[v], kOSBooleanTrue);
            _parent->setProperty(flagsKey[v], (uint64_t)flags, 32);
            _parent->setProperty(ackedKey[v],
                                 acked ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty(statusCountKey[v],
                                 (uint64_t)_nullABTxStatusCount[v], 32);
            _parent->setProperty(ackCountKey[v],
                                 (uint64_t)_nullABTxAckCount[v], 32);
        }
    } else if (skb->pkt_type == 0xD0 || skb->pkt_type == 0xA0) {
        struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
        uint32_t flags = info ? info->flags : 0;
        bool acked = (flags & IEEE80211_TX_STAT_ACK) != 0;
        _ordinaryTxStatusCount++;
        if (acked) _ordinaryTxAckCount++;
        if (_parent) {
            _parent->setProperty("AirportRTW89OrdinaryTxStatusCount",
                                 (uint64_t)_ordinaryTxStatusCount, 32);
            _parent->setProperty("AirportRTW89OrdinaryTxAckCount",
                                 (uint64_t)_ordinaryTxAckCount, 32);
            _parent->setProperty("AirportRTW89OrdinaryLastTxStatusFlags",
                                 (uint64_t)flags, 32);
            _parent->setProperty("AirportRTW89OrdinaryLastTxStatusAcked",
                                 acked ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89OrdinaryLastTxStatusKind",
                                 skb->pkt_type == 0xD0 ? "DHCP" : "ARP");
        }
    }
}

/*
 * Pick the operating channel width for the connection and program it into
 * hw->conf.chandef (consumed by rtw_set_channel via connect_hw_setup).
 *
 * We parse the AP's HT Operation (EID 61) and VHT Operation (EID 192) from the
 * cached beacon IEs to learn the BSS width, then cap to what the chip supports
 * (from its band caps).  Without this the link is pinned to 20 MHz — e.g. an
 * 80 MHz VHT AP gives 173 Mbps (20 MHz MCS8) instead of 866 Mbps (80 MHz MCS9).
 * TKIP links stay 20 MHz (HT disallowed — see htAllowed()).
 */
void RTW88IEEE80211::setConnectedChandef(struct ieee80211_channel *chan)
{
    _hw->conf.chandef.chan         = chan;
    _hw->conf.chandef.width        = NL80211_CHAN_WIDTH_20_NOHT;
    _hw->conf.chandef.center_freq1 = chan->center_freq;
    _connChanWidth = 20;

    if (!htAllowed())
        return;

    enum nl80211_band bnd =
        (_targetBSS.channel > 14) ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
    struct ieee80211_supported_band *sb =
        (_hw->wiphy) ? _hw->wiphy->bands[bnd] : nullptr;
    if (!sb) return;

    bool chip40 = (sb->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40) != 0;
    bool chip80 = chip40 && bnd == NL80211_BAND_5GHZ && sb->vht_cap.vht_supported;

    /* Parse HT/VHT Operation from the cached beacon IEs. */
    int     sco        = 0;      /* HT secondary-channel offset: 1=above 3=below */
    bool    htStaWidth = false;  /* HT "STA Channel Width" (40 MHz allowed)      */
    int     vhtWidth   = 0;      /* VHT op channel width: >=1 means 80 MHz        */
    uint8_t vhtSeg0    = 0;      /* VHT center-frequency segment 0 (center chan)  */
    const uint8_t *ies = _targetBSS.ies;
    uint16_t ielen     = _targetBSS.ies_len;
    for (uint16_t i = 0; i + 2 <= ielen; ) {
        uint8_t id = ies[i], len = ies[i + 1];
        if ((uint32_t)i + 2 + len > ielen) break;
        const uint8_t *d = ies + i + 2;
        if (id == WLAN_EID_HT_OPERATION && len >= 2) {
            sco        = d[1] & 0x03;
            htStaWidth = (d[1] & 0x04) != 0;
        } else if (id == WLAN_EID_VHT_OPERATION && len >= 3) {
            vhtWidth = d[0];
            vhtSeg0  = d[1];
        }
        i += 2 + len;
    }

    /* 40 MHz (HT). */
    if (chip40 && htStaWidth && (sco == 1 || sco == 3)) {
        _connChanWidth = 40;
        _hw->conf.chandef.width = NL80211_CHAN_WIDTH_40;
        _hw->conf.chandef.center_freq1 =
            (uint32_t)((int)chan->center_freq + (sco == 1 ? 10 : -10));
    }

    /* 80 MHz (VHT) — overrides 40 when the AP runs an 80 MHz BSS.  width==1 is
     * the 80/160/80+80 indicator; seg0 is the 80 MHz center either way, so we
     * use it and cap to 80 (the chip's max).  Deprecated width 2/3 are ignored. */
    if (chip80 && vhtWidth == 1 && vhtSeg0 != 0) {
        _connChanWidth = 80;
        _hw->conf.chandef.width = NL80211_CHAN_WIDTH_80;
        _hw->conf.chandef.center_freq1 = (uint32_t)(5000 + 5 * vhtSeg0);
    }

    IOLog("rtw88: connected chandef: %u MHz (primary=%u cf1=%u)\n",
          _connChanWidth, chan->center_freq, _hw->conf.chandef.center_freq1);
}

/* ------------------------------------------------------------------ */
/*  Scan                                                                */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::restoreConnectedChannel()
{
    if (_scanReturnState != RTW88_STATE_CONNECTED || !_hw || !_vif)
        return;

    struct ieee80211_channel *chan = nullptr;
    for (int b = 0; b < NL80211_NUM_BANDS && !chan; b++) {
        struct ieee80211_supported_band *band =
            (_hw->wiphy) ? _hw->wiphy->bands[b] : nullptr;
        if (!band) continue;
        for (int j = 0; j < band->n_channels; j++) {
            if (band->channels[j].hw_value == _targetBSS.channel) {
                chan = &band->channels[j];
                chan->band = band->band;
                break;
            }
        }
    }

    if (chan) {
        setConnectedChandef(chan);
    } else {
        IOLog("rtw88: scan restore: ch=%u not in band table\n",
              _targetBSS.channel);
    }

    rtw88_restore_connected_hw(_hw, _vif, _targetBSS.bssid);

    struct ieee80211_bss_conf *bss = &_vif->bss_conf;
    bss->bssid = bss->bssid_buf;
    memcpy(bss->bssid_buf, _targetBSS.bssid, ETH_ALEN);
    bss->assoc = true;
    bss->aid   = _assocAID;
    _vif->cfg.assoc = true;
    _vif->cfg.aid   = _assocAID;
}

bool RTW88IEEE80211::abortActiveScan(bool waitForIdle)
{
    if (_state != RTW88_STATE_SCANNING)
        return true;

    RTW88State returnState = _scanReturnState;
    if (_manualScanChannelCount) {
        _manualScanAbort = true;
    } else if (_hw && _hw->ops && _hw->ops->cancel_hw_scan) {
        RTW89CompatWiphyGuard cfgGuard(_hw);
        _hw->ops->cancel_hw_scan(_hw, _vif);
    }

    if (!waitForIdle)
        return true;

    for (int i = 0; i < 40 && _state == RTW88_STATE_SCANNING; i++)
        IOSleep(50);

    if (_state == RTW88_STATE_SCANNING) {
        if (_manualScanChannelCount)
            return false;
        if (returnState == RTW88_STATE_CONNECTED)
            restoreConnectedChannel();
        _state = (returnState == RTW88_STATE_IDLE) ?
            RTW88_STATE_IDLE : returnState;
        _scanReturnState = RTW88_STATE_IDLE;
        _manualScanChannelCount = 0;
        _manualScanOnHomeChannel = false;
    }

    return _state != RTW88_STATE_SCANNING;
}

void RTW88IEEE80211::scanDone(bool aborted)
{
    if (!aborted) {
        const uint64_t scanDoneNowNs = rtw88_now_ns();
        uint32_t expiredThisScan = 0;
        IOLockLock(_bssLock);
        RTW88BSS **link = &_bssList;
        while (*link) {
            RTW88BSS *b = *link;
            RTW88State effectiveState =
                (_state == RTW88_STATE_SCANNING) ? _scanReturnState : _state;
            bool isTarget = (effectiveState == RTW88_STATE_CONNECTED ||
                             effectiveState == RTW88_STATE_HANDSHAKING) &&
                            memcmp(b->bssid, _targetBSS.bssid, 6) == 0;

            /* 0.2.182: resolve contradictory open/security observations only
             * after a complete scan generation.  Any RSN/WPA evidence for
             * this BSSID in the same generation wins.  Never downgrade the
             * currently connected/handshaking target from a background scan;
             * a real AP security-mode change will be learned after link loss. */
            if (b->open_candidate_scan_generation == _scanGeneration) {
                const bool securitySeenThisGeneration =
                    b->last_security_scan_generation == _scanGeneration;
                const bool hasPersistentSecurity =
                    b->rsn_ie_len >= 2 || b->wpa_ie_len >= 2;
                /* A beacon/probe observation without an RSN IE is not
                 * positive evidence that an AP became open.  Hidden-SSID
                 * responses, truncated frames, and mixed beacon/probe input
                 * can all omit the security element for one generation.
                 * Keep previously parsed security attached to this persistent
                 * BSSID; expiry/replacement remains the safe way to discard
                 * it.  This also prevents SET20 from seeing a WPA2 BSSID as
                 * open between the menu scan and the join request. */
                const bool commitOpen = false;

                if (commitOpen) {
                    b->cipher = 0;
                    b->group_cipher = 0;
                    b->akm = 0;
                    b->rsn_ie_len = 0;
                    b->wpa_ie_len = 0;
                    memset(b->rsn_ie, 0, sizeof(b->rsn_ie));
                    memset(b->wpa_ie, 0, sizeof(b->wpa_ie));
                    b->capabilities &= ~0x0010U;
                    b->security_open_clear_count++;
                    if (_parent) {
                        static uint32_t openCommitCount = 0;
                        ++openCommitCount;
                        _parent->setProperty(
                            "AirportRTW89BSSSecurityOpenCommitCount",
                            (uint64_t)openCommitCount, 32);
                        _parent->setProperty(
                            "AirportRTW89BSSLastOpenCandidateCommitted",
                            kOSBooleanTrue);
                        _parent->setProperty(
                            "AirportRTW89BSSLastOpenCandidateDiscardedBySecurity",
                            kOSBooleanFalse);
                        _parent->setProperty(
                            "AirportRTW89BSSLastSecurityOpenClearCount",
                            (uint64_t)b->security_open_clear_count, 32);
                    }
                } else if (securitySeenThisGeneration || isTarget) {
                    if (_parent) {
                        static uint32_t openDiscardCount = 0;
                        ++openDiscardCount;
                        _parent->setProperty(
                            "AirportRTW89BSSSecurityOpenDiscardCount",
                            (uint64_t)openDiscardCount, 32);
                        _parent->setProperty(
                            "AirportRTW89BSSLastOpenCandidateCommitted",
                            kOSBooleanFalse);
                        _parent->setProperty(
                            "AirportRTW89BSSLastOpenCandidateDiscardedBySecurity",
                            securitySeenThisGeneration ?
                                kOSBooleanTrue : kOSBooleanFalse);
                    }
                }
                b->open_candidate_scan_generation = 0;
            }

            const uint32_t generationAge =
                _scanGeneration - b->last_seen_scan;
            const uint64_t timeAgeNs =
                (b->last_seen_ns != 0 && scanDoneNowNs >= b->last_seen_ns) ?
                    (scanDoneNowNs - b->last_seen_ns) : 0;
            const bool expireForConnectedSlices =
                _scanSnapshotUsesRecentWindow && b->last_seen_ns != 0 &&
                timeAgeNs > kRTW88PersistentBSSExpireNs;
            /* 0.2.209: decouple disconnected cache lifetime from scan request
             * frequency.  A burst of Tahoe scans must not delete a nearby BSS
             * merely because it missed four consecutive sweeps in a few
             * seconds.  0.2.226 keeps the persistent node for a bounded five
             * minutes so missed/partial channel sweeps do not destroy identity.
             * copyBSSSnapshot() still exposes the original truthful last-seen
             * age; no cache access manufactures freshness. */
            const bool expireForFullScans =
                !_scanSnapshotUsesRecentWindow &&
                ((b->last_seen_ns != 0 &&
                  timeAgeNs > kRTW88PersistentBSSExpireNs) ||
                 (b->last_seen_ns == 0 && generationAge > 3));

            if (!isTarget &&
                (expireForConnectedSlices || expireForFullScans)) {
                *link = b->next;
                IOFree(b, sizeof(*b));
                if (_bssCount)
                    _bssCount--;
                ++expiredThisScan;
                continue;
            }

            link = &b->next;
        }
        IOLockUnlock(_bssLock);
        if (_parent) {
            _parent->setProperty("AirportRTW89BSSExpiredThisScan",
                                 (uint64_t)expiredThisScan, 32);
            _parent->setProperty("AirportRTW89BSSExpiryPolicyRecentWindow",
                                 _scanSnapshotUsesRecentWindow ?
                                     kOSBooleanTrue : kOSBooleanFalse);

            char refreshBSSID[18];
            snprintf(refreshBSSID, sizeof(refreshBSSID),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     _scanBSSLastRefreshBSSID[0], _scanBSSLastRefreshBSSID[1],
                     _scanBSSLastRefreshBSSID[2], _scanBSSLastRefreshBSSID[3],
                     _scanBSSLastRefreshBSSID[4], _scanBSSLastRefreshBSSID[5]);
            _parent->setProperty("AirportRTW89BSSObservationCountThisScan",
                                 (uint64_t)_scanBSSObservationCount, 32);
            _parent->setProperty("AirportRTW89BSSExistingRefreshCountThisScan",
                                 (uint64_t)_scanBSSExistingRefreshCount, 32);
            _parent->setProperty("AirportRTW89BSSNewCountThisScan",
                                 (uint64_t)_scanBSSNewCount, 32);
            _parent->setProperty("AirportRTW89BSSLastRefreshBSSID", refreshBSSID);
            _parent->setProperty("AirportRTW89BSSLastRefreshPreviousAgeMS",
                                 _scanBSSLastRefreshPreviousAgeMS, 64);
            _parent->setProperty("AirportRTW89BSSLastRefreshChannel",
                                 (uint64_t)_scanBSSLastRefreshChannel, 8);
            _parent->setProperty("AirportRTW89BSSLastRefreshFrequency",
                                 (uint64_t)_scanBSSLastRefreshFrequency, 16);
            _parent->setProperty("AirportRTW89BSSLastRefreshGeneration",
                                 (uint64_t)_scanBSSLastRefreshGeneration, 32);
            _parent->setProperty("AirportRTW89BSSLastRefreshSource",
                                 (uint64_t)_scanBSSLastRefreshSource, 8);
            _parent->setProperty("AirportRTW89BSSLastRefreshWasBeacon",
                                 _scanBSSLastRefreshSource == 1U ?
                                     kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89BSSLastRefreshWasProbeResponse",
                                 _scanBSSLastRefreshSource == 2U ?
                                     kOSBooleanTrue : kOSBooleanFalse);

            char rssiBSSID[18];
            char previousRSSIText[16];
            char incomingRSSIText[16];
            char deltaRSSIText[16];
            snprintf(rssiBSSID, sizeof(rssiBSSID),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     _scanRSSILastBSSID[0], _scanRSSILastBSSID[1],
                     _scanRSSILastBSSID[2], _scanRSSILastBSSID[3],
                     _scanRSSILastBSSID[4], _scanRSSILastBSSID[5]);
            snprintf(previousRSSIText, sizeof(previousRSSIText), "%d",
                     (int)_scanRSSILastPrevious);
            snprintf(incomingRSSIText, sizeof(incomingRSSIText), "%d",
                     (int)_scanRSSILastIncoming);
            snprintf(deltaRSSIText, sizeof(deltaRSSIText), "%d",
                     (int)_scanRSSILastDelta);
            _parent->setProperty("AirportRTW89BSSRSSILastBSSID", rssiBSSID);
            _parent->setProperty("AirportRTW89BSSRSSIPreviousText",
                                 previousRSSIText);
            _parent->setProperty("AirportRTW89BSSRSSIIncomingText",
                                 incomingRSSIText);
            _parent->setProperty("AirportRTW89BSSRSSIDeltaText",
                                 deltaRSSIText);
            _parent->setProperty("AirportRTW89BSSRSSIAbsDelta",
                                 (uint64_t)_scanRSSILastAbsDelta, 32);
            _parent->setProperty("AirportRTW89BSSRSSIObservationGapMS",
                                 _scanRSSILastObservationGapMS, 64);
            _parent->setProperty("AirportRTW89BSSRSSIScanGeneration",
                                 (uint64_t)_scanRSSILastGeneration, 32);
            _parent->setProperty("AirportRTW89BSSRSSIUpdatedThisScan",
                                 _scanRSSILastGeneration == _scanGeneration ?
                                     kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89BSSRSSILargeJump",
                                 _scanRSSILastLargeJump ?
                                     kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89BSSRSSILargeJumpCount",
                                 (uint64_t)_scanRSSILargeJumpCount, 32);
            _parent->setProperty("AirportRTW89BSSRSSIIncomingWasMinus90",
                                 _scanRSSILastIncomingWasMinus90 ?
                                     kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89BSSRSSIIncomingWasMinus110",
                                 _scanRSSILastIncomingWasMinus110 ?
                                     kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89BSSRSSISentinelRejected",
                                 _scanRSSILastSentinelRejected ?
                                     kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89BSSRSSISentinelRejectCount",
                                 (uint64_t)_scanRSSISentinelRejectCount, 32);
            char appliedRSSIText[16];
            snprintf(appliedRSSIText, sizeof(appliedRSSIText), "%d",
                     (int)_scanRSSILastApplied);
            _parent->setProperty("AirportRTW89BSSRSSIAppliedText",
                                 appliedRSSIText);
            _parent->setProperty("AirportRTW89BSSRSSITelemetryPublishedAtScanDone",
                                 kOSBooleanTrue);
        }
    }

    if (_state == RTW88_STATE_SCANNING) {
        RTW88State returnState = _scanReturnState;
        if (returnState == RTW88_STATE_CONNECTED && _manualScanChannelCount)
            restoreConnectedChannel();
        _state = (returnState == RTW88_STATE_IDLE) ?
            RTW88_STATE_IDLE : returnState;
        _scanReturnState = RTW88_STATE_IDLE;
        _manualScanOnHomeChannel = false;
        if (_parent) {
            static uint32_t connectedScanDoneCount = 0;
            connectedScanDoneCount++;
            _parent->setProperty("AirportRTW89ConnectedScanDoneCount",
                                 (uint64_t)connectedScanDoneCount, 32);
            _parent->setProperty("AirportRTW89ConnectedScanCompleted",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89ConnectedScanAborted",
                                 aborted ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89ConnectedScanFinalState",
                                 (uint64_t)_state, 8);
        }
    }
}

IOReturn RTW88IEEE80211::cmdScan(bool boundedConnectedScan)
{
    /* 0.2.49: allow background/native scans while associated.
     * Existing scanDone()/restoreConnectedChannel() already preserves and
     * restores CONNECTED state; the old IDLE-only guard made that path
     * unreachable. */
    if (_parent) {
        _parent->setProperty("AirportRTW89ConnectedScanRequestState",
                             (uint64_t)_state, 8);
        _parent->setProperty("AirportRTW89ConnectedScanRequestedWhileConnected",
                             _state == RTW88_STATE_CONNECTED
                                 ? kOSBooleanTrue : kOSBooleanFalse);
    }

    /* 0.2.187: a stale CONNECTED enum must not turn an unassociated radio
     * into a six-channel connected scan.  Tahoe uses the driver's association
     * truth to qualify scan results; if mac80211 no longer has cfg.assoc + a
     * peer STA, normalize the stale state before beginning the scan. */
    if (_state == RTW88_STATE_CONNECTED && !hasActiveAssociation()) {
        /* Reconcile firmware/mac80211 association state as well as the enum.
         * doDisconnect() is idempotent enough for this stale-state repair and
         * preserves the established rtw89 vif_cfg_changed teardown order. */
        doDisconnect();
        if (_parent) {
            static uint32_t staleConnectedNormalizeCount = 0;
            ++staleConnectedNormalizeCount;
            _parent->setProperty("AirportRTW89StaleConnectedStateNormalized",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89StaleConnectedStateNormalizeCount",
                                 (uint64_t)staleConnectedNormalizeCount, 32);
            _parent->setProperty("AirportRTW89StaleConnectedVifAssoc",
                                 kOSBooleanFalse);
        }
    }

    if (_state != RTW88_STATE_IDLE &&
        _state != RTW88_STATE_CONNECTED)
        return kIOReturnBusy;
    if (!_hw || !_hw->ops) return kIOReturnNotReady;
    
    RTW88State returnState = _state;
    const bool connectedSlice =
        returnState == RTW88_STATE_CONNECTED && boundedConnectedScan;
    _scanSnapshotUsesRecentWindow = connectedSlice;
    if (_parent) {
        _parent->setProperty("AirportRTW89ConnectedScanAllowed",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ConnectedScanReturnState",
                             (uint64_t)returnState, 8);
        _parent->setProperty("AirportRTW89ConnectedScanBoundedRF",
                             connectedSlice ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleScanSnapshotRecentWindow",
                             connectedSlice ? kOSBooleanTrue : kOSBooleanFalse);
    }

    /* 0.2.226: reset one-scan RF observation telemetry before changing the
     * generation. These fields are published only at scanDone(). */
    _scanBSSObservationCount = 0;
    _scanBSSExistingRefreshCount = 0;
    _scanBSSNewCount = 0;
    memset(_scanBSSLastRefreshBSSID, 0, sizeof(_scanBSSLastRefreshBSSID));
    _scanBSSLastRefreshPreviousAgeMS = 0;
    _scanBSSLastRefreshChannel = 0;
    _scanBSSLastRefreshFrequency = 0;
    _scanBSSLastRefreshGeneration = 0;
    _scanBSSLastRefreshSource = 0;
    _scanBSSLastObservationSource = 0;

    IOLockLock(_bssLock);
    _scanGeneration++;
    if (_scanGeneration == 0) {
        _scanGeneration = 1;
        for (RTW88BSS *b = _bssList; b; b = b->next) {
            b->last_seen_scan = 1;
            b->last_security_scan_generation = 0;
            b->open_candidate_scan_generation = 0;
        }
    }
    IOLockUnlock(_bssLock);

    _scanReturnState = (returnState == RTW88_STATE_CONNECTED) ?
        returnState : RTW88_STATE_IDLE;
    _state = RTW88_STATE_SCANNING;

    struct ieee80211_scan_request req = {};
    int n_chans = 0;
    memset(_scanScratchChannels, 0, sizeof(_scanScratchChannels));
    
    if (_hw->wiphy) {
        for (int i = 0; i < NL80211_NUM_BANDS; i++) {
            struct ieee80211_supported_band *band = _hw->wiphy->bands[i];
            if (!band) continue;
            for (int j = 0; j < band->n_channels; j++) {
                if (n_chans < 256) {
                    /* Only scan enabled channels */
                    if (!(band->channels[j].flags & IEEE80211_CHAN_DISABLED)) {
                        band->channels[j].band = band->band;
                        _scanScratchChannels[n_chans++] = &band->channels[j];
                    }
                }
            }
        }
    }

    if (n_chans == 0) {
        IOLog("rtw88: scan has no enabled channels\n");
        _state = returnState;
        _scanReturnState = RTW88_STATE_IDLE;
        _scanSnapshotUsesRecentWindow = false;
        return kIOReturnNotReady;
    }

    /* 0.2.226: stable-prioritize frequencies that belong to persistent BSS
     * entries. This does not fake a hit and does not omit any enabled channel.
     * It only moves known channels to the front so a slow/manual sweep can
     * refresh real nearby APs before Tahoe consumes its completion edge.
     * Older observations win priority, making APs nearest CoreWiFi maxAge the
     * first ones revisited. */
    _scanPriorityFrequencyCount = 0;
    memset(_scanPriorityFrequencies, 0, sizeof(_scanPriorityFrequencies));
    memset(_scanPriorityAgesNs, 0, sizeof(_scanPriorityAgesNs));
    const uint64_t priorityNowNs = rtw88_now_ns();
    IOLockLock(_bssLock);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        if (b->freq == 0 || b->last_seen_ns == 0 ||
            priorityNowNs < b->last_seen_ns)
            continue;
        const uint64_t ageNs = priorityNowNs - b->last_seen_ns;
        if (ageNs > kRTW88PersistentBSSExpireNs)
            continue;

        uint32_t slot = _scanPriorityFrequencyCount;
        for (uint32_t p = 0; p < _scanPriorityFrequencyCount; ++p) {
            if (_scanPriorityFrequencies[p] == b->freq) {
                slot = p;
                break;
            }
        }
        if (slot < _scanPriorityFrequencyCount) {
            if (ageNs > _scanPriorityAgesNs[slot])
                _scanPriorityAgesNs[slot] = ageNs;
        } else if (_scanPriorityFrequencyCount < kRTW88PriorityFrequencyCapacity) {
            _scanPriorityFrequencies[_scanPriorityFrequencyCount] = b->freq;
            _scanPriorityAgesNs[_scanPriorityFrequencyCount] = ageNs;
            ++_scanPriorityFrequencyCount;
        }
    }
    IOLockUnlock(_bssLock);

    for (uint32_t i = 0; i < _scanPriorityFrequencyCount; ++i) {
        uint32_t best = i;
        for (uint32_t j = i + 1; j < _scanPriorityFrequencyCount; ++j) {
            if (_scanPriorityAgesNs[j] > _scanPriorityAgesNs[best])
                best = j;
        }
        if (best != i) {
            const uint16_t freq = _scanPriorityFrequencies[i];
            const uint64_t age = _scanPriorityAgesNs[i];
            _scanPriorityFrequencies[i] = _scanPriorityFrequencies[best];
            _scanPriorityAgesNs[i] = _scanPriorityAgesNs[best];
            _scanPriorityFrequencies[best] = freq;
            _scanPriorityAgesNs[best] = age;
        }
    }

    uint32_t priorityApplied = 0;
    for (uint32_t p = 0; p < _scanPriorityFrequencyCount; ++p) {
        for (int j = (int)priorityApplied; j < n_chans; ++j) {
            if (_scanScratchChannels[j] &&
                _scanScratchChannels[j]->center_freq ==
                    _scanPriorityFrequencies[p]) {
                struct ieee80211_channel *tmp =
                    _scanScratchChannels[priorityApplied];
                _scanScratchChannels[priorityApplied] = _scanScratchChannels[j];
                _scanScratchChannels[j] = tmp;
                ++priorityApplied;
                break;
            }
        }
    }

    if (_parent) {
        _parent->setProperty("AirportRTW89ScanKnownChannelPriorityApplied",
                             priorityApplied ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89ScanKnownChannelPriorityCount",
                             (uint64_t)priorityApplied, 32);
        _parent->setProperty("AirportRTW89ScanKnownChannelPriorityFirstFreq",
                             priorityApplied ?
                                 (uint64_t)_scanScratchChannels[0]->center_freq : 0, 32);
        _parent->setProperty("AirportRTW89ScanKnownChannelPriorityOldestAgeMS",
                             _scanPriorityFrequencyCount ?
                                 _scanPriorityAgesNs[0] / 1000000ULL : 0, 64);
    }

    struct ieee80211_channel **scanChannels = _scanScratchChannels;
    int scanChannelCount = n_chans;
    uint32_t sliceStart = 0;
    if (connectedSlice) {
        const uint32_t total = (uint32_t)n_chans;
        const uint32_t budget =
            total < kRTW88ConnectedScanSliceChannels ?
                total : kRTW88ConnectedScanSliceChannels;
        sliceStart = total ? (_connectedScanCursor % total) : 0;
        for (uint32_t i = 0; i < budget; ++i)
            _connectedScanChannels[i] =
                _scanScratchChannels[(sliceStart + i) % total];
        scanChannels = _connectedScanChannels;
        scanChannelCount = (int)budget;
        _connectedScanCursor = total ?
            ((sliceStart + budget) % total) : 0;
    }

    if (_parent) {
        _parent->setProperty("AirportRTW89ScanChannelCount",
                             (uint64_t)(uint32_t)scanChannelCount, 32);
        _parent->setProperty("AirportRTW89ScanTotalEnabledChannelCount",
                             (uint64_t)(uint32_t)n_chans, 32);
        _parent->setProperty("AirportRTW89ConnectedScanSliceStart",
                             (uint64_t)sliceStart, 32);
        _parent->setProperty("AirportRTW89ConnectedScanSliceCount",
                             connectedSlice ?
                                 (uint64_t)(uint32_t)scanChannelCount : 0, 32);
        _parent->setProperty("AirportRTW89ConnectedScanSliceNextCursor",
                             (uint64_t)_connectedScanCursor, 32);
    }

    if (!_hw->ops->hw_scan || !rtw88_hw_scan_supported(_hw)) {
        if (_parent) {
            _parent->setProperty("AirportRTW89ScanOffloadForcedDisabled",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89ManualScanStarted",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89ManualScanCompleted",
                                 kOSBooleanFalse);
            _parent->setProperty("AirportRTW89ManualScanAborted",
                                 kOSBooleanFalse);
        }
        if (!_manualScanTC) {
            _state = returnState;
            _scanReturnState = RTW88_STATE_IDLE;
            return kIOReturnNotReady;
        }

        _manualScanChannelCount = (uint32_t)scanChannelCount;
        for (int i = 0; i < scanChannelCount; i++)
            _manualScanChannels[i] = scanChannels[i];
        _manualScanAbort = false;
        _manualScanOnHomeChannel = false;
        _rxFrameCount = 0;

        if (!_manualScanFallbackLogged) {
            IOLog("rtw88: scan offload unavailable, using passive channel scan (%d channels)\n",
                  scanChannelCount);
            _manualScanFallbackLogged = true;
        }
        thread_call_enter(_manualScanTC);

        _timeoutMs = (_scanReturnState == RTW88_STATE_CONNECTED) ?
            30000 : 12000;
        uint64_t d;
        clock_interval_to_deadline(_timeoutMs, kMillisecondScale, &d);
        _timer->wakeAtTime(d);
        return kIOReturnSuccess;
    }
    
    req.req.channels = scanChannels;
    req.req.n_channels = scanChannelCount;

    _rxFrameCount = 0;  /* reset diagnostic counter at scan start */

    int hw_scan_ret = 0;
    {
        RTW89CompatWiphyGuard cfgGuard(_hw);
        hw_scan_ret = _hw->ops->hw_scan(_hw, _vif, &req);
    }
    if (hw_scan_ret != 0) {
        IOLog("rtw88: hw_scan returned %d -- falling back to passive scan\n",
              hw_scan_ret);
        if (_manualScanTC) {
            _manualScanChannelCount = (uint32_t)scanChannelCount;
            for (int i = 0; i < scanChannelCount; i++)
                _manualScanChannels[i] = scanChannels[i];
            _manualScanAbort = false;
            _manualScanOnHomeChannel = false;
            _rxFrameCount = 0;
            thread_call_enter(_manualScanTC);

            _timeoutMs = (_scanReturnState == RTW88_STATE_CONNECTED) ?
                30000 : 12000;
            uint64_t d;
            clock_interval_to_deadline(_timeoutMs, kMillisecondScale, &d);
            _timer->wakeAtTime(d);
            return kIOReturnSuccess;
        }
        _state = returnState;
        _scanReturnState = RTW88_STATE_IDLE;
        return kIOReturnError;
    }
    /* Timeout: if scan doesn't complete in 10s */
    _timeoutMs = 10000;
    uint64_t d; clock_interval_to_deadline(_timeoutMs, kMillisecondScale, &d); _timer->wakeAtTime(d);
    return kIOReturnSuccess;
}

void RTW88IEEE80211::manualScanTCFn(thread_call_param_t self, thread_call_param_t)
{
    ((RTW88IEEE80211 *)self)->runManualScan();
}

void RTW88IEEE80211::runManualScan()
{
    if (_parent) {
        _parent->setProperty("AirportRTW89ManualScanRunning", kOSBooleanTrue);
#ifdef RTW89_MACOS
        _parent->setProperty("AirportRTW89WiphySerializeLockEnabled",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ManualScanSerialized",
                             kOSBooleanTrue);
#endif
    }

    if (!_hw || !_vif) {
        if (_parent) {
            _parent->setProperty("AirportRTW89ManualScanRunning", kOSBooleanFalse);
            _parent->setProperty("AirportRTW89ManualScanAborted", kOSBooleanTrue);
        }
        scanDone(true);
        _manualScanChannelCount = 0;
        return;
    }

    uint32_t count = _manualScanChannelCount;
    if (count > 256)
        count = 256;
    bool connectedScan = (_scanReturnState == RTW88_STATE_CONNECTED);
    uint32_t channelSwitches = 0;
    uint32_t probeRequests = 0;
    uint32_t probeFailures = 0;

    rtw88_sw_scan_start(_hw, _vif);
    if (_parent)
        _parent->setProperty("AirportRTW89ManualScanRXFilterOpened",
                             kOSBooleanTrue);

    for (uint32_t i = 0; i < count && !_manualScanAbort; i++) {
        struct ieee80211_channel *chan = _manualScanChannels[i];
        if (!chan)
            continue;

        _manualScanOnHomeChannel = false;

        if (connectedScan) {
            restoreConnectedChannel();
            txNullFunc(true);
            IOSleep(10);
        }

        _hw->conf.chandef.chan = chan;
        _hw->conf.chandef.width = NL80211_CHAN_WIDTH_20_NOHT;
        _hw->conf.chandef.center_freq1 = chan->center_freq;

        rtw88_sw_scan_switch_channel(_hw);
        channelSwitches++;

        bool passiveOnly = (chan->flags &
            (IEEE80211_CHAN_NO_IR | IEEE80211_CHAN_RADAR)) != 0;
        if (!passiveOnly) {
            probeRequests++;
            if (!txProbeRequest())
                probeFailures++;
        }

        /* Active channels can use a short probe dwell.  0.2.186 keeps
         * Apple-originated connected slices below roughly half a second of
         * cumulative off-channel work by using shorter probe/home dwells.
         * Full diagnostic connected scans retain the older conservative dwell. */
        if (connectedScan && _scanSnapshotUsesRecentWindow)
            IOSleep(passiveOnly ? 90 : 45);
        else
            IOSleep(passiveOnly ? 140 : 70);

        if (connectedScan && !_manualScanAbort) {
            restoreConnectedChannel();
            txNullFunc(false);
            _manualScanOnHomeChannel = true;
            IOSleep(_scanSnapshotUsesRecentWindow ? 35 : 80);
        }
    }

    _manualScanOnHomeChannel = false;
    rtw88_sw_scan_complete(_hw, _vif);
    if (_parent)
        _parent->setProperty("AirportRTW89ManualScanRXFilterRestored",
                             kOSBooleanTrue);
    if (connectedScan) {
        restoreConnectedChannel();
        txNullFunc(false);
    }
    bool aborted = _manualScanAbort;
    scanDone(aborted);

    if (_parent) {
#ifdef RTW89_MACOS
        if (_hw && _hw->wiphy) {
            _parent->setProperty("AirportRTW89WiphySerializeLockAcquireCount",
                (uint64_t)_hw->wiphy->serialize_lock_acquire_count, 32);
            _parent->setProperty("AirportRTW89WiphySerializeLockContentionCount",
                (uint64_t)_hw->wiphy->serialize_lock_contention_count, 32);
        }
#endif
        uint32_t resultCount = 0;
        IOLockLock(_bssLock);
        resultCount = _bssCount;
        IOLockUnlock(_bssLock);

        _parent->setProperty("AirportRTW89ManualScanRunning", kOSBooleanFalse);
        _parent->setProperty("AirportRTW89ManualScanCompleted", kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ManualScanAborted",
                             aborted ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89ManualScanChannelSwitches",
                             (uint64_t)channelSwitches, 32);
        _parent->setProperty("AirportRTW89ManualScanProbeRequests",
                             (uint64_t)probeRequests, 32);
        _parent->setProperty("AirportRTW89ManualScanProbeFailures",
                             (uint64_t)probeFailures, 32);
        _parent->setProperty("AirportRTW89ManualScanRXFrames",
                             (uint64_t)_rxFrameCount, 32);
        _parent->setProperty("AirportRTW89ManualScanResultCount",
                             (uint64_t)resultCount, 32);
    }

    _manualScanAbort = false;
    _manualScanChannelCount = 0;
}

/* ------------------------------------------------------------------ */
/*  Connect                                                             */
/* ------------------------------------------------------------------ */

bool RTW88IEEE80211::copyBestConnectTarget(const char *ssid,
                                              const uint8_t *preferredBSSID,
                                              bool preferWPA2PSK,
                                              RTW88ConnectTargetInfo *out,
                                              uint32_t *matchCount,
                                              uint32_t *pskCount)
{
    if (matchCount)
        *matchCount = 0;
    if (pskCount)
        *pskCount = 0;
    if (!ssid || !out || !_bssLock)
        return false;

    const size_t wanted = rtw88_bounded_string_length(ssid, 32);
    if (wanted == 0)
        return false;

    const bool hasPreferredBSSID = preferredBSSID &&
        !is_zero_ether_addr(preferredBSSID);
    RTW88BSS *bestAny = nullptr;
    RTW88BSS *bestPSK = nullptr;
    uint32_t matches = 0;
    uint32_t psks = 0;

    IOLockLock(_bssLock);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        /* Tahoe's Type-0 compatibility route can preserve the BSSID selected
         * by CoreWiFi while the inner SET20 buffer still contains the SSID of
         * the previously associated network.  A nonzero preferred BSSID is
         * unambiguous, so resolve that exact persistent scan record instead
         * of rejecting it because of the stale SSID field. */
        if (hasPreferredBSSID) {
            if (memcmp(b->bssid, preferredBSSID, ETH_ALEN) != 0)
                continue;
        } else if (b->ssid_len != wanted ||
                   memcmp(b->ssid, ssid, wanted) != 0) {
            continue;
        }

        ++matches;
        const bool isWPA2PSK =
            b->cipher == WLAN_CIPHER_SUITE_CCMP && b->akm == 0x000FAC02;
        if (isWPA2PSK) {
            ++psks;
            if (!bestPSK || b->rssi > bestPSK->rssi)
                bestPSK = b;
        }
        if (!bestAny || b->rssi > bestAny->rssi)
            bestAny = b;
    }

    RTW88BSS *selected = (preferWPA2PSK && bestPSK) ? bestPSK : bestAny;
    if (selected) {
        memset(out, 0, sizeof(*out));
        out->ssid_len = selected->ssid_len;
        memcpy(out->ssid, selected->ssid, selected->ssid_len);
        memcpy(out->bssid, selected->bssid, ETH_ALEN);
        out->rssi = selected->rssi;
        out->freq = selected->freq;
        out->channel = selected->channel;
        out->capabilities = selected->capabilities;
        out->cipher = selected->cipher;
        out->group_cipher = selected->group_cipher;
        out->akm = selected->akm;
        out->rsn_ie_len = selected->rsn_ie_len;
        out->wpa_ie_len = selected->wpa_ie_len;
        out->rsn_observation_count = selected->rsn_observation_count;
        out->security_update_count = selected->security_update_count;
        out->security_preserve_count = selected->security_preserve_count;
        out->security_open_candidate_count = selected->security_open_candidate_count;
        out->security_open_clear_count = selected->security_open_clear_count;
        out->last_security_scan_generation = selected->last_security_scan_generation;
        out->open_candidate_scan_generation = selected->open_candidate_scan_generation;
    } else {
        memset(out, 0, sizeof(*out));
    }
    IOLockUnlock(_bssLock);

    if (matchCount)
        *matchCount = matches;
    if (pskCount)
        *pskCount = psks;
    return selected != nullptr;
}

IOReturn RTW88IEEE80211::cmdConnect(const char *ssid, const char *password,
                                      const uint8_t *preferredBSSID,
                                      bool requireScannedPSK)
{
    if (_state == RTW88_STATE_SCANNING && !abortActiveScan(true))
        return kIOReturnBusy;
    if (_state != RTW88_STATE_IDLE) return kIOReturnBusy;
    if (!ssid) return kIOReturnBadArgument;
    clearKeys();
    releaseSta();

    /* Find the SSID in our BSS list */
    IOLockLock(_bssLock);
    RTW88BSS *target = nullptr;
    const size_t wanted = rtw88_bounded_string_length(ssid, 32);
    const bool hasPreferredBSSID = preferredBSSID &&
        !is_zero_ether_addr(preferredBSSID);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        if (b->ssid_len != wanted || memcmp(b->ssid, ssid, wanted) != 0)
            continue;
        /* 0.2.178: when the Apple association request has already been
         * classified as WPA2-PSK, do not let an open/unknown duplicate of the
         * same SSID win merely because it has a stronger RSSI. */
        if (requireScannedPSK &&
            (b->cipher != WLAN_CIPHER_SUITE_CCMP || b->akm != 0x000FAC02))
            continue;
        if (hasPreferredBSSID) {
            if (memcmp(b->bssid, preferredBSSID, ETH_ALEN) == 0) {
                target = b;
                break;
            }
            continue;
        }
        /* Without a framework-selected BSSID, prefer the strongest matching
         * BSS inside the requested security class. */
        if (!target || b->rssi > target->rssi)
            target = b;
    }
    if (!target) {
        IOLockUnlock(_bssLock);
        return kIOReturnNotFound;
    }
    if (requireScannedPSK && target->akm != 0x000FAC02) {
        IOLockUnlock(_bssLock);
        if (_parent) {
            _parent->setProperty("AirportRTW89ConnectTransitionFallbackRejected",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89ConnectTransitionFallbackTargetAKM",
                                 (uint64_t)target->akm, 32);
        }
        return kIOReturnUnsupported;
    }
    if (requireScannedPSK && _parent)
        _parent->setProperty("AirportRTW89ConnectTransitionFallbackApplied",
                             kOSBooleanTrue);
    memcpy(&_targetBSS, target, sizeof(_targetBSS));
    IOLockUnlock(_bssLock);

    if (_parent) {
        _parent->setProperty("AirportRTW89ConnectTargetSelected", kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ConnectTargetPreferredBSSIDPresent",
                             hasPreferredBSSID ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89ConnectTargetChannel",
                             (uint64_t)_targetBSS.channel, 8);
        _parent->setProperty("AirportRTW89ConnectTargetRSSI",
                             (uint64_t)(uint16_t)_targetBSS.rssi, 16);
        _parent->setProperty("AirportRTW89ConnectTargetCipher",
                             (uint64_t)_targetBSS.cipher, 32);
        _parent->setProperty("AirportRTW89ConnectTargetGroupCipher",
                             (uint64_t)_targetBSS.group_cipher, 32);
        _parent->setProperty("AirportRTW89ConnectTargetAKM",
                             (uint64_t)_targetBSS.akm, 32);
    }

    strlcpy(_password, password ? password : "", sizeof(_password));
    _pmkProvided = false;
    _wpa2 = (_targetBSS.cipher == WLAN_CIPHER_SUITE_CCMP);
    _authRetries = 0;

    /* Kill any timer still pending from the preceding operation (a scan
     * timeout, or a prior connect attempt) BEFORE we enter AUTHENTICATING.
     * doAuthenticate() sleeps ~500 ms settling the firmware before it arms
     * its own 3 s auth timer; a stale short-deadline timer left over from the
     * scan would otherwise fire during that window, be misread by onTimer as
     * an auth timeout, and launch a *second* doAuthenticate() on the workloop
     * thread concurrently with the one running on the connect thread_call —
     * two interleaved auth/assoc/EAPOL sequences that wedge the firmware
     * (c2h reg timeout, RSSI 0). */
    _timer->cancelTimeout();
    _state = RTW88_STATE_AUTHENTICATING;
    if (_parent) {
        _parent->setProperty("AirportRTW89ConnectAttemptStarted", kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ConnectAttemptUsesPMK", kOSBooleanFalse);
    }

    /* Run doAuthenticate on a background thread_call so the IOUserClient
     * call returns immediately.  The connect machinery (channel change,
     * mutex acquisition, TX) must not block the MIG thread. */
    if (_connectTC)
        thread_call_enter(_connectTC);
    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::cmdConnectWithPMK(const char *ssid,
                                            const uint8_t *pmk,
                                            uint32_t pmkLen,
                                            const uint8_t *preferredBSSID,
                                            bool requireScannedPSK)
{
    if (!ssid || !pmk || pmkLen != sizeof(_pmk))
        return kIOReturnBadArgument;
    if (_state == RTW88_STATE_SCANNING && !abortActiveScan(true))
        return kIOReturnBusy;
    if (_state != RTW88_STATE_IDLE)
        return kIOReturnBusy;

    clearKeys();
    releaseSta();

    IOLockLock(_bssLock);
    RTW88BSS *target = nullptr;
    size_t wanted = rtw88_bounded_string_length(ssid, 32);
    const bool hasPreferredBSSID = preferredBSSID &&
        !is_zero_ether_addr(preferredBSSID);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        if (b->ssid_len != wanted || memcmp(b->ssid, ssid, wanted) != 0)
            continue;
        if (requireScannedPSK &&
            (b->cipher != WLAN_CIPHER_SUITE_CCMP || b->akm != 0x000FAC02))
            continue;
        if (hasPreferredBSSID) {
            if (memcmp(b->bssid, preferredBSSID, ETH_ALEN) == 0) {
                target = b;
                break;
            }
            continue;
        }
        if (!target || b->rssi > target->rssi)
            target = b;
    }
    if (!target) {
        IOLockUnlock(_bssLock);
        return kIOReturnNotFound;
    }
    if (requireScannedPSK && target->akm != 0x000FAC02) {
        IOLockUnlock(_bssLock);
        if (_parent) {
            _parent->setProperty("AirportRTW89ConnectTransitionFallbackRejected",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89ConnectTransitionFallbackTargetAKM",
                                 (uint64_t)target->akm, 32);
        }
        return kIOReturnUnsupported;
    }
    if (requireScannedPSK && _parent)
        _parent->setProperty("AirportRTW89ConnectTransitionFallbackApplied",
                             kOSBooleanTrue);
    memcpy(&_targetBSS, target, sizeof(_targetBSS));
    IOLockUnlock(_bssLock);

    if (_parent) {
        _parent->setProperty("AirportRTW89ConnectTargetSelected", kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ConnectTargetPreferredBSSIDPresent",
                             hasPreferredBSSID ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89ConnectTargetChannel",
                             (uint64_t)_targetBSS.channel, 8);
        _parent->setProperty("AirportRTW89ConnectTargetRSSI",
                             (uint64_t)(uint16_t)_targetBSS.rssi, 16);
        _parent->setProperty("AirportRTW89ConnectTargetCipher",
                             (uint64_t)_targetBSS.cipher, 32);
        _parent->setProperty("AirportRTW89ConnectTargetGroupCipher",
                             (uint64_t)_targetBSS.group_cipher, 32);
        _parent->setProperty("AirportRTW89ConnectTargetAKM",
                             (uint64_t)_targetBSS.akm, 32);
    }

    memset(_password, 0, sizeof(_password));
    memcpy(_pmk, pmk, sizeof(_pmk));
    _pmkProvided = true;
    _wpa2 = (_targetBSS.cipher == WLAN_CIPHER_SUITE_CCMP);
    _authRetries = 0;
    _timer->cancelTimeout();
    _state = RTW88_STATE_AUTHENTICATING;
    if (_parent) {
        _parent->setProperty("AirportRTW89ConnectAttemptStarted", kOSBooleanTrue);
        _parent->setProperty("AirportRTW89ConnectAttemptUsesPMK", kOSBooleanTrue);
    }
    if (_connectTC)
        thread_call_enter(_connectTC);
    return kIOReturnSuccess;
}

void RTW88IEEE80211::connectTCFn(thread_call_param_t self, thread_call_param_t)
{
    ((RTW88IEEE80211 *)self)->doAuthenticate();
}

void RTW88IEEE80211::doAuthenticate()
{
    if (!_hw || !_vif) return;

    /* Cancel any pending timer so no stale timeout fires during the settle
     * sleep below and re-enters us concurrently (see cmdConnect).  When called
     * from onTimer's retry path the timer has already fired and this is a
     * no-op; when called from the connect thread_call it closes the window. */
    _timer->cancelTimeout();

    IOLog("rtw88: doAuthenticate entry — BSSID %02x:%02x:%02x:%02x:%02x:%02x ch=%u\n",
          _targetBSS.bssid[0], _targetBSS.bssid[1], _targetBSS.bssid[2],
          _targetBSS.bssid[3], _targetBSS.bssid[4], _targetBSS.bssid[5],
          _targetBSS.channel);

    /* Wait for RTW_FLAG_SCANNING to clear.
     * The flag is cleared inside rtw_core_scan_complete() which runs under
     * rtwdev->mutex in the c2h_work thread. */
    for (int i = 0; i < 100; i++) {
        if (!rtw88_is_scanning()) break;
        IOSleep(50);
    }
    IOLog("rtw88: doAuthenticate: scan flag clear\n");

    /* Firmware settle delay.
     *
     * After HW scan the firmware needs ~200-500 ms to fully exit its
     * internal scan-mode critical section before it can safely process
     * channel-switch register writes.  On Linux/FreeBSD this gap is filled
     * naturally by the wpa_supplicant userspace round-trip; we must add it
     * explicitly.  Without this, rtw_set_channel's BB/RF MMIO reads hit the
     * chip while the firmware is still transitioning → PCIe bus hang →
     * system freeze.  500 ms is comfortably below the watch-dog LPS timer
     * (~2 s), so the chip stays awake. */
    IOSleep(500);
    IOLog("rtw88: doAuthenticate: firmware settled\n");

    /* ----- 1. Channel switch + BSSID (single mutex section) ----- *
     *
     * We call rtw88_connect_hw_setup() instead of ops->config +
     * ops->bss_info_changed because both of those call rtw_leave_lps_deep()
     * → __rtw_fw_leave_lps_check_reg() → polling MMIO reads on REG_TCR.
     * If the chip is slow to respond, those reads stall the calling CPU core
     * indefinitely (PCIe timeout → system freeze).
     *
     * 0.3.4: rtw88_connect_hw_setup() holds the compat wiphy serialization
     * mutex expected by upstream rtw89 while it assigns chanctx/entity state,
     * calls rtw89_set_channel(), and updates BSSID/CAM state. */
    struct ieee80211_channel *chan = nullptr;
    for (int b = 0; b < NL80211_NUM_BANDS && !chan; b++) {
        struct ieee80211_supported_band *band =
            (_hw->wiphy) ? _hw->wiphy->bands[b] : nullptr;
        if (!band) continue;
        for (int j = 0; j < band->n_channels; j++) {
            if (band->channels[j].hw_value == _targetBSS.channel) {
                chan = &band->channels[j];
                /* The channel tables omit the per-channel .band field (Linux
                 * fills it in at wiphy_register, which we don't run), so 5GHz
                 * channels otherwise report band 0 == 2GHz.  Backfill it from
                 * the parent band so chandef.chan->band and rx_status->band
                 * are correct. */
                chan->band = band->band;
                break;
            }
        }
    }
    if (chan) {
        setConnectedChandef(chan);
        IOLog("rtw88: doAuthenticate: calling connect_hw_setup ch=%u\n",
              _targetBSS.channel);
        rtw88_connect_hw_setup(_hw, _vif, _targetBSS.bssid);
        IOLog("rtw88: doAuthenticate: connect_hw_setup done\n");
    } else {
        IOLog("rtw88: doAuthenticate: ch=%u not in band table — "
              "skipping channel switch, sending auth anyway\n",
              _targetBSS.channel);
        /* Still set BSSID even if channel is unknown */
        rtw88_connect_hw_setup(_hw, _vif, _targetBSS.bssid);
    }

    /* Also update the vif bss_conf bssid so any driver-internal code
     * that reads it sees the right value. */
    struct ieee80211_bss_conf *bss = &_vif->bss_conf;
    bss->bssid = bss->bssid_buf;
    memcpy(bss->bssid_buf, _targetBSS.bssid, 6);
    bss->assoc = false;
    bss->aid   = 0;

    /* ----- 2. Send Authentication frame ----- */
    IOLog("rtw88: doAuthenticate: building auth frame\n");
    uint8_t auth[30] = {};
    uint32_t authlen = 0;
    buildAuthReq(auth, &authlen);
    IOLog("rtw88: doAuthenticate: transmitting auth frame (%u bytes)\n", authlen);
    txMgmtFrame(auth, authlen);
    IOLog("rtw88: doAuthenticate: auth frame sent — waiting for response\n");

    _state = RTW88_STATE_AUTHENTICATING;
    uint64_t d; clock_interval_to_deadline(3000, kMillisecondScale, &d);
    _timer->wakeAtTime(d);
}

void RTW88IEEE80211::doAssociate()
{
    if (!_hw || !_vif) return;

    uint8_t assoc[512] = {};
    uint32_t assoclen  = 0;
    buildAssocReq(assoc, &assoclen);
    txMgmtFrame(assoc, assoclen);

    _state = RTW88_STATE_ASSOCIATING;
    uint64_t d; clock_interval_to_deadline(3000, kMillisecondScale, &d); _timer->wakeAtTime(d);
}

void RTW88IEEE80211::processAssocResponse(struct sk_buff *skb)
{
    /* Assoc-resp body (after 24-byte 802.11 hdr):
     * capability(2), status(2), AID(2), [IEs...] */
    const uint32_t hdrlen = sizeof(struct ieee80211_hdr_3addr);
    if (!skb || skb->len < hdrlen) {
        IOLog("rtw88: assoc-resp too short for 802.11 header\n");
        if (skb)
            kfree_skb(skb);
        _state = RTW88_STATE_IDLE;
        return;
    }

    /* Reject an assoc response that isn't from our target AP (see auth path). */
    struct ieee80211_hdr_3addr *h3 = (struct ieee80211_hdr_3addr *)skb->data;
    if (memcmp(h3->addr3, _targetBSS.bssid, 6) != 0) {
        IOLog("rtw88: assoc resp from %02x:%02x:%02x:%02x:%02x:%02x "
              "!= target BSSID — ignoring\n",
              h3->addr3[0], h3->addr3[1], h3->addr3[2],
              h3->addr3[3], h3->addr3[4], h3->addr3[5]);
        kfree_skb(skb);
        return;   /* stay in ASSOCIATING; timeout fires if no real response */
    }

    const uint32_t bodylen = skb->len - hdrlen;
    if (bodylen < 6) {
        IOLog("rtw88: assoc-resp fixed fields too short: %u\n", bodylen);
        kfree_skb(skb);
        _state = RTW88_STATE_IDLE;
        return;
    }

    /*
     * Copy the fixed fields before releasing the RX skb.
     *
     * 0.2.21 kept a pointer into skb->data, freed the skb, and only then
     * decoded status/AID.  The compatibility kfree_skb() releases both the
     * data allocation and the skb itself, so that was a real use-after-free.
     * It produced a local AID of zero even though the AP subsequently sent M1.
     */
    uint8_t fixed[6];
    memcpy(fixed, skb->data + hdrlen, sizeof(fixed));

    struct ieee80211_tx_queue_params edca[IEEE80211_NUM_ACS];
    rtw88DefaultEdca(edca);
    uint8_t edcaQosInfo = 0;
    uint8_t edcaParameterSetCount = 0;
    uint8_t edcaAcmMask = 0;
    uint8_t edcaSource = 0; /* 0=defaults, 1=scan cache, 2=assoc response */

    const uint8_t *assocIes = skb->data + hdrlen + sizeof(fixed);
    const uint32_t assocIesLen = bodylen - sizeof(fixed);
    if (rtw88ParseWmmParameters(assocIes, assocIesLen, edca,
                                &edcaQosInfo, &edcaParameterSetCount,
                                &edcaAcmMask)) {
        edcaSource = 2;
    } else if (rtw88ParseWmmParameters(_targetBSS.ies, _targetBSS.ies_len,
                                       edca, &edcaQosInfo,
                                       &edcaParameterSetCount,
                                       &edcaAcmMask)) {
        edcaSource = 1;
    }

    kfree_skb(skb);

    const uint16_t capability =
        (uint16_t)(fixed[0] | ((uint16_t)fixed[1] << 8));
    const uint16_t status =
        (uint16_t)(fixed[2] | ((uint16_t)fixed[3] << 8));
    const uint16_t rawAid =
        (uint16_t)(fixed[4] | ((uint16_t)fixed[5] << 8));
    const uint16_t aid = (uint16_t)(rawAid & 0x3FFF);

    if (_parent) {
        _parent->setProperty("AirportRTW89AssocResponseFixedCopied",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89AssocResponseCapability",
                             (uint64_t)capability, 16);
        _parent->setProperty("AirportRTW89AssocResponseStatus",
                             (uint64_t)status, 16);
        _parent->setProperty("AirportRTW89AssocResponseRawAID",
                             (uint64_t)rawAid, 16);
        _parent->setProperty("AirportRTW89AssocResponseAID",
                             (uint64_t)aid, 16);
        _parent->setProperty("AirportRTW89AssocResponseAIDValid",
                             (aid >= 1 && aid <= 2007)
                                 ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89EDCASource", (uint64_t)edcaSource, 8);
        _parent->setProperty("AirportRTW89EDCAWMMParameterFound",
                             edcaSource ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89EDCAQoSInfo",
                             (uint64_t)edcaQosInfo, 8);
        _parent->setProperty("AirportRTW89EDCAParameterSetCount",
                             (uint64_t)edcaParameterSetCount, 8);
        _parent->setProperty("AirportRTW89EDCAACMMask",
                             (uint64_t)edcaAcmMask, 8);
    }

    if (status != 0) {
        IOLog("rtw88: assoc failed status=%u\n", status);
        _state = RTW88_STATE_IDLE;
        return;
    }
    if (aid == 0 || aid > 2007) {
        IOLog("rtw88: assoc response has invalid AID raw=0x%04x aid=%u\n",
              rawAid, aid);
        _state = RTW88_STATE_IDLE;
        return;
    }

    IOLog("rtw88: associated! AID=%u raw=0x%04x cap=0x%04x EDCA-source=%u\n",
          aid, rawAid, capability, edcaSource);
    _assocAID = aid;

    /* ----- 1. Allocate and register peer STA ----- */
    if (_sta == nullptr && _hw->ops &&
        (_hw->ops->sta_add || _hw->ops->sta_state)) {
        size_t sta_sz = sizeof(struct ieee80211_sta) + _hw->sta_data_size;
        _sta = (struct ieee80211_sta *)IOMallocZero(sta_sz);
        if (_sta) {
            _staAllocSize = sta_sz;
            memcpy(_sta->addr, _targetBSS.bssid, ETH_ALEN);
            _sta->aid  = aid;
            _sta->wme  = true;
            /* Non-MLO contract: link 0 is deflink (valid_links stays 0).
             * rtw89's link deref helpers read sta->link[link_id], and its
             * CAM code reads link_sta->addr / link_sta->sta. */
            _sta->link[0] = &_sta->deflink;
            _sta->deflink.sta = _sta;
            memcpy(_sta->deflink.addr, _sta->addr, ETH_ALEN);

            /* Populate supported rates so rtw_update_sta_info() builds a
             * non-empty rate-adaptation mask. */
            _sta->deflink.supp_rates[NL80211_BAND_2GHZ] = 0xFFF; /* CCK+OFDM */
            _sta->deflink.supp_rates[NL80211_BAND_5GHZ] = 0xFF;  /* OFDM     */
            _sta->deflink.bandwidth =
                (_connChanWidth == 80) ? IEEE80211_STA_RX_BW_80 :
                (_connChanWidth == 40) ? IEEE80211_STA_RX_BW_40 :
                                         IEEE80211_STA_RX_BW_20;

            /* 0.2.43: mac80211 peer-NSS contract bootstrap.
             * The compat ieee80211_link_sta is zero-allocated and the
             * AirPort association path does not yet populate rx_nss from
             * peer HT/VHT/HE capabilities.  rtw89 encodes:
             *
             *   ss_num = min(link_sta->rx_nss, hal.tx_nss) - 1
             *
             * so rx_nss == 0 underflows to ss_num == 7.  Use 1SS as the
             * conservative interoperable bootstrap until peer capability
             * parsing supplies the real value. */
            _sta->deflink.rx_nss = 1;

            /* Mirror the chip's HT/VHT capabilities onto the peer STA so
             * rtw_update_sta_info() (invoked by sta_add) builds a firmware
             * rate-adaptation mask that includes HT/VHT MCS rates instead of
             * legacy-only.  This MUST match what buildAssocReq() advertised to
             * the AP.  Operation is held to 20 MHz (clear the 40 MHz HT bits)
             * to match the 20 MHz PHY. */
            enum nl80211_band sta_band =
                (_targetBSS.channel > 14) ? NL80211_BAND_5GHZ
                                          : NL80211_BAND_2GHZ;
            struct ieee80211_supported_band *sband =
                (_hw->wiphy) ? _hw->wiphy->bands[sta_band] : nullptr;
            if (htAllowed() && sband) {
                _sta->deflink.ht_cap = sband->ht_cap;
                if (_connChanWidth < 40)
                    _sta->deflink.ht_cap.cap &=
                        ~(uint16_t)(IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
                                    IEEE80211_HT_CAP_SGI_40 |
                                    IEEE80211_HT_CAP_DSSSCCK40);
                if (sta_band == NL80211_BAND_5GHZ)
                    _sta->deflink.vht_cap = sband->vht_cap;
            }

            RTW89CompatWiphyGuard cfgGuard(_hw);
            if (_hw->ops->sta_state) {
                /* rtw89 has no sta_add — drive mac80211's sta state
                 * machine.  NOTEXIST→NONE allocates the peer's mac_id
                 * and firmware entry; AUTH→ASSOC is a deliberate no-op
                 * for station vifs (rtw89 defers the real assoc H2C to
                 * vif_cfg_changed(BSS_CHANGED_ASSOC) below). */
                int sret = _hw->ops->sta_state(_hw, _vif, _sta,
                    IEEE80211_STA_NOTEXIST, IEEE80211_STA_NONE);
                if (sret == 0)
                    sret = _hw->ops->sta_state(_hw, _vif, _sta,
                        IEEE80211_STA_NONE, IEEE80211_STA_AUTH);
                if (sret == 0)
                    sret = _hw->ops->sta_state(_hw, _vif, _sta,
                        IEEE80211_STA_AUTH, IEEE80211_STA_ASSOC);
                if (sret != 0)
                    IOLog("rtw88: sta_state failed: %d\n", sret);
            } else {
                _hw->ops->sta_add(_hw, _vif, _sta);
            }
            /* Make ieee80211_find_sta() resolve the peer — rtw89's
             * assoc path looks the sta up by vif->cfg.ap_addr. */
            rtw88_register_sta(_sta);
        }
    }

    /* ----- 2. Notify driver of full association ----- */
    bool handshakeArmedBeforeAssocNotify = false;
    if (_hw->ops) {
        struct ieee80211_bss_conf *bss = &_vif->bss_conf;
        bss->assoc = true;
        bss->aid   = aid;
        bss->qos   = true;
        bss->assoc_capability = capability;
        bss->use_short_preamble = (capability & 0x0020) != 0;
        bss->use_short_slot = (capability & 0x0400) != 0;
        bss->bssid = bss->bssid_buf;
        memcpy(bss->bssid_buf, _targetBSS.bssid, ETH_ALEN);
        /* Beacon parameters — rtw89's beacon tracker divides by both;
         * zero DTIM = divide-by-zero panic in rtw89_core_bcn_track_assoc.
         * Beacon interval isn't carried in the assoc response, so use
         * the common default; DTIM period comes from the TIM IE we
         * stored with the scan result when present. */
        bss->beacon_int  = 100;
        bss->dtim_period = 1;
        for (uint32_t o = 0; o + 2 <= _targetBSS.ies_len; ) {
            uint8_t id  = _targetBSS.ies[o];
            uint8_t len = _targetBSS.ies[o + 1];
            if (o + 2 + len > _targetBSS.ies_len)
                break;
            if (id == 5 /* TIM */ && len >= 2 && _targetBSS.ies[o + 3])
                bss->dtim_period = _targetBSS.ies[o + 3];
            o += 2 + len;
        }
        uint8_t edcaSuccessMask = 0;
        uint8_t edcaErrorMask = 0;
        if (_hw->ops->conf_tx) {
            for (uint16_t ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
                int ret = _hw->ops->conf_tx(_hw, _vif, 0, ac, &edca[ac]);
                if (ret == 0)
                    edcaSuccessMask |= (uint8_t)(1U << ac);
                else {
                    edcaErrorMask |= (uint8_t)(1U << ac);
                    IOLog("rtw88: conf_tx ac=%u failed: %d\n", ac, ret);
                }
            }
        }

        if (_parent) {
            _parent->setProperty("AirportRTW89EDCAConfigured",
                                 edcaSuccessMask == 0x0f
                                     ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89EDCASuccessMask",
                                 (uint64_t)edcaSuccessMask, 8);
            _parent->setProperty("AirportRTW89EDCAErrorMask",
                                 (uint64_t)edcaErrorMask, 8);
#define RTW89_SET_EDCA_PROP(name, ac, field) \
            _parent->setProperty("AirportRTW89EDCA" name, \
                                 (uint64_t)edca[ac].field, 16)
            RTW89_SET_EDCA_PROP("VOAIFS", IEEE80211_AC_VO, aifs);
            RTW89_SET_EDCA_PROP("VOCWMin", IEEE80211_AC_VO, cw_min);
            RTW89_SET_EDCA_PROP("VOCWMax", IEEE80211_AC_VO, cw_max);
            RTW89_SET_EDCA_PROP("VOTXOP", IEEE80211_AC_VO, txop);
            RTW89_SET_EDCA_PROP("VIAIFS", IEEE80211_AC_VI, aifs);
            RTW89_SET_EDCA_PROP("VICWMin", IEEE80211_AC_VI, cw_min);
            RTW89_SET_EDCA_PROP("VICWMax", IEEE80211_AC_VI, cw_max);
            RTW89_SET_EDCA_PROP("VITXOP", IEEE80211_AC_VI, txop);
            RTW89_SET_EDCA_PROP("BEAIFS", IEEE80211_AC_BE, aifs);
            RTW89_SET_EDCA_PROP("BECWMin", IEEE80211_AC_BE, cw_min);
            RTW89_SET_EDCA_PROP("BECWMax", IEEE80211_AC_BE, cw_max);
            RTW89_SET_EDCA_PROP("BETXOP", IEEE80211_AC_BE, txop);
            RTW89_SET_EDCA_PROP("BKAIFS", IEEE80211_AC_BK, aifs);
            RTW89_SET_EDCA_PROP("BKCWMin", IEEE80211_AC_BK, cw_min);
            RTW89_SET_EDCA_PROP("BKCWMax", IEEE80211_AC_BK, cw_max);
            RTW89_SET_EDCA_PROP("BKTXOP", IEEE80211_AC_BK, txop);
#undef RTW89_SET_EDCA_PROP
        }

        IOLog("rtw88: EDCA source=%u success=0x%02x error=0x%02x "
              "VO[aifs=%u cw=%u/%u txop=%u] BE[aifs=%u cw=%u/%u txop=%u]\n",
              edcaSource, edcaSuccessMask, edcaErrorMask,
              edca[IEEE80211_AC_VO].aifs,
              edca[IEEE80211_AC_VO].cw_min,
              edca[IEEE80211_AC_VO].cw_max,
              edca[IEEE80211_AC_VO].txop,
              edca[IEEE80211_AC_BE].aifs,
              edca[IEEE80211_AC_BE].cw_min,
              edca[IEEE80211_AC_BE].cw_max,
              edca[IEEE80211_AC_BE].txop);

        _vif->cfg.assoc = true;
        _vif->cfg.aid   = aid;
        memcpy(_vif->cfg.ap_addr, _targetBSS.bssid, ETH_ALEN);

        /* WPA2 must be ready to receive M1 before rtw89 is told association is
         * complete.  In 0.2.163 the Airport path can delegate the 4-way
         * handshake to Apple's RSN supplicant; utility/legacy paths keep the
         * existing internal supplicant. */
        if (_wpa2) {
            if (!_appleRSNMode && !_pmkProvided)
                derivePMK((uint8_t *)_password, (uint8_t *)_targetBSS.ssid,
                          _targetBSS.ssid_len, _pmk);
            resetHandshakeDiagnostics();
            _state = RTW88_STATE_HANDSHAKING;
            setHandshakeRxFilter(true);
            handshakeArmedBeforeAssocNotify =
                (_state == RTW88_STATE_HANDSHAKING) &&
                _handshakeRxFilterOpen && _sta && _vif->cfg.assoc;
            if (_parent) {
                _parent->setProperty("AirportRTW89HandshakeArmedBeforeAssocNotify",
                    handshakeArmedBeforeAssocNotify ? kOSBooleanTrue
                                                    : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89HandshakeStateBeforeAssocNotify",
                                     (uint64_t)_state, 8);
                _parent->setProperty("AirportRTW89HandshakeRXFilterOpenBeforeAssocNotify",
                    _handshakeRxFilterOpen ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89HandshakeStaPresentBeforeAssocNotify",
                    _sta ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89HandshakeVifAssocBeforeAssocNotify",
                    _vif->cfg.assoc ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89HandshakePMKReadyBeforeAssocNotify",
                    (!_appleRSNMode && (_pmkProvided || _password[0]))
                        ? kOSBooleanTrue : kOSBooleanFalse);
                _parent->setProperty("AirportRTW89AppleRSNWaitingForEAPOL",
                    _appleRSNMode ? kOSBooleanTrue : kOSBooleanFalse);
            }
            IOLog("rtw88: WPA2 armed before association notify "
                  "apple-rsn=%u state=%u filter=%u sta=%u vif_assoc=%u\n",
                  _appleRSNMode ? 1U : 0U, (unsigned)_state,
                  _handshakeRxFilterOpen ? 1U : 0U,
                  _sta ? 1U : 0U, _vif->cfg.assoc ? 1U : 0U);
        }

        _assocNotifyInProgress = _wpa2;
        if (_wpa2 && _parent) {
            _parent->setProperty("AirportRTW89HandshakeAssocNotifyStarted",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89HandshakeAssocNotifyInProgress",
                                 kOSBooleanTrue);
        }
        RTW89CompatWiphyGuard cfgGuard(_hw);
        if (_hw->ops->vif_cfg_changed || _hw->ops->link_info_changed) {
            /* rtw89 split API: per-link conf first (BSSID → CAM), then
             * vif config (ASSOC → sta_assoc H2C + join info). */
            if (_hw->ops->link_info_changed)
                _hw->ops->link_info_changed(_hw, _vif, bss,
                                            BSS_CHANGED_BSSID);


            if (_hw->ops->vif_cfg_changed)
                _hw->ops->vif_cfg_changed(_hw, _vif, BSS_CHANGED_ASSOC);

        } else if (_hw->ops->bss_info_changed) {

            _hw->ops->bss_info_changed(_hw, _vif, bss,
                BSS_CHANGED_ASSOC | BSS_CHANGED_QOS);

        }
        _assocNotifyInProgress = false;
        if (_wpa2 && _parent) {
            _parent->setProperty("AirportRTW89HandshakeAssocNotifyInProgress",
                                 kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeAssocNotifyCompleted",
                                 kOSBooleanTrue);
        }
    }

    captureHandshakeStationContext();

    if (_wpa2) {
        /* Fallback for an unexpected driver with no association callbacks.
         * Normal rtw89 runs must have armed before notification above. */
        if (!handshakeArmedBeforeAssocNotify) {
            if (!_appleRSNMode && !_pmkProvided)
                derivePMK((uint8_t *)_password, (uint8_t *)_targetBSS.ssid,
                          _targetBSS.ssid_len, _pmk);
            resetHandshakeDiagnostics();
            _state = RTW88_STATE_HANDSHAKING;
            setHandshakeRxFilter(true);
            if (_parent) {
                _parent->setProperty("AirportRTW89HandshakeArmedBeforeAssocNotify",
                                     kOSBooleanFalse);
                _parent->setProperty("AirportRTW89HandshakePMKReadyBeforeAssocNotify",
                                     kOSBooleanFalse);
            }
        }
        if (_parent)
            _parent->setProperty("AirportRTW89HandshakeAssocSucceeded",
                                 kOSBooleanTrue);
        IOLog("rtw88: WPA2 — waiting for %s EAPOL handshake (early arm=%u)\n",
              _appleRSNMode ? "Apple RSN" : "internal",
              handshakeArmedBeforeAssocNotify ? 1U : 0U);
        uint64_t d;
        clock_interval_to_deadline(_appleRSNMode ? 12000 : 8000,
                                   kMillisecondScale, &d);
        _timer->wakeAtTime(d);
    } else {
        _state = RTW88_STATE_CONNECTED;
        /* 0.2.29 direct link publication: do not wait for a one-second poll to
         * notice the open-network CONNECTED edge. */
#ifdef RTW_AIRPORT
        if (_parent)
            _parent->airportPublishLinkState(true, _targetBSS.rssi, false);
#endif
        startTxAggregation();   /* negotiate uplink A-MPDU now the link is up */
        _timer->cancelTimeout();
    }
}

bool RTW88IEEE80211::buildAuthReq(uint8_t *buf, uint32_t *len)
{
    /* 802.11 Authentication frame (open system, seq 1) */
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)buf;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH);
    hdr->duration_id   = 0;
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ << 4));

    uint8_t *body = buf + sizeof(*hdr);
    /* Algorithm: 0 (Open), Transaction: 1, Status: 0 */
    body[0] = 0; body[1] = 0; /* algorithm */
    body[2] = 1; body[3] = 0; /* transaction seq */
    body[4] = 0; body[5] = 0; /* status code */
    *len = sizeof(*hdr) + 6;
    return true;
}

bool RTW88IEEE80211::buildAssocReq(uint8_t *buf, uint32_t *len)
{
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)buf;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ);
    hdr->duration_id   = 0;
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ << 4));

    uint8_t *body = buf + sizeof(*hdr);
    /* Capability: ESS, Short Preamble, and Privacy for encrypted APs. */
    uint16_t cap = 0x0421; /* ESS + short preamble + short slot */
    if (_wpa2)
        cap |= 0x0010;      /* Privacy only for encrypted association */
    body[0] = (uint8_t)(cap & 0xff);
    body[1] = (uint8_t)(cap >> 8);
    /* Listen interval: 10 */
    body[2] = 10; body[3] = 0;
    body += 4;

    /* SSID IE */
    body[0] = WLAN_EID_SSID;
    body[1] = (uint8_t)_targetBSS.ssid_len;
    memcpy(body + 2, _targetBSS.ssid, _targetBSS.ssid_len);
    body += 2 + _targetBSS.ssid_len;

    /* Supported rates. */
    static const uint8_t rates_2g[] = {
        0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
    };
    static const uint8_t rates_5g[] = {
        0x8c, 0x12, 0x98, 0x24, 0x30, 0x48, 0x60, 0x6c
    };
    static const uint8_t ext_rates_2g[] = {
        0x30, 0x48, 0x60, 0x6c
    };
    const uint8_t *rates =
        (_targetBSS.channel > 14) ? rates_5g : rates_2g;
    uint8_t rates_len =
        (_targetBSS.channel > 14) ? sizeof(rates_5g) : sizeof(rates_2g);

    body[0] = WLAN_EID_SUPP_RATES;
    body[1] = rates_len;
    memcpy(body + 2, rates, rates_len);
    body += 2 + rates_len;

    if (_targetBSS.channel <= 14) {
        body[0] = WLAN_EID_EXT_SUPP_RATES;
        body[1] = sizeof(ext_rates_2g);
        memcpy(body + 2, ext_rates_2g, sizeof(ext_rates_2g));
        body += 2 + sizeof(ext_rates_2g);
    }

    /*
     * HT/VHT Capabilities — advertise 802.11n/ac so the AP associates us as a
     * high-throughput station (high MCS rates) and is willing to set up A-MPDU
     * BlockAck aggregation.  Without these IEs the AP treats us as legacy a/g
     * (<=54 Mbps, no aggregation), which is the root cause of the ~13 Mbps cap.
     *
     * We copy directly from the chip's own band capabilities (filled by
     * rtw_init_ht_cap/rtw_init_vht_cap during rtw_register_hw) so we never
     * claim more than the hardware supports.  The 40/80 MHz channel-width bits
     * are cleared because the PHY stays on a 20 MHz channel this pass — wider
     * operation needs HT/VHT Operation parsing + a re-tune (future work).
     */
    enum nl80211_band band =
        (_targetBSS.channel > 14) ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
    struct ieee80211_supported_band *sband =
        (_hw && _hw->wiphy) ? _hw->wiphy->bands[band] : nullptr;

    if (htAllowed() && sband && sband->ht_cap.ht_supported) {
        const struct ieee80211_sta_ht_cap *ht = &sband->ht_cap;
        body[0] = WLAN_EID_HT_CAPABILITY;
        body[1] = 26;
        uint8_t *p = body + 2;
        /* HT Capabilities Info (2 bytes, LE).  Advertise 40 MHz only when we
         * actually operate at >=40 MHz; otherwise clear the width bits to keep
         * the AP at 20 MHz. */
        uint16_t htcap = ht->cap;
        if (_connChanWidth < 40)
            htcap &= ~(uint16_t)(IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
                                 IEEE80211_HT_CAP_SGI_40 |
                                 IEEE80211_HT_CAP_DSSSCCK40);
        p[0] = (uint8_t)(htcap & 0xff);
        p[1] = (uint8_t)(htcap >> 8);
        /* A-MPDU Parameters: max-length exponent (bits 1:0) | density (4:2). */
        p[2] = (uint8_t)((ht->ampdu_factor & 0x3) |
                         ((ht->ampdu_density & 0x7) << 2));
        /* Supported MCS Set (16 bytes): rx_mask[10], rx_highest(2),
         * tx_params(1), 3 reserved. */
        memcpy(p + 3, ht->mcs.rx_mask, 10);
        p[13] = (uint8_t)(ht->mcs.rx_highest & 0xff);
        p[14] = (uint8_t)((ht->mcs.rx_highest >> 8) & 0xff);
        p[15] = (uint8_t)(ht->mcs.tx_params & 0xff);
        /* p[16..25]: MCS-set reserved (3) + HT-ext (2) + TxBF (4) + ASEL (1). */
        memset(p + 16, 0, 10);
        body += 2 + 26;
    }

    if (htAllowed() && band == NL80211_BAND_5GHZ &&
        sband && sband->vht_cap.vht_supported) {
        const struct ieee80211_sta_vht_cap *vht = &sband->vht_cap;
        body[0] = WLAN_EID_VHT_CAPABILITY;
        body[1] = 12;
        uint8_t *p = body + 2;
        /* VHT Capabilities Info (4 bytes, LE).  The Supported Channel Width
         * Set subfield (bits 2:3) stays 0 (<=80 MHz capable); actual operation
         * is held to 20 MHz by the HT cap above. */
        uint32_t vcap = vht->cap;
        p[0] = (uint8_t)(vcap & 0xff);
        p[1] = (uint8_t)((vcap >> 8) & 0xff);
        p[2] = (uint8_t)((vcap >> 16) & 0xff);
        p[3] = (uint8_t)((vcap >> 24) & 0xff);
        /* Supported VHT-MCS and NSS Set (8 bytes). */
        uint16_t rxmap = (uint16_t)le32_to_cpu(vht->vht_mcs.rx_mcs_map);
        uint16_t rxhi  = le16_to_cpu(vht->vht_mcs.rx_highest);
        uint16_t txmap = (uint16_t)le32_to_cpu(vht->vht_mcs.tx_mcs_map);
        uint16_t txhi  = le16_to_cpu(vht->vht_mcs.tx_highest);
        p[4] = (uint8_t)(rxmap & 0xff); p[5] = (uint8_t)(rxmap >> 8);
        p[6] = (uint8_t)(rxhi & 0xff);  p[7] = (uint8_t)(rxhi >> 8);
        p[8] = (uint8_t)(txmap & 0xff); p[9] = (uint8_t)(txmap >> 8);
        p[10] = (uint8_t)(txhi & 0xff); p[11] = (uint8_t)(txhi >> 8);
        body += 2 + 12;
    }

    /* WME information element. We later notify rtw88 that QoS is enabled, so
     * advertise WME to the AP as well, especially for stricter 5GHz networks. */
    static const uint8_t wme_info[] = {
        0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
    };
    memcpy(body, wme_info, sizeof(wme_info));
    body += sizeof(wme_info);

    /* Advertise the cipher choice we actually implement: pairwise CCMP/AES
     * with the AP's selected group cipher.  Mixed TKIP+AES APs often list
     * both pairwise ciphers; copying that raw IE can make the AP pick a path
     * we do not want. */
    if (_wpa2) {
        if (_appleRSNMode && _appleRSNIELen >= 2 &&
            _appleRSNIELen <= sizeof(_appleRSNIE)) {
            memcpy(body, _appleRSNIE, _appleRSNIELen);
            body += _appleRSNIELen;
            if (_parent) {
                _parent->setProperty("AirportRTW89AppleRSNIEUsedInAssoc",
                                     kOSBooleanTrue);
                _parent->setProperty("AirportRTW89AppleRSNAssocIELength",
                                     (uint64_t)_appleRSNIELen, 16);
            }
        } else {
            uint16_t rsn_len =
                rtw88BuildSelectedRsnIe(body, _targetBSS.group_cipher);
            body += rsn_len;
            if (_parent && _appleRSNMode)
                _parent->setProperty("AirportRTW89AppleRSNIEFallbackGenerated",
                                     kOSBooleanTrue);
        }
    }

    *len = (uint32_t)(body - buf);
    return true;
}

/* ------------------------------------------------------------------ */
/*  Disconnect                                                          */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::cmdDisconnect()
{
    if (_state == RTW88_STATE_IDLE) return kIOReturnSuccess;
    doDisconnect();
    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::flushBSSCache()
{
    if (!_bssLock)
        return kIOReturnNotReady;
    if (_state == RTW88_STATE_SCANNING)
        return kIOReturnBusy;

    uint32_t freed = 0;
    IOLockLock(_bssLock);
    RTW88BSS *b = _bssList;
    while (b) {
        RTW88BSS *next = b->next;
        IOFree(b, sizeof(*b));
        b = next;
        ++freed;
    }
    _bssList = nullptr;
    _bssCount = 0;
    _scanGeneration = 0;
    _connectedScanCursor = 0;
    _scanSnapshotUsesRecentWindow = false;
    IOLockUnlock(_bssLock);

    memset(&_targetBSS, 0, sizeof(_targetBSS));
    if (_parent) {
        _parent->setProperty("AirportRTW89PersistentBSSCacheFlushCount",
                             (uint64_t)freed, 32);
        _parent->setProperty("AirportRTW89PersistentBSSCacheFlushed",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89PersistentBSSCacheCountAfterFlush",
                             (uint64_t)0, 32);
    }
    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::cmdSetUserPower(bool on)
{
    /* 0.2.165: make the macOS Wi-Fi switch useful without cycling the RTW89
     * firmware.  Full ops->stop()/ops->start() has historically been much
     * less stable than the now-working steady-state data path.  Logical OFF
     * therefore quiesces scan/association state only; logical ON starts from
     * the existing powered hardware and lets the controller launch a fresh
     * scan immediately. */
    if (on) {
        if (!_powered)
            return powerOn();
        if (_state == RTW88_STATE_DISCONNECTING)
            _state = RTW88_STATE_IDLE;
        return kIOReturnSuccess;
    }

    if (_state == RTW88_STATE_SCANNING) {
        if (!abortActiveScan(true))
            return kIOReturnBusy;
    }

    if (_state == RTW88_STATE_CONNECTED ||
        _state == RTW88_STATE_AUTHENTICATING ||
        _state == RTW88_STATE_ASSOCIATING ||
        _state == RTW88_STATE_HANDSHAKING) {
        doDisconnect();
    } else {
        clearKeys();
        releaseSta();
        _state = RTW88_STATE_IDLE;
        _scanReturnState = RTW88_STATE_IDLE;
        if (_timer)
            _timer->cancelTimeout();
    }

    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::cmdPowerOn()
{
    IOReturn ret = powerOn();
    if (ret == kIOReturnSuccess && _state == RTW88_STATE_DISCONNECTING)
        _state = RTW88_STATE_IDLE;
    return ret;
}

IOReturn RTW88IEEE80211::cmdPowerOff()
{
    if (_state == RTW88_STATE_SCANNING)
        abortActiveScan(true);

    if (_state == RTW88_STATE_CONNECTED ||
        _state == RTW88_STATE_AUTHENTICATING ||
        _state == RTW88_STATE_ASSOCIATING ||
        _state == RTW88_STATE_HANDSHAKING)
        doDisconnect();
    else {
        clearKeys();
        releaseSta();
    }

    powerOff();
    _state = RTW88_STATE_IDLE;
    _scanReturnState = RTW88_STATE_IDLE;
#ifdef RTW_AIRPORT
    if (_parent)
        _parent->airportPublishLinkState(false, _targetBSS.rssi, false);
#endif
    return kIOReturnSuccess;
}

void RTW88IEEE80211::doDisconnect()
{
    setHandshakeRxFilter(false);
    if (!_hw || !_vif) {
        _state = RTW88_STATE_IDLE;
        _scanReturnState = RTW88_STATE_IDLE;
        return;
    }
    clearKeys();

    /* Send deauth frame */
    uint8_t deauth[28] = {};
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)deauth;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DEAUTH);
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    uint8_t *body = deauth + sizeof(*hdr);
    body[0] = WLAN_REASON_DEAUTH_LEAVING; body[1] = 0;
    txMgmtFrame(deauth, sizeof(*hdr) + 2);

    /* Notify driver of disassociation — split API, mirroring the assoc path
     * in reverse.  rtw89 dropped bss_info_changed entirely: the firmware join
     * state is torn down by vif_cfg_changed(BSS_CHANGED_ASSOC) observing
     * vif->cfg.assoc == false (→ rtw89_station_mode_sta_assoc disassoc path).
     * The old bss_info_changed call was a no-op under rtw89, so the firmware
     * kept its stale join/channel context — the *next* connect's first
     * register-H2C then timed out ("c2h reg timeout"), leaving RSSI 0 and no
     * traffic.  vif_cfg_changed MUST run before releaseSta() drops the peer
     * STA, so the disassoc H2C still has a valid mac_id to reference. */
    struct ieee80211_bss_conf *bss = &_vif->bss_conf;
    bss->assoc = false;
    _vif->cfg.assoc = false;
    if (_hw->ops) {
        RTW89CompatWiphyGuard cfgGuard(_hw);
        if (_hw->ops->vif_cfg_changed)
            _hw->ops->vif_cfg_changed(_hw, _vif, BSS_CHANGED_ASSOC);
        else if (_hw->ops->bss_info_changed)
            _hw->ops->bss_info_changed(_hw, _vif, bss, BSS_CHANGED_ASSOC);
    }
    releaseSta();

    _state = RTW88_STATE_IDLE;
    _scanReturnState = RTW88_STATE_IDLE;
    _timer->cancelTimeout();
#ifdef RTW_AIRPORT
    if (_parent)
        _parent->airportPublishLinkState(false, _targetBSS.rssi, false);
#endif
}

/* ------------------------------------------------------------------ */
/*  WPA2 4-way handshake                                                */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::resetHandshakeDiagnostics()
{
    _handshakeRxFrames = 0;
    _handshakeDataFrames = 0;
    _handshakeEapolFrames = 0;
    _handshakeM1Count = 0;
    _handshakeM3Count = 0;
    _pendingEapolTxStep = 0;
    _handshakeM2TxStatusCount = 0;
    _handshakeM4TxStatusCount = 0;
    _handshakeDisconnectCount = 0;
    _handshakeLastDisconnectReason = 0;
    _handshakeLastDisconnectSubtype = 0;
    _assocNotifyInProgress = false;
    if (!_parent) return;
    _parent->setProperty("AirportRTW89HandshakeRXFrames", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeDataFrames", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeEAPOLFrames", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM1Count", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM3Count", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM2Transmitted", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM4Transmitted", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM2TxStatusSeen", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM2TxStatusCount", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM2TxFlags", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM2TxAcked", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM4TxStatusSeen", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM4TxStatusCount", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM4TxFlags", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeM4TxAcked", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeLastEAPOLTxStep", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeLastEAPOLTxFlags", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeLastEAPOLTxAcked", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLPortControl", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLFixedBasicRate", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLRateIndex", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLRateBand", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLTxControlFlags", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeEAPOLTxInfoFlags", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeEAPOLHighQueueDiagnostic", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLSendAfterDTIM", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLExpectedQSel", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLExpectedTxChannel", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLQoSData", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLFrameControl", (uint64_t)0, 16);
    _parent->setProperty("AirportRTW89HandshakeEAPOLFrameHeaderLength", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLQoSControlPresent", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLFrameQoSTIDValid", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLTID", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLTIDIndicate", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLQueueMapping", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeEAPOLPriority", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeDisconnectCount", (uint64_t)0, 32);
    _parent->setProperty("AirportRTW89HandshakeLastDisconnectReason", (uint64_t)0, 16);
    _parent->setProperty("AirportRTW89HandshakeLastDisconnectSubtype", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeTimedOut", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM2SnapshotValid", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeTimeoutSnapshotValid", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeAssocSucceeded", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeRXFilterOpen", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeRXFilterOpened", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeRXFilterRestored", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeArmedBeforeAssocNotify", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeStateBeforeAssocNotify", (uint64_t)0, 8);
    _parent->setProperty("AirportRTW89HandshakeRXFilterOpenBeforeAssocNotify", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeStaPresentBeforeAssocNotify", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeVifAssocBeforeAssocNotify", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakePMKReadyBeforeAssocNotify", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeAssocNotifyStarted", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeAssocNotifyInProgress", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeAssocNotifyCompleted", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeEAPOLBeforeAssocNotifyComplete", kOSBooleanFalse);
    _parent->setProperty("AirportRTW89HandshakeM1BeforeAssocNotifyComplete", kOSBooleanFalse);
}

void RTW88IEEE80211::captureHandshakeTxSnapshot(bool atTimeout)
{
    struct rtw88_tx_ring_snapshot snapshot = {};
    bool valid = rtw88_get_tx_ring_snapshot_highq(_rtwdev, 0, &snapshot);
    if (!_parent)
        return;

#define RTW89_SNAPSHOT_NAME(suffix) \
    (atTimeout ? "AirportRTW89HandshakeTimeout" suffix \
               : "AirportRTW89HandshakeM2" suffix)
#define RTW89_SET_SNAPSHOT_U32(suffix, field) \
    _parent->setProperty(RTW89_SNAPSHOT_NAME(suffix), \
                         (uint64_t)snapshot.field, 32)
#define RTW89_SET_SNAPSHOT_U64(suffix, field) \
    _parent->setProperty(RTW89_SNAPSHOT_NAME(suffix), \
                         (uint64_t)snapshot.field, 64)

    _parent->setProperty(RTW89_SNAPSHOT_NAME("SnapshotValid"),
                         valid ? kOSBooleanTrue : kOSBooleanFalse);
    if (valid) {
        RTW89_SET_SNAPSHOT_U32("BETxChannel", be_txch);
        RTW89_SET_SNAPSHOT_U32("BEBDWP", be_bd_wp);
        RTW89_SET_SNAPSHOT_U32("BEBDRP", be_bd_rp);
        RTW89_SET_SNAPSHOT_U32("BEBDLen", be_bd_len);
        RTW89_SET_SNAPSHOT_U32("BEBDPending", be_bd_pending);
        RTW89_SET_SNAPSHOT_U32("BEBDAvail", be_bd_avail);
        RTW89_SET_SNAPSHOT_U32("BEWDAvail", be_wd_avail);
        RTW89_SET_SNAPSHOT_U32("BEWDTotal", be_wd_total);
        RTW89_SET_SNAPSHOT_U32("BETag", be_tag);
        RTW89_SET_SNAPSHOT_U32("BEDMAEnabled", be_dma_enabled);
        RTW89_SET_SNAPSHOT_U64("BETxCount", be_tx_cnt);
        RTW89_SET_SNAPSHOT_U64("BETxAcked", be_tx_acked);
        RTW89_SET_SNAPSHOT_U64("BETxRetryLimit", be_tx_retry_lmt);
        RTW89_SET_SNAPSHOT_U64("BETxLifetime", be_tx_life_time);
        RTW89_SET_SNAPSHOT_U64("BETxMacIdDrop", be_tx_mac_id_drop);
        RTW89_SET_SNAPSHOT_U32("TxQTID", txq_tid);
        RTW89_SET_SNAPSHOT_U32("TxQQSel", txq_qsel);
        RTW89_SET_SNAPSHOT_U32("TxQChannel", txq_txch);
        RTW89_SET_SNAPSHOT_U32("TxQBDWP", txq_bd_wp);
        RTW89_SET_SNAPSHOT_U32("TxQBDRP", txq_bd_rp);
        RTW89_SET_SNAPSHOT_U32("TxQBDLen", txq_bd_len);
        RTW89_SET_SNAPSHOT_U32("TxQBDPending", txq_bd_pending);
        RTW89_SET_SNAPSHOT_U32("TxQBDAvail", txq_bd_avail);
        RTW89_SET_SNAPSHOT_U32("TxQWDAvail", txq_wd_avail);
        RTW89_SET_SNAPSHOT_U32("TxQWDTotal", txq_wd_total);
        RTW89_SET_SNAPSHOT_U32("TxQTag", txq_tag);
        RTW89_SET_SNAPSHOT_U32("TxQDMAEnabled", txq_dma_enabled);
        RTW89_SET_SNAPSHOT_U64("TxQTxCount", txq_tx_cnt);
        RTW89_SET_SNAPSHOT_U64("TxQTxAcked", txq_tx_acked);
        RTW89_SET_SNAPSHOT_U64("TxQTxRetryLimit", txq_tx_retry_lmt);
        RTW89_SET_SNAPSHOT_U64("TxQTxLifetime", txq_tx_life_time);
        RTW89_SET_SNAPSHOT_U64("TxQTxMacIdDrop", txq_tx_mac_id_drop);
        RTW89_SET_SNAPSHOT_U32("RPQBDWP", rpq_bd_wp);
        RTW89_SET_SNAPSHOT_U32("RPQBDRP", rpq_bd_rp);
        RTW89_SET_SNAPSHOT_U32("RPQBDLen", rpq_bd_len);
        RTW89_SET_SNAPSHOT_U32("FWCmdBDWP", fwcmd_bd_wp);
        RTW89_SET_SNAPSHOT_U32("FWCmdBDRP", fwcmd_bd_rp);
        RTW89_SET_SNAPSHOT_U32("FWCmdBDLen", fwcmd_bd_len);
        RTW89_SET_SNAPSHOT_U32("FWCmdBDPending", fwcmd_bd_pending);
        RTW89_SET_SNAPSHOT_U32("FWCmdBDAvail", fwcmd_bd_avail);
        RTW89_SET_SNAPSHOT_U32("H2CQueueLen", h2c_queue_len);
        RTW89_SET_SNAPSHOT_U32("H2CReleaseQueueLen", h2c_release_queue_len);
        RTW89_SET_SNAPSHOT_U32("PCIRunning", pci_running);
        RTW89_SET_SNAPSHOT_U32("PCIUnderRecovery", pci_under_recovery);
        RTW89_SET_SNAPSHOT_U32("PowerOn", power_on);

        IOLog("rtw88: passive %s TX snapshot: qsel=%u ch=%u wp=%u rp=%u pending=%u "
              "BE wp=%u rp=%u RPQ wp=%u rp=%u FWCMD wp=%u rp=%u h2c=%u/%u\n",
              atTimeout ? "timeout" : "M2",
              snapshot.txq_qsel, snapshot.txq_txch,
              snapshot.txq_bd_wp, snapshot.txq_bd_rp,
              snapshot.txq_bd_pending,
              snapshot.be_bd_wp, snapshot.be_bd_rp,
              snapshot.rpq_bd_wp, snapshot.rpq_bd_rp,
              snapshot.fwcmd_bd_wp, snapshot.fwcmd_bd_rp,
              snapshot.h2c_queue_len, snapshot.h2c_release_queue_len);
    }

#undef RTW89_SET_SNAPSHOT_U64
#undef RTW89_SET_SNAPSHOT_U32
#undef RTW89_SNAPSHOT_NAME
}

void RTW88IEEE80211::captureHandshakeStationContext()
{
    struct rtw88_sta_context_snapshot c = {};
    bool valid = rtw88_get_sta_context_snapshot(_rtwdev, _vif, _sta, &c);
    if (!_parent)
        return;

#define RTW89_SET_CONTEXT(name, field) \
    _parent->setProperty("AirportRTW89HandshakeContext" name, \
                         (uint64_t)c.field, 32)

    _parent->setProperty("AirportRTW89HandshakeContextValid",
                         valid ? kOSBooleanTrue : kOSBooleanFalse);
    if (valid) {
        RTW89_SET_CONTEXT("VifLinkPresent", vif_link_present);
        RTW89_SET_CONTEXT("StaLinkPresent", sta_link_present);
        RTW89_SET_CONTEXT("VifMacId", vif_mac_id);
        RTW89_SET_CONTEXT("StaMacId", sta_mac_id);
        RTW89_SET_CONTEXT("MacIdMatch", mac_id_match);
        RTW89_SET_CONTEXT("AssocMapMatch", assoc_map_match);
        RTW89_SET_CONTEXT("StaVifLinkMatch", sta_vif_link_match);
        RTW89_SET_CONTEXT("Port", port);
        RTW89_SET_CONTEXT("MacIndex", mac_idx);
        RTW89_SET_CONTEXT("PhyIndex", phy_idx);
        RTW89_SET_CONTEXT("WMM", wmm);
        RTW89_SET_CONTEXT("NetType", net_type);
        RTW89_SET_CONTEXT("WifiRole", wifi_role);
        RTW89_SET_CONTEXT("SelfRole", self_role);
        RTW89_SET_CONTEXT("ChanctxAssigned", chanctx_assigned);
        RTW89_SET_CONTEXT("ChanctxIndex", chanctx_idx);
        RTW89_SET_CONTEXT("AddrCAMValid", addr_cam_valid);
        RTW89_SET_CONTEXT("AddrCAMIndex", addr_cam_idx);
        RTW89_SET_CONTEXT("AddrCAMBSSIDIndex", addr_cam_bssid_idx);
        RTW89_SET_CONTEXT("AddrCAMMaskSelect", addr_cam_mask_sel);
        RTW89_SET_CONTEXT("AddrCAMAddressMask", addr_cam_addr_mask);
        RTW89_SET_CONTEXT("BSSIDCAMValid", bssid_cam_valid);
        RTW89_SET_CONTEXT("BSSIDCAMIndex", bssid_cam_idx);
        RTW89_SET_CONTEXT("BSSIDCAMPhyIndex", bssid_cam_phy_idx);
        RTW89_SET_CONTEXT("VifAssoc", vif_cfg_assoc);
        RTW89_SET_CONTEXT("BSSAssoc", bss_assoc);
        RTW89_SET_CONTEXT("BSSQoS", bss_qos);
        RTW89_SET_CONTEXT("StaWME", sta_wme);
        RTW89_SET_CONTEXT("AID", aid);
        RTW89_SET_CONTEXT("VOAIFS", vo_aifs);
        RTW89_SET_CONTEXT("VOCWMin", vo_cw_min);
        RTW89_SET_CONTEXT("VOCWMax", vo_cw_max);
        RTW89_SET_CONTEXT("VOTXOP", vo_txop);
        RTW89_SET_CONTEXT("BEAIFS", be_aifs);
        RTW89_SET_CONTEXT("BECWMin", be_cw_min);
        RTW89_SET_CONTEXT("BECWMax", be_cw_max);
        RTW89_SET_CONTEXT("BETXOP", be_txop);

        IOLog("rtw88: station context macid vif/sta=%u/%u map=%u cam=%u:%u bssid=%u:%u "
              "port=%u wmm=%u VO[aifs=%u cw=%u/%u txop=%u]\n",
              c.vif_mac_id, c.sta_mac_id, c.assoc_map_match,
              c.addr_cam_valid, c.addr_cam_idx,
              c.bssid_cam_valid, c.bssid_cam_idx,
              c.port, c.wmm, c.vo_aifs, c.vo_cw_min, c.vo_cw_max, c.vo_txop);
    }
#undef RTW89_SET_CONTEXT
}

void RTW88IEEE80211::setHandshakeRxFilter(bool open)
{
    if (!_hw || _handshakeRxFilterOpen == open)
        return;
    rtw88_handshake_rx_filter(_hw, open);
    _handshakeRxFilterOpen = open;
    if (_parent) {
        _parent->setProperty("AirportRTW89HandshakeRXFilterOpen",
                             open ? kOSBooleanTrue : kOSBooleanFalse);
        if (open)
            _parent->setProperty("AirportRTW89HandshakeRXFilterOpened",
                                 kOSBooleanTrue);
        else
            _parent->setProperty("AirportRTW89HandshakeRXFilterRestored",
                                 kOSBooleanTrue);
    }
}

void RTW88IEEE80211::handleEAPOL(const uint8_t *data, uint32_t len)
{
    if (len < 99 || data[1] != 3)
        return;

    uint16_t eapol_body_len = (uint16_t)((data[2] << 8) | data[3]);
    uint32_t eapol_len = 4 + eapol_body_len;
    if (eapol_len > len || eapol_len < 99)
        return;

    uint16_t key_info = (uint16_t)((data[5] << 8) | data[6]);
    bool is_m1 = (key_info & 0x0088) == 0x0088 && !(key_info & 0x0100);
    bool is_m3 = (key_info & 0x01c8) == 0x01c8;
    uint16_t key_data_len = (uint16_t)((data[97] << 8) | data[98]);

    IOLog("rtw88: EAPOL key_info=0x%04x key_data_len=%u M1=%d M3=%d\n",
          key_info, key_data_len, is_m1, is_m3);
    if (_parent)
        _parent->setProperty("AirportRTW89HandshakeLastKeyInfo",
                             (uint64_t)key_info, 16);

    if (is_m1) {
        _handshakeM1Count++;
        if (_parent) {
            _parent->setProperty("AirportRTW89HandshakeM1Count",
                                 (uint64_t)_handshakeM1Count, 32);
            if (_assocNotifyInProgress)
                _parent->setProperty(
                    "AirportRTW89HandshakeM1BeforeAssocNotifyComplete",
                    kOSBooleanTrue);
        }
        memcpy(_anonce, data + 17, 32);
        read_random(_snonce, 32);
        derivePTK(_pmk, _anonce, _snonce, _macAddr, _targetBSS.bssid, _ptk);
        memcpy(_replayCtr, data + 9, 8);
        sendEAPOLKey(2, _replayCtr, false, false, true);
        uint64_t d;
        clock_interval_to_deadline(5000, kMillisecondScale, &d);
        _timer->wakeAtTime(d);
    } else if (is_m3) {
        _handshakeM3Count++;
        if (_parent)
            _parent->setProperty("AirportRTW89HandshakeM3Count",
                                 (uint64_t)_handshakeM3Count, 32);
        if (!eapol_mic_ok(_ptk, data, eapol_len)) {
            IOLog("rtw88: EAPOL M3 MIC check failed\n");
            return;
        }

        if (99 + key_data_len > eapol_len) {
            IOLog("rtw88: EAPOL M3 key data truncated\n");
            return;
        }

        uint8_t gtk[32] = {};
        uint8_t gtk_len = 0;
        uint8_t gtk_idx = 0;
        const uint8_t *key_data = data + 99;
        uint8_t unwrapped[256] = {};
        uint16_t unwrapped_len = 0;

        if (key_data_len) {
            if (key_info & 0x1000) {
                if (!aes_unwrap_128(_ptk + 16, key_data, key_data_len,
                                    unwrapped, &unwrapped_len)) {
                    IOLog("rtw88: failed to unwrap GTK key data\n");
                    return;
                }
                key_data = unwrapped;
                key_data_len = unwrapped_len;
            }

            if (!extract_gtk_from_kde(key_data, key_data_len,
                                      gtk, &gtk_len, &gtk_idx)) {
                IOLog("rtw88: no GTK KDE found in M3 key data\n");
            }
        }

        memcpy(_replayCtr, data + 9, 8);

        if (!installKey(&_ptkConf, true, 0, WLAN_CIPHER_SUITE_CCMP,
                        _ptk + 32, 16))
            return;
        uint32_t groupCipher = (_targetBSS.group_cipher == WLAN_CIPHER_SUITE_TKIP) ?
            WLAN_CIPHER_SUITE_TKIP : WLAN_CIPHER_SUITE_CCMP;
        if (gtk_len && !installKey(&_gtkConf, false, gtk_idx, groupCipher,
                                   gtk, gtk_len))
            return;

        sendEAPOLKey(4, _replayCtr, false, false, true);
        setHandshakeRxFilter(false);
        _state = RTW88_STATE_CONNECTED;
        _timer->cancelTimeout();
#ifdef RTW_AIRPORT
        if (_parent) {
            _parent->airportPublishLinkState(true, _targetBSS.rssi, true);
            /* The private-control/internal-supplicant path installs PTK/GTK
             * here rather than through Apple SET3.  Publish the same truthful
             * RSN-complete edge used by the Apple key-install path, but only
             * after M3 validation, real key installation, and M4 transmit. */
            _parent->setProperty("IO80211RSNDone", kOSBooleanTrue);
            if (IO80211Interface *interface =
                    _parent->getNetworkInterface()) {
                interface->setProperty("IO80211RSNDone", kOSBooleanTrue);
                interface->postMessage(APPLE80211_M_RSN_HANDSHAKE_DONE,
                                       nullptr, 0);
            }
            _parent->setProperty(
                "AirportRTW89InternalSupplicantRSNDonePublished",
                kOSBooleanTrue);
        }
#endif
        startTxAggregation();   /* keys are installed — negotiate uplink A-MPDU */
        IOLog("rtw88: WPA2 connected! gtk_len=%u gtk_idx=%u\n", gtk_len, gtk_idx);
    }
}

void RTW88IEEE80211::sendEAPOLKey(int step, const uint8_t *replay_counter,
                                    bool install, bool ack, bool mic)
{
    uint8_t frame[512] = {};
    uint8_t *eth = frame;
    memcpy(eth,     _targetBSS.bssid, 6); /* DA = AP */
    memcpy(eth + 6, _macAddr, 6);          /* SA = us */
    eth[12] = 0x88; eth[13] = 0x8e;        /* EAPOL ethertype */

    uint8_t *eapol = eth + 14;
    eapol[0] = 2;  /* version 2 */
    eapol[1] = 3;  /* EAPOL-Key */

    uint8_t *key = eapol + 4;
    key[0] = 2;  /* key descriptor = RSN */
    uint16_t ki = 0x000A; /* version=2 (HMAC-SHA1/AES), pairwise */
    if (mic)     ki |= 0x0100; /* MIC */
    if (install) ki |= 0x0040; /* Install */
    if (ack)     ki |= 0x0080; /* ACK */
    if (step == 4) ki |= 0x0200; /* Secure (bit 9) */
    key[1] = (uint8_t)(ki >> 8);
    key[2] = (uint8_t)(ki & 0xff);
    key[3] = 0; key[4] = 16; /* key length = 16 (AES-128) */
    memcpy(key + 5, replay_counter, 8);  /* key[5..12]  = Replay Counter */
    memcpy(key + 13, _snonce, 32);       /* key[13..44] = SNonce */
    /* key[45..60] = Key IV (zeros), key[61..68] = RSC (zeros) */
    /* key[69..76] = Reserved (zeros), key[77..92] = MIC (below) */

    uint16_t key_data_len = 0;
    if (step == 2) {
        key_data_len = rtw88BuildSelectedRsnIe(eapol + 99, _targetBSS.group_cipher);
        if (99 + key_data_len > sizeof(frame) - 14)
            key_data_len = 0;
    }

    key[93] = (uint8_t)(key_data_len >> 8);
    key[94] = (uint8_t)(key_data_len & 0xff);

    uint16_t eapol_key_len = (uint16_t)(95 + key_data_len);
    uint32_t eapol_total = 4 + eapol_key_len;
    eapol[2] = (uint8_t)(eapol_key_len >> 8);
    eapol[3] = (uint8_t)(eapol_key_len & 0xff);

    if (mic) {
        /* MIC = first 16 bytes of HMAC-SHA1(KCK, EAPOL frame with MIC zeroed)
         * KCK = _ptk[0..15]. */
        uint8_t mic_buf[20];
        kern_hmac_sha1(_ptk, 16, eapol, eapol_total, mic_buf);
        memcpy(key + 77, mic_buf, 16);
    }

    uint32_t ethlen = 14 + eapol_total;
    _pendingEapolTxStep = (uint8_t)step;
    mbuf_t m = rtw88_make_packet_mbuf(frame, ethlen);
    bool transmitted = m ? txDataFrame(m) : false;
    if (!transmitted)
        _pendingEapolTxStep = 0;
    if (_parent) {
        if (step == 2) {
            _parent->setProperty("AirportRTW89HandshakeM2Transmitted",
                                 transmitted ? kOSBooleanTrue : kOSBooleanFalse);
            if (transmitted)
                captureHandshakeTxSnapshot(false);
        } else if (step == 4)
            _parent->setProperty("AirportRTW89HandshakeM4Transmitted",
                                 transmitted ? kOSBooleanTrue : kOSBooleanFalse);
    }
}

/* ------------------------------------------------------------------ */
/*  Frame TX helpers                                                    */
/* ------------------------------------------------------------------ */

bool RTW88IEEE80211::txMgmtFrame(const uint8_t *frame, uint32_t len)
{
    if (!_hw || !_hw->ops || !_hw->ops->tx) return false;

    struct sk_buff *skb = alloc_skb(len + 128, GFP_ATOMIC);
    if (!skb) return false;
    skb_reserve(skb, 128); /* headroom for TX descriptor (48 B) + pkt_offset padding */
    skb_put_data(skb, frame, len);

    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->flags  = IEEE80211_TX_CTL_FIRST_FRAGMENT | IEEE80211_TX_CTL_NO_ACK;
    info->control.vif = _vif;

    struct ieee80211_tx_control ctrl = { .sta = nullptr };
    _hw->ops->tx(_hw, &ctrl, skb);
    return true;
}

/* ------------------------------------------------------------------ */
/*  A-MPDU BlockAck negotiation                                          */
/*                                                                      */
/*  802.11n/ac throughput depends on A-MPDU aggregation, which requires */
/*  a per-TID BlockAck agreement negotiated over the air with ADDBA     */
/*  action frames (category 3 = BACK).  mac80211 normally does this; we  */
/*  bypass mac80211, so the MLME drives it here:                         */
/*    - TX (uplink) agg: we send an ADDBA Request and, on a successful   */
/*      ADDBA Response, tag our data frames with IEEE80211_TX_CTL_AMPDU. */
/*    - RX (downlink) agg: we answer the AP's ADDBA Request; Realtek HW  */
/*      then auto-generates the RX BlockAck and de-aggregates for us     */
/*      (rtw88's ampdu_action is a no-op for RX_START/STOP).             */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::sendAddbaRequest(uint8_t tid)
{
    uint8_t f[24 + 9] = {};
    struct ieee80211_hdr_3addr *h = (struct ieee80211_hdr_3addr *)f;
    h->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
    h->duration_id   = 0;
    memcpy(h->addr1, _targetBSS.bssid, 6);
    memcpy(h->addr2, _macAddr, 6);
    memcpy(h->addr3, _targetBSS.bssid, 6);
    h->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ & 0xFFF) << 4);

    if (++_baDialog == 0) _baDialog = 1;   /* dialog token must be non-zero */

    uint8_t *b = f + 24;
    b[0] = WLAN_CATEGORY_BACK;
    b[1] = WLAN_ACTION_ADDBA_REQ;
    b[2] = _baDialog;
    /* Block Ack Parameter Set: A-MSDU(bit0)=0, policy(bit1)=1 (immediate),
     * TID(bits 2-5), Buffer Size(bits 6-15). */
    uint16_t param = (uint16_t)((1u << 1) |
                                ((unsigned)(tid & 0xf) << 2) |
                                ((unsigned)(_baBufSize & 0x3ff) << 6));
    b[3] = (uint8_t)(param & 0xff);
    b[4] = (uint8_t)(param >> 8);
    b[5] = 0; b[6] = 0;   /* Block Ack Timeout = 0 (no timeout) */
    /* Block Ack Starting Sequence Control: SSN (bits 4-15) = next data SN, so
     * the AP's reorder window aligns with the TID-0 data stream. */
    uint16_t ssc = (uint16_t)((uint16_t)(_dataSeq & 0xFFF) << 4);
    b[7] = (uint8_t)(ssc & 0xff);
    b[8] = (uint8_t)(ssc >> 8);

    txMgmtFrame(f, sizeof(f));
}

void RTW88IEEE80211::sendAddbaResponse(uint8_t tid, uint8_t dialog,
                                       uint16_t req_param, uint16_t ba_timeout,
                                       uint16_t status)
{
    uint8_t f[24 + 9] = {};
    struct ieee80211_hdr_3addr *h = (struct ieee80211_hdr_3addr *)f;
    h->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
    h->duration_id   = 0;
    memcpy(h->addr1, _targetBSS.bssid, 6);
    memcpy(h->addr2, _macAddr, 6);
    memcpy(h->addr3, _targetBSS.bssid, 6);
    h->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ & 0xFFF) << 4);

    uint8_t *b = f + 24;
    b[0] = WLAN_CATEGORY_BACK;
    b[1] = WLAN_ACTION_ADDBA_RESP;
    b[2] = dialog;
    b[3] = (uint8_t)(status & 0xff);
    b[4] = (uint8_t)(status >> 8);
    /* Echo the requester's A-MSDU bit; force immediate policy and our TID. */
    uint16_t param = (uint16_t)((unsigned)(req_param & 0x0001u) |
                                (1u << 1) |
                                ((unsigned)(tid & 0xf) << 2) |
                                ((unsigned)(_baBufSize & 0x3ff) << 6));
    b[5] = (uint8_t)(param & 0xff);
    b[6] = (uint8_t)(param >> 8);
    b[7] = (uint8_t)(ba_timeout & 0xff);
    b[8] = (uint8_t)(ba_timeout >> 8);

    txMgmtFrame(f, sizeof(f));
}

/* HT/VHT and A-MPDU are not used with TKIP.  An AP whose BSS uses TKIP
 * (pairwise or group cipher) operates in a non-HT mode; advertising HT to it
 * stalls the 4-way handshake or draws a deauth.  Open and CCMP links use HT. */
bool RTW88IEEE80211::htAllowed() const
{
    /* TKIP as either the pairwise or group cipher rules out HT (open and CCMP
     * links are fine).  _targetBSS.cipher/group_cipher are 0 for open networks. */
    if (_targetBSS.cipher       == WLAN_CIPHER_SUITE_TKIP) return false;
    if (_targetBSS.group_cipher == WLAN_CIPHER_SUITE_TKIP) return false;
    return true;
}

/*
 * A-MPDU master switch.
 *
 * Aggregation is DISABLED for now.  With the rtw89 CMAC/BA-CAM H2Cs wired up
 * the hardware A-MPDU datapath is genuinely exercised even by light traffic,
 * and on this port it does not work: TX aggregation stalls the fwcmd ring
 * ("no tx fwcmd resource") and RX aggregation desyncs the RX reassembly state
 * machine ("desc info should not be ready before first segment start"), so
 * DHCP never completes.  Non-aggregated TX/RX is the known-good path (it
 * carried working DHCP + internet on first connect) and also sidesteps the
 * under-load TX halt entirely, since the AMPDU engine is never engaged.
 *
 * Flip to true to re-enable and continue debugging the aggregated datapath on
 * real hardware; all the BA-setup plumbing below remains in place.
 */
static const bool kEnableAmpdu = false;

void RTW88IEEE80211::startTxAggregation()
{
    if (!kEnableAmpdu) return;
    if (_txBaActive) return;
    if (!htAllowed()) return;
    if (!_sta || !_sta->deflink.ht_cap.ht_supported) return;
    IOLog("rtw88: starting TX A-MPDU — sending ADDBA request (tid=%u)\n", _baTid);
    sendAddbaRequest(_baTid);
}

void RTW88IEEE80211::handleBackAction(const uint8_t *b, uint32_t len)
{
    if (len < 2) return;
    switch (b[1]) {   /* BlockAck action field */
    case WLAN_ACTION_ADDBA_REQ: {
        /* AP wants to aggregate downlink traffic to us — accept it and stand
         * up an RX reorder buffer for the TID so we deliver in order. */
        if (len < 9) return;
        uint8_t  dialog    = b[2];
        uint16_t req_param = (uint16_t)(b[3] | (b[4] << 8));
        uint16_t ba_to     = (uint16_t)(b[5] | (b[6] << 8));
        uint16_t ssc       = (uint16_t)(b[7] | (b[8] << 8));
        uint8_t  tid       = (uint8_t)((req_param >> 2) & 0xf);
        uint16_t bufsz     = (uint16_t)((req_param >> 6) & 0x3ff);
        uint16_t ssn       = (uint16_t)(ssc >> 4);

        _rxAddbaRequestCount++;
        if (_parent) {
            _parent->setProperty("AirportRTW89RxAddbaRequestSeen", kOSBooleanTrue);
            _parent->setProperty("AirportRTW89RxAddbaRequestCount",
                                 (uint64_t)_rxAddbaRequestCount, 32);
            _parent->setProperty("AirportRTW89RxAddbaLastTID", (uint64_t)tid, 8);
            _parent->setProperty("AirportRTW89RxAddbaLastSSN", (uint64_t)ssn, 16);
            _parent->setProperty("AirportRTW89RxAddbaLastBufferSize",
                                 (uint64_t)bufsz, 16);
        }

        /* 0.2.161: Do not advertise a BA agreement that the datapath has
         * deliberately disabled.  0.2.160 replied SUCCESS here even while
         * kEnableAmpdu=false, allowing the AP to transmit A-MPDUs without the
         * Realtek RX BA CAM being programmed.  That produced a severe
         * downlink/uplink asymmetry.  Status 37 is REQUEST_DECLINED. */
        if (!kEnableAmpdu) {
            const uint16_t kAddbaRequestDeclined = 37;
            rxBaTeardown(tid);
            sendAddbaResponse(tid, dialog, req_param, ba_to,
                              kAddbaRequestDeclined);
            _rxAddbaDeclinedCount++;
            if (_parent) {
                _parent->setProperty("AirportRTW89RxAddbaDeclinedWhileDisabled",
                                     kOSBooleanTrue);
                _parent->setProperty("AirportRTW89RxAddbaDeclinedCount",
                                     (uint64_t)_rxAddbaDeclinedCount, 32);
                _parent->setProperty("AirportRTW89RxAddbaLastResponseStatus",
                                     (uint64_t)kAddbaRequestDeclined, 16);
                _parent->setProperty("AirportRTW89RxAddbaSoftwareReorderActive",
                                     kOSBooleanFalse);
                _parent->setProperty("AirportRTW89RxAddbaHardwareBACAMActive",
                                     kOSBooleanFalse);
            }
            IOLog("rtw88: RX ADDBA request (tid=%u ssn=%u buf=%u) — "
                  "declined because A-MPDU datapath is disabled\n",
                  tid, ssn, bufsz);
            break;
        }

        rxBaSetup(tid, ssn, bufsz);
        if (_sta)
            rtw88_rx_ampdu_start(_sta, tid, ssn, bufsz);
        sendAddbaResponse(tid, dialog, req_param, ba_to, WLAN_STATUS_SUCCESS);
        if (_parent) {
            _parent->setProperty("AirportRTW89RxAddbaLastResponseStatus",
                                 (uint64_t)WLAN_STATUS_SUCCESS, 16);
            _parent->setProperty("AirportRTW89RxAddbaSoftwareReorderActive",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89RxAddbaHardwareBACAMActive",
                                 kOSBooleanTrue);
        }
        IOLog("rtw88: RX ADDBA request (tid=%u ssn=%u buf=%u) — accepted, "
              "downlink A-MPDU on\n", tid, ssn, bufsz);
        break;
    }
    case WLAN_ACTION_ADDBA_RESP: {
        /* Response to our TX ADDBA request. */
        if (len < 9) return;
        uint16_t status = (uint16_t)(b[3] | (b[4] << 8));
        uint16_t param  = (uint16_t)(b[5] | (b[6] << 8));
        uint8_t  tid    = (uint8_t)((param >> 2) & 0xf);
        uint16_t bufsz  = (uint16_t)((param >> 6) & 0x3ff);
        if (kEnableAmpdu && status == 0 && tid == _baTid) {
            /* Program the per-TID CMAC aggregation table BEFORE we start
             * tagging frames IEEE80211_TX_CTL_AMPDU.  If the H2C fails, leave
             * aggregation off so TX degrades to stable non-aggregated frames
             * rather than feeding the AMPDU engine against an unconfigured
             * CMAC table (which freezes the TX DMA ring under load). */
            int r = (_sta && _vif)
                    ? rtw88_tx_ampdu_start(_vif, _sta, tid, bufsz) : -1;
            if (r == 0) {
                _txBaActive = true;
                IOLog("rtw88: TX ADDBA accepted (tid=%u agg=%u) — uplink "
                      "A-MPDU on\n", tid, bufsz);
            } else {
                _txBaActive = false;
                IOLog("rtw88: TX ADDBA accepted but CMAC H2C failed (%d) — "
                      "TX stays non-aggregated\n", r);
            }
        } else {
            IOLog("rtw88: TX ADDBA rejected status=%u tid=%u\n", status, tid);
        }
        break;
    }
    case WLAN_ACTION_DELBA: {
        if (len < 6) return;
        uint16_t del_param = (uint16_t)(b[2] | (b[3] << 8));
        uint8_t  tid       = (uint8_t)((del_param >> 12) & 0xf);
        bool     initiator = (del_param & (1u << 11)) != 0;
        /* initiator=0: AP is the recipient of the agreement it is tearing down
         * — our uplink TX BA, so stop aggregating.  initiator=1: AP is the
         * originator — its downlink BA, so drop our RX reorder buffer. */
        if (!initiator && tid == _baTid) {
            _txBaActive = false;
            if (kEnableAmpdu && _sta && _vif)
                rtw88_tx_ampdu_stop(_vif, _sta, tid);   /* clear CMAC agg */
        }
        if (initiator) {
            rxBaTeardown(tid);
            if (kEnableAmpdu && _sta)
                rtw88_rx_ampdu_stop(_sta, tid);         /* clear BA CAM */
        }
        IOLog("rtw88: RX DELBA tid=%u initiator=%d\n", tid, initiator);
        break;
    }
    default:
        break;
    }
}

bool RTW88IEEE80211::txNullFunc(bool powerSave)
{
    if (!_hw || !_hw->ops || !_hw->ops->tx || !_vif || !_sta)
        return false;

    static const uint16_t IEEE80211_STYPE_NULLFUNC = 0x0040;
    struct sk_buff *skb = alloc_skb(24 + 128, GFP_ATOMIC);
    if (!skb) return false;
    skb_reserve(skb, 128);

    struct ieee80211_hdr_3addr *h =
        (struct ieee80211_hdr_3addr *)skb_put(skb, 24);
    uint16_t fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC |
                  IEEE80211_FCTL_TODS;
    if (powerSave)
        fc |= IEEE80211_FCTL_PM;
    h->frame_control = cpu_to_le16(fc);
    h->duration_id   = 0;
    memcpy(h->addr1, _targetBSS.bssid, 6);
    memcpy(h->addr2, _macAddr, 6);
    memcpy(h->addr3, _targetBSS.bssid, 6);
    h->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ & 0xFFF) << 4);

    skb_set_queue_mapping(skb, IEEE80211_AC_BE);
    skb->priority = 0;

    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->band  = (_targetBSS.channel > 14) ? NL80211_BAND_5GHZ
                                            : NL80211_BAND_2GHZ;
    info->flags = IEEE80211_TX_CTL_FIRST_FRAGMENT;
    info->control.vif = _vif;
    info->control.sta = _sta;

    struct ieee80211_tx_control ctrl = { .sta = _sta };
    _hw->ops->tx(_hw, &ctrl, skb);
    return true;
}

/* 0.2.36 valid ADDBA metadata discriminator.
 *
 * Every variant transmits the same valid 33-byte ADDBA Request frame.
 * Only station attachment and injected-rate metadata form a 2x2 matrix:
 *
 * A = VIF-only, native management rate
 * B = associated station, native management rate
 * C = VIF-only, injected rate index 0
 * D = associated station, injected rate index 0
 *
 * All four request explicit TX status and allow normal ACK handling.
 */void RTW88IEEE80211::raAuditU32(unsigned int field, uint32_t value)
{
    static const char *const key[] = {
        "AirportRTW89RAAudit_MacID",
        "AirportRTW89RAAudit_ModeCtrl",
        "AirportRTW89RAAudit_BWCap",
        "AirportRTW89RAAudit_SSNum",
        "AirportRTW89RAAudit_InitRateLV",
        "AirportRTW89RAAudit_UpdAll",
        "AirportRTW89RAAudit_DCMCap",
        "AirportRTW89RAAudit_ERCap",
        "AirportRTW89RAAudit_EnSGI",
        "AirportRTW89RAAudit_LDPCCap",
        "AirportRTW89RAAudit_STBCCap",
        "AirportRTW89RAAudit_GILTF",
        "AirportRTW89RAAudit_UpdBWNSSMask",
        "AirportRTW89RAAudit_UpdMask",
        "AirportRTW89RAAudit_BandNum",
        "AirportRTW89RAAudit_RACsiRateEn",
        "AirportRTW89RAAudit_FixedCsiRateEn",
        "AirportRTW89RAAudit_CrTblSel",
        "AirportRTW89RAAudit_FixGILTFEn",
        "AirportRTW89RAAudit_FixGILTF",
        "AirportRTW89RAAudit_PartialBWER",
        "AirportRTW89RAAudit_CsiMcsSsIdx",
        "AirportRTW89RAAudit_CsiMode",
        "AirportRTW89RAAudit_CsiGILTF",
        "AirportRTW89RAAudit_CsiBW",
        "AirportRTW89RAAudit_IsNoisy",
        "AirportRTW89RAAudit_PSRAEn",
        "AirportRTW89RAAudit_MacIDMSB",
        "AirportRTW89RAAudit_Band",
        "AirportRTW89RAAudit_IsNewDbgReg",
        "AirportRTW89RAAudit_CSI",
        "AirportRTW89RAAudit_RSSI",
        "AirportRTW89RAAudit_H2CLen",
        "AirportRTW89RAAudit_H2CVer",
        "AirportRTW89RAAudit_H2CW0",
        "AirportRTW89RAAudit_H2CW1",
        "AirportRTW89RAAudit_H2CW2",
        "AirportRTW89RAAudit_H2CW3",
        "AirportRTW89RAAudit_H2CW4",
        "AirportRTW89RAAudit_ChipGen",
        "AirportRTW89RAAudit_Valid",
        "AirportRTW89RAAudit_PeerRxNSS",
        "AirportRTW89RAAudit_HalTxNSS"
    };

    if (!_parent || field >= (sizeof(key) / sizeof(key[0])))
        return;

    _parent->setProperty(key[field], (uint64_t)value, 32);
}

void RTW88IEEE80211::raAuditU64(unsigned int field, uint64_t value)
{
    static const char *const key[] = {
        "AirportRTW89RAAudit_RAMask"
    };

    if (!_parent || field >= (sizeof(key) / sizeof(key[0])))
        return;

    _parent->setProperty(key[field], value, 64);
}

extern "C" void rtw89_macos_ra_audit_u32(unsigned int field,
                                           unsigned int value)
{
    RTW88IEEE80211 *self = g_assoc_probe_instance;
    if (!self)
        return;
    self->raAuditU32(field, (uint32_t)value);
}

extern "C" void rtw89_macos_ra_audit_u64(unsigned int field,
                                           unsigned long long value)
{
    RTW88IEEE80211 *self = g_assoc_probe_instance;
    if (!self)
        return;
    self->raAuditU64(field, (uint64_t)value);
}

bool RTW88IEEE80211::assocStageProbe(uint8_t stage)
{
    if (stage < 1 || stage > 4)
        return false;

    const unsigned int v = stage - 1;
    static const char *const submittedKey[] = {
        "AirportRTW89NullAB_A_Submitted", "AirportRTW89NullAB_B_Submitted",
        "AirportRTW89NullAB_C_Submitted", "AirportRTW89NullAB_D_Submitted"};
    static const char *const submitResultKey[] = {
        "AirportRTW89NullAB_A_SubmitResult", "AirportRTW89NullAB_B_SubmitResult",
        "AirportRTW89NullAB_C_SubmitResult", "AirportRTW89NullAB_D_SubmitResult"};
    static const char *const statusSeenKey[] = {
        "AirportRTW89NullAB_A_StatusSeen", "AirportRTW89NullAB_B_StatusSeen",
        "AirportRTW89NullAB_C_StatusSeen", "AirportRTW89NullAB_D_StatusSeen"};
    static const char *const ackedKey[] = {
        "AirportRTW89NullAB_A_Acked", "AirportRTW89NullAB_B_Acked",
        "AirportRTW89NullAB_C_Acked", "AirportRTW89NullAB_D_Acked"};
    static const char *const stageName[] = {
        "RAAUDIT-A-post-STA-UPDATE",
        "RAAUDIT-B-pre-H2C",
        "RAAUDIT-C-pre-H2C-TX",
        "RAAUDIT-D-post-H2C-TX"};

    _nullABSubmitCount[v] = 0;
    _nullABTxStatusCount[v] = 0;
    _nullABTxAckCount[v] = 0;

    if (_parent) {
        _parent->setProperty(submittedKey[v], kOSBooleanFalse);
        _parent->setProperty(submitResultKey[v], kOSBooleanFalse);
        _parent->setProperty(statusSeenKey[v], kOSBooleanFalse);
        _parent->setProperty(ackedKey[v], kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AssocBisectStage",
                             (uint64_t)stage, 8);
        _parent->setProperty("AirportRTW89AssocBisectStageName",
                             stageName[v]);
    }

    bool submitted = txNullDescriptorVariant(stage);
    if (_parent)
        _parent->setProperty(submitResultKey[v],
                             submitted ? kOSBooleanTrue : kOSBooleanFalse);
    if (!submitted)
        return false;

    /* TX completion is delivered by the PCI interrupt/bottom-half path.
     * Wait for that completion before allowing the next association H2C
     * command to execute, removing the timing ambiguity of 0.2.37. */
    volatile uint32_t *statusCount = &_nullABTxStatusCount[v];
    volatile uint32_t *ackCount = &_nullABTxAckCount[v];
    unsigned int waitedMs = 0;

    while (*statusCount == 0 && waitedMs < 250) {
        IOSleep(1);
        waitedMs++;
    }

    const bool statusSeen = *statusCount != 0;
    const bool acked = *ackCount != 0;

    if (_parent) {
        _parent->setProperty("AirportRTW89AssocBisectWaitedMs",
                             (uint64_t)waitedMs, 32);
        _parent->setProperty("AirportRTW89AssocBisectStatusSeen",
                             statusSeen ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AssocBisectAcked",
                             acked ? kOSBooleanTrue : kOSBooleanFalse);
    }

    IOLog("rtw88: 0.2.43 NSS/RA stage %c waited=%u status=%u ack=%u\n",
          (char)('A' + v), waitedMs, statusSeen ? 1U : 0U,
          acked ? 1U : 0U);

    return statusSeen && acked;
}

extern "C" bool rtw89_macos_assoc_stage_probe(unsigned int stage)
{
    RTW88IEEE80211 *self = g_assoc_probe_instance;
    if (!self)
        return false;
    return self->assocStageProbe((uint8_t)stage);
}

bool RTW88IEEE80211::txNullDescriptorVariant(uint8_t variant)
{
    if (!_hw || !_hw->ops || !_hw->ops->tx || !_vif ||
        variant < 1 || variant > 4)
        return false;

    static const char *const submittedKey[] = {
        "AirportRTW89NullAB_A_Submitted", "AirportRTW89NullAB_B_Submitted",
        "AirportRTW89NullAB_C_Submitted", "AirportRTW89NullAB_D_Submitted"};
    static const char *const submitCountKey[] = {
        "AirportRTW89NullAB_A_SubmitCount", "AirportRTW89NullAB_B_SubmitCount",
        "AirportRTW89NullAB_C_SubmitCount", "AirportRTW89NullAB_D_SubmitCount"};
    static const char *const classKey[] = {
        "AirportRTW89FrameClass_A", "AirportRTW89FrameClass_B",
        "AirportRTW89FrameClass_C", "AirportRTW89FrameClass_D"};
    static const char *const className[] = {
        "RAAUDIT-A-post-STA-UPDATE",
        "RAAUDIT-B-pre-H2C",
        "RAAUDIT-C-pre-H2C-TX",
        "RAAUDIT-D-post-H2C-TX"};

    const unsigned int v = variant - 1;
    const uint32_t frameLen = 24 + 9;

    struct sk_buff *skb = alloc_skb(frameLen + 128, GFP_ATOMIC);
    if (!skb)
        return false;

    skb_reserve(skb, 128);

    uint8_t *frame = (uint8_t *)skb_put(skb, frameLen);
    memset(frame, 0, frameLen);

    struct ieee80211_hdr_3addr *h =
        (struct ieee80211_hdr_3addr *)frame;

    h->frame_control =
        cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
    h->duration_id = 0;
    memcpy(h->addr1, _targetBSS.bssid, ETH_ALEN);
    memcpy(h->addr2, _macAddr, ETH_ALEN);
    memcpy(h->addr3, _targetBSS.bssid, ETH_ALEN);
    h->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ & 0xFFF) << 4);

    uint8_t *b = frame + 24;
    b[0] = WLAN_CATEGORY_BACK;
    b[1] = WLAN_ACTION_ADDBA_REQ;
    b[2] = 0x55;

    const uint16_t param =
        (uint16_t)((1u << 1) |
                   (0u << 2) |
                   (64u << 6));

    b[3] = (uint8_t)(param & 0xff);
    b[4] = (uint8_t)(param >> 8);
    b[5] = 0;
    b[6] = 0;

    const uint16_t ssc =
        (uint16_t)((uint16_t)(_dataSeq & 0xFFF) << 4);

    b[7] = (uint8_t)(ssc & 0xff);
    b[8] = (uint8_t)(ssc >> 8);

    skb->pkt_type = (uint8_t)(0xB0 + variant);

    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));

    info->flags = IEEE80211_TX_CTL_FIRST_FRAGMENT |
                  IEEE80211_TX_CTL_REQ_TX_STATUS;
    info->control.vif = _vif;
    info->control.sta = nullptr;

    _nullABSubmitCount[v]++;

    if (_parent) {
        _parent->setProperty(submittedKey[v], kOSBooleanTrue);
        _parent->setProperty(submitCountKey[v],
                             (uint64_t)_nullABSubmitCount[v], 32);
        _parent->setProperty(classKey[v], className[v]);
    }

    struct ieee80211_tx_control ctrl = {
        .sta = nullptr
    };

    _hw->ops->tx(_hw, &ctrl, skb);
    return true;
}

bool RTW88IEEE80211::txProbeRequest()
{
    if (!_hw || !_hw->ops || !_hw->ops->tx)
        return false;

    uint8_t frame[128] = {};
    struct ieee80211_hdr_3addr *hdr =
        (struct ieee80211_hdr_3addr *)frame;
    hdr->frame_control =
        cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ);
    memset(hdr->addr1, 0xff, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memset(hdr->addr3, 0xff, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ & 0xFFF) << 4);

    uint8_t *body = frame + sizeof(*hdr);
    body[0] = WLAN_EID_SSID;
    body[1] = 0;
    body += 2;

    static const uint8_t rates_2g[] = {
        0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
    };
    static const uint8_t rates_5g[] = {
        0x8c, 0x12, 0x98, 0x24, 0x30, 0x48, 0x60, 0x6c
    };
    bool is5g = _hw->conf.chandef.chan &&
                _hw->conf.chandef.chan->band == NL80211_BAND_5GHZ;
    const uint8_t *rates = is5g ? rates_5g : rates_2g;
    uint8_t ratesLen = is5g ? sizeof(rates_5g) : sizeof(rates_2g);

    body[0] = WLAN_EID_SUPP_RATES;
    body[1] = ratesLen;
    memcpy(body + 2, rates, ratesLen);
    body += 2 + ratesLen;

    return txMgmtFrame(frame, (uint32_t)(body - frame));
}

bool RTW88IEEE80211::txDataFrame(mbuf_t m)
{
    if (!_hw || !_hw->ops || !_hw->ops->tx || !_vif || !_sta) {
        mbuf_freem(m);
        return false;
    }

    /* The mbuf is an Ethernet frame: [DA(6)][SA(6)][ethertype(2)][payload].
     * The rtw88 driver's tx op expects an 802.11 frame, so we must
     * encapsulate: 802.11 data header (24) + LLC/SNAP (8) + IP payload.
     * mac80211 normally does this; we are bypassing mac80211's tx path. */
    size_t total = mbuf_pkthdr_len(m);
    if (total < 14 || total > 2048) { mbuf_freem(m); return false; }
    uint32_t paylen = (uint32_t)total - 14;

    uint8_t eh[14];
    if (mbuf_copydata(m, 0, 14, eh) != 0) { mbuf_freem(m); return false; }
    uint16_t ethertype = (uint16_t)((eh[12] << 8) | eh[13]);
    uint16_t classifiedEthertype = 0;
    bool is_dhcp = rtw88_is_dhcp_mbuf(m, &classifiedEthertype);
    bool is_arp = ethertype == 0x0806;
    bool is_eapol = ethertype == ETH_P_PAE;
    if (!is_eapol) {
        _ordinaryTxDataFrameCount++;
#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
        if (_parent) {
            _parent->setProperty("AirportRTW89TxDataFrameCount",
                                 (uint64_t)_ordinaryTxDataFrameCount, 64);
            _parent->setProperty("AirportRTW89TxDataLastEthertype",
                                 (uint64_t)ethertype, 16);
            _parent->setProperty("AirportRTW89TxDataLastARP",
                                 is_arp ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89TxDataLastDHCP",
                                 is_dhcp ? kOSBooleanTrue : kOSBooleanFalse);
        }
#endif
    }
    bool protected_frame = _wpa2 && _ptkConf && !is_eapol;

    /* 0.2.27 diagnostic: serialize EAPOL as legacy/non-QoS DATA while
     * retaining control-port routing to qsel 18 / DMA channel 8.  EAPOL keeps
     * skb priority 0, but the 802.11 frame has no QoS Control field at all.
     * This isolates the QoS DATA subtype/header from the failed 0.2.26 M2. */
    bool qos = !is_eapol && kEnableAmpdu && htAllowed();
    uint8_t tx_tid = is_eapol ? 0 : (uint8_t)(_baTid & IEEE80211_QOS_CTL_TID_MASK);
    uint32_t hlen = qos ? 26 : 24;
    uint32_t framelen = hlen + (protected_frame ? 8 : 0) + 8 + paylen;
    struct sk_buff *skb = alloc_skb(framelen + 128, GFP_ATOMIC);
    if (!skb) { mbuf_freem(m); return false; }
    skb_reserve(skb, 128);  /* TX descriptor headroom */

    /* 802.11 data header (ToDS: station -> AP) */
    struct ieee80211_hdr_3addr *h =
        (struct ieee80211_hdr_3addr *)skb_put(skb, 24);
    uint16_t fc = IEEE80211_FTYPE_DATA | IEEE80211_FCTL_TODS;
    if (qos)
        fc |= IEEE80211_STYPE_QOS_DATA;
    if (protected_frame)
        fc |= IEEE80211_FCTL_PROTECTED;
    h->frame_control = cpu_to_le16(fc);
    h->duration_id   = 0;
    memcpy(h->addr1, _targetBSS.bssid, 6); /* RA = BSSID (the AP)        */
    memcpy(h->addr2, _macAddr, 6);         /* TA = SA  (us)              */
    memcpy(h->addr3, eh, 6);               /* DA = Ethernet destination  */
    /* Each data frame needs a unique sequence number.  QoS data uses a
     * dedicated per-TID space so the BlockAck window stays gap-free; non-QoS
     * shares the mgmt counter (legacy behaviour).  rtw88 uses this header SN
     * for data frames (no hw-assigned SN on the data path). */
    h->seq_ctrl = cpu_to_le16((uint16_t)((qos ? _dataSeq++ : _txSeq++) & 0xFFF) << 4);

    /* QoS Control (2 bytes, LE): TID in bits 0-3, Normal-Ack, no A-MSDU.
     * In 0.2.27, EAPOL is non-QoS and therefore never enters this block. */
    if (qos) {
        uint8_t *qosc = skb_put(skb, 2);
        qosc[0] = tx_tid;
        qosc[1] = 0;
    }

    if (protected_frame) {
        for (int i = 0; i < 6; i++) {
            if (++_ccmpTxPn[i] != 0)
                break;
        }

        uint8_t *ccmp = skb_put(skb, 8);
        ccmp[0] = _ccmpTxPn[0];
        ccmp[1] = _ccmpTxPn[1];
        ccmp[2] = 0x00;
        ccmp[3] = (uint8_t)(0x20 | (((uint8_t)_ptkConf->keyidx & 0x3) << 6));
        ccmp[4] = _ccmpTxPn[2];
        ccmp[5] = _ccmpTxPn[3];
        ccmp[6] = _ccmpTxPn[4];
        ccmp[7] = _ccmpTxPn[5];
    }

    /* RFC 1042 LLC/SNAP header */
    uint8_t *snap = skb_put(skb, 8);
    snap[0] = 0xAA; snap[1] = 0xAA; snap[2] = 0x03;
    snap[3] = 0x00; snap[4] = 0x00; snap[5] = 0x00;
    snap[6] = (uint8_t)(ethertype >> 8);
    snap[7] = (uint8_t)(ethertype & 0xff);

    /* Payload (IP packet) copied straight from the Ethernet mbuf */
    if (paylen) {
        uint8_t *pay = (uint8_t *)skb_put(skb, paylen);
        if (mbuf_copydata(m, 14, paylen, pay) != 0) {
            kfree_skb(skb);
            mbuf_freem(m);
            return false;
        }
    }

    /* 0.2.27 diagnostic: EAPOL uses non-QoS DATA with Best-Effort
     * software priority 0.  The port-control qsel override still routes the
     * DATA descriptor to B0_MGMT/channel 8. */
    if (is_eapol) {
        skb_set_queue_mapping(skb, IEEE80211_AC_BE);
        skb->priority = 0;
    } else {
        skb_set_queue_mapping(skb, IEEE80211_AC_BE);
        skb->priority = 0;
    }
    skb->protocol = cpu_to_be16(ethertype);
    if (ethertype == ETH_P_PAE)
        skb->pkt_type = _pendingEapolTxStep;

    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->band  = (_targetBSS.channel > 14) ? NL80211_BAND_5GHZ
                                            : NL80211_BAND_2GHZ;
    info->flags = IEEE80211_TX_CTL_FIRST_FRAGMENT;
    if (ethertype == ETH_P_PAE) {
        /* Reproduce the mac80211 control-port treatment that this native
         * wrapper bypasses.  Linux marks EAPOL as a port-control protocol and
         * sends it at a minimum/basic rate.  rtw89 consumes the former to set
         * its special-packet TX descriptor bit; the injected-rate path gives
         * us the latter without implementing the whole mac80211 rate-control
         * pipeline.  Rate index 0 maps to CCK 1 Mbps on 2.4 GHz and OFDM
         * 6 Mbps on 5 GHz in rtw89_core_tx_update_injection(). */
        /* 0.2.27 diagnostic: retain port-control routing to
         * QSEL_B0_MGMT (0x12) / DMA channel 8 and keep SEND_AFTER_DTIM off.
         * The only functional delta from 0.2.26 is that EAPOL is serialized
         * as legacy/non-QoS DATA with a 24-byte MAC header. */
        info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS |
                       IEEE80211_TX_CTL_USE_MINRATE |
                       IEEE80211_TX_CTL_INJECTED;
        info->control.flags |= IEEE80211_TX_CTRL_PORT_CTRL_PROTO;
        info->control.rates[0].idx = 0;
        info->control.rates[0].count = 1;
        info->control.rates[0].flags = 0;
        for (int i = 1; i < IEEE80211_TX_MAX_RATES; i++)
            info->control.rates[i].idx = -1;

        if (_parent) {
            _parent->setProperty("AirportRTW89HandshakeEAPOLPortControl",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89HandshakeEAPOLFixedBasicRate",
                                 kOSBooleanTrue);
            _parent->setProperty("AirportRTW89HandshakeEAPOLRateIndex",
                                 (uint64_t)0, 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLRateBand",
                                 (uint64_t)info->band, 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLTxControlFlags",
                                 (uint64_t)info->control.flags, 32);
            _parent->setProperty("AirportRTW89HandshakeEAPOLTxInfoFlags",
                                 (uint64_t)info->flags, 32);
            _parent->setProperty("AirportRTW89HandshakeEAPOLHighQueueDiagnostic",
                                 kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeEAPOLSendAfterDTIM",
                                 kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeEAPOLExpectedQSel",
                                 (uint64_t)0x12, 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLExpectedTxChannel",
                                 (uint64_t)8, 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLQoSData",
                                 qos ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeEAPOLFrameControl",
                                 (uint64_t)fc, 16);
            _parent->setProperty("AirportRTW89HandshakeEAPOLFrameHeaderLength",
                                 (uint64_t)hlen, 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLQoSControlPresent",
                                 qos ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeEAPOLFrameQoSTIDValid",
                                 qos ? kOSBooleanTrue : kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeEAPOLTID",
                                 (uint64_t)tx_tid, 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLTIDIndicate",
                                 kOSBooleanFalse);
            _parent->setProperty("AirportRTW89HandshakeEAPOLQueueMapping",
                                 (uint64_t)skb_get_queue_mapping(skb), 8);
            _parent->setProperty("AirportRTW89HandshakeEAPOLPriority",
                                 (uint64_t)skb->priority, 8);
        }
    }
    /* Once the uplink BlockAck agreement is up, mark BE-TID frames for
     * aggregation: rtw88 then sets the descriptor's AGG_EN bit and the hardware
     * builds A-MPDUs. (rtw_tx reads this flag directly; the txq/RTW_TXQ_AMPDU
     * path is unused by this port.) */
    if (qos && _txBaActive)
        info->flags |= IEEE80211_TX_CTL_AMPDU;
    if (!is_eapol && (is_arp || is_dhcp)) {
        info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
        skb->pkt_type = is_dhcp ? 0xD0 : 0xA0;
    }
    info->control.vif = _vif;
    info->control.sta = _sta;
    if (protected_frame)
        info->control.hw_key = _ptkConf;

    if (!is_eapol) {
        _ordinaryHwSubmitCount++;
        if (is_arp) _ordinaryARPSubmitCount++;
        if (is_dhcp) _ordinaryDHCPSubmitCount++;
#if RTW89_PER_PACKET_IOREG_DIAGNOSTICS
        if (_parent) {
            _parent->setProperty("AirportRTW89OrdinaryHWSubmitCount",
                                 (uint64_t)_ordinaryHwSubmitCount, 64);
            _parent->setProperty("AirportRTW89OrdinaryARPSubmitCount",
                                 (uint64_t)_ordinaryARPSubmitCount, 32);
            _parent->setProperty("AirportRTW89OrdinaryDHCPSubmitCount",
                                 (uint64_t)_ordinaryDHCPSubmitCount, 32);
            _parent->setProperty("AirportRTW89OrdinaryLastTxInfoFlags",
                                 (uint64_t)info->flags, 32);
            _parent->setProperty("AirportRTW89OrdinaryLastQueueMapping",
                                 (uint64_t)skb_get_queue_mapping(skb), 8);
            _parent->setProperty("AirportRTW89OrdinaryLastPriority",
                                 (uint64_t)skb->priority, 8);
        }
#endif
    }
    struct ieee80211_tx_control ctrl = { .sta = _sta };
    _hw->ops->tx(_hw, &ctrl, skb);
    mbuf_freem(m);
    return true;
}

/* ------------------------------------------------------------------ */
/*  mbuf ↔ sk_buff conversion                                           */
/* ------------------------------------------------------------------ */

/*
 * Allocate a packet-header mbuf and copy `len` bytes from `src` into it.
 *
 * IMPORTANT: mbuf_allocpacket() may return a *chain* of mbufs (multiple
 * ~2 KB clusters) for packets larger than one cluster — e.g. A-MSDU
 * aggregated 802.11 data frames, which can be several KB.  In that case
 * mbuf_data(m) points only at the FIRST segment, and writing the whole
 * packet there overflows into adjacent kernel/mbuf-zone memory, corrupting
 * the heap (later manifesting as a GP fault in an unrelated mbuf walk such
 * as sbconcat_mbufs).
 *
 * mbuf_copyback() correctly distributes the data across every segment of
 * the chain and never overflows, so we use it instead of a raw memcpy.
 * mbuf_allocpacket() already sets each segment's length and pkthdr.len, so
 * we must NOT call mbuf_setlen() (which would wrongly set the first
 * segment's length to the whole-packet length).
 */
static mbuf_t rtw88_make_packet_mbuf(const void *src, uint32_t len)
{
    mbuf_t m = nullptr;
    if (mbuf_allocpacket(MBUF_WAITOK, len, nullptr, &m) != 0)
        return nullptr;
    if (mbuf_copyback(m, 0, len, src, MBUF_WAITOK) != 0) {
        mbuf_freem(m);
        return nullptr;
    }
    /* mbuf_allocpacket does not reliably set pkthdr.len, and depending on the
     * kernel, mbuf_copyback may not either.  Set it explicitly — otherwise
     * ether_input() strips the 14-byte header from a pkthdr.len of 0 and
     * panics with "Failed mbuf validity check: len -14". */
    mbuf_pkthdr_setlen(m, len);
    return m;
}

struct sk_buff *RTW88IEEE80211::mbufToSkb(mbuf_t m)
{
    size_t total = mbuf_pkthdr_len(m);
    struct sk_buff *skb = alloc_skb((uint32_t)(total + 64), GFP_ATOMIC);
    if (!skb) return nullptr;
    skb_reserve(skb, 128); /* headroom for TX descriptor (48 B) + pkt_offset padding */

    /* Copy contiguous mbuf chain data */
    mbuf_t cur = m;
    while (cur) {
        size_t chunk = mbuf_len(cur);
        if (chunk > 0) {
            memcpy(skb_put(skb, (uint32_t)chunk), mbuf_data(cur), chunk);
        }
        cur = mbuf_next(cur);
    }
    return skb;
}

mbuf_t RTW88IEEE80211::skbToMbuf(struct sk_buff *skb)
{
    return rtw88_make_packet_mbuf(skb->data, skb->len);
}

/* ------------------------------------------------------------------ */
/*  Timer (state machine timeout)                                       */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::timerFired(OSObject *owner, IOTimerEventSource *timer)
{
    RTW88IEEE80211 *self = OSDynamicCast(RTW88IEEE80211, owner);
    if (self) self->onTimer();
}

void RTW88IEEE80211::onTimer()
{
    switch (_state) {
    case RTW88_STATE_SCANNING:
        IOLog("rtw88: scan timeout\n");
        if (_manualScanChannelCount) {
            _manualScanAbort = true;
            break;
        } else if (_hw && _hw->ops && _hw->ops->cancel_hw_scan) {
            RTW89CompatWiphyGuard cfgGuard(_hw);
            _hw->ops->cancel_hw_scan(_hw, _vif);
        }
        {
            RTW88State returnState = _scanReturnState;
            if (returnState == RTW88_STATE_CONNECTED)
                restoreConnectedChannel();
            _state = (returnState == RTW88_STATE_IDLE) ?
                RTW88_STATE_IDLE : returnState;
            _scanReturnState = RTW88_STATE_IDLE;
        }
        break;

    case RTW88_STATE_AUTHENTICATING:
        if (_parent)
            _parent->setProperty("AirportRTW89AuthTimeoutObserved",
                                 kOSBooleanTrue);
        if (++_authRetries >= kMaxAuthRetries) {
            IOLog("rtw88: auth failed after %u attempts — giving up\n",
                  _authRetries);
            _authRetries = 0;
            _state = RTW88_STATE_IDLE;
            break;
        }
        IOLog("rtw88: auth timeout, retrying (%u/%u)\n",
              _authRetries, kMaxAuthRetries);
        doAuthenticate();
        break;

    case RTW88_STATE_ASSOCIATING:
        if (_parent)
            _parent->setProperty("AirportRTW89AssocTimeoutObserved",
                                 kOSBooleanTrue);
        IOLog("rtw88: assoc timeout\n");
        _state = RTW88_STATE_IDLE;
        break;

    case RTW88_STATE_HANDSHAKING:
        IOLog("rtw88: 4-way handshake timeout\n");
        if (_parent)
            _parent->setProperty("AirportRTW89HandshakeTimedOut",
                                 kOSBooleanTrue);
        captureHandshakeTxSnapshot(true);
        setHandshakeRxFilter(false);
        doDisconnect();
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Status queries                                                       */
/* ------------------------------------------------------------------ */

bool RTW88IEEE80211::hasActiveAssociation() const
{
    if (!_powered || !_vif || !_sta || !_vif->cfg.assoc)
        return false;

    return _state == RTW88_STATE_CONNECTED ||
           (_state == RTW88_STATE_SCANNING &&
            _scanReturnState == RTW88_STATE_CONNECTED);
}

bool RTW88IEEE80211::isConnectedScanInProgress() const
{
    return _state == RTW88_STATE_SCANNING &&
           _scanReturnState == RTW88_STATE_CONNECTED &&
           hasActiveAssociation();
}

void RTW88IEEE80211::publishRxSanityTelemetry()
{
    if (!_parent)
        return;

    _parent->setProperty("AirportRTW89RxMac80211SanityEnabled", kOSBooleanTrue);
    _parent->setProperty("AirportRTW89RxDataFrameCount",
                         (uint64_t)_rxDataFrameCount, 64);
    _parent->setProperty("AirportRTW89RxDataByteCount",
                         (uint64_t)_rxDataByteCount, 64);
    _parent->setProperty("AirportRTW89RxFailedFCSDropCount",
                         (uint64_t)_rxFailedFcsDropCount, 64);
    _parent->setProperty("AirportRTW89RxFailedPLCPDropCount",
                         (uint64_t)_rxFailedPlcpDropCount, 64);
    _parent->setProperty("AirportRTW89RxRetryFrameCount",
                         (uint64_t)_rxRetryFrameCount, 64);
    _parent->setProperty("AirportRTW89RxRetryDuplicateDropCount",
                         (uint64_t)_rxRetryDuplicateDropCount, 64);
    _parent->setProperty("AirportRTW89RxAMSDUFrameCount",
                         (uint64_t)_rxAmsduFrameCount, 64);
    _parent->setProperty("AirportRTW89RxAMSDUSubframeCount",
                         (uint64_t)_rxAmsduSubframeCount, 64);
    _parent->setProperty("AirportRTW89RxAMSDUMalformedCount",
                         (uint64_t)_rxAmsduMalformedCount, 64);
    _parent->setProperty("AirportRTW89RxEncodingLegacyCount",
                         (uint64_t)_rxEncodingCount[RX_ENC_LEGACY], 64);
    _parent->setProperty("AirportRTW89RxEncodingHTCount",
                         (uint64_t)_rxEncodingCount[RX_ENC_HT], 64);
    _parent->setProperty("AirportRTW89RxEncodingVHTCount",
                         (uint64_t)_rxEncodingCount[RX_ENC_VHT], 64);
    _parent->setProperty("AirportRTW89RxEncodingHECount",
                         (uint64_t)_rxEncodingCount[RX_ENC_HE], 64);
    _parent->setProperty("AirportRTW89RxEncodingEHTCount",
                         (uint64_t)_rxEncodingCount[RX_ENC_EHT], 64);
    _parent->setProperty("AirportRTW89RxLastStatusFlags",
                         (uint64_t)_rxLastStatusFlags, 32);
    _parent->setProperty("AirportRTW89RxLastEncFlags",
                         (uint64_t)_rxLastEncFlags, 16);
    _parent->setProperty("AirportRTW89RxLastFrameLength",
                         (uint64_t)_rxLastFrameLength, 16);
    _parent->setProperty("AirportRTW89RxLastEncoding",
                         (uint64_t)_rxLastEncoding, 8);
    _parent->setProperty("AirportRTW89RxLastRateIndex",
                         (uint64_t)_rxLastRateIndex, 8);
    _parent->setProperty("AirportRTW89RxLastNSS",
                         (uint64_t)_rxLastNSS, 8);
    _parent->setProperty("AirportRTW89RxLastBandwidth",
                         (uint64_t)_rxLastBandwidth, 8);
    _parent->setProperty("AirportRTW89RxLastSignal",
                         (uint64_t)(int64_t)_rxLastSignal, 64);
    _parent->setProperty("AirportRTW89RxLastSignalDBMNegated",
                         (uint64_t)(_rxLastSignal < 0 ? -_rxLastSignal
                                                     : _rxLastSignal), 16);
}

IOReturn RTW88IEEE80211::cmdGetState(struct RTW88StateResult *result)
{
    if (!result) return kIOReturnBadArgument;

    result->state = _state;
    result->rssi = _rssi;
    memcpy(result->ssid, _targetBSS.ssid, sizeof(result->ssid));
    memcpy(result->bssid, _targetBSS.bssid, sizeof(result->bssid));
    result->channel = _targetBSS.channel;
    
    memcpy(result->mac_addr, _macAddr, 6);

    rtw88_get_fw_version(_rtwdev, &result->fw_version, &result->fw_sub_version);
    rtw88_get_chip_name(_rtwdev, result->chip_name, sizeof(result->chip_name));
    rtw88_get_stats(_rtwdev, &result->tx_byte_count, &result->rx_byte_count);
    result->scan_offload_supported =
        (_hw && _hw->ops && _hw->ops->hw_scan &&
         rtw88_hw_scan_supported(_hw)) ? 1 : 0;
    result->powered = _powered ? 1 : 0;

    return kIOReturnSuccess;
}

bool RTW88IEEE80211::getRegulatoryCountry(char outAlpha2[3]) const
{
    return rtw88_get_country_code(_rtwdev, outAlpha2);
}

bool RTW88IEEE80211::setRegulatoryCountry(const char alpha2[2])
{
    return rtw88_set_country_code(_rtwdev, alpha2);
}

IOReturn RTW88IEEE80211::cmdGetRSSI(int *rssi)
{
    *rssi = _rssi;
    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::copyBSSSnapshot(RTW88BSS *out,
                                                   uint32_t capacity,
                                                   uint32_t *count)
{
    if (!out || !count || capacity == 0)
        return kIOReturnBadArgument;

    uint32_t copied = 0;
    uint32_t staleSkipped = 0;
    uint32_t currentGenerationCount = 0;
    uint32_t recentCarryCount = 0;
    uint64_t oldestRecentCarryAgeNs = 0;
    uint32_t ageLE10sCount = 0;
    uint32_t age10To30sCount = 0;
    uint32_t age30To60sCount = 0;
    uint32_t age60To300sCount = 0;
    uint32_t ageGT300sCount = 0;
    uint32_t generation = 0;
    bool connectedRecentWindow = false;
    bool disconnectedRecentWindow = false;
    const uint64_t nowNs = rtw88_now_ns();
    IOLockLock(_bssLock);
    generation = _scanGeneration;
    connectedRecentWindow = _scanSnapshotUsesRecentWindow;
    bool currentGenerationAnchorPresent = generation == 0;
    if (generation != 0) {
        for (RTW88BSS *b = _bssList; b; b = b->next) {
            if (b->last_seen_scan == generation) {
                currentGenerationAnchorPresent = true;
                break;
            }
        }
    }
    /* 0.2.209: a completed disconnected scan always gets the bounded recent
     * window.  During the historical 100 ms early SCAN_DONE interval, allow
     * that same window only after at least one BSS from THIS generation has
     * actually arrived.  Thus an all-old cache can never satisfy an empty RF
     * scan, while a partial first-channel sweep no longer collapses the menu
     * from five recent APs to whichever single AP answered first. */
    disconnectedRecentWindow =
        !connectedRecentWindow &&
        (_state == RTW88_STATE_IDLE ||
         (_state == RTW88_STATE_SCANNING && currentGenerationAnchorPresent));
    const bool useRecentWindow =
        connectedRecentWindow || disconnectedRecentWindow;
    const uint64_t visibleWindowNs = connectedRecentWindow ?
        kRTW88ConnectedScanVisibleNs :
        (disconnectedRecentWindow ? kRTW88DisconnectedScanVisibleNs : 0);

    for (RTW88BSS *b = _bssList; b && copied < capacity; b = b->next) {
        const bool currentGeneration =
            generation == 0 || b->last_seen_scan == generation;
        const uint64_t ageNs =
            (b->last_seen_ns != 0 && nowNs >= b->last_seen_ns) ?
                (nowNs - b->last_seen_ns) : UINT64_MAX;

        if (ageNs == UINT64_MAX || ageNs > 300000000000ULL)
            ++ageGT300sCount;
        else if (ageNs > 60000000000ULL)
            ++age60To300sCount;
        else if (ageNs <= 10000000000ULL)
            ++ageLE10sCount;
        else if (ageNs <= 30000000000ULL)
            ++age10To30sCount;
        else
            ++age30To60sCount;

        bool eligible = true;
        if (generation != 0) {
            if (useRecentWindow)
                eligible = ageNs <= visibleWindowNs;
            else
                eligible = currentGeneration;
        }
        if (!eligible) {
            staleSkipped++;
            continue;
        }

        if (currentGeneration) {
            currentGenerationCount++;
        } else {
            recentCarryCount++;
            if (ageNs != UINT64_MAX && ageNs > oldestRecentCarryAgeNs)
                oldestRecentCarryAgeNs = ageNs;
        }

        memcpy(&out[copied], b, sizeof(RTW88BSS));
        out[copied].next = nullptr;
        copied++;
    }
    IOLockUnlock(_bssLock);

    if (_parent) {
        _parent->setProperty("AirportRTW89AppleScanSnapshotGeneration",
                             (uint64_t)generation, 32);
        /* Preserve the historical property as Apple-visible count for script
         * compatibility; 0.2.209 publishes true current/carry counts below. */
        _parent->setProperty("AirportRTW89AppleScanSnapshotFreshCount",
                             (uint64_t)copied, 32);
        _parent->setProperty("AirportRTW89AppleScanSnapshotVisibleCount",
                             (uint64_t)copied, 32);
        _parent->setProperty("AirportRTW89AppleScanSnapshotCurrentGenerationCount",
                             (uint64_t)currentGenerationCount, 32);
        _parent->setProperty("AirportRTW89AppleScanSnapshotRecentCarryCount",
                             (uint64_t)recentCarryCount, 32);
        _parent->setProperty("AirportRTW89AppleScanSnapshotRecentCarryOldestAgeMS",
                             oldestRecentCarryAgeNs / 1000000ULL, 64);
        _parent->setProperty("AirportRTW89AppleScanSnapshotStaleSkipped",
                             (uint64_t)staleSkipped, 32);
        _parent->setProperty("AirportRTW89AppleScanSnapshotCurrentGenerationOnly",
                             (generation != 0 && !useRecentWindow) ?
                                 kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleScanSnapshotRecentWindow",
                             useRecentWindow ? kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleScanSnapshotConnectedRecentWindow",
                             connectedRecentWindow ?
                                 kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleScanSnapshotDisconnectedRecentWindow",
                             disconnectedRecentWindow ?
                                 kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleScanSnapshotCurrentGenerationAnchorPresent",
                             currentGenerationAnchorPresent ?
                                 kOSBooleanTrue : kOSBooleanFalse);
        _parent->setProperty("AirportRTW89AppleScanSnapshotVisibleWindowMS",
                             visibleWindowNs / 1000000ULL, 32);
        _parent->setProperty("AirportRTW89AppleScanSnapshotRetentionIsTimeBounded",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89BSSCachePolicyPersistentByBSSID",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89BSSCachePolicyRefreshOnObservationOnly",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89BSSCachePolicyPreserveSecurity",
                             kOSBooleanTrue);
        _parent->setProperty("AirportRTW89BSSCachePersistentExpireMS",
                             kRTW88PersistentBSSExpireNs / 1000000ULL, 64);
        _parent->setProperty("AirportRTW89BSSCacheAgeLE10sCount",
                             (uint64_t)ageLE10sCount, 32);
        _parent->setProperty("AirportRTW89BSSCacheAge10To30sCount",
                             (uint64_t)age10To30sCount, 32);
        _parent->setProperty("AirportRTW89BSSCacheAge30To60sCount",
                             (uint64_t)age30To60sCount, 32);
        _parent->setProperty("AirportRTW89BSSCacheAge60To300sCount",
                             (uint64_t)age60To300sCount, 32);
        _parent->setProperty("AirportRTW89BSSCacheAgeGT300sCount",
                             (uint64_t)ageGT300sCount, 32);
    }

    *count = copied;
    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::cmdGetBSSList(uint8_t *buf, uint32_t *len)
{
    if (!buf || !len) return kIOReturnBadArgument;

    uint32_t max     = *len;
    if (max > 4095) max = 4095;

    if (max < 4) {
        *len = 0;
        return kIOReturnSuccess;
    }
    
    uint32_t written = 4; // reserve first 4 bytes for total length

    IOLockLock(_bssLock);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        /* Each entry: ssid_len(1), ssid(ssid_len), bssid(6), rssi(2),
         *             channel(1), cipher(4) */
        uint32_t entry_sz = 1 + b->ssid_len + 6 + 2 + 1 + 4;
        if (written + entry_sz > max) {
            IOLog("rtw88: BSS entry skipped (buffer full: written=%u max=%u)\n", written, max);
            break;
        }

        buf[written++] = b->ssid_len;
        memcpy(buf + written, b->ssid, b->ssid_len); written += b->ssid_len;
        memcpy(buf + written, b->bssid, 6);           written += 6;
        buf[written++] = (uint8_t)((b->rssi >> 8) & 0xff);
        buf[written++] = (uint8_t)(b->rssi & 0xff);
        buf[written++] = b->channel;
        memcpy(buf + written, &b->cipher, 4);          written += 4;
    }
    IOLockUnlock(_bssLock);

    /* Write total written bytes into the first 4 bytes */
    uint32_t total = written;
    memcpy(buf, &total, sizeof(total));

    *len = written;
    return kIOReturnSuccess;
}

void RTW88IEEE80211::getMACAddress(uint8_t *mac)
{
    memcpy(mac, _macAddr, 6);
}
