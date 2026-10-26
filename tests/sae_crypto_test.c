/* Known-answer tests for the SAE adapter's crypto, independent of peer exchanges. */
#include "../rtw80211/sae/rtw_sae_crypto.h"
#include <assert.h>
#include <string.h>

struct crypto_bignum;
struct crypto_bignum *airport_sae_crypto_bignum_init_set(const uint8_t *, size_t);
int airport_sae_crypto_bignum_exptmod(const struct crypto_bignum *, const struct crypto_bignum *, const struct crypto_bignum *, struct crypto_bignum *);
int airport_sae_crypto_bignum_to_bin(const struct crypto_bignum *, uint8_t *, size_t, size_t);
void airport_sae_crypto_bignum_deinit(struct crypto_bignum *, int);

int main(void)
{
    uint8_t out[32];
    const uint8_t sha256[] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    rtw_sae_sha256((const uint8_t *)"abc",3,out);
    assert(!memcmp(out,sha256,32));
    /* RFC 4493 example 1: empty-message AES-CMAC. */
    const uint8_t key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    const uint8_t cmac[]={0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
    rtw_sae_aes_cmac(key,(const uint8_t *)"",0,out);
    assert(!memcmp(out,cmac,16));
    /* RFC 3394 section 4.1: wrap and integrity-checked unwrap. */
    const uint8_t kek[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint8_t plain[]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t wrapped[]={0x1f,0xa6,0x8b,0x0a,0x81,0x12,0xb4,0x47,0xae,0xf3,0x4b,0xd8,0xfb,0x5a,0x7b,0x82,0x9d,0x3e,0x86,0x23,0x71,0xd2,0xcf,0xe5};
    uint8_t decoded[16];
    rtw_sae_aes_wrap(kek,plain,16,out);
    assert(!memcmp(out,wrapped,24));
    assert(rtw_sae_aes_unwrap(kek,out,24,decoded) && !memcmp(decoded,plain,16));
    out[0]^=1;
    assert(!rtw_sae_aes_unwrap(kek,out,24,decoded));
    /* H2E requires modular exponentiation with output aliasing its exponent. */
    const uint8_t av=5, ev=3, mv=13;
    struct crypto_bignum *a=airport_sae_crypto_bignum_init_set(&av,1);
    struct crypto_bignum *e=airport_sae_crypto_bignum_init_set(&ev,1);
    struct crypto_bignum *m=airport_sae_crypto_bignum_init_set(&mv,1);
    assert(a && e && m);
    assert(!airport_sae_crypto_bignum_exptmod(a,e,m,e));
    assert(airport_sae_crypto_bignum_to_bin(e,out,sizeof(out),1)==1 && out[0]==8);
    airport_sae_crypto_bignum_deinit(a,1);
    airport_sae_crypto_bignum_deinit(e,1);
    airport_sae_crypto_bignum_deinit(m,1);
    return 0;
}
