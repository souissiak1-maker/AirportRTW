#include "../rtw80211/sae/rtw_sae.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static void exchange(int h2e, int wrong, int challenged)
{
    fprintf(stderr,"SAE exchange h2e=%d wrong=%d challenged=%d\n",h2e,wrong,challenged);
    const uint8_t sta[6]={2,0,0,0,0,1}, ap[6]={2,0,0,0,0,2};
    const uint8_t password[]="Test SAE password", bad[]="different password";
    const uint8_t ssid[]="SAE test";
    struct rtw_sae *a=rtw_sae_begin(sta,ap,password,sizeof(password)-1,ssid,sizeof(ssid)-1,h2e);
    struct rtw_sae *b=rtw_sae_begin(ap,sta,wrong?bad:password,wrong?sizeof(bad)-1:sizeof(password)-1,ssid,sizeof(ssid)-1,h2e);
    assert(a && b);
    uint8_t ac[512],bc[512],af[128],bf[128];
    const uint8_t token[32]={1,2,3,4,5,6,7,8};
    assert(rtw_sae_write_commit(a,NULL,1,ac,sizeof(ac))<0);
    assert(rtw_sae_write_commit(a,NULL,0,ac,1)<0);
    int an=rtw_sae_write_commit(a,challenged?token:NULL,challenged?sizeof(token):0,ac,sizeof(ac));
    int bn=rtw_sae_write_commit(b,0,0,bc,sizeof(bc));
    assert(an>0 && bn>0);
    // Truncated, reflected, and unsupported-group commits must not authenticate.
    assert(rtw_sae_rx_commit(a,bc,1)!=0);
    assert(rtw_sae_rx_commit(a,ac,an)!=0);
    uint8_t invalid[512]; memcpy(invalid,bc,bn); invalid[0]=20;
    assert(rtw_sae_rx_commit(a,invalid,bn)!=0);
    assert(rtw_sae_rx_commit(a,bc,bn)==0 && rtw_sae_rx_commit(b,ac,an)==0);
    int al=rtw_sae_write_confirm(a,af,sizeof(af)), bl=rtw_sae_write_confirm(b,bf,sizeof(bf));
    assert(al==34 && bl==34);
    assert(rtw_sae_rx_confirm(a,bf,bl-1)!=0);
    bf[2]^=1; assert(rtw_sae_rx_confirm(a,bf,bl)!=0); bf[2]^=1;
    assert((rtw_sae_rx_confirm(a,bf,bl)==0)==!wrong);
    assert((rtw_sae_rx_confirm(b,af,al)==0)==!wrong);
    if(!wrong) {
        uint8_t ak[32],bk[32],ai[16],bi[16];
        rtw_sae_keys(a,ak,ai);rtw_sae_keys(b,bk,bi);
        assert(!memcmp(ak,bk,32) && !memcmp(ai,bi,16));
    }
    rtw_sae_end(a);rtw_sae_end(b);
}
int main(void)
{
    const uint8_t mac[6]={2,0,0,0,0,1}, peer[6]={2,0,0,0,0,2}, text[]="test";
    assert(!rtw_sae_begin(mac,mac,text,4,text,4,0));
    assert(!rtw_sae_begin(mac,peer,text,64,text,4,1));
    assert(!rtw_sae_begin(mac,peer,text,4,text,33,1));
    assert(!rtw_sae_begin(mac,peer,NULL,4,text,4,0));
    assert(rtw_sae_rx_commit(NULL,text,4)!=0);
    assert(rtw_sae_rx_confirm(NULL,text,4)!=0);
    for(int h2e=0;h2e<2;++h2e)
        for(int wrong=0;wrong<2;++wrong)
            for(int challenged=0;challenged<2;++challenged) exchange(h2e,wrong,challenged);
    return 0;
}
