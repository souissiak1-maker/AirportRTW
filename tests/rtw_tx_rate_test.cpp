#include "../include/HAL/RTWTxRate.h"
#include <cassert>
int main()
{
    RTWTxRate r{};
    assert(rtw_tx_rate_calculate(nullptr)==0);
    r.mode=RTW_RATE_HT;r.widthMHz=20;r.mcs=7;r.nss=1;
    assert(rtw_tx_rate_calculate(&r)==650);
    r.shortGI=true;assert(rtw_tx_rate_calculate(&r)==722);
    r.widthMHz=40;r.mcs=15;r.nss=2;
    assert(rtw_tx_rate_calculate(&r)==3000);
    r.mcs=31;r.nss=4;assert(rtw_tx_rate_calculate(&r)==6000);
    r.mcs=32;assert(rtw_tx_rate_calculate(&r)==0);
    r.mcs=7;r.widthMHz=80;assert(rtw_tx_rate_calculate(&r)==0);
    r.mode=RTW_RATE_VHT;r.mcs=9;r.nss=1;r.widthMHz=80;
    assert(rtw_tx_rate_calculate(&r)==4333);
    r.nss=2;assert(rtw_tx_rate_calculate(&r)==8667);
    r.widthMHz=40;r.nss=1;assert(rtw_tx_rate_calculate(&r)==2000);
    r.shortGI=false;assert(rtw_tx_rate_calculate(&r)==1800);
    r.mcs=7;assert(rtw_tx_rate_calculate(&r)==1350);
    r.nss=0;assert(rtw_tx_rate_calculate(&r)==0);
    r.nss=5;assert(rtw_tx_rate_calculate(&r)==0);
    r.nss=1;r.mcs=10;assert(rtw_tx_rate_calculate(&r)==0);
    r.mcs=0;r.widthMHz=10;assert(rtw_tx_rate_calculate(&r)==0);
    r.mode=RTW_RATE_HE;r.widthMHz=80;r.mcs=11;r.nss=2;r.guardIntervalNs=800;
    r.shortGI=false;r.dcm=false;
    assert(rtw_tx_rate_calculate(&r)==12010);
    r.nss=1;assert(rtw_tx_rate_calculate(&r)==6005);
    r.widthMHz=20;assert(rtw_tx_rate_calculate(&r)==1434);
    r.mcs=0;assert(rtw_tx_rate_calculate(&r)==86);
    r.dcm=true;assert(rtw_tx_rate_calculate(&r)==43);
    r.mcs=11;assert(rtw_tx_rate_calculate(&r)==0); // DCM is not valid at MCS11.
    r.dcm=false;r.widthMHz=80;r.nss=2;r.guardIntervalNs=1600;
    assert(rtw_tx_rate_calculate(&r)==11343);
    r.guardIntervalNs=3200;assert(rtw_tx_rate_calculate(&r)==10208);
    r.guardIntervalNs=400;assert(rtw_tx_rate_calculate(&r)==0);
    r.guardIntervalNs=800;r.mcs=12;assert(rtw_tx_rate_calculate(&r)==0);
    r.mcs=11;r.nss=0;assert(rtw_tx_rate_calculate(&r)==0);
    r.nss=9;assert(rtw_tx_rate_calculate(&r)==0);
    r.nss=1;r.widthMHz=320;assert(rtw_tx_rate_calculate(&r)==0);
    r.mode=RTW_RATE_LEGACY;r.bitrate100Kbps=540;
    assert(rtw_tx_rate_calculate(&r)==540);
    r.bitrate100Kbps=55;assert(rtw_tx_rate_calculate(&r)==55);
}
