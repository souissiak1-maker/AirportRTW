#!/usr/bin/env python3
"""Exercise actual RTW89 bridge reservation/gate code with driver fault injection."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
s=(ROOT/'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text()
code=s[s.index('static struct ieee80211_channel *awdlFrequencyChannel('):s.index('uint32_t rtw89LinuxAwdlPeerCapacity(')]
start=s.index('unsigned int rtw89LinuxTxAvailableSlots(')
code+=s[start:s.index('bool rtw89LinuxAmpduStart(',start)]
shim=r'''
#include <AWDL/RTWAwdlTxGate.hpp>
#include <HAL/RTWAwdlRadio.hpp>
#include <cassert>
#include <cstdint>
#include <cerrno>
#include <cstdio>
#define NL80211_BAND_2GHZ 0
#define NL80211_BAND_5GHZ 1
#define NL80211_CHAN_WIDTH_20 20
#define IEEE80211_STA_AUTHORIZED 4
#define IEEE80211_CHAN_DISABLED 1
#define IEEE80211_CHAN_NO_IR 2
#define IEEE80211_CHAN_RADAR 4
#define IEEE80211_CHAN_NO_OFDM 8
struct ieee80211_channel { unsigned band,flags;uint16_t center_freq; };
struct Band { ieee80211_channel *channels;int n_channels; };
struct Wiphy { Band *bands[2]; };
struct ieee80211_hw { Wiphy *wiphy;struct{struct{ieee80211_channel*chan;int width;}chandef;}conf; };
struct ieee80211_vif { struct{ieee80211_channel*chandef_chan;int chandef_width;}bss_conf; };
struct Rtw89LinuxContext {
    void *hardware;bool started,interfaceAdded,scanning;void *station;unsigned stationState;
    struct{bool hardwareAdded,registered;void *vif;}awdlInterface;
    RTWAwdl::TxGate awdlTxGate;void *nativeOwner;void(*txResume)(void*);bool awdlRecovery=false;
};
static unsigned depth,sleeps,reserves,restores,wakes;
static bool recovering,driverLive;
static int reserveError,restoreError;
static ieee80211_channel *liveChannel;
static RTWAwdl::TxGate *drainAfterSleep;
struct WiphyGuard {
    explicit WiphyGuard(ieee80211_hw*){assert(!depth++);}
    ~WiphyGuard(){assert(depth--==1);}
};
static void IOSleep(unsigned n){assert(n==1&&!depth);++sleeps;if(drainAfterSleep){drainAfterSleep->leave();drainAfterSleep=nullptr;}}
static int rtw89_macos_awdl_reserve(ieee80211_hw*,ieee80211_vif*,ieee80211_channel*c,unsigned ms){
    assert(depth && ms);++reserves;if(!reserveError){driverLive=true;recovering=true;liveChannel=c;}return reserveError;
}
static bool rtw89_macos_awdl_needs_restore(ieee80211_hw*,ieee80211_vif*){assert(depth);return recovering;}
static ieee80211_channel *rtw89_macos_awdl_current_channel(ieee80211_hw*hw,ieee80211_vif*){assert(depth);return driverLive?liveChannel:(recovering?nullptr:hw->conf.chandef.chan);}
static int rtw89_macos_awdl_restore(ieee80211_hw*,ieee80211_vif*){
    assert(depth);++restores;if(!restoreError){driverLive=recovering=false;}return restoreError;
}
static unsigned rtw88_be_tx_avail(){return 255;}
static void wake(void*){assert(!depth);++wakes;}
struct Fixture {
    ieee80211_channel channels[2]={{0,0,2437},{1,0,5180}};
    Band low{channels,1},high{channels+1,1};Wiphy wiphy{{&low,&high}};
    ieee80211_hw hw{&wiphy,{{channels,80}}};ieee80211_vif vif{{channels,80}};
    Rtw89LinuxContext c{&hw,true,true,false,nullptr,0,{true,true,&vif},{},nullptr,wake};
    Fixture(){assert(!depth);sleeps=reserves=restores=wakes=0;reserveError=restoreError=0;driverLive=recovering=false;drainAfterSleep=nullptr;}
};
'''
cases=r'''
int main(){
    {RTWAwdl::Radio unsupported;
     assert(!unsupported.awdlRadioState().ready&&!unsupported.awdlChannelAllowed(2437));
     assert(unsupported.reserveAwdlRadio(2437,50)==RTWAwdl::RadioReservation::Rejected);
     assert(!unsupported.restoreAwdlRadio());}
    {Fixture f;
     auto state=rtw89LinuxAwdlRadioState(&f.c);
     assert(state.ready&&state.frequency==2437&&!state.recoveryRequired);
     assert(rtw89LinuxAwdlChannelAllowed(&f.c,5180));
     assert(!rtw89LinuxAwdlChannelAllowed(&f.c,5975));
     f.channels[1].flags=IEEE80211_CHAN_RADAR;
     assert(!rtw89LinuxAwdlChannelAllowed(&f.c,5180));
     f.channels[1].flags=0;
     assert(rtw89LinuxAwdlReserveRadio(&f.c,5180,101)==RTWAwdl::RadioReservation::Rejected&&!reserves);
     assert(rtw89LinuxAwdlReserveRadio(&f.c,5180,50)==RTWAwdl::RadioReservation::Granted);
     state=rtw89LinuxAwdlRadioState(&f.c);
     assert(state.ready&&state.frequency==5180&&state.recoveryRequired);
     driverLive=false;recovering=true;
     state=rtw89LinuxAwdlRadioState(&f.c);
     assert(state.frequency==0&&state.recoveryRequired);
     assert(!rtw89LinuxAwdlRestore(&f.c));
     reserveError=-11;recovering=true;
     assert(rtw89LinuxAwdlReserveRadio(&f.c,5180,50)==RTWAwdl::RadioReservation::RecoveryRequired);
     assert(!rtw89LinuxAwdlRestore(&f.c));
     recovering=false;
     assert(rtw89LinuxAwdlReserveRadio(&f.c,5180,50)==RTWAwdl::RadioReservation::Rejected);
     f.c.scanning=true;assert(!rtw89LinuxAwdlRadioState(&f.c).ready);
     assert(!rtw89LinuxAwdlRadioState(nullptr).frequency);
     assert(!rtw89LinuxAwdlChannelAllowed(nullptr,2437));}

    {Fixture f;
     assert(rtw89LinuxAwdlReserve(&f.c,5180,50)==0);
     assert(f.c.awdlTxGate.isPaused() && f.vif.bss_conf.chandef_chan==f.channels+1);
     assert(f.vif.bss_conf.chandef_width==20 && f.hw.conf.chandef.width==80);
     assert(rtw89LinuxTxAvailableSlots(&f.c)==0);
     assert(rtw89LinuxAwdlReserve(&f.c,2437,50)==-EBUSY && reserves==1);
     restoreError=-7;assert(rtw89LinuxAwdlRestore(&f.c)==-7);
     assert(f.c.awdlTxGate.isPaused()&&!wakes);
     restoreError=0;assert(!rtw89LinuxAwdlRestore(&f.c));
     assert(!f.c.awdlTxGate.isPaused()&&wakes==1&&rtw89LinuxTxAvailableSlots(&f.c)==255);
     assert(f.vif.bss_conf.chandef_chan==f.channels&&f.vif.bss_conf.chandef_width==80);}
    {Fixture f;f.channels[1].flags=IEEE80211_CHAN_NO_IR;
     assert(rtw89LinuxAwdlReserve(&f.c,5180,50)==-EINVAL && !reserves);
     assert(!f.c.awdlTxGate.isPaused()&&wakes==1);}
    {Fixture f;f.c.station=&f;f.c.stationState=3;
     assert(rtw89LinuxAwdlReserve(&f.c,5180,50)==-EBUSY && !reserves);
     assert(!f.c.awdlTxGate.isPaused());}
    {Fixture f;reserveError=-11;recovering=true;
     assert(rtw89LinuxAwdlReserve(&f.c,5180,50)==-11);
     assert(f.c.awdlTxGate.isPaused()&&!wakes);
     assert(!rtw89LinuxAwdlRestore(&f.c)&&!f.c.awdlTxGate.isPaused());}
    {Fixture f;reserveError=-11;
     assert(rtw89LinuxAwdlReserve(&f.c,5180,50)==-11);
     assert(!f.c.awdlTxGate.isPaused()&&wakes==1);}
    {Fixture f;assert(f.c.awdlTxGate.enter());drainAfterSleep=&f.c.awdlTxGate;
     assert(!rtw89LinuxAwdlReserve(&f.c,5180,50)&&sleeps==1);
     assert(f.c.awdlTxGate.drained());assert(!rtw89LinuxAwdlRestore(&f.c));}
    {Fixture f;assert(f.c.awdlTxGate.enter());
     assert(rtw89LinuxAwdlReserve(&f.c,5180,50)==-EBUSY&&sleeps==100&&!reserves);
     assert(!f.c.awdlTxGate.isPaused()&&wakes==1);f.c.awdlTxGate.leave();}
    puts("PASS: RTW89 bridge drains primary submissions and retains recovery ownership on failure");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-radio-bridge-') as tmp:
    source=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    source.write_text(shim+code+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
