#!/usr/bin/env python3
"""Exercise the production native control provider with a fault-injected backend."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
strip=lambda text: re.sub(r'^#include[^\n]*\n','',text,flags=re.M)
ioctl=(ROOT/'include/Airport/apple80211_ioctl.h').read_text()
names=['ssid_data','state_data','channel_data','awdl_sync_params','awdl_sync_state',
       'awdl_sync_channel_sequence','awdl_election_rssi_thresholds','awdl_sync_enabled',
       'awdl_presence_mode','awdl_election_id','awdl_election_metric','awdl_af_tx_mode',
       'awdl_sync_frame_template']
structs=[]
for suffix in names:
    match=re.search(r'\bstruct apple80211_'+suffix+r'\s*\{.*?\}\s*(?:__attribute__\(\(packed\)\))?;',ioctl,re.S)
    assert match,suffix
    structs.append(match[0])
shim=r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <sys/types.h>
#include <AWDL/RTWAwdlTxTemplate.hpp>
#include <AWDL/RTWAwdlData.hpp>
#define APPLE80211_VERSION 1
#define APPLE80211_MAX_SSID_LEN 32
#define APPLE80211_MAX_CHANNELS 128
#define APPLE80211_S_RUN 4
#define APPLE80211_S_INIT 0
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnError=2;
constexpr int kIOReturnBadArgument=3,kIOReturnBusy=4,kIOReturnUnsupported=5;
struct IO80211VirtualInterface {};
struct apple80211_channel { uint32_t version,channel,flags; };
'''
scenario=r'''
using namespace AirportRTWAwdl;
struct Backend : RuntimeBackend {
    unsigned opens=0,closes=0,activations=0,configures=0,templates=0,sends=0;
    uint32_t caps=Control::requiredCapabilities;
    int openResult=0,activateResult=0,configureResult=0,templateResult=0;
    bool online=true,hasChannel=true,hasConfiguration=true;
    Settings applied{};
    RTWAwdl::TxTemplate frame;
    uint32_t capabilities()const override{return caps;}
    bool ready()const override{return online;}
    IOReturn open(IO80211VirtualInterface*,const uint8_t*)override{++opens;return openResult;}
    IOReturn activate(bool)override{++activations;return activateResult;}
    void close()override{++closes;}
    bool channelAllowed(const apple80211_channel &c)const override{
        return c.version<=1 && c.channel==6 && c.flags==0x10;
    }
    bool currentChannel(apple80211_channel &c)const override{c={1,6,0x10};return hasChannel;}
    IOReturn configure(const Settings &s)override{
        ++configures;if(!configureResult)applied=s;return configureResult;
    }
    bool configuration(Settings &s)const override{s=applied;return hasConfiguration;}
    IOReturn installTemplate(const RTWAwdl::TxTemplate &t)override{
        ++templates;if(!templateResult)frame=t;return templateResult;
    }
    IOReturn setAddress(const uint8_t*)override{return 0;}
    bool transmitEthernet(const uint8_t*,size_t)override{++sends;return true;}
};
int main(){
    IO80211VirtualInterface interface;uint8_t mac[6]={2,0,0,0,0,1};
    {Backend b;Runtime r(b);b.caps&=~Control::RadioScheduling;
     assert(r.prepare(&interface,mac)==kIOReturnNotReady && !b.opens);}
    {Backend b;Runtime r(b);b.openResult=kIOReturnError;
     assert(r.prepare(&interface,mac)==kIOReturnError && b.closes==1);
     r.shutdown();assert(b.closes==1);}
    {Backend b;Runtime r(b);b.hasConfiguration=false;
     assert(r.prepare(&interface,mac)==kIOReturnNotReady && b.closes==1);}
    Backend b;Runtime r(b);
    assert(r.enable(true)==kIOReturnNotReady);
    assert(r.prepare(nullptr,mac)==kIOReturnBadArgument);
    assert(r.prepare(&interface,mac)==0 && b.opens==1);
    assert(r.prepare(&interface,mac)==kIOReturnBadArgument);
    apple80211_awdl_presence_mode presence{1,4},out{};
    b.configureResult=kIOReturnError;
    assert(r.request(Request::AWDL_PRESENCE_MODE,true,&presence)==kIOReturnError);
    assert(!r.request(Request::AWDL_PRESENCE_MODE,false,&out) && out.mode==0);
    b.configureResult=0;
    assert(!r.request(Request::AWDL_PRESENCE_MODE,true,&presence));presence.mode=16;
    assert(!r.request(Request::AWDL_PRESENCE_MODE,false,&out) && out.mode==4);
    presence.mode=3;assert(r.request(Request::AWDL_PRESENCE_MODE,true,&presence)==kIOReturnUnsupported);
    presence.version=2;assert(r.request(Request::AWDL_PRESENCE_MODE,true,&presence)==kIOReturnBadArgument);
    apple80211_awdl_sync_channel_sequence channels{};
    channels.version=1;channels.length=16;channels.step_count=3;
    channels.seqs[0]={1,6,0x10};
    assert(!r.request(Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE,true,&channels));
    channels.seqs[0].channel=149;
    assert(r.request(Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE,true,&channels)==kIOReturnBadArgument);
    assert(b.applied.channels.seqs[0].channel==6);
    channels.seqs[0]={1,6,0x2010}; // Never alias 6 GHz channel 6 to 2.4 GHz.
    assert(r.request(Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE,true,&channels)==kIOReturnBadArgument);
    apple80211_awdl_sync_params sync{1,16,16,16,110,0};
    assert(!r.request(Request::AWDL_SYNC_PARAMS,true,&sync));
    sync.non_election_master=2;assert(r.request(Request::AWDL_SYNC_PARAMS,true,&sync)==kIOReturnUnsupported);
    apple80211_awdl_sync_state parent{};parent.version=1;parent.state=2;
    assert(r.request(Request::AWDL_SYNC_STATE,true,&parent)==kIOReturnBadArgument);
    memcpy(parent.master,mac,6);assert(!r.request(Request::AWDL_SYNC_STATE,true,&parent));
    apple80211_awdl_sync_enabled enabled{1,0,1};
    assert(!r.request(Request::AWDL_SYNC_ENABLED,true,&enabled));
    parent.state=0;assert(!r.request(Request::AWDL_SYNC_STATE,true,&parent));
    assert(!r.request(Request::AWDL_SYNC_ENABLED,false,&enabled) && !enabled.enabled);
    uint8_t tlv[4]={99,1,0,7};
    apple80211_awdl_sync_frame_template t{1,sizeof(tlv),tlv};
    assert(!r.request(Request::AWDL_SYNC_FRAME_TEMPLATE,true,&t));
    uint8_t wire[100]{};size_t written=0;uint8_t dest[6]={255,255,255,255,255,255};
    uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
    tlv[3]=8;
    b.templateResult=kIOReturnError;
    assert(r.request(Request::AWDL_SYNC_FRAME_TEMPLATE,true,&t)==kIOReturnError);
    assert(b.frame.build(wire,sizeof(wire),dest,mac,bssid,1,2,3,written) && wire[43]==7);
    tlv[1]=2;assert(r.request(Request::AWDL_SYNC_FRAME_TEMPLATE,true,&t)==kIOReturnBadArgument);
    assert(r.request(Request::AWDL_CONFIG,true,&sync)==kIOReturnUnsupported);
    apple80211_channel_data channel{};b.hasChannel=false;
    assert(r.request(Request::CHANNEL,false,&channel)==kIOReturnNotReady);
    b.hasChannel=true;assert(!r.request(Request::CHANNEL,false,&channel) && channel.channel.channel==6);
    b.activateResult=kIOReturnError;assert(r.enable(true)==kIOReturnError);
    b.activateResult=0;assert(!r.enable(true));unsigned changes=b.activations;
    assert(!r.enable(true) && b.activations==changes);
    assert(r.setAddress(mac)==kIOReturnBusy);
    uint8_t eth[54]{};eth[0]=0x33;eth[6]=2;eth[12]=0x86;eth[13]=0xdd;eth[14]=0x60;
    assert(r.transmitEthernet(eth,sizeof(eth)) && b.sends==1);
    b.online=false;assert(!r.transmitEthernet(eth,sizeof(eth)) && b.sends==1);b.online=true;
    eth[12]=8;assert(!r.transmitEthernet(eth,sizeof(eth)) && b.sends==1);
    assert(!r.enable(false) && !r.transmitEthernet(eth,sizeof(eth)));
    assert(!r.setAddress(mac));r.shutdown();r.shutdown();
    assert(b.closes==1 && !r.ready() && r.enable(true)==kIOReturnNotReady);
    assert(r.request(Request::AWDL_SYNC_PARAMS,false,&sync)==kIOReturnNotReady);
    puts("PASS: native runtime lifecycle, atomic configuration, owned templates and backend failures");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-runtime-') as tmp:
    source=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    source.write_text(shim+'\n'.join(structs)+
        strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlControl.hpp').read_text())+
        strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlRuntime.hpp').read_text())+scenario)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-DAIRPORT_WCL','-D__MAC_26_0=260000',
        '-D__IO80211_TARGET=260000','-I'+str(ROOT/'include'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
