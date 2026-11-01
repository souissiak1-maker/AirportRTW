#!/usr/bin/env python3
"""Link both production radio helpers with independent HAL adapters at -O0."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'tests/rtw_awdl_linux_interface_test.cpp').read_text()
# Reuse the lifecycle adapters, compiling them independently just as the two
# HALs compile their incompatible/namespaced Linux compatibility environments.
fixture=source[:source.index('int main()')]
with tempfile.TemporaryDirectory(prefix='rtw-awdl-isolation-') as tmp:
    objects=[]
    for name in ('88','89'):
        wrapper='''
extern "C" void runHAL%s() {
    Ops ops={add,remove,bssid,nullptr}; ieee80211_hw hw={&ops,128,64,{}};
    uint8_t primary[]={2,1,2,3,4,5},mac[]={2,1,2,3,4,6};
    RTWAwdl::InterfaceState state={};
    assert(!adds && !registrations && !removes && !live);
    assert(RTWAwdl::addLinuxInterface(&hw,state,mac,primary,true));
    assert(adds==1 && registrations==1 && hardwareLive && registryLive && live==2);
    RTWAwdl::removeLinuxInterface(&hw,state);
    assert(removes==1 && !hardwareLive && !registryLive && !live);
}
''' % name
        path=Path(tmp)/f'hal{name}.cpp';obj=Path(tmp)/f'hal{name}.o'
        path.write_text(fixture+wrapper)
        subprocess.run(['xcrun','clang++','-std=c++14','-O0','-fno-inline',
            '-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'include'),
            '-c',str(path),'-o',str(obj)],check=True)
        objects.append(str(obj))
    main=Path(tmp)/'main.cpp';binary=Path(tmp)/'test'
    main.write_text('extern "C" void runHAL88(); extern "C" void runHAL89();\nint main(){runHAL88();runHAL89();}\n')
    subprocess.run(['xcrun','clang++','-fsanitize=address,undefined',*objects,str(main),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PASS: combined-HAL secondary interface helpers retain independent backend ownership')

# The action helper also calls a HAL-specific skb allocator. Exercise both in
# one linked binary, so a weak-inline allocator binding cannot hide in a unit test.
source=(ROOT/'tests/rtw_awdl_linux_action_tx_test.cpp').read_text()
fixture=source[:source.index('int main()')]
with tempfile.TemporaryDirectory(prefix='rtw-awdl-action-isolation-') as tmp:
    objects=[]
    for name in ('88','89'):
        wrapper='''
extern "C" void runHAL%s() {
    Channel channel={NL80211_BAND_2GHZ,2437,0};
    ieee80211_vif vif={true,NL80211_IFTYPE_ADHOC,{2,1,2,3,4,5},{&channel}};
    Ops ops={tx}; ieee80211_hw hw={&ops,{{&channel}}};
    uint8_t frame[40]={0xd0}; memset(frame+4,255,6); memcpy(frame+10,vif.addr,6);
    const uint8_t bssid[]={0,0x25,0,0xff,0x94,0x73}; memcpy(frame+16,bssid,6);
    const uint8_t body[]={127,0,0x17,0xf2,8,0x10,0}; memcpy(frame+24,body,7);
    assert(!allocations && !submitted);
    assert(RTWAwdl::submitLinuxAction(&hw,&vif,frame,sizeof(frame),2437)==
           RTWAwdl::ActionSubmission::Submitted);
    assert(allocations==1 && submitted && submitted->info.control.vif==&vif);
    delete submitted; submitted=nullptr;
}
''' % name
        path=Path(tmp)/f'hal{name}.cpp';obj=Path(tmp)/f'hal{name}.o'
        path.write_text(fixture+wrapper)
        subprocess.run(['xcrun','clang++','-std=c++14','-O0','-fno-inline',
            '-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'include'),
            '-c',str(path),'-o',str(obj)],check=True)
        objects.append(str(obj))
    main=Path(tmp)/'main.cpp';binary=Path(tmp)/'test'
    main.write_text('extern "C" void runHAL88(); extern "C" void runHAL89();\nint main(){runHAL88();runHAL89();}\n')
    subprocess.run(['xcrun','clang++','-fsanitize=address,undefined',*objects,str(main),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PASS: combined-HAL action TX retains independent skb allocator ownership')
