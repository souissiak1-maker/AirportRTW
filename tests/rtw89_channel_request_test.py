#!/usr/bin/env python3
"""Exercise channel publication consumed by the production HE callback."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text()
start = source.index('    vif->bss_conf.chanreq.oper =')
end = source.index('\n\n', start)
publication = source[start:end]
associate = source.index('bool rtw89LinuxAssociate(')
assert associate < start < source.index('hw->ops->sta_state(hw, vif, sta, IEEE80211_STA_AUTH', associate)
assert start < source.index('hw->ops->vif_cfg_changed(hw, vif, BSS_CHANGED_ASSOC)', associate)
fixture = r'''
#include <cassert>
struct Channel { unsigned flags; };
struct Definition { Channel *chan; int width,center_freq1,center_freq2; };
struct Hardware { struct { Definition chandef; } conf; };
struct Vif { struct {
 struct { Definition oper; } chanreq;
 Channel *chandef_chan; int chandef_width;
} bss_conf; };
void publish(Hardware *hw,Vif *vif) {
''' + publication + r'''
}
int main() {
 Channel channels[]={{0},{1}};
 for(auto &channel:channels) for(int width=0;width<3;++width) {
  Hardware hw{{{&channel,width,2417+width*10,0}}};Vif vif{};
  publish(&hw,&vif);
  // HE OBSS setup dereferences oper.chan->flags after publication.
  assert(vif.bss_conf.chanreq.oper.chan->flags==channel.flags);
  assert(vif.bss_conf.chanreq.oper.width==width);
  assert(vif.bss_conf.chanreq.oper.center_freq1==hw.conf.chandef.center_freq1);
  assert(vif.bss_conf.chanreq.oper.center_freq2==0);
  assert(vif.bss_conf.chandef_chan==&channel);
  assert(vif.bss_conf.chandef_width==width);
 }
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-channel-request-') as directory:
    path = Path(directory) / 'test.cpp'
    binary = Path(directory) / 'test'
    path.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: operating channel is published before HE association callbacks')
