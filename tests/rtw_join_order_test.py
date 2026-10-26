#!/usr/bin/env python3
"""Exercise native association completion blocks from production sources."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
stack = root / 'rtw80211/openbsd/net80211'
source = (stack / 'ieee80211_input.c').read_text()
start = source.index('    const int transitionResult =')
completion = source[start:source.index('\n#else', start)]
source = (stack / 'ieee80211_proto.c').read_text()
start = source.index('            if (ostate == IEEE80211_S_ASSOC &&')
notification = source[start:source.index('            if (!(ic->ic_flags & IEEE80211_F_RSNON))', start)]
fixture = r'''
#include <cassert>
#include <cstddef>
#define IEEE80211_S_RUN 4
#define IEEE80211_S_ASSOC 3
#define IEEE80211_M_STA 1
#define IEEE80211_FC0_SUBTYPE_ASSOC_RESP 0x10
#define IEEE80211_STATUS_UNSPECIFIED 1
#define IEEE80211_EVT_STA_ASSOC_DONE 1
struct State {
 int ic_state=3,ic_opmode=1,ic_assoc_status=0;
 unsigned ic_sae_error=0;
 int (*ic_newstate)(State*,int,int);
 void (*ic_event_handler)(State*,int,void*);
};
static int events,result,phase,links;
static bool enterRun,rsn;
static void event(State*,int,void*) {
 assert(phase==1 && links==0); ++events;
}
static int transition(State *ic,int,int) {
 assert(phase==0);phase=1;
 if(result || !enterRun) return result;
 int ostate=ic->ic_state;
 ic->ic_state=IEEE80211_S_RUN;
''' + notification + r'''
 if(!rsn) {
  if(ic->ic_event_handler) assert(events==1);
  ++links;
 }
 return 0;
}
static void complete(State *ic) {
''' + completion + r'''
}
int main() {
 for(int scenario=0;scenario<4;++scenario) {
  State ic;ic.ic_newstate=transition;ic.ic_event_handler=event;
  events=phase=links=0;result=scenario==2?5:0;
  enterRun=scenario!=3;rsn=scenario!=0;
  complete(&ic);
  assert(events==1);
  if(scenario<2) {
   assert(ic.ic_assoc_status==0 && ic.ic_sae_error==0);
   assert(links==(rsn?0:1));
  } else assert(links==0 && ic.ic_assoc_status==1 && (ic.ic_sae_error&0x40000));
 }
 State ic;ic.ic_newstate=transition;ic.ic_event_handler=nullptr;
 events=phase=links=result=0;enterRun=true;rsn=false;
 complete(&ic);assert(events==0 && links==1);
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-join-order-') as directory:
    source_path = Path(directory) / 'test.cpp'
    binary = Path(directory) / 'test'
    source_path.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(source_path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: association precedes open link-up; RSN waits; HAL failures report once')
