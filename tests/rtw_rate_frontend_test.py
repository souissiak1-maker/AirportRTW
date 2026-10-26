#!/usr/bin/env python3
"""Exercise production rate/MCS early returns in all three Apple frontends."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
paths = ['AirportRTW/WCL/AirportRTWSkywalkInterface.cpp',
         'AirportRTW/AirportRTWSkywalkInterface.cpp', 'AirportRTW/AirportSTAIOCTL.cpp']
fixture = '#include "' + str(root / 'include/HAL/RTWTxRate.h') + '"\n' + r'''
#include <cassert>
#define kIOReturnSuccess 0
#define APPLE80211_VERSION 1
#define APPLE80211_GI_SHORT 1
#define APPLE80211_GI_LONG 0
struct Rate { unsigned rate[1]; };
struct MCS { unsigned version,index; };
struct VHT { unsigned guard_interval,index,nss,bw; };
struct Driver { bool owns;RTWTxRate sample;
 bool getTxRate(RTWTxRate &out) {out=sample;return owns;} };
struct Service {Driver driver;Driver *getDriverInfo() {return &driver;} };
static Service service;static Service *fHalService=&service;
'''
calls = []
for i, filename in enumerate(paths):
    source = (root / filename).read_text()
    for method, argument in [('getRATE', 'Rate *rd'), ('getMCS', 'MCS *md'), ('getMCS_VHT', 'VHT *data')]:
        a = source.index('RTWTxRate liveRate =', source.index(method + '('))
        brace = source.index('{', source.index('if (fHalService->getDriverInfo()->getTxRate(liveRate))', a))
        depth, end = 1, brace + 1
        while depth:
            depth += (source[end] == '{') - (source[end] == '}')
            end += 1
        name = method + str(i)
        fixture += '\nstatic int ' + name + '(' + argument + ') {\n' + source[a:end] + '\nreturn 99;\n}\n'
    calls.append(f'''
 for(bool owns:{{false,true}}) {{
  service.driver.owns=owns;service.driver.sample={{}};
  Rate r{{}};MCS m{{}};VHT v{{}};
  assert(getRATE{i}(&r)==(owns?6:99));
  assert(getMCS{i}(&m)==(owns?6:99));
  assert(getMCS_VHT{i}(&v)==(owns?6:99));
 }}
 service.driver.owns=true;
 service.driver.sample={{4333,80,9,1,RTW_RATE_VHT,true,true,400,false}};
 Rate r{i}{{}};MCS m{i}{{}};VHT v{i}{{}};
 assert(getRATE{i}(&r{i})==0 && r{i}.rate[0]==433);
 assert(getMCS{i}(&m{i})==0 && m{i}.index==9);
 assert(getMCS_VHT{i}(&v{i})==0 && v{i}.index==9 && v{i}.nss==1 && v{i}.bw==80 && v{i}.guard_interval==1);
 service.driver.sample={{1350,40,7,1,RTW_RATE_VHT,false,true,800,false}};
 assert(getRATE{i}(&r{i})==0 && r{i}.rate[0]==135);
 assert(getMCS_VHT{i}(&v{i})==0 && v{i}.index==7 && v{i}.guard_interval==0);
 service.driver.sample={{12010,80,11,2,RTW_RATE_HE,false,true,800,false}};
 assert(getRATE{i}(&r{i})==0 && r{i}.rate[0]==1201);
 assert(getMCS{i}(&m{i})==0 && m{i}.index==11);
 assert(getMCS_VHT{i}(&v{i})==6); // Do not label HE guard intervals as VHT SGI.
 service.driver.sample.mode=RTW_RATE_LEGACY;
 assert(getMCS{i}(&m{i})==6 && getMCS_VHT{i}(&v{i})==6);
''')
fixture += '\n#include <initializer_list>\nint main() {\n' + ''.join(calls) + '\n}\n'
with tempfile.TemporaryDirectory(prefix='rtw-rate-frontend-') as directory:
    source = Path(directory) / 'test.cpp'
    binary = Path(directory) / 'test'
    source.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: all frontends use live rates, actual NSS/GI, unknown samples and other-HAL fallback')
