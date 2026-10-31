#!/usr/bin/env python3
"""Run production native datapath logic with host family/IOKit adapters."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
header=(ROOT/'AirportRTW/WCL/AirportRTWAwdlDatapath.hpp').read_text()
source=(ROOT/'AirportRTW/WCL/AirportRTWAwdlDatapath.cpp').read_text()
def strip_includes(text):
    return re.sub(r'^#include[^\n]*\n','',text,flags=re.M)
with tempfile.TemporaryDirectory(prefix='awdl-native-packets-') as temp:
    path=Path(temp)/'host.cpp'
    path.write_text('#include <AWDL/RTWAwdlData.hpp>\n#include <AWDL/RTWAwdlPacketFlow.hpp>\n'+
        (ROOT/'tests/host/rtw_awdl_datapath_shim.hpp').read_text()+strip_includes(header)+strip_includes(source)+
        (ROOT/'tests/host/rtw_awdl_datapath_scenarios.hpp').read_text())
    binary=str(Path(temp)/'test')
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-Wno-unused-parameter','-Wno-unused-function','-DAIRPORT_WCL',
        '-D__MAC_26_0=260000','-D__IO80211_TARGET=260000',
        '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(path),'-o',binary],check=True)
    subprocess.run([binary],check=True,timeout=10)
