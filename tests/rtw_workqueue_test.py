#!/usr/bin/env python3
"""Execute each HAL's production queue functions with threaded host adapters."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
for family in ('88','89'):
    base=ROOT/f'rtw/hal_rtw{family}/compat'
    header=(base/'linux/workqueue.h').read_text()
    header=re.sub(r'^#include[^\n]*\n','',header,flags=re.M)
    source=(base/'rtw88_compat.c').read_text()
    a=source.index('static void wq_thread_fn(')
    b=source.index('\n/* ------------------------------------------------------------------ */\n/*  Timer',a)
    with tempfile.TemporaryDirectory(prefix='rtw-workqueue-') as temp:
        path=Path(temp)/'host.cpp'
        path.write_text((ROOT/'tests/host/rtw_workqueue_shim.hpp').read_text()+ '\n'+header+
            '\nstruct workqueue_struct *system_wq=nullptr,*system_long_wq=nullptr;\n'+source[a:b]+
            '\n'+(ROOT/'tests/host/rtw_workqueue_scenarios.hpp').read_text())
        binary=str(Path(temp)/'test')
        subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
            '-Wno-unused-parameter','-Wno-unused-function','-fsanitize=address,undefined',
            str(path),'-o',binary],check=True)
        subprocess.run([binary],check=True,timeout=10)
    print(f'RTW{family} production queue tests passed')
