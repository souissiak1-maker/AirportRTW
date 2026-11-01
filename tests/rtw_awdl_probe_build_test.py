#!/usr/bin/env python3
"""Check real build wrapper argument isolation with Xcode/strip adapters."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='rtw-awdl-build-') as tmp:
    directory=Path(tmp)
    xcode=directory/'xcodebuild'
    # /usr/bin/python3 is available in the macOS build/test environment.
    xcode.write_text('#!/usr/bin/python3\nimport json,os,sys\nopen(os.environ["CAPTURE"],"w").write(json.dumps(sys.argv[1:]))\n')
    xcode.chmod(0o755)
    strip=directory/'xcrun';strip.write_text('#!/bin/sh\nexit 0\n');strip.chmod(0o755)
    capture=directory/'args.json'
    for probe in ('0','1'):
        env=dict(os.environ,PATH=str(directory)+':'+os.environ['PATH'],
                 CAPTURE=str(capture),CONFIGURATION='Release',AWDL_STARTUP_PROBE=probe)
        subprocess.run(['/bin/bash',str(ROOT/'scripts/build_release_kexts.sh'),'AirportRTW-Tahoe'],
                       env=env,check=True,capture_output=True)
        args=json.loads(capture.read_text())
        flags=[a for a in args if a.startswith('OTHER_CPLUSPLUSFLAGS=')]
        if probe=='1':
            assert flags==['OTHER_CPLUSPLUSFLAGS=$(inherited) -DRTW_AWDL_STARTUP_PROBE=1']
            assert 'SYMROOT='+str(ROOT/'build/awdl-startup-probe') in args
            assert 'OBJROOT='+str(ROOT/'build/awdl-startup-probe-obj') in args
        else:
            assert not flags
            assert 'SYMROOT='+str(ROOT/'build/releases') in args
            assert 'OBJROOT='+str(ROOT/'build/releases-obj') in args
    capture.unlink()
    result=subprocess.run(['/bin/bash',str(ROOT/'scripts/build_release_kexts.sh'),'AirportRTW-Monterey'],
                          env=env,capture_output=True)
    assert result.returncode==2 and not capture.exists()
print('PASS: probe builds have isolated flags/artifacts; normal builds and target guards preserved')
