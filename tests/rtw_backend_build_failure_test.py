#!/usr/bin/env python3
"""A failed backend archive must stop the actual Xcode shell phase."""
from pathlib import Path
import json
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
project=(ROOT/'AirportRTW.xcodeproj/project.pbxproj').read_text()
phases=[]
for literal in re.findall(r'shellScript = ("(?:\\.|[^"\\])*");',project):
    script=json.loads(literal)
    if 'scripts/build_rtw89_c_archive.sh' in script:phases.append(script)
assert len(phases)==3
for phase in phases:
    for fail in ('89','88','sae',None):
        with tempfile.TemporaryDirectory(prefix='rtw-archive-failure-') as tmp:
            root=Path(tmp);(root/'scripts').mkdir()
            for name in ('89','88','sae'):
                filename=f'build_rtw{name}_c_archive.sh' if name!='sae' else 'build_sae_archive.sh'
                stub=root/'scripts'/filename
                stub.write_text('#!/bin/bash\nprintf "%s\\n" '+name+' >> trace\nexit '+('23' if fail==name else '0')+'\n')
                stub.chmod(0o700)
            result=subprocess.run(['/bin/bash','-c',phase],cwd=root,capture_output=True,text=True)
            expected=['89','88','sae']
            if fail:expected=expected[:expected.index(fail)+1]
            assert (root/'trace').read_text().splitlines()==expected,(fail,result.stderr)
            assert result.returncode==(23 if fail else 0),(fail,result.returncode)
print('PASS: all Xcode backend phases stop on any archive failure')
