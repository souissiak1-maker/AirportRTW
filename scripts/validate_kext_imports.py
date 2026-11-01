#!/usr/bin/env python3
"""Resolve every Mach-O import against the installed macOS kernel libraries.

A successful Xcode kext link permits dynamic imports and is not this check.
No kext is loaded, approved, installed or added to a kernel collection.
"""
import argparse,json,re,subprocess
from pathlib import Path

def validate(kext):
    binary=kext/'Contents/MacOS/AirportRTW'
    symbols=subprocess.check_output(['xcrun','nm','-arch','x86_64','-u',str(binary)],text=True)
    needed={line.strip() for line in symbols.splitlines() if line.strip().startswith('_')}
    if not needed:raise RuntimeError('No imports found; cannot validate this binary')
    result=subprocess.run(['/usr/bin/kmutil','libraries','-a','x86_64','-p',str(kext),
        '--undef-symbols','--onedef-symbols'],capture_output=True,text=True,timeout=120)
    if result.returncode:raise RuntimeError(result.stderr or result.stdout)
    found=set(re.findall(r'^\s*(\S+) in ',result.stdout,re.M))
    if not found:raise RuntimeError('kmutil returned no symbol definitions; validation unavailable')
    missing=sorted(needed-found)
    return {'kext':str(kext),'architecture':'x86_64','imported_symbols':len(needed),
        'resolved_symbols':len(needed&found),'unresolved_symbols':missing,'passed':not missing}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('kext',type=Path);parser.add_argument('--report',type=Path)
    args=parser.parse_args();report=validate(args.kext.resolve());text=json.dumps(report,indent=2)+'\n'
    if args.report:args.report.write_text(text)
    print(text,end='');raise SystemExit(0 if report['passed'] else 1)
if __name__=='__main__':main()
