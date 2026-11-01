#!/usr/bin/env python3
"""Bounded disconnected-only AWDL discovery capture; never changes networks."""
import argparse
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('wifi_diagnostics', ROOT / 'tools/collect_wifi_diagnostics.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def check_idle(record):
    states = [v for e in record['entries'] for k, v in e.items()
              if k in ('RTW88Net80211State', 'RTW89Net80211State')]
    ports = [v for e in record['entries'] for k, v in e.items()
             if k in ('RTW88PortValid', 'RTW89PortValid')]
    # INIT/SCAN only: reject AUTH, ASSOC and RUN, even before port authorization.
    if not states or any(s not in (0, 1) for s in states) or any(ports):
        raise RuntimeError('Disconnect Wi-Fi first; driver must report INIT or SCAN. No scan was requested.')
    if not any(e.get('RTWAwdlFilterAccepted') is True for e in record['entries']):
        raise RuntimeError('AWDL receive filter is not accepted. Install the discovery test kext first.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    first = diag.snapshot()
    check_idle(first)
    with tempfile.TemporaryDirectory(prefix='airportrtw-awdl-') as temp:
        binary = str(Path(temp) / 'scan')
        subprocess.run(['xcrun', 'swiftc', str(Path(__file__).with_name('scan.swift')),
                        '-framework', 'CoreWLAN', '-o', binary], check=True, timeout=120)
        # Re-check after compilation, which can take long enough for auto-join.
        check_idle(diag.snapshot())
        records = [first]
        def capture():
            for _ in range(45):
                records.append(diag.snapshot())
                time.sleep(1)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(capture)
                messages = []
                code = 0
                for _ in range(3):
                    try:
                        check_idle(diag.snapshot())
                    except RuntimeError as error:
                        messages.append(str(error))
                        code = 4
                        break
                    result = subprocess.run([binary, args.interface], capture_output=True,
                                            text=True, timeout=20)
                    messages.append(result.stdout + result.stderr)
                    code = result.returncode
                    if code:
                        break
                future.result()
            outcome = {'exitCode': code, 'message': '\n'.join(messages)}
        except subprocess.TimeoutExpired:
            outcome = {'exitCode': -1, 'message': 'Scan timed out; child terminated.'}
        finally:
            args.output.write_text(json.dumps({'samples': records, 'scan': locals().get('outcome',
                {'exitCode': -2, 'message': 'Capture interrupted'})}, indent=2) + '\n')
        print(outcome['message'].strip())
        print(f'Saved bounded diagnostics to {args.output}')

if __name__ == '__main__':
    main()
