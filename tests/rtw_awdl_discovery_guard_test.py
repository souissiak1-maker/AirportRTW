#!/usr/bin/env python3
"""Check discovery refusal on unknown, joining or connected driver states."""
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('discovery', Path(__file__).resolve().parents[1] / 'tools/awdl_discovery/run.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
for family in ('88', '89'):
    for state in range(5):
        for port in (False, True):
            r = {'entries': [{f'RTW{family}Net80211State': state,
                             f'RTW{family}PortValid': port,
                             'RTWAwdlFilterAccepted': True}]}
            allowed = state in (0, 1) and not port
            try:
                m.check_idle(r)
            except RuntimeError:
                assert not allowed
            else:
                assert allowed
for entries in ([], [{}], [{'RTW88Net80211State': 0}],
                [{'RTW89Net80211State': 0, 'RTWAwdlFilterAccepted': False}]):
    try:
        m.check_idle({'entries': entries})
    except RuntimeError:
        pass
    else:
        raise AssertionError('Unknown/filter-disabled state accepted')
print('AWDL discovery guards passed')
