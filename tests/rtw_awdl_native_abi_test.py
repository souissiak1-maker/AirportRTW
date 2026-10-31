#!/usr/bin/env python3
"""Compile native AWDL declarations and check their virtual slots (no loading)."""
import argparse
from pathlib import Path
import re
import subprocess
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def verify_family(path):
    """Inspect x86_64 on-disk symbols/relocations, never live kernel memory."""
    data = path.read_bytes()
    if data[:4] == b'\xca\xfe\xba\xbe':
        count = struct.unpack_from('>I', data, 4)[0]
        for index in range(count):
            cpu, _, offset, length, _ = struct.unpack_from('>IIIII', data, 8 + 20 * index)
            if cpu == 0x1000007:
                data = data[offset:offset+length]
                break
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf, 'Expected x86_64 Mach-O'
    segments = []
    symtab = dysymtab = None
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, length = struct.unpack_from('<II', data, offset)
        assert length >= 8 and offset + length <= len(data)
        if command == 0x19:
            _, va, size, file_offset, file_size = struct.unpack_from('<16sQQQQ', data, offset+8)
            segments.append((va, size, file_offset, file_size))
        elif command == 2:
            symtab = struct.unpack_from('<6I', data, offset)[2:]
        elif command == 0xb:
            dysymtab = struct.unpack_from('<20I', data, offset)
        offset += length
    assert symtab and dysymtab, 'Family symbols or relocations unavailable'
    symbols = []
    addresses = {}
    symoff, count, stroff, strsize = symtab
    strings = data[stroff:stroff+strsize]
    for i in range(count):
        name_index, _, _, _, address = struct.unpack_from('<IBBHQ', data, symoff+16*i)
        name = strings[name_index:].split(b'\0', 1)[0].decode('utf-8')
        symbols.append(name)
        if address:
            addresses.setdefault(address, []).append(name)
    values = {name: address for address,names in addresses.items() for name in names}
    table = values['__ZTV19IO80211AWDLProtocol']
    relocation_offset, count = dysymtab[16:18]
    imports = {}
    for i in range(count):
        address, info = struct.unpack_from('<II', data, relocation_offset+8*i)
        if info & (1 << 27):
            imports[address] = symbols[info & 0xffffff]
    for index in [490] + list(range(507,570)):
        assert imports.get(table+8*index) == '___cxa_pure_virtual', (index,imports.get(table+8*index))
    def pointer_at(address):
        for va, size, file_offset, file_size in segments:
            if va <= address and address+8 <= va+min(size,file_size):
                return struct.unpack_from('<Q',data,file_offset+address-va)[0]
        raise AssertionError('Vtable slot outside file-backed sections')
    for index,name in [(463,'4initEP17IO80211ControllerP10ether_addrjPKc'),
                       (464,'12setLinkStateE16IO80211LinkStatej')]:
        target = pointer_at(table+8*index)
        assert '__ZN23IO80211VirtualInterface'+name in addresses.get(target,[]), (index,addresses.get(target))
    print('PASS: installed x86_64 family matches AWDL pure-slot and virtual-interface boundaries')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--family', type=Path, help='Optional IO80211Family binary to verify native boundaries')
    p.add_argument('--response', type=Path, help='Tahoe Xcode C++ response file')
    args = p.parse_args()
    responses = sorted(ROOT.glob('build/releases-obj/AirportRTW.build/*/AirportRTW-Tahoe.build/Objects-normal/x86_64/*common-args.resp'))
    response = args.response or (responses[0] if responses else None)
    if not response:
        p.error('Build the Tahoe target first, or specify --response')
    with tempfile.TemporaryDirectory(prefix='rtw-awdl-abi-') as directory:
        source = Path(directory) / 'probe.cpp'
        source.write_text('#include <Airport/macOS26/IO80211AWDLProtocol.h>\n'
                          '#include \"' + str(ROOT/'AirportRTW/WCL/AirportRTWAwdlInterface.hpp') + '\"\n'
                          'IOReturn probe(IO80211AWDLProtocol *p, apple80211_channel_data *c) { return p->getCHANNEL(c); }\n'
                          'IOReturn nativeProbe(AirportRTWAwdlInterface *p, apple80211_channel_data *c) { return p->getCHANNEL(c); }\n')
        result = subprocess.run(['xcrun', 'clang++', '@' + str(response.resolve()),
            '-Wno-inconsistent-missing-override', '-Wno-overloaded-virtual',
            '-Xclang', '-fdump-vtable-layouts', '-c', str(source),
            '-o', str(Path(directory) / 'probe.o')], cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        text = result.stdout
        match = re.search(r"Vtable for 'IO80211AWDLProtocol' .*?\n(.*?)(?:\n\n|\Z)", text, re.S)
        assert match, 'Compiler did not emit native AWDL vtable'
        slots = {int(n): v for n,v in re.findall(r'^\s*(\d+) \| (.*)$', match[1], re.M)}
        assert 'setMacAddress' in slots[490] and '[pure]' in slots[490]
        header = (ROOT/'include/Airport/macOS26/IO80211AWDLProtocol.h').read_text()
        awdl = header.split('class IO80211AWDLProtocol :',1)[1]
        methods = re.findall(r'virtual IOReturn\s+(\w+)\([^;]+?= 0;', awdl, re.S)
        assert len(methods)==63, len(methods)
        for index,name in enumerate(methods,507):
            assert 'IO80211AWDLProtocol::'+name+'(' in slots[index] and '[pure]' in slots[index], (index,name,slots.get(index))
        assert 'IO80211VirtualInterface::init(' in slots[463], slots[463]
        concrete = re.search(r"Vtable for 'AirportRTWAwdlInterface' .*?\n(.*?)(?:\n\n|\Z)", text, re.S)
        assert concrete, 'Compiler did not emit the concrete native interface layout'
        concrete_slots = {int(n): v for n,v in re.findall(r'^\s*(\d+) \| (.*)$', concrete[1], re.M)}
        for index,name in enumerate(methods,507):
            assert 'AirportRTWAwdlInterface::'+name+'(' in concrete_slots[index] and '[pure]' not in concrete_slots[index], (index,name)
        print('PASS: native Tahoe class sizes, virtual-interface boundary and all 63 concrete AWDL slots')
    if args.family:
        verify_family(args.family)

if __name__ == '__main__':
    main()
