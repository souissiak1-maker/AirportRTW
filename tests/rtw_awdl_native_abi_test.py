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
    def bytes_at(address, length):
        for va, size, file_offset, file_size in segments:
            if va <= address and address+length <= va+min(size,file_size):
                return data[file_offset+address-va:file_offset+address-va+length]
        raise AssertionError('Native ABI evidence outside file-backed sections')
    traffic_wrapper = values['__ZL33setAWDL_PEER_TRAFFIC_REGISTRATIONP17IO80211ControllerP23IO80211SkywalkInterfaceP20IO80211APIUserClientP13apple80211req']
    # cmp dword [rcx+0x18],0xb8: native request-length check.
    assert bytes.fromhex('817918b8000000') in bytes_at(traffic_wrapper,64), 'Traffic request size changed'
    traffic_manager = values['__ZN22IO80211AWDLPeerManager30setAwdlPeerTrafficRegistrationEP41apple80211_awdl_peer_traffic_registration']
    traffic_code = bytes_at(traffic_manager,0x1000)
    assert bytes.fromhex('4d8d7e04') in traffic_code, 'Inline traffic MAC offset changed'
    assert bytes.fromhex('418b86a8000000') in traffic_code, 'Traffic active offset changed'
    cache_handler=values['__ZN25IO80211P2PDataPathManager26handleCacheControlMessagesEP29apple80211_peer_cache_control']
    cache_code=bytes_at(cache_handler,48)
    assert bytes.fromhex('8b5604') in cache_code, 'Cache completion operation offset changed'
    assert bytes.fromhex('83fa03') in cache_code and bytes.fromhex('83fa01') in cache_code, 'Cache completion values changed'
    print('PASS: installed x86_64 family matches AWDL slots, traffic layout and cache completion values')

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
        source.write_text('#include "'+str(ROOT/'AirportRTW/WCL/AirportRTWAwdlRuntime.hpp')+'"\n'
                          '#include "'+str(ROOT/'AirportRTW/WCL/AirportRTWAwdlPeers.hpp')+'"\n'
                          '#include <Airport/apple80211_var.h>\n'
                          '#include <Airport/apple80211_ioctl.h>\n'
                          'static_assert(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START==41, "native start event");\n'
                          'static_assert(sizeof(apple80211_awdl_peer_traffic_registration)==184, "native traffic size");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_peer_traffic_registration,addr)==4, "inline peer");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_peer_traffic_registration,name_len)==12, "name length");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_peer_traffic_registration,active)==168, "traffic active");\n'
                          'static_assert(sizeof(apple80211_awdl_sync_state)==24, "sync state");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_sync_state,master)==8, "parent address");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_sync_state,mode_flags)==20, "mode flags");\n'
                          'static_assert(sizeof(apple80211_awdl_sync_params)==24, "sync params");\n'
                          'static_assert(sizeof(apple80211_awdl_election_rssi_thresholds)==20, "RSSI thresholds");\n'
                          'static_assert(sizeof(apple80211_awdl_af_tx_mode)==8, "TX mode");\n'
                          'static_assert(sizeof(apple80211_awdl_oob_request)==56, "borrowed OOB request");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_oob_request,data)==48, "OOB pointer");\n'
                          'static_assert(sizeof(apple80211_awdl_sync_channel_sequence)==400, "channel sequence");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_sync_channel_sequence,seqs)==12, "channel descriptors");\n'
                          'static_assert(sizeof(((apple80211_awdl_sync_channel_sequence*)0)->seqs[0])==12, "channel descriptor stride");\n'
                          '#include <Airport/macOS26/IO80211AWDLProtocol.h>\n'
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
        # The shared header must retain old layouts for older targets.
        source.write_text('#include <Availability.h>\n#undef __IO80211_TARGET\n'
                          '#define __IO80211_TARGET __MAC_12_0\n'
                          '#include <Airport/apple80211_var.h>\n'
                          '#include <Airport/apple80211_ioctl.h>\n'
                          'static_assert(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START==42, "legacy start event preserved");\n'
                          'static_assert(sizeof(apple80211_awdl_peer_traffic_registration)==172, "legacy traffic size");\n'
                          'static_assert(sizeof(((apple80211_awdl_peer_traffic_registration*)0)->addr)==sizeof(void*), "legacy pointer preserved");\n'
                          'static_assert(sizeof(apple80211_awdl_sync_state)==8, "legacy sync state");\n'
                          'static_assert(sizeof(apple80211_awdl_sync_params)==20, "legacy sync params");\n'
                          'static_assert(sizeof(apple80211_awdl_election_rssi_thresholds)==16, "legacy RSSI");\n'
                          'static_assert(sizeof(apple80211_awdl_af_tx_mode)==12, "legacy TX mode");\n'
                          'static_assert(sizeof(apple80211_awdl_oob_request)==1830, "legacy inline OOB");\n'
                          'static_assert(__builtin_offsetof(apple80211_awdl_sync_channel_sequence,seqs)==16, "legacy channel sequence");\n')
        result = subprocess.run(['xcrun','clang++','@'+str(response.resolve()),
            '-fsyntax-only',str(source)], cwd=ROOT,capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        print('PASS: native Tahoe payloads and 63 AWDL slots; legacy payload layouts preserved')
    if args.family:
        verify_family(args.family)

if __name__ == '__main__':
    main()
