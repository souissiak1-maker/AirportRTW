#!/usr/bin/env python3
"""Read non-secret WPA2/WPA3 join and PHY diagnostics from the loaded driver."""
import json
import plistlib
import struct
import subprocess

tree = plistlib.loads(subprocess.check_output(
    ["ioreg", "-a", "-r", "-c", "AirportRTW", "-l"]))

def controllers(value):
    if isinstance(value, dict):
        if "RTWSAEStage" in value:
            yield value
        for child in value.get("IORegistryEntryChildren", []):
            yield from controllers(child)
    elif isinstance(value, list):
        for child in value:
            yield from controllers(child)

def decode_headers(raw, count):
    records = []
    if isinstance(raw, bytes) and len(raw) == 128:
        for number in range(max(0, count - 8), count):
            control, length, flags, ether_type = struct.unpack_from("<IIII", raw, (number % 8) * 16)
            records.append({"number": number + 1, "control": hex(control), "length": length,
                "state": flags >> 8, "null_data": bool(control & 0x40),
                "protected": bool(control & 0x4000), "decrypted": bool(flags & 1),
                "iv_stripped": bool(flags & 2), "addressed_to_station": bool(flags & 4),
                "multicast": bool(flags & 8),
                "ether_type": None if ether_type == 0xffffffff else hex(ether_type)})
    return records

def decode_early(raw):
    names = ("core_data", "core_eapol", "core_crc_errors", "core_icv_errors",
             "core_wrong_destination", "bridge_data", "bridge_eapol", "bridge_crc_errors",
             "delivered_data", "delivered_eapol", "core_management", "core_beacons",
             "core_ppdu_queued_data")
    if not isinstance(raw, bytes) or len(raw) not in (52, 132):
        return None
    result = dict(zip(names, struct.unpack_from("<13I", raw)))
    if len(raw) == 132:
        subtypes = ("assoc_request", "assoc_response", "reassoc_request", "reassoc_response",
                    "probe_request", "probe_response", "timing_advertisement", "reserved7",
                    "beacon", "atim", "disassoc", "auth", "deauth", "action", "action_no_ack", "reserved15")
        result["management_subtypes"] = dict(zip(subtypes, struct.unpack_from("<16I", raw, 52)))
        result.update(zip(("management_wrong_destination", "association_retries",
                           "association_envelope_valid", "association_dispatch_rejected"),
                          struct.unpack_from("<4I", raw, 116)))
    return result

def decode_peer(raw):
    if not isinstance(raw, bytes) or len(raw) != 44:
        return None
    names = ("configured_rx_filter", "hardware_rx_filter", "management_forwarding",
             "data_forwarding", "network_type", "address_cam_valid", "bssid_cam_valid",
             "station_mac_matches", "peer_bssid_matches", "scanning", "associated")
    return dict(zip(names, struct.unpack("<11I", raw)))

for properties in controllers(tree):
    result = {k: v for k, v in properties.items()
              if ((k.startswith("RTWSAE") or k.startswith("RTWLastIncompleteJoin"))
                  and not k.endswith(("Headers", "EarlyRx"))) or
              k in ("RTW89HECapable", "RTW89HEEnabled", "RTW89NegotiatedPHY", "RTW89StationState",
                       "RTW89EAPOLTxPolicy", "RTW89EAPOLTxSubmitted", "RTW89EAPOLTxAcked")}
    result["headers"] = decode_headers(properties.get("RTWSAERxHeaders", b""),
                                        properties.get("RTWSAERawData", 0))
    result["last_incomplete_headers"] = decode_headers(
        properties.get("RTWLastIncompleteJoinHeaders", b""),
        properties.get("RTWLastIncompleteJoinData", 0))
    result["peer_audit"] = decode_peer(properties.get("RTW89PeerAudit"))
    result["early_rx"] = decode_early(properties.get("RTWJoinEarlyRx"))
    result["last_incomplete_early_rx"] = decode_early(properties.get("RTWLastIncompleteJoinEarlyRx"))
    result["incomplete_joins"] = []
    for saved in properties.get("RTWIncompleteJoins", []):
        record = {k: v for k, v in saved.items() if k not in ("Headers", "EarlyRx", "PeerAudit")}
        record["headers"] = decode_headers(saved.get("Headers"), saved.get("Data", 0))
        record["early_rx"] = decode_early(saved.get("EarlyRx"))
        record["peer_audit"] = decode_peer(saved.get("PeerAudit"))
        result["incomplete_joins"].append(record)
    print(json.dumps(result, indent=2))
