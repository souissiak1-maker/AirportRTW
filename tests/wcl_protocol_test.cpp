// Host-side regression checks for untrusted native Wi-Fi request decoding.
#include "../AirportRTW/WCL/WCL.hpp"
#include <assert.h>

int main()
{
    AirportWCL::LqmBeaconUpdate beaconHealth;
    assert(!AirportWCL::makeBeaconUpdate(0, beaconHealth));
    assert(AirportWCL::makeBeaconUpdate(8, beaconHealth));
    assert(beaconHealth.receivedDelta == 8 && beaconHealth.scheduledDelta == 0);
    assert(beaconHealth.beaconValid && beaconHealth.snapshotValid && beaconHealth.countersValid);
    using namespace AirportWCL;
    const uint8_t valid[] = {0, 3, 'a', 'p', '1', 1, 1, 0x82};
    const uint8_t truncated[] = {0, 3, 'a'};
    assert(validIEs(valid, sizeof(valid)));
    assert(!validIEs(truncated, sizeof(truncated)));
    assert(!validIEs(nullptr, 3));

    uint8_t request[0x2cc] = {};
    JoinRequest join;
    // An empty request, an oversized SSID and a multicast AP must all fail.
    assert(!decodeJoin(request, sizeof(request), join));
    request[0x10] = 1;
    request[0x1c] = 3;
    memcpy(request + 0x20, "ap1", 3);
    request[0x214] = 1;
    request[0x21c] = 2;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Open);
    assert(!decodeJoin(request, 0x218, join));
    request[0x1c] = 33;
    assert(!decodeJoin(request, sizeof(request), join));
    request[0x1c] = 3;
    request[0x21c] = 1;
    assert(!decodeJoin(request, sizeof(request), join));

    // SAE needs the passphrase; a WPA2 PMK must never be treated as one.
    request[0x21c] = 2;
    request[0x15] = 0x10; // SAE: upper auth bit 12
    request[0x44] = 63; request[0x48] = 10;
    memset(request + 0x50, 'p', 63);
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::SAE);
    request[0x44] = 64;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    request[0x44] = 32; request[0x48] = 6;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    request[0x15] = 0; request[0x14] = 8;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Personal);
    request[0x48] = 10;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalPassphrase);
    request[0x44] = 7;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);

    uint8_t channels[32] = {};
    channels[36 / 8] |= 1u << (36 % 8);
    assert(scanChannelSelected(channels, true, 36));
    assert(!scanChannelSelected(channels, true, 1));
    assert(!scanChannelSelected(channels, true, 256));
    assert(!probeChannel(true, true, false));
    assert(!probeChannel(true, false, true));

    const uint8_t mac[] = {2, 1, 2, 3, 4, 5};
    const uint8_t multicast[] = {1, 1, 2, 3, 4, 5};
    assert(planMacUpdate(mac, mac, sizeof(mac), false) == MacUpdate::Unchanged);
    assert(planMacUpdate(mac, multicast, sizeof(mac), false) == MacUpdate::Invalid);
    assert(!validCipherKey(6, 31, 0, 0, 0));
    assert(validCipherKey(6, 32, 0, 0, 8));
    NativeChannelInfo native = {};
    assert(!appendChannel(native, 0, false, false, false, false, false));
    assert(appendChannel(native, 36, true, false, false, true, true));
    assert(native.count == 1 && native.channelSpec[0] == 0xd024);
    assert(native.firmwareChannelSpec[0] == native.channelSpec[0]);
    assert(native.supports80MHz[0] == 1);
    native.count = 400;
    assert(!appendChannel(native, 1, false, false, false, false, false));
    const uint64_t tx[] = {10, 20, 30, 40}, rx[] = {1, 2, 3, 4};
    auto counters = makeTrafficCounters(tx, rx, 123);
    assert(counters.infraTx == 100 && counters.infraRx == 10);
    assert(counters.realtimeInfraTx == 70 && counters.realtimeInfraRx == 7);
    assert(counters.timestampNanoseconds == 123);
    return 0;
}
