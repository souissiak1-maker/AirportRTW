/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_RECEIVE_REGISTRATION_HPP
#define RTW_AWDL_RECEIVE_REGISTRATION_HPP
#include <HAL/RTWAwdlReceive.hpp>
#include <AWDL/RTWAwdlFrame.hpp>
#include <AWDL/RTWAwdlData.hpp>
// Include after IOKit locking and OSObject declarations (host adapters in tests).
namespace RTWAwdl {
struct ReceiveRegistration {
    IOLock *lock;
    OSObject *owner;
    ReceiveHandler handler;
    uint8_t localAddress[6];
    bool enabled;
};
static inline bool initializeReceiver(ReceiveRegistration &r) {
    if (r.lock) return false;
    r = {}; r.lock = IOLockAlloc(); return r.lock != nullptr;
}
static inline bool openReceiver(ReceiveRegistration &r, const uint8_t mac[6]) {
    if (!r.lock || !mac || (mac[0] & 1)) return false;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= mac[i];
    if (!bits) return false;
    IOLockLock(r.lock);
    bool opened = !__atomic_load_n(&r.enabled, __ATOMIC_ACQUIRE) && !r.owner;
    if (opened) { memcpy(r.localAddress, mac, 6); __atomic_store_n(&r.enabled, true, __ATOMIC_RELEASE); }
    IOLockUnlock(r.lock);
    return opened;
}
static inline bool bindReceiver(ReceiveRegistration &r, OSObject *owner,
                                ReceiveHandler handler) {
    if (!r.lock || bool(owner) != bool(handler)) return false;
    if (owner) owner->retain();
    IOLockLock(r.lock);
    const bool accepted = !owner || __atomic_load_n(&r.enabled, __ATOMIC_ACQUIRE);
    OSObject *old = nullptr;
    if (accepted) { old = r.owner; r.owner = owner; r.handler = handler; }
    IOLockUnlock(r.lock);
    // Final release may run a destructor; never do it while holding RX's lock.
    if (old) old->release();
    if (!accepted && owner) owner->release();
    return accepted;
}
static inline void closeReceiver(ReceiveRegistration &r) {
    if (!r.lock) return;
    IOLockLock(r.lock);
    __atomic_store_n(&r.enabled, false, __ATOMIC_RELEASE);
    OSObject *old = r.owner; r.owner = nullptr; r.handler = nullptr;
    memset(r.localAddress, 0, 6);
    IOLockUnlock(r.lock);
    if (old) old->release();
}
// Only after the HAL's RX producers have stopped; close alone does not permit
// freeing a lock while another RX worker is about to enter dispatchReceiver.
static inline void destroyReceiver(ReceiveRegistration &r) {
    closeReceiver(r);
    if (r.lock) IOLockFree(r.lock);
    r = {};
}
static inline bool dispatchReceiver(ReceiveRegistration &r,
    const uint8_t *frame, size_t length, int32_t rssi, uint16_t frequency,
    uint32_t timestamp, bool timestampValid) {
    if (!r.lock || !__atomic_load_n(&r.enabled, __ATOMIC_ACQUIRE) ||
        !frame || length < 24 || length > DataCodec::maximumAggregateFrame) return false;
    IOLockLock(r.lock);
    bool handled = false;
    if (__atomic_load_n(&r.enabled, __ATOMIC_ACQUIRE) && r.owner && r.handler) {
        const bool addressed = (frame[4] & 1) || !memcmp(frame + 4, r.localAddress, 6);
        uint8_t sourceBits = 0;
        for (unsigned i = 0; i < 6; ++i) sourceBits |= frame[10 + i];
        if (addressed && sourceBits && !(frame[10] & 1) &&
            memcmp(frame + 10, r.localAddress, 6)) {
            ActionInfo action;
            DataCodec::View data;
            ReceiveMetadata metadata = {FrameKind::Action,rssi,frequency,timestamp,timestampValid};
            static const uint8_t bssid[6] = {0,0x25,0,0xff,0x94,0x73};
            if (parseFrame(frame,length,action) == ParseResult::Valid &&
                (action.subtype == 0 || action.subtype == 3) &&
                !memcmp(frame + 16, bssid, 6)) handled = true;
            else if (DataCodec::inspect(frame,length,data) || DataCodec::validAggregate(frame,length)) {
                metadata.kind = FrameKind::IPv6; handled = true;
            }
            if (handled) r.handler(r.owner,frame,length,metadata);
        }
    }
    IOLockUnlock(r.lock);
    return handled;
}
}
#endif
