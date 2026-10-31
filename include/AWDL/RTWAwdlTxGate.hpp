/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_TX_GATE_HPP
#define RTW_AWDL_TX_GATE_HPP
#include <stdint.h>
namespace RTWAwdl {
// Initialize to zero before producers start; never copy a live gate. The radio
// owner serializes pause/resume and waits for drained() before retuning.
// Producers enter before dequeueing a packet, preserving queue ownership when
// paused. This gate protects software submissions, not DMA/TX already in flight.
// Sequential consistency closes the cross-atomic paused/users handshake:
// pause+drain must not race a producer observing an old unpaused value.
struct TxGate {
    uint32_t paused;
    uint32_t users;
    bool enter() {
        if (isPaused()) return false;
        uint32_t count=__atomic_load_n(&users,__ATOMIC_RELAXED);
        do {
            if (count==UINT32_MAX) return false;
        } while (!__atomic_compare_exchange_n(&users,&count,count+1,false,
                                              __ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST));
        if (isPaused()) { leave(); return false; }
        return true;
    }
    void leave() { __atomic_fetch_sub(&users,1,__ATOMIC_SEQ_CST); }
    bool pause() {
        uint32_t expected=0;
        return __atomic_compare_exchange_n(&paused,&expected,1,false,
                                           __ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
    }
    bool drained() const { return __atomic_load_n(&users,__ATOMIC_SEQ_CST)==0; }
    bool isPaused() const { return __atomic_load_n(&paused,__ATOMIC_SEQ_CST)!=0; }
    void resume() { __atomic_store_n(&paused,0,__ATOMIC_SEQ_CST); }
};
class TxGuard {
public:
    explicit TxGuard(TxGate &gate) : gate_(gate), entered_(gate.enter()) {}
    ~TxGuard() { if (entered_) gate_.leave(); }
    explicit operator bool() const { return entered_; }
    TxGuard(const TxGuard &)=delete;
    TxGuard &operator=(const TxGuard &)=delete;
private:
    TxGate &gate_;
    bool entered_;
};
}
#endif
