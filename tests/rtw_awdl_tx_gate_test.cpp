/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlTxGate.hpp>
#include <atomic>
#include <cassert>
#include <thread>
#include <vector>
#include <cstdio>
int main() {
    RTWAwdl::TxGate gate{};
    {
        RTWAwdl::TxGuard active(gate);assert(active);
        assert(gate.pause() && !gate.pause() && !gate.drained());
        RTWAwdl::TxGuard rejected(gate);assert(!rejected);
    }
    assert(gate.drained());gate.resume();
    // Producers race pause acquisition. A drained paused gate must protect the
    // radio owner's critical section until resume, without losing queue entries.
    std::atomic<bool> stop{false};
    std::atomic<unsigned> inside{0},submitted{0};
    std::vector<std::thread> workers;
    for(unsigned i=0;i<4;++i) workers.emplace_back([&]{
        while(!stop.load()) {
            RTWAwdl::TxGuard guard(gate);
            if(guard) {++inside;++submitted;std::this_thread::yield();--inside;}
        }
    });
    while(!submitted.load())std::this_thread::yield();
    for(unsigned i=0;i<2000;++i) {
        assert(gate.pause());
        while(!gate.drained())std::this_thread::yield();
        assert(!inside.load());
        for(unsigned j=0;j<8;++j) {std::this_thread::yield();assert(!inside.load());}
        gate.resume();
    }
    stop=true;for(auto &worker:workers)worker.join();
    assert(gate.drained() && submitted.load());
    gate.users=UINT32_MAX;assert(!gate.enter() && gate.users==UINT32_MAX);gate.users=0;
    puts("PASS: AWDL submission gate drains in-flight producers before retune");
}
