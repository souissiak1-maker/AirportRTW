/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <Availability.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include "AirportRTWAwdlActionInput.hpp"
#include <AWDL/RTWAwdlFrame.hpp>
#include <libkern/libkern.h>

// Concrete exported MallocBuffer methods avoid fabricating a buffer class,
// guessing its vtable or borrowing radio memory across asynchronous delivery.
extern "C" {
void *rtw_awdl_action_allocate(const void *)
    __asm__("__ZN19IO80211MallocBuffer11withOptionsEP20IO80211BufferOptions");
void *rtw_awdl_action_bytes(void *)
    __asm__("__ZN19IO80211MallocBuffer14getBytesNoCopyEv");
void rtw_awdl_action_set_length(void *, size_t)
    __asm__("__ZN19IO80211MallocBuffer9setLengthEm");
void rtw_awdl_action_release(void *)
    __asm__("__ZN19IO80211MallocBuffer12returnBufferEv");
void rtw_awdl_action_input(IO80211VirtualInterface *, void *, uint32_t, void *, size_t)
    __asm__("__ZN23IO80211VirtualInterface11bpfTapInputEP13IO80211BufferjPvm");
}

bool AirportRTWAwdlActionInput::deliver(IO80211VirtualInterface *interface,
    const uint8_t *frame, size_t length, const uint8_t *metadata, size_t metadataLength)
{
    // IO80211AWDLPeerManager traps on metadata >72 and rejects <72. Validate
    // before allocating, and never pass a caller-controlled length through.
    if (!interface || !metadata || metadataLength != 72) return false;
    RTWAwdl::ActionInfo info;
    if (RTWAwdl::parseFrame(frame,length,info) != RTWAwdl::ParseResult::Valid ||
        (info.subtype != 0 && info.subtype != 3)) return false;
    if ((frame[10] & 1) || memcmp(frame + 10,metadata,6)) return false;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= frame[10+i];
    if (!bits) return false;
    // Native MallocBuffer options are 48 bytes: capacity in the first word.
    // Verified against the local family's MallocBufferPool::getBuffer and
    // MallocBuffer::initWithOptions. No pool/slab pointer is borrowed.
    uint64_t options[6] {length - 24,0,0,0,0,0};
    void *buffer = rtw_awdl_action_allocate(options);
    if (!buffer) return false;
    void *bytes = rtw_awdl_action_bytes(buffer);
    if (!bytes) { rtw_awdl_action_release(buffer); return false; }
    memcpy(bytes,frame + 24,length - 24);
    rtw_awdl_action_set_length(buffer,length - 24);
    uint8_t header[72]; memcpy(header,metadata,sizeof(header));
    // The family consumes buffer on every path, including peer-manager reject.
    // It copies the metadata before returning; never release or reuse buffer.
    rtw_awdl_action_input(interface,buffer,12,header,sizeof(header));
    return true;
}
#endif
