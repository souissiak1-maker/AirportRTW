// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 *  rtw89_compat.c — rtw89-only pieces of the Linux-compat layer.
 *
 *  Compiled only into the rtw89 kext (RTW89_MACOS).  Complements the
 *  generic rtw88_compat.c, which stays in both builds; the rtw88-specific
 *  driver helpers there are guarded out and reimplemented by rtw89's
 *  in-driver bridge (Senmiko.c).
 */

#include "rtw88_compat.h"
#include "rtw89_compat.h"
#include <linux/usb.h>
#include <net/mac80211.h>

/* Defined in net/wireless/util.c on Linux; rtw89's fw.c uses it to build
 * the ARP-offload LLC header. */
const u8 rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

/* ------------------------------------------------------------------ */
/*  USB anchors                                                        */
/* ------------------------------------------------------------------ */
/* rtw89's usb.c tracks in-flight URBs with anchors.  The port's URB
 * emulation is synchronous-stub only (usb_submit_urb rejects, the kext
 * probes USB chips as unsupported), so the anchor just has to keep the
 * list bookkeeping consistent. */

void usb_anchor_urb(struct urb *urb, struct usb_anchor *anchor)
{
	if (!urb || !anchor)
		return;
	urb->anchor = anchor;
	list_add_tail(&urb->anchor_list, &anchor->urb_list);
}

void usb_unanchor_urb(struct urb *urb)
{
	if (!urb || !urb->anchor)
		return;
	list_del(&urb->anchor_list);
	urb->anchor = NULL;
}

void usb_kill_anchored_urbs(struct usb_anchor *anchor)
{
	struct urb *urb, *tmp;

	if (!anchor)
		return;
	list_for_each_entry_safe(urb, tmp, &anchor->urb_list, anchor_list) {
		usb_kill_urb(urb);
		list_del(&urb->anchor_list);
		urb->anchor = NULL;
	}
}
