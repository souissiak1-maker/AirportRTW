// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Senmiko.c — macOS (Senmiko kext) bridge for rtw89.
 *
 * Compiled only for the macOS port (RTW89_MACOS).  The Senmiko kext was
 * written against the rtw88 port and links against a fixed set of symbol
 * names (rtw88_* helpers plus a few rtw_* driver entry points).  This file
 * implements those same names on top of rtw89 so the kext sources build
 * against either driver unchanged.
 *
 * It lives inside the driver tree (not in the kext's compat layer) because
 * it needs the real rtw89 headers; the compat tree's linux/pci.h shadows
 * the driver's pci.h on the kext include path.
 */
#ifdef RTW89_MACOS

#include "cam.h"
#include "chan.h"
#include "coex.h"
#include "core.h"
#include "debug.h"
#include "fw.h"
#include "mac.h"
#include "pci.h"
#include "ps.h"
#include "txrx.h"

/* The kext-facing API (declared in rtw88_compat.h, force-included) passes
 * an opaque "struct rtw_dev *"; here it is really a struct rtw89_dev. */
#define to_rtw89(p) ((struct rtw89_dev *)(p))

/* Globals shared with the generic compat layer (rtw88_compat.c). */
extern void *g_irq_dev_id;                       /* rtw89_dev of active IRQ */
extern struct ieee80211_hw *rtw88_get_hw(void);

/* Track-work kill switch consumed by core.c (macOS diagnostic patch).
 *
 * Enabled: the 2 s periodic track_work runs only *after association* its
 * STA-specific RF-dynamic routines (RA/DIG/CFO/BF-monitor/beacon-track/RFK).
 * These are the prime suspect for the "no tx fwcmd resource" wedge that hits a
 * few seconds after connect and kills DHCP (the first post-assoc track_work
 * fires ~2 s in, before DHCP completes; the fwcmd ring exhausts ~40 s later).
 * Set true to bypass all of it and confirm whether periodic RF work is the
 * cause; if the link then stays alive and DHCP succeeds, bisect the routines
 * in rtw89_track_work() to find the offender. */
bool rtw89_disable_track_work = true;

/* ------------------------------------------------------------------ */
/*  PCI probe/remove                                                   */
/* ------------------------------------------------------------------ */

/* Per-chip PCI id tables exported by the rtw89 *e.c files under
 * RTW89_MACOS.  Each table is zero-terminated and its driver_data
 * carries the chip's rtw89_driver_info, exactly as the Linux PCI core
 * would pass it. */
extern const struct pci_device_id *rtw89_8851be_feixiao_ids;
extern const struct pci_device_id *rtw89_8852ae_feixiao_ids;
extern const struct pci_device_id *rtw89_8852be_feixiao_ids;
extern const struct pci_device_id *rtw89_8852bte_feixiao_ids;
extern const struct pci_device_id *rtw89_8852ce_feixiao_ids;
extern const struct pci_device_id *rtw89_8922ae_feixiao_ids;

static const struct pci_device_id *rtw89_feixiao_match(u16 device)
{
	const struct pci_device_id **tables[] = {
		&rtw89_8851be_feixiao_ids,
		&rtw89_8852ae_feixiao_ids,
		&rtw89_8852be_feixiao_ids,
		&rtw89_8852bte_feixiao_ids,
		&rtw89_8852ce_feixiao_ids,
		&rtw89_8922ae_feixiao_ids,
	};
	const struct pci_device_id *id;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		for (id = *tables[i]; id->vendor; id++)
			if (id->device == device)
				return id;
	return NULL;
}

/* The kext calls rtw_pci_probe() with a fake pci_device_id it built from
 * its own chip table; for rtw89 the real driver_data (rtw89_driver_info)
 * lives in the *e.c id tables, so match by PCI device id and ignore the
 * caller's driver_data. */
int rtw_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	const struct pci_device_id *real_id = rtw89_feixiao_match(pdev->device);

	if (!real_id) {
		pr_err("rtw89: no chip info for PCI device %04x\n",
		       pdev->device);
		return -ENODEV;
	}

	return rtw89_pci_probe(pdev, real_id);
}

void rtw_pci_remove(struct pci_dev *pdev)
{
	rtw89_pci_remove(pdev);
}

/* USB path not wired up for rtw89 yet; PCIe chips only. */
int rtw_usb_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	return -ENODEV;
}

void rtw_usb_disconnect(struct usb_interface *intf)
{
}

/* ------------------------------------------------------------------ */
/*  Interrupt / TX-ring helpers                                        */
/* ------------------------------------------------------------------ */

void rtw88_reenable_interrupt(void)
{
	if (g_irq_dev_id)
		rtw89_pci_enable_intr_lock(to_rtw89(g_irq_dev_id));
}

/* BE-ring free-slot count for the kext TX flow-control (backpressure)
 * decision.  Same math as pci.c's rtw89_pci_get_avail_txbd_num(), clamped
 * by the wd ring like __rtw89_pci_check_and_reclaim_tx_resource_noio();
 * read locklessly — a stale value only makes the kext stall or resume one
 * frame early, never corrupts state. */
u32 rtw88_be_ring_avail(struct rtw_dev *rtwdev_opaque)
{
	struct rtw89_dev *rtwdev = to_rtw89(rtwdev_opaque);
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	struct rtw89_pci_tx_ring *tx_ring;
	struct rtw89_pci_dma_ring *bd_ring;
	u32 avail;
	u8 txch;

	txch = rtw89_chip_get_ch_dma(rtwdev, RTW89_TX_QSEL_BE_0);
	tx_ring = &rtwpci->tx.rings[txch];
	bd_ring = &tx_ring->bd_ring;

	if (bd_ring->rp > bd_ring->wp)
		avail = bd_ring->rp - bd_ring->wp - 1;
	else
		avail = bd_ring->len - (bd_ring->wp - bd_ring->rp) - 1;

	return min(avail, tx_ring->wd_ring.curr_num);
}

static u32 rtw89_feixiao_ring_pending(u32 wp, u32 rp, u32 len)
{
	if (!len)
		return 0;
	return wp >= rp ? wp - rp : len - (rp - wp);
}

static u32 rtw89_feixiao_ring_avail(u32 wp, u32 rp, u32 len)
{
	u32 pending;

	if (len < 2)
		return 0;
	pending = rtw89_feixiao_ring_pending(wp, rp, len);
	return pending < len ? len - pending - 1 : 0;
}

/* Passive snapshot for the WPA2 M2 diagnostic.  This deliberately reads only
 * cached software fields.  In particular it does NOT read MMIO, schedule NAPI,
 * acknowledge interrupts, reclaim descriptors, dequeue skbs or walk lists. */
bool rtw88_get_tx_ring_snapshot(struct rtw_dev *rtwdev_opaque,
				struct rtw88_tx_ring_snapshot *snapshot)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_pci *rtwpci;
	struct rtw89_pci_tx_ring *be;
	struct rtw89_pci_tx_ring *fwcmd;
	struct rtw89_pci_rx_ring *rpq;
	u32 be_wp, be_rp, be_len;
	u32 fw_wp, fw_rp, fw_len;
	u8 txch;

	if (!rtwdev_opaque || !snapshot)
		return false;
	memset(snapshot, 0, sizeof(*snapshot));

	rtwdev = to_rtw89(rtwdev_opaque);
	rtwpci = (struct rtw89_pci *)rtwdev->priv;
	txch = rtw89_chip_get_ch_dma(rtwdev, RTW89_TX_QSEL_BE_0);
	if (txch >= RTW89_TXCH_NUM)
		return false;

	be = &rtwpci->tx.rings[txch];
	fwcmd = &rtwpci->tx.rings[RTW89_TXCH_CH12];
	rpq = &rtwpci->rx.rings[RTW89_RXCH_RPQ];

	be_wp = READ_ONCE(be->bd_ring.wp);
	be_rp = READ_ONCE(be->bd_ring.rp);
	be_len = READ_ONCE(be->bd_ring.len);
	fw_wp = READ_ONCE(fwcmd->bd_ring.wp);
	fw_rp = READ_ONCE(fwcmd->bd_ring.rp);
	fw_len = READ_ONCE(fwcmd->bd_ring.len);

	snapshot->valid = 1;
	snapshot->be_txch = txch;
	snapshot->be_bd_wp = be_wp;
	snapshot->be_bd_rp = be_rp;
	snapshot->be_bd_len = be_len;
	snapshot->be_bd_pending = rtw89_feixiao_ring_pending(be_wp, be_rp, be_len);
	snapshot->be_bd_avail = rtw89_feixiao_ring_avail(be_wp, be_rp, be_len);
	snapshot->be_wd_avail = READ_ONCE(be->wd_ring.curr_num);
	snapshot->be_wd_total = READ_ONCE(be->wd_ring.page_num);
	snapshot->be_tag = READ_ONCE(be->tag);
	snapshot->be_dma_enabled = READ_ONCE(be->dma_enabled) ? 1 : 0;
	snapshot->be_tx_cnt = READ_ONCE(be->tx_cnt);
	snapshot->be_tx_acked = READ_ONCE(be->tx_acked);
	snapshot->be_tx_retry_lmt = READ_ONCE(be->tx_retry_lmt);
	snapshot->be_tx_life_time = READ_ONCE(be->tx_life_time);
	snapshot->be_tx_mac_id_drop = READ_ONCE(be->tx_mac_id_drop);
	snapshot->rpq_bd_wp = READ_ONCE(rpq->bd_ring.wp);
	snapshot->rpq_bd_rp = READ_ONCE(rpq->bd_ring.rp);
	snapshot->rpq_bd_len = READ_ONCE(rpq->bd_ring.len);
	snapshot->fwcmd_bd_wp = fw_wp;
	snapshot->fwcmd_bd_rp = fw_rp;
	snapshot->fwcmd_bd_len = fw_len;
	snapshot->fwcmd_bd_pending = rtw89_feixiao_ring_pending(fw_wp, fw_rp, fw_len);
	snapshot->fwcmd_bd_avail = rtw89_feixiao_ring_avail(fw_wp, fw_rp, fw_len);
	/* Reading qlen is a single aligned scalar load in this compat layer. */
	snapshot->h2c_queue_len = READ_ONCE(rtwpci->h2c_queue.qlen);
	snapshot->h2c_release_queue_len = READ_ONCE(rtwpci->h2c_release_queue.qlen);
	snapshot->pci_running = READ_ONCE(rtwpci->running) ? 1 : 0;
	snapshot->pci_under_recovery = READ_ONCE(rtwpci->under_recovery) ? 1 : 0;
	snapshot->power_on = test_bit(RTW89_FLAG_POWERON, rtwdev->flags) ? 1 : 0;
	return true;
}

/* Same passive snapshot, plus the exact hardware TX ring selected by a TID.
 * This is needed now that EAPOL is sent on TID 7/VO rather than the BE ring. */
bool rtw88_get_tx_ring_snapshot_tid(struct rtw_dev *rtwdev_opaque, u8 tid,
				    struct rtw88_tx_ring_snapshot *snapshot)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_pci *rtwpci;
	struct rtw89_pci_tx_ring *tx_ring;
	u32 wp, rp, len;
	u8 qsel, txch;

	if (!rtw88_get_tx_ring_snapshot(rtwdev_opaque, snapshot))
		return false;

	rtwdev = to_rtw89(rtwdev_opaque);
	rtwpci = (struct rtw89_pci *)rtwdev->priv;
	tid &= IEEE80211_QOS_CTL_TAG1D_MASK;
	qsel = rtw89_core_get_qsel(rtwdev, tid);
	txch = rtw89_chip_get_ch_dma(rtwdev, qsel);
	if (txch >= RTW89_TXCH_NUM)
		return false;

	tx_ring = &rtwpci->tx.rings[txch];
	wp = READ_ONCE(tx_ring->bd_ring.wp);
	rp = READ_ONCE(tx_ring->bd_ring.rp);
	len = READ_ONCE(tx_ring->bd_ring.len);

	snapshot->txq_tid = tid;
	snapshot->txq_qsel = qsel;
	snapshot->txq_txch = txch;
	snapshot->txq_bd_wp = wp;
	snapshot->txq_bd_rp = rp;
	snapshot->txq_bd_len = len;
	snapshot->txq_bd_pending = rtw89_feixiao_ring_pending(wp, rp, len);
	snapshot->txq_bd_avail = rtw89_feixiao_ring_avail(wp, rp, len);
	snapshot->txq_wd_avail = READ_ONCE(tx_ring->wd_ring.curr_num);
	snapshot->txq_wd_total = READ_ONCE(tx_ring->wd_ring.page_num);
	snapshot->txq_tag = READ_ONCE(tx_ring->tag);
	snapshot->txq_dma_enabled = READ_ONCE(tx_ring->dma_enabled) ? 1 : 0;
	snapshot->txq_tx_cnt = READ_ONCE(tx_ring->tx_cnt);
	snapshot->txq_tx_acked = READ_ONCE(tx_ring->tx_acked);
	snapshot->txq_tx_retry_lmt = READ_ONCE(tx_ring->tx_retry_lmt);
	snapshot->txq_tx_life_time = READ_ONCE(tx_ring->tx_life_time);
	snapshot->txq_tx_mac_id_drop = READ_ONCE(tx_ring->tx_mac_id_drop);
	return true;
}

/* Passive snapshot of the B0 management queue used by the 0.2.25
 * EAPOL DATA-frame diagnostic.  The rtw89 port-control override selects
 * QSEL_B0_MGMT while preserving the normal DATA descriptor construction. */
bool rtw88_get_tx_ring_snapshot_highq(struct rtw_dev *rtwdev_opaque, u8 tid,
                                      struct rtw88_tx_ring_snapshot *snapshot)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_pci *rtwpci;
	struct rtw89_pci_tx_ring *tx_ring;
	u32 wp, rp, len;
	u8 qsel = RTW89_TX_QSEL_B0_MGMT;
	u8 txch;

	if (!rtw88_get_tx_ring_snapshot(rtwdev_opaque, snapshot))
		return false;

	rtwdev = to_rtw89(rtwdev_opaque);
	rtwpci = (struct rtw89_pci *)rtwdev->priv;
	txch = rtw89_chip_get_ch_dma(rtwdev, qsel);
	if (txch >= RTW89_TXCH_NUM)
		return false;

	tx_ring = &rtwpci->tx.rings[txch];
	wp = READ_ONCE(tx_ring->bd_ring.wp);
	rp = READ_ONCE(tx_ring->bd_ring.rp);
	len = READ_ONCE(tx_ring->bd_ring.len);

	snapshot->txq_tid = tid & IEEE80211_QOS_CTL_TAG1D_MASK;
	snapshot->txq_qsel = qsel;
	snapshot->txq_txch = txch;
	snapshot->txq_bd_wp = wp;
	snapshot->txq_bd_rp = rp;
	snapshot->txq_bd_len = len;
	snapshot->txq_bd_pending = rtw89_feixiao_ring_pending(wp, rp, len);
	snapshot->txq_bd_avail = rtw89_feixiao_ring_avail(wp, rp, len);
	snapshot->txq_wd_avail = READ_ONCE(tx_ring->wd_ring.curr_num);
	snapshot->txq_wd_total = READ_ONCE(tx_ring->wd_ring.page_num);
	snapshot->txq_tag = READ_ONCE(tx_ring->tag);
	snapshot->txq_dma_enabled = READ_ONCE(tx_ring->dma_enabled) ? 1 : 0;
	snapshot->txq_tx_cnt = READ_ONCE(tx_ring->tx_cnt);
	snapshot->txq_tx_acked = READ_ONCE(tx_ring->tx_acked);
	snapshot->txq_tx_retry_lmt = READ_ONCE(tx_ring->tx_retry_lmt);
	snapshot->txq_tx_life_time = READ_ONCE(tx_ring->tx_life_time);
	snapshot->txq_tx_mac_id_drop = READ_ONCE(tx_ring->tx_mac_id_drop);
	return true;
}

/* Cached station/VIF/CAM context only.  No firmware command or MMIO access. */
bool rtw88_get_sta_context_snapshot(struct rtw_dev *rtwdev_opaque,
				    struct ieee80211_vif *vif,
				    struct ieee80211_sta *sta,
				    struct rtw88_sta_context_snapshot *snapshot)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_vif *rtwvif;
	struct rtw89_sta *rtwsta;
	struct rtw89_vif_link *rtwvif_link;
	struct rtw89_sta_link *rtwsta_link;
	struct rtw89_addr_cam_entry *addr_cam;
	struct rtw89_bssid_cam_entry *bssid_cam;
	unsigned int link_id;

	if (!rtwdev_opaque || !vif || !sta || !snapshot)
		return false;
	memset(snapshot, 0, sizeof(*snapshot));

	rtwdev = to_rtw89(rtwdev_opaque);
	rtwvif = vif_to_rtwvif(vif);
	rtwsta = sta_to_rtwsta(sta);
	link_id = vif->bss_conf.link_id;
	if (link_id >= IEEE80211_MLD_MAX_NUM_LINKS)
		return false;
	rtwvif_link = rtwvif->links[link_id];
	rtwsta_link = rtwsta->links[link_id];

	snapshot->valid = 1;
	snapshot->vif_link_present = rtwvif_link ? 1 : 0;
	snapshot->sta_link_present = rtwsta_link ? 1 : 0;
	snapshot->vif_cfg_assoc = vif->cfg.assoc ? 1 : 0;
	snapshot->bss_assoc = vif->bss_conf.assoc ? 1 : 0;
	snapshot->bss_qos = vif->bss_conf.qos ? 1 : 0;
	snapshot->sta_wme = sta->wme ? 1 : 0;
	snapshot->aid = sta->aid;
	if (!rtwvif_link || !rtwsta_link)
		return true;

	snapshot->vif_mac_id = rtwvif_link->mac_id;
	snapshot->sta_mac_id = rtwsta_link->mac_id;
	snapshot->mac_id_match = rtwvif_link->mac_id == rtwsta_link->mac_id;
	snapshot->assoc_map_match =
		READ_ONCE(rtwdev->assoc_link_on_macid[rtwsta_link->mac_id]) == rtwsta_link;
	snapshot->sta_vif_link_match = rtwsta_link->rtwvif_link == rtwvif_link;
	snapshot->port = rtwvif_link->port;
	snapshot->mac_idx = rtwvif_link->mac_idx;
	snapshot->phy_idx = rtwvif_link->phy_idx;
	snapshot->wmm = rtwvif_link->wmm;
	snapshot->net_type = rtwvif_link->net_type;
	snapshot->wifi_role = rtwvif_link->wifi_role;
	snapshot->self_role = rtwvif_link->self_role;
	snapshot->chanctx_assigned = rtwvif_link->chanctx_assigned ? 1 : 0;
	snapshot->chanctx_idx = rtwvif_link->chanctx_idx;

	addr_cam = rtw89_get_addr_cam_of(rtwvif_link, rtwsta_link);
	bssid_cam = rtw89_get_bssid_cam_of(rtwvif_link, rtwsta_link);
	if (addr_cam) {
		snapshot->addr_cam_valid = addr_cam->valid;
		snapshot->addr_cam_idx = addr_cam->addr_cam_idx;
		snapshot->addr_cam_bssid_idx = addr_cam->bssid_cam_idx;
		snapshot->addr_cam_mask_sel = addr_cam->mask_sel;
		snapshot->addr_cam_addr_mask = addr_cam->addr_mask;
	}
	if (bssid_cam) {
		snapshot->bssid_cam_valid = bssid_cam->valid;
		snapshot->bssid_cam_idx = bssid_cam->bssid_cam_idx;
		snapshot->bssid_cam_phy_idx = bssid_cam->phy_idx;
	}

	snapshot->vo_aifs = rtwvif_link->tx_params[IEEE80211_AC_VO].aifs;
	snapshot->vo_cw_min = rtwvif_link->tx_params[IEEE80211_AC_VO].cw_min;
	snapshot->vo_cw_max = rtwvif_link->tx_params[IEEE80211_AC_VO].cw_max;
	snapshot->vo_txop = rtwvif_link->tx_params[IEEE80211_AC_VO].txop;
	snapshot->be_aifs = rtwvif_link->tx_params[IEEE80211_AC_BE].aifs;
	snapshot->be_cw_min = rtwvif_link->tx_params[IEEE80211_AC_BE].cw_min;
	snapshot->be_cw_max = rtwvif_link->tx_params[IEEE80211_AC_BE].cw_max;
	snapshot->be_txop = rtwvif_link->tx_params[IEEE80211_AC_BE].txop;
	return true;
}

/* Dump SW-side BE TX ring + device state.  Called by the kext's periodic
 * debug timer to diagnose a TX freeze.  Unlike the rtw88 version this
 * stays off the MMIO bus: register maps differ per rtw89 generation
 * (AX/BE), and the SW counters plus RPQ state already distinguish
 * "chip stopped consuming" from "no release reports coming back". */
void rtw88_debug_dump_tx_state(void)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_pci *rtwpci;
	struct rtw89_pci_tx_ring *tx_ring;
	struct rtw89_pci_rx_ring *rpq;
	u8 txch;

	if (!g_irq_dev_id)
		return;
	rtwdev = to_rtw89(g_irq_dev_id);
	rtwpci = (struct rtw89_pci *)rtwdev->priv;

	txch = rtw89_chip_get_ch_dma(rtwdev, RTW89_TX_QSEL_BE_0);
	tx_ring = &rtwpci->tx.rings[txch];
	rpq = &rtwpci->rx.rings[RTW89_RXCH_RPQ];

	pr_info("rtw89: TXSTATE BE(ch%u) bd wp=%u rp=%u len=%u wd_avail=%u/%u rpq wp=%u rp=%u running=%d power=%d\n",
		txch,
		tx_ring->bd_ring.wp, tx_ring->bd_ring.rp,
		tx_ring->bd_ring.len,
		tx_ring->wd_ring.curr_num, tx_ring->wd_ring.page_num,
		rpq->bd_ring.wp, rpq->bd_ring.rp,
		rtwpci->running ? 1 : 0,
		test_bit(RTW89_FLAG_POWERON, rtwdev->flags) ? 1 : 0);
}

/* ------------------------------------------------------------------ */
/*  A-MPDU BlockAck hardware setup                                      */
/*                                                                     */
/*  The Feixiao kext runs the ADDBA/DELBA handshake over the air but    */
/*  cannot call mac80211's ampdu_action op: rtw89_ops_ampdu_action      */
/*  dereferences sta->txq[tid]->drv_priv, and this port never           */
/*  allocates per-TID txqs.  We instead call the rtw89 H2C helpers      */
/*  directly with the negotiated parameters — TX_OPERATIONAL programs   */
/*  the per-TID CMAC aggregation table, RX_START/STOP the BA CAM.       */
/*  Without these the MAC aggregates frames (tagged TX_CTL_AMPDU by the */
/*  kext) against an unconfigured CMAC/BA CAM, and the AMPDU engine      */
/*  desyncs under load → frozen TX bd ring / "no tx fwcmd resource".    */

int rtw88_tx_ampdu_start(struct ieee80211_vif *vif, struct ieee80211_sta *sta,
			 u8 tid, u16 agg_num)
{
	struct ieee80211_hw *hw = rtw88_get_hw();
	struct rtw89_dev *rtwdev;
	struct rtw89_sta *rtwsta;
	struct rtw89_vif *rtwvif;

	if (!hw || !hw->priv || !vif || !sta || tid >= IEEE80211_NUM_TIDS)
		return -EINVAL;

	rtwdev = to_rtw89(hw->priv);
	rtwsta = sta_to_rtwsta(sta);
	rtwvif = vif_to_rtwvif(vif);

	/* Mirror rtw89_ops_ampdu_action(TX_OPERATIONAL) minus the txq flag. */
	rtwsta->ampdu_params[tid].agg_num = agg_num;
	rtwsta->ampdu_params[tid].amsdu = false;
	set_bit(tid, rtwsta->ampdu_map);

	return rtw89_chip_h2c_ampdu_cmac_tbl(rtwdev, rtwvif, rtwsta);
}

void rtw88_tx_ampdu_stop(struct ieee80211_vif *vif, struct ieee80211_sta *sta,
			 u8 tid)
{
	struct ieee80211_hw *hw = rtw88_get_hw();
	struct rtw89_dev *rtwdev;
	struct rtw89_sta *rtwsta;
	struct rtw89_vif *rtwvif;

	if (!hw || !hw->priv || !vif || !sta || tid >= IEEE80211_NUM_TIDS)
		return;

	rtwdev = to_rtw89(hw->priv);
	rtwsta = sta_to_rtwsta(sta);
	rtwvif = vif_to_rtwvif(vif);

	clear_bit(tid, rtwsta->ampdu_map);
	rtw89_chip_h2c_ampdu_cmac_tbl(rtwdev, rtwvif, rtwsta);
}

int rtw88_rx_ampdu_start(struct ieee80211_sta *sta, u8 tid, u16 ssn,
			 u16 buf_size)
{
	struct ieee80211_hw *hw = rtw88_get_hw();
	struct ieee80211_ampdu_params params;
	struct rtw89_dev *rtwdev;

	if (!hw || !hw->priv || !sta || tid >= IEEE80211_NUM_TIDS)
		return -EINVAL;

	rtwdev = to_rtw89(hw->priv);

	/* h2c_ba_cam reads only tid/ssn/buf_size from params (never sta->txq). */
	memset(&params, 0, sizeof(params));
	params.sta = sta;
	params.tid = tid;
	params.ssn = ssn;
	params.buf_size = buf_size;

	return rtw89_chip_h2c_ba_cam(rtwdev, sta_to_rtwsta(sta), true, &params);
}

void rtw88_rx_ampdu_stop(struct ieee80211_sta *sta, u8 tid)
{
	struct ieee80211_hw *hw = rtw88_get_hw();
	struct ieee80211_ampdu_params params;
	struct rtw89_dev *rtwdev;

	if (!hw || !hw->priv || !sta || tid >= IEEE80211_NUM_TIDS)
		return;

	rtwdev = to_rtw89(hw->priv);

	memset(&params, 0, sizeof(params));
	params.sta = sta;
	params.tid = tid;

	rtw89_chip_h2c_ba_cam(rtwdev, sta_to_rtwsta(sta), false, &params);
}

/* ------------------------------------------------------------------ */
/*  Scan bridges                                                       */
/* ------------------------------------------------------------------ */

bool rtw88_is_scanning(void)
{
	struct ieee80211_hw *hw = rtw88_get_hw();

	if (!hw || !hw->priv)
		return false;
	return to_rtw89(hw->priv)->scanning;
}

bool rtw88_hw_scan_supported(struct ieee80211_hw *hw)
{
	struct rtw89_dev *rtwdev;

	if (!hw || !hw->priv)
		return false;
	rtwdev = to_rtw89(hw->priv);

	/* RTL8852A firmware 0.13.36 advertises SCAN_OFFLOAD, but the
	 * offload H2C path halts firmware (C2H 0x10 -> 0x1001 -> 0x1002)
	 * and times out with -ETIMEDOUT on this macOS port.  Keep the
	 * feature bit intact for diagnostics, but force the already-existing
	 * software/manual channel scan path for this chip. */
	if (rtwdev->chip && rtwdev->chip->chip_id == RTL8852A)
		return false;

	return RTW89_CHK_FW_FEATURE(SCAN_OFFLOAD, &rtwdev->fw);
}

/* mac80211 normally calls rtw89_ops_configure_filter() around a software
 * scan.  The kext bypasses mac80211 and calls rtw89_core_scan_start()
 * directly, so without this bridge the normal BSSID/A1 beacon filters stay
 * enabled and every beacon/probe response from an unassociated AP is dropped
 * in hardware.  Mirror the scanning branch of rtw89_ops_configure_filter():
 * accept beacons/broadcast/other-BSS traffic while scanning, then restore the
 * driver's baseline filter when the scan completes. */
static void rtw88_program_rx_filter(struct rtw89_dev *rtwdev,
				      bool open, bool open_cam,
				      const char *reason)
{
	const struct rtw89_mac_gen_def *mac;
	u32 rx_fltr;
	u32 reg;
	u32 before;
	u32 after;

	if (!rtwdev || !rtwdev->chip || !rtwdev->chip->mac_def)
		return;

	mac = rtwdev->chip->mac_def;
	rx_fltr = rtwdev->hal.rx_fltr;
	if (open) {
		rx_fltr &= ~B_AX_A_BCN_CHK_EN;
		rx_fltr &= ~B_AX_A_BC;
		rx_fltr &= ~B_AX_A_A1_MATCH;
		if (open_cam) {
			rx_fltr &= ~B_AX_A_BC_CAM_MATCH;
			rx_fltr &= ~B_AX_A_UC_CAM_MATCH;
		}
	}

	reg = rtw89_mac_reg_by_idx(rtwdev, mac->rx_fltr, RTW89_MAC_0);
	before = rtw89_read32(rtwdev, reg);
	rtw89_mac_set_rx_fltr(rtwdev, RTW89_MAC_0, rx_fltr);
	if (rtwdev->dbcc_en)
		rtw89_mac_set_rx_fltr(rtwdev, RTW89_MAC_1, rx_fltr);
	after = rtw89_read32(rtwdev, reg);

	rtw89_info(rtwdev,
		   "%s RX filter %s: 0x%08x -> 0x%08x (base 0x%08x)\n",
		   reason ? reason : "temporary", open ? "open" : "restore",
		   before, after, rtwdev->hal.rx_fltr);
}

/* Mirrors rtw89_ops_sw_scan_start() (mac80211.c). 0.3.4 explicitly
 * restores the wiphy serialization Linux normally supplies around this op. */
void rtw88_sw_scan_start(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_vif *rtwvif;
	struct rtw89_vif_link *rtwvif_link;

	if (!hw || !hw->priv || !vif)
		return;
	rtwdev = to_rtw89(hw->priv);
	rtwvif = (struct rtw89_vif *)vif->drv_priv;

	wiphy_lock(hw->wiphy);
	rtwvif_link = rtw89_get_designated_link(rtwvif);
	if (!rtwvif_link) {
		rtw89_err(rtwdev, "sw scan start: find no designated link\n");
		wiphy_unlock(hw->wiphy);
		return;
	}

	rtw89_leave_lps(rtwdev);
	rtw89_core_scan_start(rtwdev, rtwvif_link, vif->addr, false);
	rtw88_program_rx_filter(rtwdev, true, false, "manual scan");
	wiphy_unlock(hw->wiphy);
}

void rtw88_sw_scan_switch_channel(struct ieee80211_hw *hw)
{
	struct rtw89_dev *rtwdev;

	if (!hw || !hw->priv)
		return;
	rtwdev = to_rtw89(hw->priv);

	/* rtw89 derives the channel from its entity state, not hw->conf —
	 * mirror the chandef the kext just wrote before programming. */
	wiphy_lock(hw->wiphy);
	rtw89_config_entity_chandef(rtwdev, RTW89_CHANCTX_0,
				    &hw->conf.chandef);
	rtw89_set_channel(rtwdev);
	wiphy_unlock(hw->wiphy);
}

void rtw88_sw_scan_complete(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_vif *rtwvif;
	struct rtw89_vif_link *rtwvif_link;

	if (!hw || !hw->priv || !vif)
		return;
	rtwdev = to_rtw89(hw->priv);
	rtwvif = (struct rtw89_vif *)vif->drv_priv;

	wiphy_lock(hw->wiphy);
	rtwvif_link = rtw89_get_designated_link(rtwvif);
	if (!rtwvif_link) {
		wiphy_unlock(hw->wiphy);
		return;
	}

	rtw89_core_scan_complete(rtwdev, rtwvif_link, false);
	rtw88_program_rx_filter(rtwdev, false, false, "manual scan");
	wiphy_unlock(hw->wiphy);
}

/* Temporarily make the receive path permissive during the WPA2 handshake.
 * The direct-connect test reaches association and then remains in HANDSHAKING
 * until timeout.  Clear both the ordinary address/BSSID gates and CAM-match
 * gates so the diagnostic also catches an incomplete peer/address-CAM setup.
 * The baseline filter is restored on M4, timeout, or disconnect. */
void rtw88_handshake_rx_filter(struct ieee80211_hw *hw, bool open)
{
	struct rtw89_dev *rtwdev;

	if (!hw || !hw->priv)
		return;
	rtwdev = to_rtw89(hw->priv);
	rtw88_program_rx_filter(rtwdev, open, true, "WPA2 handshake");
}

/* ------------------------------------------------------------------ */
/*  Coex / connect helpers                                             */
/* ------------------------------------------------------------------ */

/* rtw88 semantics: stop the WiFi/BT coexistence engine from throttling
 * WiFi on machines with no functional BT controller.  rtw89 has no
 * efuse.btcoex flag; the equivalent is BTC manual control, which stops
 * the periodic coex algorithm from reacting to (never-arriving) BT
 * firmware replies.  Same mechanism as debugfs' btc_manual node. */
static bool feixiao_wifi_only;

/* core.c boots BTC in BTC_MODE_WL (wifi-only policy) at every
 * ops->start while this reads true. */
bool rtw88_btc_wifi_only(void)
{
	return feixiao_wifi_only;
}

void rtw88_force_wifi_only(void)
{
	struct ieee80211_hw *hw = rtw88_get_hw();

	/* Sticky: the kext may call this before rtw_pci_probe registers the
	 * hw; record the request first, rtw89_core_start applies it via
	 * rtw89_btc_ntfy_init(BTC_MODE_WL). */
	feixiao_wifi_only = true;

	if (hw && hw->priv &&
	    test_bit(RTW89_FLAG_RUNNING, to_rtw89(hw->priv)->flags))
		rtw89_btc_ntfy_init(to_rtw89(hw->priv), BTC_MODE_WL);

	pr_info("rtw89: forcing wifi-only (BTC_MODE_WL)\n");
}

/* Single STA chanctx emulating mac80211's add/assign flow (the kext
 * never calls the chanctx ops itself). */
static struct ieee80211_chanctx_conf *feixiao_chanctx;
static bool feixiao_chanctx_added;

/* Set channel + BSSID for the kext's connect flow (it bypasses mac80211's
 * bss_info_changed path).  Caller populates hw->conf.chandef first, same
 * contract as the rtw88 version. */
void rtw88_connect_hw_setup(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    const uint8_t *bssid)
{
	struct rtw89_dev *rtwdev;
	struct rtw89_vif *rtwvif;
	struct rtw89_vif_link *rtwvif_link;

	if (!hw || !hw->priv || !vif || !bssid)
		return;
	rtwdev = to_rtw89(hw->priv);
	rtwvif = (struct rtw89_vif *)vif->drv_priv;

	wiphy_lock(hw->wiphy);
	rtwvif_link = rtw89_get_designated_link(rtwvif);
	if (!rtwvif_link) {
		wiphy_unlock(hw->wiphy);
		return;
	}

	rtw89_leave_lps(rtwdev);

	/* Emulate mac80211's chanctx flow (add_chanctx + assign_vif_chanctx).
	 * That is where rtw89 hooks mgnt-role bookkeeping, TAS and — via the
	 * assign wrapper — the full per-channel RF calibration (IQK/DPK/
	 * TSSI).  Only configuring the entity chandef tunes the synthesizer
	 * but leaves the RF front-end uncalibrated for the target channel:
	 * RX still hears beacons, TX is crippled and the AP never answers.
	 * The chanctx is pinned to RTW89_CHANCTX_0 (single-vif kext), which
	 * also keeps rtw89_chanctx_ops_add()'s find_first_zero_bit from
	 * tripping over a bit the sw-scan bridge may already have set. */
	if (!feixiao_chanctx) {
		feixiao_chanctx = kzalloc(sizeof(*feixiao_chanctx) +
					  hw->chanctx_data_size, GFP_KERNEL);
		if (!feixiao_chanctx) {
			rtw89_err(rtwdev, "connect: no mem for chanctx\n");
			wiphy_unlock(hw->wiphy);
			return;
		}
	}
	feixiao_chanctx->def = hw->conf.chandef;

	if (!feixiao_chanctx_added) {
		struct rtw89_chanctx_cfg *cfg =
			(struct rtw89_chanctx_cfg *)feixiao_chanctx->drv_priv;

		cfg->idx = RTW89_CHANCTX_0;
		cfg->ref_count = 0;
		rtwdev->hal.chanctx[RTW89_CHANCTX_0].cfg = cfg;
		feixiao_chanctx_added = true;
	}
	rtw89_config_entity_chandef(rtwdev, RTW89_CHANCTX_0,
				    &feixiao_chanctx->def);

	if (!rtwvif_link->chanctx_assigned) {
		if (rtw89_chanctx_ops_assign_vif(rtwdev, rtwvif_link,
						 feixiao_chanctx)) {
			rtw89_err(rtwdev, "connect: assign chanctx failed\n");
			wiphy_unlock(hw->wiphy);
			return;
		}
		/* Same as rtw89_ops_assign_vif_chanctx(): calibrate the RF
		 * front-end for the channel we are about to camp on. */
		rtw89_chip_rfk_channel(rtwdev, rtwvif_link);
	}

	rtw89_set_channel(rtwdev);

	{
		const struct rtw89_chan *cur =
			rtw89_chan_get(rtwdev, rtwvif_link->chanctx_idx);

		rtw89_info(rtwdev, "connect: tuned primary ch %u band %u bw %u\n",
			   cur->primary_channel, cur->band_type, cur->band_width);
	}

	/* BSSID goes to the address CAM via H2C, not an MMIO port register
	 * like rtw88's PORT_SET_BSSID. */
	ether_addr_copy(rtwvif_link->bssid, bssid);
	rtw89_cam_bssid_changed(rtwdev, rtwvif_link);
	rtw89_fw_h2c_cam(rtwdev, rtwvif_link, NULL, NULL,
			 RTW89_ROLE_INFO_CHANGE);
	wiphy_unlock(hw->wiphy);
}

/* Re-apply channel + BSSID after an internal reset while associated. */
void rtw88_restore_connected_hw(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				const uint8_t *bssid)
{
	rtw88_connect_hw_setup(hw, vif, bssid);
}

/* Undo the connect-flow chanctx emulation.  mac80211 guarantees
 * unassign_vif_chanctx before remove_interface; the kext does not, so
 * rtw89_ops_remove_interface() calls this to unlink the vif from the
 * mgnt bookkeeping before its memory goes away. */
void rtw88_release_chanctx(struct rtw89_dev *rtwdev,
			   struct rtw89_vif_link *rtwvif_link)
{
	if (!feixiao_chanctx || !rtwvif_link->chanctx_assigned)
		return;

	rtw89_chanctx_ops_unassign_vif(rtwdev, rtwvif_link, feixiao_chanctx);
	rtw89_chanctx_ops_remove(rtwdev, feixiao_chanctx);
	feixiao_chanctx_added = false;
}

/* ------------------------------------------------------------------ */
/*  Info helpers                                                       */
/* ------------------------------------------------------------------ */

void rtw88_get_fw_version(struct rtw_dev *rtwdev_opaque, uint16_t *version,
			  uint8_t *sub_version)
{
	struct rtw89_dev *rtwdev = to_rtw89(rtwdev_opaque);
	const struct rtw89_fw_suit *fw_suit;

	if (version)
		*version = 0;
	if (sub_version)
		*sub_version = 0;
	if (!rtwdev)
		return;

	fw_suit = rtw89_fw_suit_get(rtwdev, RTW89_FW_NORMAL);
	if (version)
		*version = ((uint16_t)fw_suit->major_ver << 8) |
			   fw_suit->minor_ver;
	if (sub_version)
		*sub_version = fw_suit->sub_ver;
}

static bool rtw89_alpha2_valid(const char alpha2[2])
{
	unsigned char a;
	unsigned char b;

	if (!alpha2)
		return false;
	a = (unsigned char)alpha2[0];
	b = (unsigned char)alpha2[1];
	if (!((a >= 'A' && a <= 'Z') || (a >= 'a' && a <= 'z')) ||
	    !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')))
		return false;
	return true;
}

static char rtw89_alpha2_upper(char c)
{
	return (c >= 'a' && c <= 'z') ? (char)(c - ('a' - 'A')) : c;
}

bool rtw88_get_country_code(struct rtw_dev *rtwdev_opaque, char out_alpha2[3])
{
	struct rtw89_dev *rtwdev = to_rtw89(rtwdev_opaque);
	const char *alpha2 = NULL;

	if (!out_alpha2)
		return false;
	out_alpha2[0] = '\0';
	out_alpha2[1] = '\0';
	out_alpha2[2] = '\0';
	if (!rtwdev)
		return false;

	/* Prefer the domain actually selected by rtw89_regd_setup/init_hint.
	 * "00" is the driver's worldwide/unknown domain and must not be exposed
	 * to CoreWLAN as a real ISO country. */
	if (rtwdev->regulatory.regd &&
	    rtw89_alpha2_valid(rtwdev->regulatory.regd->alpha2) &&
	    !(rtwdev->regulatory.regd->alpha2[0] == '0' &&
	      rtwdev->regulatory.regd->alpha2[1] == '0')) {
		alpha2 = rtwdev->regulatory.regd->alpha2;
	} else if (rtwdev->efuse.valid &&
		   rtw89_alpha2_valid(rtwdev->efuse.country_code)) {
		alpha2 = rtwdev->efuse.country_code;
	}

	if (!alpha2)
		return false;
	out_alpha2[0] = rtw89_alpha2_upper(alpha2[0]);
	out_alpha2[1] = rtw89_alpha2_upper(alpha2[1]);
	out_alpha2[2] = '\0';
	return true;
}

bool rtw88_set_country_code(struct rtw_dev *rtwdev_opaque,
			    const char alpha2[2])
{
	struct rtw89_dev *rtwdev = to_rtw89(rtwdev_opaque);
	struct regulatory_request request = {0};
	char requested[3];
	char effective[3];

	if (!rtwdev || !rtwdev->hw || !rtwdev->hw->wiphy ||
	    !rtw89_alpha2_valid(alpha2))
		return false;

	requested[0] = rtw89_alpha2_upper(alpha2[0]);
	requested[1] = rtw89_alpha2_upper(alpha2[1]);
	requested[2] = '\0';

	/* Avoid re-running the notifier/TX-power programming when already active. */
	if (rtw88_get_country_code(rtwdev_opaque, effective) &&
	    effective[0] == requested[0] && effective[1] == requested[1])
		return true;

	/* Programmed EFUSE regulatory data is authoritative. */
	if (rtwdev->regulatory.programmed) {
		if (!rtw88_get_country_code(rtwdev_opaque, effective))
			return false;
		return effective[0] == requested[0] && effective[1] == requested[1];
	}

	if (!rtwdev->hw->wiphy->reg_notifier)
		return false;

	request.initiator = NL80211_REGDOM_SET_BY_USER;
	request.alpha2[0] = requested[0];
	request.alpha2[1] = requested[1];
	request.dfs_region = NL80211_DFS_UNSET;
	rtwdev->hw->wiphy->reg_notifier(rtwdev->hw->wiphy, &request);

	if (!rtw88_get_country_code(rtwdev_opaque, effective))
		return false;
	return effective[0] == requested[0] && effective[1] == requested[1];
}

void rtw88_get_chip_name(struct rtw_dev *rtwdev_opaque, char *name_buf,
			 size_t buf_sz)
{
	struct rtw89_dev *rtwdev = to_rtw89(rtwdev_opaque);

	if (!name_buf || buf_sz == 0)
		return;
	name_buf[0] = '\0';
	if (!rtwdev || !rtwdev->chip) {
		strlcpy(name_buf, "Unknown", buf_sz);
		return;
	}

	switch (rtwdev->chip->chip_id) {
	case RTL8851B:
		strlcpy(name_buf, "RTL8851BE", buf_sz);
		break;
	case RTL8852A:
		strlcpy(name_buf, "RTL8852AE", buf_sz);
		break;
	case RTL8852B:
		strlcpy(name_buf, "RTL8852BE", buf_sz);
		break;
	case RTL8852BT:
		strlcpy(name_buf, "RTL8852BTE", buf_sz);
		break;
	case RTL8852C:
		strlcpy(name_buf, "RTL8852CE", buf_sz);
		break;
	case RTL8922A:
		strlcpy(name_buf, "RTL8922AE", buf_sz);
		break;
	default:
		strlcpy(name_buf, "RTL89xx (Unknown)", buf_sz);
		break;
	}
}

void rtw88_get_stats(struct rtw_dev *rtwdev_opaque, uint32_t *tx_bytes,
		     uint32_t *rx_bytes)
{
	struct rtw89_dev *rtwdev = to_rtw89(rtwdev_opaque);

	if (tx_bytes)
		*tx_bytes = 0;
	if (rx_bytes)
		*rx_bytes = 0;
	if (!rtwdev)
		return;
	if (tx_bytes)
		*tx_bytes = (uint32_t)rtwdev->stats.tx_unicast;
	if (rx_bytes)
		*rx_bytes = (uint32_t)rtwdev->stats.rx_unicast;
}

#endif /* RTW89_MACOS */
