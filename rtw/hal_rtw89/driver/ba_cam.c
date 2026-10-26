/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2019-2020 Realtek Corporation */
#include "core.h"

int rtw89_core_acquire_sta_ba_entry(struct rtw89_dev *rtwdev,
				    struct rtw89_sta_link *rtwsta_link, u8 tid,
				    u8 *cam_idx)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	struct rtw89_cam_info *cam_info = &rtwdev->cam_info;
	struct rtw89_ba_cam_entry *entry = NULL, *tmp;
	u8 idx;
	int i;

	lockdep_assert_wiphy(rtwdev->hw->wiphy);

	/* Repeated ADDBA for one TID updates its existing CAM entry.  Allocating
	 * duplicates makes RX_STOP release only one entry and leaves a list node
	 * pointing into the station after it is freed. */
	list_for_each_entry(tmp, &rtwsta_link->ba_cam_list, list) {
		if (tmp->tid == tid) {
			*cam_idx = tmp - cam_info->ba_cam_entry;
			return 0;
		}
	}

	idx = rtw89_core_acquire_bit_map(cam_info->ba_cam_map, chip->bacam_num);
	if (idx == chip->bacam_num) {
		/* allocate a static BA CAM to tid=0/5, so replace the existing
		 * one if BA CAM is full. Hardware will process the original tid
		 * automatically.
		 */
		if (tid != 0 && tid != 5)
			return -ENOSPC;

		for_each_set_bit(i, cam_info->ba_cam_map, chip->bacam_num) {
			tmp = &cam_info->ba_cam_entry[i];
			if (tmp->tid == 0 || tmp->tid == 5)
				continue;

			idx = i;
			entry = tmp;
			list_del(&entry->list);
			break;
		}

		if (!entry)
			return -ENOSPC;
	} else {
		entry = &cam_info->ba_cam_entry[idx];
	}

	entry->tid = tid;
	list_add_tail(&entry->list, &rtwsta_link->ba_cam_list);

	*cam_idx = idx;

	return 0;
}

int rtw89_core_release_sta_ba_entry(struct rtw89_dev *rtwdev,
				    struct rtw89_sta_link *rtwsta_link, u8 tid,
				    u8 *cam_idx)
{
	struct rtw89_cam_info *cam_info = &rtwdev->cam_info;
	struct rtw89_ba_cam_entry *entry = NULL, *tmp;
	u8 idx;

	lockdep_assert_wiphy(rtwdev->hw->wiphy);

	list_for_each_entry_safe(entry, tmp, &rtwsta_link->ba_cam_list, list) {
		if (entry->tid != tid)
			continue;

		idx = entry - cam_info->ba_cam_entry;
		list_del(&entry->list);

		rtw89_core_release_bit_map(cam_info->ba_cam_map, idx);
		*cam_idx = idx;
		return 0;
	}

	return -ENOENT;
}

/* Firmware failures must not leave device CAM nodes linked into freed sta. */
void rtw89_core_purge_sta_ba_entries(struct rtw89_dev *rtwdev,
                                   struct rtw89_sta_link *rtwsta_link)
{
    struct rtw89_cam_info *cam_info = &rtwdev->cam_info;
    struct rtw89_ba_cam_entry *entry, *tmp;
    lockdep_assert_wiphy(rtwdev->hw->wiphy);
    list_for_each_entry_safe(entry, tmp, &rtwsta_link->ba_cam_list, list) {
        u8 idx = entry - cam_info->ba_cam_entry;
        list_del(&entry->list);
        INIT_LIST_HEAD(&entry->list);
        rtw89_core_release_bit_map(cam_info->ba_cam_map, idx);
    }
}
