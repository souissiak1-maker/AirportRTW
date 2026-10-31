/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Included after mac80211 types and g_rtw88_hw. Each HAL owns a registry.
 * Writers and iterators hold the recursive registry lock. Lookup returns a
 * borrowed pointer: callers must serialize peer teardown for its entire use.
 * This is not an RCU implementation. Never free a peer from an iterator.
 */
#define RTW_REGISTRY_VIFS 4
#define RTW_REGISTRY_PEERS 32
static struct ieee80211_vif *g_registry_vifs[RTW_REGISTRY_VIFS];
static struct { struct ieee80211_vif *vif; struct ieee80211_sta *sta; }
    g_registry_peers[RTW_REGISTRY_PEERS];
static struct ieee80211_vif *g_rtw88_vif;
static struct ieee80211_sta *g_rtw88_sta;
static IORecursiveLock *g_station_lock;

static bool rtw_registry_has_vif(struct ieee80211_vif *vif)
{
    for (unsigned i = 0; i < RTW_REGISTRY_VIFS; ++i)
        if (g_registry_vifs[i] == vif && vif) return true;
    return false;
}

bool rtw88_add_vif(struct ieee80211_vif *vif)
{
    bool added = false;
    if (!g_station_lock || !vif) return false;
    IORecursiveLockLock(g_station_lock);
    if (rtw_registry_has_vif(vif)) added = true;
    else for (unsigned i = 0; i < RTW_REGISTRY_VIFS; ++i) {
        if (!g_registry_vifs[i]) { g_registry_vifs[i] = vif; added = true; break; }
    }
    IORecursiveLockUnlock(g_station_lock);
    return added;
}

void rtw88_remove_sta(struct ieee80211_sta *sta)
{
    if (!g_station_lock || !sta) return;
    IORecursiveLockLock(g_station_lock);
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i)
        if (g_registry_peers[i].sta == sta) {
            g_registry_peers[i].sta = NULL; g_registry_peers[i].vif = NULL;
        }
    if (g_rtw88_sta == sta) g_rtw88_sta = NULL;
    IORecursiveLockUnlock(g_station_lock);
}

void rtw88_remove_vif(struct ieee80211_vif *vif)
{
    if (!g_station_lock || !vif) return;
    IORecursiveLockLock(g_station_lock);
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i)
        if (g_registry_peers[i].vif == vif) rtw88_remove_sta(g_registry_peers[i].sta);
    for (unsigned i = 0; i < RTW_REGISTRY_VIFS; ++i)
        if (g_registry_vifs[i] == vif) g_registry_vifs[i] = NULL;
    if (g_rtw88_vif == vif) g_rtw88_vif = NULL;
    IORecursiveLockUnlock(g_station_lock);
}

bool rtw88_add_sta(struct ieee80211_vif *vif, struct ieee80211_sta *sta)
{
    bool added = false;
    if (!g_station_lock || !vif || !sta) return false;
    IORecursiveLockLock(g_station_lock);
    if (!rtw_registry_has_vif(vif)) goto done;
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i) {
        if (g_registry_peers[i].sta == sta) {
            added = g_registry_peers[i].vif == vif; goto done;
        }
        if (g_registry_peers[i].vif == vif && g_registry_peers[i].sta &&
            memcmp(g_registry_peers[i].sta->addr, sta->addr, ETH_ALEN) == 0)
            goto done; /* Do not silently replace a live peer. */
    }
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i)
        if (!g_registry_peers[i].sta) {
            g_registry_peers[i].vif = vif; g_registry_peers[i].sta = sta;
            added = true; break;
        }
done:
    IORecursiveLockUnlock(g_station_lock);
    return added;
}

/* Compatibility entry points affect the primary station only. */
void rtw88_register_vif(struct ieee80211_vif *vif)
{
    if (!g_station_lock) return;
    IORecursiveLockLock(g_station_lock);
    if (g_rtw88_vif != vif) rtw88_remove_vif(g_rtw88_vif);
    if (rtw88_add_vif(vif)) g_rtw88_vif = vif;
    IORecursiveLockUnlock(g_station_lock);
}
void rtw88_unregister_vif(void) { rtw88_register_vif(NULL); }
void rtw88_register_sta(struct ieee80211_sta *sta)
{
    if (!g_station_lock) return;
    IORecursiveLockLock(g_station_lock);
    if (g_rtw88_sta != sta) rtw88_remove_sta(g_rtw88_sta);
    if (rtw88_add_sta(g_rtw88_vif, sta)) g_rtw88_sta = sta;
    IORecursiveLockUnlock(g_station_lock);
}
void rtw88_unregister_sta(void) { rtw88_register_sta(NULL); }

void ieee80211_iterate_active_interfaces_atomic(
    struct ieee80211_hw *hw, unsigned int iter_flags,
    void (*iterator)(void *, u8 *, struct ieee80211_vif *), void *data)
{
    (void)iter_flags;
    if (!g_station_lock || hw != g_rtw88_hw || !iterator) return;
    IORecursiveLockLock(g_station_lock);
    for (unsigned i = 0; i < RTW_REGISTRY_VIFS; ++i) {
        struct ieee80211_vif *vif = g_registry_vifs[i];
        if (vif) iterator(data, vif->addr, vif);
    }
    IORecursiveLockUnlock(g_station_lock);
}
void ieee80211_iterate_active_interfaces(
    struct ieee80211_hw *hw, unsigned int iter_flags,
    void (*iterator)(void *, u8 *, struct ieee80211_vif *), void *data)
{
    ieee80211_iterate_active_interfaces_atomic(hw, iter_flags, iterator, data);
}
void ieee80211_iterate_stations_atomic(struct ieee80211_hw *hw,
    void (*iterator)(void *, struct ieee80211_sta *), void *data)
{
    if (!g_station_lock || hw != g_rtw88_hw || !iterator) return;
    IORecursiveLockLock(g_station_lock);
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i)
        if (g_registry_peers[i].sta) iterator(data, g_registry_peers[i].sta);
    IORecursiveLockUnlock(g_station_lock);
}

struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_vif *vif, const u8 *addr)
{
    struct ieee80211_sta *result = NULL;
    if (!g_station_lock || !vif || !addr) return NULL;
    IORecursiveLockLock(g_station_lock);
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i)
        if (g_registry_peers[i].vif == vif && g_registry_peers[i].sta &&
            memcmp(g_registry_peers[i].sta->addr, addr, ETH_ALEN) == 0) {
            result = g_registry_peers[i].sta; break;
        }
    IORecursiveLockUnlock(g_station_lock);
    return result;
}
struct ieee80211_sta *ieee80211_find_sta_by_ifaddr(struct ieee80211_hw *hw,
    const u8 *addr, const u8 *localaddr)
{
    struct ieee80211_sta *result = NULL;
    if (!g_station_lock || hw != g_rtw88_hw || !addr) return NULL;
    IORecursiveLockLock(g_station_lock);
    for (unsigned i = 0; i < RTW_REGISTRY_PEERS; ++i)
        if (g_registry_peers[i].sta &&
            (!localaddr || memcmp(g_registry_peers[i].vif->addr, localaddr, ETH_ALEN) == 0) &&
            memcmp(g_registry_peers[i].sta->addr, addr, ETH_ALEN) == 0) {
            result = g_registry_peers[i].sta; break;
        }
    IORecursiveLockUnlock(g_station_lock);
    return result;
}
static void rtw_registry_reset(void)
{
    /* Called after producers and driver callbacks have been quiesced. */
    memset(g_registry_vifs, 0, sizeof(g_registry_vifs));
    memset(g_registry_peers, 0, sizeof(g_registry_peers));
    g_rtw88_vif = NULL; g_rtw88_sta = NULL;
}
