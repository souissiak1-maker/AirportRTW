#!/usr/bin/env python3
"""Run the production RTW88 coexistence maintenance and BT enable detection."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
main = (ROOT / 'rtw/hal_rtw88/driver/main.c').read_text()
coex = (ROOT / 'rtw/hal_rtw88/driver/coex.c').read_text()

def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 3]

maintenance = function(main, 'static void rtw_macos_coex_watchdog(')
monitor = function(coex, 'static void rtw_coex_monitor_bt_enable(')
bridge = (ROOT / 'rtw/hal_rtw88/Rtw88LinuxBridge.cpp').read_text()
assert 'rtw88_force_wifi_only' not in bridge
assert 'rtwdev->efuse.btcoex = 0' not in (ROOT / 'rtw/hal_rtw88/compat/rtw88_compat.c').read_text()
assert 'if (!rtw88_disable_watchdog_work || rtwdev->efuse.btcoex)' in main
watchdog = function(main, 'static void rtw_watch_dog_work(')
assert watchdog.index('if (!test_bit(RTW_FLAG_RUNNING') < watchdog.index('rtw_macos_coex_watchdog(rtwdev)')
assert 'rtw_macos_coex_watchdog(rtwdev);\n\t\tgoto unlock;' in watchdog
stop = function(main, 'void rtw_core_stop(')
assert stop.index('clear_bit(RTW_FLAG_RUNNING') < stop.index('cancel_delayed_work_sync(&rtwdev->watch_dog_work)')
assert stop.index('mutex_unlock(&rtwdev->mutex)') < stop.index('cancel_delayed_work_sync(&rtwdev->watch_dog_work)')

fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef uint16_t u16;
#define HZ 1000
#define RTW_FLAG_SCANNING 0
#define RTW_FLAG_BUSY_TRAFFIC 1
#define RTW_WATCH_DOG_DELAY_TIME 2000
#define RTW_TP_SHIFT 18
#define COEX_SCBD_ONOFF 2
#define RTW_DBG_COEX 0
#define rtw_dbg(...) ((void)0)
struct delayed_work { int unused; };
struct rtw_traffic_stats { unsigned tx_cnt,rx_cnt; uint64_t tx_unicast,rx_unicast; unsigned tx_throughput,rx_throughput; };
struct rtw_coex_stat { unsigned hi_pri_tx,hi_pri_rx,lo_pri_tx,lo_pri_rx,bt_disable_cnt,bt_ble_scan_type; bool bt_disabled,bt_reenable,bt_mailbox_reply; };
struct rtw_coex_dm { unsigned cur_bt_lna_lvl; };
struct rtw_coex { struct rtw_coex_stat stat; struct rtw_coex_dm dm; struct delayed_work bt_reenable_work; };
struct rtw_chip_info { bool scbd_support; };
struct rtw_dev { struct rtw_traffic_stats stats; struct { bool btcoex; } efuse; struct delayed_work watch_dog_work; void *hw; unsigned flags[1]; struct rtw_coex coex; const struct rtw_chip_info *chip; };
static bool test_bit(unsigned n,unsigned *flags) { return !!(*flags & (1U<<n)); }
static void set_bit(unsigned n,unsigned *flags) { *flags |= 1U<<n; }
static void clear_bit(unsigned n,unsigned *flags) { *flags &= ~(1U<<n); }
static unsigned queued,queried,checked,policies,sequence;
static u16 scoreboard;
static void ieee80211_queue_delayed_work(void *hw,struct delayed_work *w,unsigned delay) { (void)hw;(void)w;assert(delay==2000 || delay==15000);++queued; }
static u16 rtw_coex_read_scbd(struct rtw_dev *d) { (void)d; return scoreboard; }
static void rtw_coex_wl_status_check(struct rtw_dev *d) { (void)d;assert(sequence++==0);++checked; }
static void rtw_coex_query_bt_info(struct rtw_dev *d) { (void)d;assert(sequence++==1);++queried; }
static void rtw_coex_wl_status_change_notify(struct rtw_dev *d,unsigned type) { (void)d;assert(!type);assert(sequence++==2);++policies; }
''' + monitor + maintenance + r'''
int main(void) {
    struct rtw_dev d={0};
    rtw_macos_coex_watchdog(&d); assert(!queued && !policies);
    d.efuse.btcoex=true;
    set_bit(RTW_FLAG_SCANNING,d.flags);
    rtw_macos_coex_watchdog(&d); assert(queued==1 && !policies);
    clear_bit(RTW_FLAG_SCANNING,d.flags);
    d.stats.tx_cnt=101;d.stats.tx_unicast=3U<<RTW_TP_SHIFT;
    rtw_macos_coex_watchdog(&d);
    assert(test_bit(RTW_FLAG_BUSY_TRAFFIC,d.flags));
    assert(d.stats.tx_throughput==3 && !d.stats.tx_cnt && !d.stats.tx_unicast);
    assert(checked==1 && queried==1 && policies==1);
    sequence=0;rtw_macos_coex_watchdog(&d);
    assert(!test_bit(RTW_FLAG_BUSY_TRAFFIC,d.flags) && policies==2 && queued==3);
    const struct rtw_chip_info chip={true};d.chip=&chip;
    scoreboard=0;rtw_coex_monitor_bt_enable(&d);assert(d.coex.stat.bt_disabled);
    scoreboard=COEX_SCBD_ONOFF;rtw_coex_monitor_bt_enable(&d);
    assert(!d.coex.stat.bt_disabled && d.coex.stat.bt_reenable);
    scoreboard=0;rtw_coex_monitor_bt_enable(&d);
    assert(d.coex.stat.bt_disabled && !d.coex.stat.bt_reenable);
    const struct rtw_chip_info counter_chip={false};d.chip=&counter_chip;
    d.coex.stat.bt_disabled=false;
    for(int i=0;i<9;++i) {rtw_coex_monitor_bt_enable(&d);assert(!d.coex.stat.bt_disabled);}
    rtw_coex_monitor_bt_enable(&d);assert(d.coex.stat.bt_disabled);
    d.coex.stat.hi_pri_rx=1;rtw_coex_monitor_bt_enable(&d);
    assert(!d.coex.stat.bt_disabled && !d.coex.stat.bt_disable_cnt);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='rtw88-btcoex-') as tmp:
    source = Path(tmp) / 'test.c'; source.write_text(fixture)
    exe = Path(tmp) / 'test'
    subprocess.run(['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
print('PASS: RTW88 coexistence-only maintenance, traffic windows, BT on/off detection, scan/lifecycle guards')
