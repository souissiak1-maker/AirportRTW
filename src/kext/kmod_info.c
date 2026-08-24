/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * kmod_info.c — _kmod_info symbol + _realmain/_antimain wiring.
 *
 * libkmod.a's c_start.c defines _start(ki, data) -> (*_realmain)(ki, data).
 * On x86_64 we provide _realmain/_antimain ourselves.
 * OSRuntimeInitializeCPP/FinalizeCPP are not exported by macOS 15+ KPIs;
 * the kernel handles C++ ctor/dtor via __mod_init_func when loading the
 * auxiliary kernel collection, so we don't call them explicitly.
 */
#include <mach/mach_types.h>
#include <mach/kmod.h>

extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);

#ifdef RTW_AIRPORT
KMOD_EXPLICIT_DECL(com.rtw.airport, "0.2.106", _start, _stop)
#elif defined(RTW89_MACOS)
KMOD_EXPLICIT_DECL(com.rtw89.driver, "1.1.0", _start, _stop)
#else
KMOD_EXPLICIT_DECL(com.rtw88.driver, "1.1.0", _start, _stop)
#endif

extern int  rtw88_compat_init(void);
extern void rtw88_compat_exit(void);

static kern_return_t rtw88_module_start(kmod_info_t *ki, void *data)
{
    (void)ki; (void)data;
    return (rtw88_compat_init() == 0) ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t rtw88_module_stop(kmod_info_t *ki, void *data)
{
    (void)ki; (void)data;
    rtw88_compat_exit();
    return KERN_SUCCESS;
}

kmod_start_func_t *_realmain = rtw88_module_start;
kmod_stop_func_t  *_antimain = rtw88_module_stop;
