/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_ACPI_H
#define _RTW88_COMPAT_ACPI_H

#include "types.h"
#include "slab.h"
#include "uuid.h"

/*
 * ACPI stub layer for the rtw89 macOS port.
 *
 * rtw89 consults ACPI only for optional platform policy (SAR power tables,
 * regulatory DSM hints, tuned TAS).  macOS kexts have no equivalent of the
 * Linux ACPI evaluation API, so every entry point here fails cleanly:
 * ACPI_HANDLE() returns NULL and the driver takes its built-in defaults,
 * exactly as on a Linux machine whose DSDT lacks the Realtek objects.
 */

typedef void *acpi_handle;
typedef char *acpi_string;
typedef u32   acpi_status;
typedef u64   acpi_size;

#define AE_OK        ((acpi_status)0)
#define AE_ERROR     ((acpi_status)1)
#define AE_NOT_FOUND ((acpi_status)5)

#define ACPI_SUCCESS(s) ((s) == AE_OK)
#define ACPI_FAILURE(s) ((s) != AE_OK)

#define ACPI_TYPE_ANY      0
#define ACPI_TYPE_INTEGER  1
#define ACPI_TYPE_STRING   2
#define ACPI_TYPE_BUFFER   3
#define ACPI_TYPE_PACKAGE  4

union acpi_object {
    u32 type;
    struct {
        u32 type;
        u64 value;
    } integer;
    struct {
        u32 type;
        u32 length;
        u8 *pointer;
    } buffer;
    struct {
        u32 type;
        u32 count;
        union acpi_object *elements;
    } package;
};

struct acpi_buffer {
    acpi_size length;
    void *pointer;
};

#define ACPI_ALLOCATE_BUFFER ((acpi_size)-1)

struct device;

/* No ACPI companion on macOS — forces the graceful fallback path. */
#define ACPI_HANDLE(dev) ((acpi_handle)0)

#define ACPI_FREE(p) kfree(p)

static inline acpi_status acpi_get_handle(acpi_handle parent,
                                          acpi_string pathname,
                                          acpi_handle *ret_handle)
{
    return AE_NOT_FOUND;
}

static inline acpi_status acpi_evaluate_object(acpi_handle handle,
                                               acpi_string pathname,
                                               void *external_params,
                                               struct acpi_buffer *return_buffer)
{
    return AE_NOT_FOUND;
}

static inline union acpi_object *acpi_evaluate_dsm(acpi_handle handle,
                                                   const guid_t *guid,
                                                   u64 rev, u64 func,
                                                   union acpi_object *argv4)
{
    return NULL;
}

#endif /* _RTW88_COMPAT_ACPI_H */
