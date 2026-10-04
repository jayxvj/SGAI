/*
 * sentinal_driver.h
 *
 * Internal declarations for the Sentinal AI minifilter driver.
 *
 * Phase 1.24 — Windows Minifilter Foundation
 * This header is kernel-mode only. Do not include from user-mode code.
 */

#ifndef SENTINAL_DRIVER_H
#define SENTINAL_DRIVER_H

#include <fltKernel.h>
#include <dontuse.h>

/* =========================================================================
 * Driver identity
 * ========================================================================= */

#define SENTINAL_DRIVER_NAME    L"SentinalDriver"
#define SENTINAL_DRIVER_TAG     'lntS'   /* 'Stnl' in little-endian pool tag */

/* =========================================================================
 * Global driver state
 * ========================================================================= */

/*
 * Handle returned by FltRegisterFilter.
 * Stored at DriverEntry; used by DriverUnload to call FltUnregisterFilter.
 */
extern PFLT_FILTER g_SentinalFilter;

/* =========================================================================
 * Filter registration
 * ========================================================================= */

extern const FLT_REGISTRATION g_SentinalFilterRegistration;

/* =========================================================================
 * Driver lifecycle
 * ========================================================================= */

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
SentinalDriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

/* =========================================================================
 * Pre-operation observation callbacks (pass-through)
 *
 * Registered for observed operations; currently pass everything through.
 * Future phases will add event extraction and user-mode communication.
 * ========================================================================= */

FLT_PREOP_CALLBACK_STATUS
SentinalPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
SentinalPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
SentinalPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

#endif /* SENTINAL_DRIVER_H */
