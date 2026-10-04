/*
 * driver_entry.c
 *
 * Sentinal AI minifilter driver — DriverEntry and filter lifecycle.
 *
 * Phase 1.24 — Windows Minifilter Foundation
 *
 * Responsibilities:
 *   - Register the minifilter with Filter Manager (FltRegisterFilter)
 *   - Start filtering (FltStartFiltering)
 *   - Unregister on unload (FltUnregisterFilter)
 *   - Provide a pass-through pre-operation callback for all I/O
 *
 * This file contains NO:
 *   - file blocking or access-denial logic
 *   - policy evaluation
 *   - encryption / decryption
 *   - communication port (FltCreateCommunicationPort)
 *   - IOCTL handling
 *   - user-mode messaging
 */

#include "sentinal_driver.h"

/* =========================================================================
 * Global filter handle
 * ========================================================================= */

PFLT_FILTER g_SentinalFilter = NULL;

/* =========================================================================
 * Operation registration table
 *
 * A single entry covers all major function codes (IRP_MJ_OPERATION_END
 * sentinel terminates the table). The pre-operation callback is pass-through.
 * ========================================================================= */

static const FLT_OPERATION_REGISTRATION c_OperationCallbacks[] = {
    {
        IRP_MJ_OPERATION_END  /* table terminator — no callbacks registered yet */
    }
};

/* =========================================================================
 * Filter registration descriptor
 * ========================================================================= */

const FLT_REGISTRATION g_SentinalFilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags — no special flags for foundation */
    NULL,                           /* ContextRegistration — none in this phase */
    c_OperationCallbacks,           /* OperationRegistration */
    SentinalDriverUnload,           /* FilterUnloadCallback */
    NULL,                           /* InstanceSetupCallback */
    NULL,                           /* InstanceQueryTeardownCallback */
    NULL,                           /* InstanceTeardownStartCallback */
    NULL,                           /* InstanceTeardownCompleteCallback */
    NULL,                           /* GenerateFileNameCallback */
    NULL,                           /* NormalizeNameComponentCallback */
    NULL                            /* NormalizeContextCleanupCallback */
};

/* =========================================================================
 * DriverEntry
 * ========================================================================= */

#pragma alloc_text(INIT, DriverEntry)

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    /*
     * Register the minifilter with Filter Manager.
     * On success, g_SentinalFilter holds the opaque filter handle.
     */
    status = FltRegisterFilter(
        DriverObject,
        &g_SentinalFilterRegistration,
        &g_SentinalFilter
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * Begin filtering I/O.
     * If this fails, unregister before returning so we do not leak the handle.
     */
    status = FltStartFiltering(g_SentinalFilter);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_SentinalFilter);
        g_SentinalFilter = NULL;
    }

    return status;
}

/* =========================================================================
 * SentinalDriverUnload
 *
 * Called by Filter Manager when the driver is being unloaded.
 * Unregisters the filter and clears the global handle.
 * ========================================================================= */

NTSTATUS
SentinalDriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_SentinalFilter != NULL) {
        FltUnregisterFilter(g_SentinalFilter);
        g_SentinalFilter = NULL;
    }

    return STATUS_SUCCESS;
}

/* =========================================================================
 * SentinalPreOperationCallback
 *
 * Pass-through pre-operation callback.
 * Reserved for future policy evaluation phases.
 * ========================================================================= */

FLT_PREOP_CALLBACK_STATUS
SentinalPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* ponytail: pass-through — policy evaluation added in a future phase */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
