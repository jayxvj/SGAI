/*
 * driver_entry.c
 *
 * Sentinal AI minifilter driver — DriverEntry and filter lifecycle.
 *
 * Phase 1.25 — Kernel Minifilter Observation
 *
 * Responsibilities:
 *   - Register the minifilter with Filter Manager (FltRegisterFilter)
 *   - Start filtering (FltStartFiltering)
 *   - Unregister on unload (FltUnregisterFilter)
 *   - Observe IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION
 *     via pass-through pre-operation callbacks (FLT_PREOP_SUCCESS_NO_CALLBACK)
 *
 * This file contains NO:
 *   - file blocking or access-denial logic (no FLT_PREOP_COMPLETE)
 *   - asynchronous completion (no FLT_PREOP_PENDING)
 *   - parameter modification or redirection
 *   - policy evaluation
 *   - encryption / decryption
 *   - communication port (FltCreateCommunicationPort)
 *   - user-mode messaging (FltSendMessage)
 *   - IOCTL handling
 *   - filesystem operations (no ZwCreateFile / ZwWriteFile / ZwReadFile)
 */

#include "sentinal_driver.h"

/* =========================================================================
 * Global filter handle
 * ========================================================================= */

PFLT_FILTER g_SentinalFilter = NULL;

/* =========================================================================
 * Operation registration table
 *
 * Registers observation callbacks for IRP_MJ_CREATE, IRP_MJ_WRITE, and
 * IRP_MJ_SET_INFORMATION. Terminated with IRP_MJ_OPERATION_END.
 * All callbacks return FLT_PREOP_SUCCESS_NO_CALLBACK (pure pass-through).
 * ========================================================================= */

static const FLT_OPERATION_REGISTRATION c_OperationCallbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        SentinalPreCreate,
        NULL
    },
    {
        IRP_MJ_WRITE,
        0,
        SentinalPreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        SentinalPreSetInformation,
        NULL
    },
    {
        IRP_MJ_OPERATION_END
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
 * Pre-operation observation callbacks
 *
 * All callbacks in this phase are observation-only pass-through:
 *   - Safely receive callback parameters
 *   - Do not allocate memory or perform expensive processing
 *   - Do not access user buffers or dereference unsafe pointers
 *   - Do not perform filesystem operations
 *   - Always return FLT_PREOP_SUCCESS_NO_CALLBACK
 * ========================================================================= */

FLT_PREOP_CALLBACK_STATUS
SentinalPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* ponytail: observation-only — pass through without altering outcome */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
SentinalPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* ponytail: observation-only — pass through without altering outcome */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
SentinalPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* ponytail: observation-only — pass through without altering outcome */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
