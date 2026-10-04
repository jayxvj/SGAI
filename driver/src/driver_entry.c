/*
 * driver_entry.c
 *
 * Sentinal AI minifilter driver — DriverEntry and filter lifecycle.
 *
 * Phase 1.26 — Kernel Observation Event Model
 *
 * Responsibilities:
 *   - Register the minifilter with Filter Manager (FltRegisterFilter)
 *   - Start filtering (FltStartFiltering)
 *   - Unregister on unload (FltUnregisterFilter)
 *   - Construct and validate kernel observation events for IRP_MJ_CREATE,
 *     IRP_MJ_WRITE, and IRP_MJ_SET_INFORMATION in pre-operation callbacks
 *   - Pass through all operations (FLT_PREOP_SUCCESS_NO_CALLBACK)
 *
 * This file contains NO:
 *   - file blocking or access denial
 *   - asynchronous completion
 *   - parameter modification or redirection
 *   - policy evaluation
 *   - encryption or decryption
 *   - communication ports or user-mode IPC
 *   - IOCTL handling
 *   - kernel filesystem calls or re-entrant I/O
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
    SENTINAL_OBSERVATION_EVENT event;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    event.Size = sizeof(SENTINAL_OBSERVATION_EVENT);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedCreate;

    status = SentinalValidateObservationEvent(&event);
    UNREFERENCED_PARAMETER(status);

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
    SENTINAL_OBSERVATION_EVENT event;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    event.Size = sizeof(SENTINAL_OBSERVATION_EVENT);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedWrite;

    status = SentinalValidateObservationEvent(&event);
    UNREFERENCED_PARAMETER(status);

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
    SENTINAL_OBSERVATION_EVENT event;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    event.Size = sizeof(SENTINAL_OBSERVATION_EVENT);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedSetInformation;

    status = SentinalValidateObservationEvent(&event);
    UNREFERENCED_PARAMETER(status);

    /* ponytail: observation-only — pass through without altering outcome */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
