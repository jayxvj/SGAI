/*
 * driver_entry.c
 *
 * Sentinal AI minifilter driver — DriverEntry and filter lifecycle.
 *
 * Phase 1.30 — Filter Manager Communication Port Foundation
 *
 * Responsibilities:
 *   - Register the minifilter with Filter Manager (FltRegisterFilter)
 *   - Initialize the communication port (SentinalInitializeCommunicationPort)
 *   - Start filtering (FltStartFiltering)
 *   - Clean up communication port and unregister on unload (SentinalDriverUnload)
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
 *   - message payload processing
 *   - IOCTL handling
 *   - kernel filesystem calls or re-entrant I/O
 */

#include "sentinal_driver.h"
#include "sentinal_path_acquisition.h"
#include "sentinal_communication_port.h"

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
     * Establish the Filter Manager communication port BEFORE filtering starts.
     * The communication endpoint must be fully established before the minifilter
     * begins processing active filesystem I/O.
     */
    status = SentinalInitializeCommunicationPort(g_SentinalFilter);

    if (!NT_SUCCESS(status)) {
        SentinalCleanupCommunicationPort(g_SentinalFilter);
        FltUnregisterFilter(g_SentinalFilter);
        g_SentinalFilter = NULL;
        return status;
    }

    /*
     * Begin filtering I/O.
     * If start fails, clean up the communication port and unregister the filter.
     */
    status = FltStartFiltering(g_SentinalFilter);

    if (!NT_SUCCESS(status)) {
        SentinalCleanupCommunicationPort(g_SentinalFilter);
        FltUnregisterFilter(g_SentinalFilter);
        g_SentinalFilter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

/* =========================================================================
 * SentinalDriverUnload
 *
 * Called by Filter Manager when the driver is being unloaded.
 * Deterministic cleanup ordering:
 *   1. Close communication port (server & client)
 *   2. Unregister filter
 *   3. Clear global handle
 * ========================================================================= */

NTSTATUS
SentinalDriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_SentinalFilter != NULL) {
        SentinalCleanupCommunicationPort(g_SentinalFilter);
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

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    RtlZeroMemory(&event, sizeof(event));
    event.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    event.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedCreate;

    status = SentinalAcquireObservationPath(Data, &event);
    if (NT_SUCCESS(status)) {
        /*
         * Path acquired. Validate the fully-populated event.
         * Adapter is not invoked here (no communication channel yet).
         * ponytail: discard status — observation-only, no side effects.
         */
        status = SentinalValidateObservationEvent(&event);
        UNREFERENCED_PARAMETER(status);
    }
    /* If path acquisition failed, silently discard. Never fabricate. */

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

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    RtlZeroMemory(&event, sizeof(event));
    event.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    event.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedWrite;

    status = SentinalAcquireObservationPath(Data, &event);
    if (NT_SUCCESS(status)) {
        status = SentinalValidateObservationEvent(&event);
        UNREFERENCED_PARAMETER(status);
    }

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

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    RtlZeroMemory(&event, sizeof(event));
    event.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    event.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedSetInformation;

    status = SentinalAcquireObservationPath(Data, &event);
    if (NT_SUCCESS(status)) {
        status = SentinalValidateObservationEvent(&event);
        UNREFERENCED_PARAMETER(status);
    }

    /* ponytail: observation-only — pass through without altering outcome */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
