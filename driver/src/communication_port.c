/*
 * communication_port.c
 *
 * Filter Manager Communication Port Foundation for Sentinal AI minifilter driver.
 *
 * Phase 1.30 — Filter Manager Communication Port Foundation
 *
 * Responsibilities:
 *   - Creates and manages the server communication port lifecycle
 *   - Implements connect notify callback with single-client policy enforcement
 *   - Implements disconnect notify callback with safe resource cleanup
 *   - Closes communication ports in correct order prior to filter unregistration
 *
 * Security:
 *   - The port security descriptor is created via FltBuildDefaultSecurityDescriptor
 *     with FLT_PORT_ALL_ACCESS. This restricts port connection access to:
 *       1. System Administrators (Administrators group / BUILTIN\Administrators)
 *       2. LocalSystem (NT AUTHORITY\SYSTEM)
 *   - Standard, unprivileged user accounts are denied connection by the Windows
 *     object manager at the Filter Manager port boundary.
 *   - Note: This provides the baseline kernel/user privilege boundary for development.
 *     Full cryptographic process authentication will be layered in subsequent phases.
 *
 * Lifecycle and Synchronization:
 *   - All port lifecycle functions and callbacks execute at IRQL = PASSIVE_LEVEL.
 *   - Connection state uses atomic pointer intrinsics (InterlockedCompareExchangePointer,
 *     InterlockedExchangePointer). This avoids spinlocks (which raise IRQL to
 *     DISPATCH_LEVEL and would violate FltCloseClientPort's PASSIVE_LEVEL contract)
 *     and avoids mutex allocation overhead.
 *   - Cleanup is deterministic: the server port is closed first (stopping new
 *     connections), followed by any active client port, prior to FltUnregisterFilter.
 */

#include "sentinal_communication_port.h"
#include "sentinal_message_transport.h"
#include "sentinal_driver_unicode_contract_adapter.h"

/* =========================================================================
 * Internal Communication State
 * ========================================================================= */

typedef struct _SENTINAL_COMMUNICATION_STATE {
    PFLT_FILTER Filter;
    PFLT_PORT   ServerPort;
    PFLT_PORT   ClientPort;
} SENTINAL_COMMUNICATION_STATE;

static SENTINAL_COMMUNICATION_STATE g_CommunicationState = { NULL, NULL, NULL };

/* =========================================================================
 * SentinalInitializeCommunicationPort
 * ========================================================================= */

_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SentinalInitializeCommunicationPort(
    _In_ PFLT_FILTER Filter
)
{
    NTSTATUS             status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES    objectAttributes;
    UNICODE_STRING       portName;
    PFLT_PORT            serverPort = NULL;

    PAGED_CODE();

    if (Filter == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Build the default security descriptor granting access only to
     * System Administrators and LocalSystem.
     * Rejects Everyone / unprivileged callers at the kernel boundary.
     */
    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, SENTINAL_COMMUNICATION_PORT_NAME);

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
    );

    /*
     * Create the communication server port.
     *
     * MaxConnections = 1: Filter Manager enforces at most one concurrent connection.
     * MessageNotifyCallback = SentinalPortMessageNotify: Transport boundary message validation.
     * ServerPortCookie = NULL: No per-server cookie required.
     */
    status = FltCreateCommunicationPort(
        Filter,
        &serverPort,
        &objectAttributes,
        NULL,
        SentinalPortConnectNotify,
        SentinalPortDisconnectNotify,
        SentinalPortMessageNotify,
        1     /* MaxConnections */
    );

    /*
     * FltCreateCommunicationPort captures the security descriptor into the
     * created port object; free the temporary descriptor immediately.
     */
    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        g_CommunicationState.ServerPort = NULL;
        return status;
    }

    g_CommunicationState.Filter     = Filter;
    g_CommunicationState.ServerPort = serverPort;

    return STATUS_SUCCESS;
}

/* =========================================================================
 * SentinalCleanupCommunicationPort
 * ========================================================================= */

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SentinalCleanupCommunicationPort(
    _In_ PFLT_FILTER Filter
)
{
    PFLT_PORT serverPort;
    PFLT_PORT clientPort;

    PAGED_CODE();

    /*
     * Step 1: Atomically close the server communication port.
     * This stops Filter Manager from accepting any new client connections.
     */
    serverPort = (PFLT_PORT)InterlockedExchangePointer(
        (PVOID volatile *)&g_CommunicationState.ServerPort,
        NULL
    );

    if (serverPort != NULL) {
        FltCloseCommunicationPort(serverPort);
    }

    /*
     * Step 2: Atomically close any active client communication port.
     * Ensures no client connection remains alive past driver teardown.
     */
    clientPort = (PFLT_PORT)InterlockedExchangePointer(
        (PVOID volatile *)&g_CommunicationState.ClientPort,
        NULL
    );

    if (clientPort != NULL && Filter != NULL) {
        FltCloseClientPort(Filter, &clientPort);
    }

    g_CommunicationState.Filter = NULL;
}

/* =========================================================================
 * SentinalPortConnectNotify
 * ========================================================================= */

_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
SentinalPortConnectNotify(
    _In_                          PFLT_PORT ClientPort,
    _In_opt_                      PVOID     ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_                          ULONG     SizeOfContext,
    _Outptr_result_maybenull_     PVOID    *ConnectionPortCookie
)
{
    PFLT_PORT oldClient;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    /*
     * Validate incoming ClientPort handle.
     * ServerPortCookie is an optional input and may be NULL (must not be rejected).
     */
    if (ClientPort == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * ConnectionPortCookie is an output pointer supplied by Filter Manager.
     * For this single-client foundation, tracked state resides in g_CommunicationState.
     * We initialize the output cookie to NULL if the output pointer is provided.
     */
    if (ConnectionPortCookie != NULL) {
        *ConnectionPortCookie = NULL;
    }

    /*
     * Enforce single-client connection policy:
     * Atomically store the new ClientPort if currently NULL.
     * If a client is already connected, reject the second connection with STATUS_DEVICE_BUSY.
     */
    oldClient = (PFLT_PORT)InterlockedCompareExchangePointer(
        (PVOID volatile *)&g_CommunicationState.ClientPort,
        (PVOID)ClientPort,
        NULL
    );

    if (oldClient != NULL) {
        /* A client is already connected; reject concurrent connection */
        return STATUS_DEVICE_BUSY;
    }

    return STATUS_SUCCESS;
}

/* =========================================================================
 * SentinalPortDisconnectNotify
 * ========================================================================= */

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FLTAPI
SentinalPortDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
)
{
    PFLT_PORT clientPort;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ConnectionCookie);

    /*
     * Atomically retrieve and clear the tracked client port.
     * Filter Manager requires the minifilter to call FltCloseClientPort to
     * release its reference to the client communication port.
     */
    clientPort = (PFLT_PORT)InterlockedExchangePointer(
        (PVOID volatile *)&g_CommunicationState.ClientPort,
        NULL
    );

    if (clientPort != NULL && g_CommunicationState.Filter != NULL) {
        FltCloseClientPort(g_CommunicationState.Filter, &clientPort);
    }
}

/* =========================================================================
 * SentinalIsClientConnected
 * ========================================================================= */

BOOLEAN
SentinalIsClientConnected(
    VOID
)
{
    return (g_CommunicationState.ClientPort != NULL) ? TRUE : FALSE;
}

/* =========================================================================
 * SentinalSendWriteObservation (Phase 1.32)
 *
 * Integration point: connects a validated IRP_MJ_WRITE observation event
 * to the existing kernel->user FltSendMessage transport.
 *
 * The function is fire-and-forget from the filesystem callback perspective.
 * The filesystem WRITE always continues regardless of transport outcome.
 *
 * Synchronization note:
 *   g_CommunicationState.ClientPort is read without a lock by the same
 *   SentinalIsClientConnected() pattern used throughout this file.
 *   FltSendMessage itself handles concurrent port teardown safely via the
 *   Filter Manager reference-counted port model.
 * ========================================================================= */

_IRQL_requires_max_(APC_LEVEL)
VOID
SentinalSendWriteObservation(
    _In_ PFLT_FILTER                      Filter,
    _In_ const SENTINAL_OBSERVATION_EVENT *Event
)
{
    NTSTATUS                               status;
    ULONGLONG                              requestId;
    SentinalDriverUnicodeProtectionRequest request;
    SentinalDriverUnicodeProtectionResponse response;

    if (Filter == NULL || Event == NULL) {
        return;
    }

    /*
     * 1. Early-exit if no user-mode client is connected.
     *    Avoids generating a requestId or performing conversion when nobody
     *    is listening. Pass-through continues unconditionally.
     */
    if (g_CommunicationState.ClientPort == NULL) {
        return;
    }

    /*
     * 2. Generate a nonzero monotonic request ID.
     *    Atomic; safe at any IRQL.
     */
    requestId = SentinalGenerateRequestId();

    /*
     * 3. Convert the observation event to the Unicode contract format.
     *    SentinalObservationToUnicodeDriverRequest:
     *      - Validates the event (size, version, operation, path length).
     *      - Maps SentinalObservedWrite -> SENTINAL_OP_WRITE.
     *      - Rejects CREATE and SET_INFORMATION (STATUS_NOT_SUPPORTED).
     *      - Copies the UTF-16 path without narrowing.
     *      - Validates the resulting request.
     *
     *    If conversion fails (unsupported operation, bad path, etc.),
     *    silently discard and pass through the write.
     */
    RtlZeroMemory(&request, sizeof(request));
    status = SentinalObservationToUnicodeDriverRequest(Event, requestId, &request);
    if (!NT_SUCCESS(status)) {
        /* Conversion failed — not a transport error, just unsupported/invalid.
         * Filesystem write continues unchanged. */
        return;
    }

    /*
     * 4. Send the request to user-mode via FltSendMessage.
     *    Bounded timeout: SENTINAL_TRANSPORT_DEFAULT_TIMEOUT_MS (1000 ms).
     *    On timeout, STATUS_TIMEOUT is returned — NEVER converted to ALLOW.
     *
     *    ClientPort is passed by address (&g_CommunicationState.ClientPort)
     *    as required by FltSendMessage's port-reference semantics.
     *    Filter Manager handles concurrent port teardown safely.
     *
     *    Transport result is diagnostic only: the WRITE always continues.
     */
    RtlZeroMemory(&response, sizeof(response));
    status = SentinalSendProtectionRequest(
        Filter,
        &g_CommunicationState.ClientPort,
        &request,
        &response,
        SENTINAL_TRANSPORT_DEFAULT_TIMEOUT_MS
    );

    /*
     * 5. Transport result handling.
     *    In Phase 1.32 the result is ONLY diagnostic. The WRITE is never
     *    blocked, denied, or modified regardless of:
     *      - STATUS_SUCCESS with ALLOW response
     *      - STATUS_SUCCESS with DENY response (still passes through)
     *      - STATUS_TIMEOUT
     *      - STATUS_DATA_ERROR (mismatched requestId or malformed response)
     *      - STATUS_INFO_LENGTH_MISMATCH
     *      - Any other transport failure
     *
     *    ponytail: transport-result discarded here; upgrade path = policy
     *    enforcement phase where status/response.decision drives a real action.
     */
    (VOID)status;
    (VOID)response;

    /* Filesystem write ALWAYS continues regardless of transport outcome. */
}
