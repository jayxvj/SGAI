/*
 * sentinal_communication_port.h
 *
 * Filter Manager Communication Port Foundation for Sentinal AI minifilter driver.
 *
 * Phase 1.30 — Filter Manager Communication Port Foundation
 *
 * Responsibilities:
 *   - Defines the internal kernel/user Filter Manager communication port name
 *   - Declares lifecycle management functions (init, cleanup)
 *   - Declares connect and disconnect notify callbacks
 *   - Kernel-mode only: requires <fltKernel.h>
 *
 * Security:
 *   - The communication port is restricted via FltBuildDefaultSecurityDescriptor
 *     to System Administrators (Administrators group) and LocalSystem (SYSTEM).
 *   - Unprivileged standard user processes are denied access by the object manager.
 *   - Single-client connection model: secondary connections receive STATUS_DEVICE_BUSY.
 *
 * Non-responsibilities (strictly NOT in this phase):
 *   - No message processing (MessageNotifyCallback is NULL)
 *   - No FltSendMessage or FltReplyMessage
 *   - No policy evaluation or file blocking
 *   - No user-mode connection code or transport integration
 */

#ifndef SENTINAL_COMMUNICATION_PORT_H
#define SENTINAL_COMMUNICATION_PORT_H

#include <fltKernel.h>
#include "sentinal_observation_event.h"
#include "sentinal_message_transport.h"

/* =========================================================================
 * Port Name Definition
 *
 * Internal kernel/user communication endpoint name.
 * Filter Manager communication ports exist in the \FilterSupport object
 * directory and are accessed in user-mode via FilterConnectCommunicationPort.
 * ========================================================================= */

#define SENTINAL_COMMUNICATION_PORT_NAME L"\\SentinalAI\\ProtectionPort"

/* =========================================================================
 * Port Lifecycle Declarations
 * ========================================================================= */

/*
 * SentinalInitializeCommunicationPort
 *
 * Builds the default security descriptor (Administrators + LocalSystem),
 * initializes object attributes, and calls FltCreateCommunicationPort
 * to establish the server communication port.
 *
 * Must be called at IRQL = PASSIVE_LEVEL after FltRegisterFilter and before FltStartFiltering.
 */
_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SentinalInitializeCommunicationPort(
    _In_ PFLT_FILTER Filter
);

/*
 * SentinalCleanupCommunicationPort
 *
 * Closes the server communication port (stopping new connections) and
 * closes any active client communication port.
 *
 * Must be called at IRQL = PASSIVE_LEVEL before FltUnregisterFilter.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SentinalCleanupCommunicationPort(
    _In_ PFLT_FILTER Filter
);

/* =========================================================================
 * Filter Manager Port Callbacks
 * ========================================================================= */

/*
 * SentinalPortConnectNotify
 *
 * Invoked by Filter Manager when a user-mode client calls
 * FilterConnectCommunicationPort.
 *
 * Enforces a single-client connection policy: accepts the first connection
 * and rejects concurrent connections with STATUS_DEVICE_BUSY.
 *
 * Does NOT process messages, evaluate policy, or perform blocking operations.
 */
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
);

/*
 * SentinalPortDisconnectNotify
 *
 * Invoked by Filter Manager when the user-mode client closes its port handle
 * or when the minifilter is being unloaded.
 *
 * Releases the minifilter reference to the client port via FltCloseClientPort
 * and clears the tracked client connection state.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FLTAPI
SentinalPortDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
);

/* =========================================================================
 * State Inspection Helpers
 * ========================================================================= */

/*
 * SentinalIsClientConnected
 *
 * Returns TRUE if a client is currently connected, FALSE otherwise.
 */
BOOLEAN
SentinalIsClientConnected(
    VOID
);

/* =========================================================================
 * Phase 1.32 — Kernel Observation to Transport Integration
 * ========================================================================= */

/*
 * SentinalSendWriteObservation
 *
 * Connects a validated IRP_MJ_WRITE observation event to the kernel->user
 * message transport.
 *
 * Steps (internal):
 *   1. Early-exit if no user-mode client is connected (pass-through).
 *   2. Generate a nonzero monotonic requestId.
 *   3. Convert the observation event to a Unicode protection request via
 *      SentinalObservationToUnicodeDriverRequest.
 *   4. Send via SentinalSendProtectionRequest (FltSendMessage, 1000ms timeout).
 *   5. Validate the response (requestId match, contract validity).
 *   6. Discard the transport result — caller ALWAYS passes through.
 *
 * The filesystem operation is NEVER blocked, denied, or modified regardless
 * of the transport outcome. This function is purely diagnostic transport.
 *
 * IRQL: <= APC_LEVEL (same as FltSendMessage and FltGetFileNameInformation).
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
SentinalSendWriteObservation(
    _In_ PFLT_FILTER                      Filter,
    _In_ const SENTINAL_OBSERVATION_EVENT *Event
);

#endif /* SENTINAL_COMMUNICATION_PORT_H */
