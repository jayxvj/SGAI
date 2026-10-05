/*
 * sentinal_message_transport.h
 *
 * Kernel/User-Mode Message Transport Foundation for Sentinal AI minifilter.
 *
 * Phase 1.31 — Kernel/User-Mode Message Transport Foundation
 *
 * Responsibilities:
 *   - Declares kernel-to-user message transport helper (SentinalSendProtectionRequest)
 *   - Declares Filter Manager message notification callback (SentinalPortMessageNotify)
 *   - Declares atomic, non-zero request ID generator (SentinalGenerateRequestId)
 *   - Defines default bounded communication timeout
 *
 * Architectural constraints:
 *   - Uses the authoritative Unicode contract (SentinalDriverUnicodeProtectionRequest / Response)
 *   - Pure transport boundary: no policy evaluation, no file blocking, no enforcement
 *   - Bounded timeout: transport failure or timeout is NEVER converted to ALLOW
 *   - Kernel-mode only: requires <fltKernel.h>
 */

#ifndef SENTINAL_MESSAGE_TRANSPORT_H
#define SENTINAL_MESSAGE_TRANSPORT_H

#include <fltKernel.h>
#include <sentinal/driver_unicode_contract.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

/*
 * Default bounded transport timeout for kernel->user messages.
 * Conservative development timeout: 1000 milliseconds (1 second).
 */
#define SENTINAL_TRANSPORT_DEFAULT_TIMEOUT_MS 1000U

/* =========================================================================
 * Request ID Generation
 * ========================================================================= */

/*
 * SentinalGenerateRequestId
 *
 * Monotonically increasing, atomic, non-zero request ID generator.
 * Skips 0 on potential 64-bit integer wraparound.
 * Safe to call at any IRQL.
 */
uint64_t
SentinalGenerateRequestId(
    VOID
);

/* =========================================================================
 * Kernel Message Notification Callback (User -> Kernel)
 * ========================================================================= */

/*
 * SentinalPortMessageNotify
 *
 * Invoked by Filter Manager when a user-mode client sends a message via
 * FilterSendMessage.
 *
 * Validates the incoming message against the Unicode driver contract.
 * Rejects malformed messages with STATUS_INVALID_PARAMETER or STATUS_BUFFER_TOO_SMALL.
 * For Phase 1.31, returns a deterministic transport-test response (SENTINAL_DECISION_ALLOW)
 * with the matching requestId.
 *
 * Executes at IRQL = PASSIVE_LEVEL.
 */
_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
SentinalPortMessageNotify(
    _In_opt_                                                        PVOID  PortCookie,
    _In_reads_bytes_opt_(InputBufferLength)                         PVOID  InputBuffer,
    _In_                                                            ULONG  InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_                                                            ULONG  OutputBufferLength,
    _Out_                                                           PULONG ReturnOutputBufferLength
);

/* =========================================================================
 * Kernel -> User Message Transport Helper
 * ========================================================================= */

/*
 * SentinalSendProtectionRequest
 *
 * Sends a validated Unicode protection request to the connected user-mode
 * client using FltSendMessage, waits up to TimeoutMilliseconds, and validates
 * the received reply.
 *
 * Guarantees:
 *   - Verifies client port is connected before sending
 *   - Validates Request before transmission
 *   - Applies explicit bounded timeout (relative 100ns units)
 *   - On timeout, returns STATUS_TIMEOUT (never fabricates ALLOW)
 *   - Validates OutResponse structure, size, version, decision, status, and reserved fields
 *   - Enforces OutResponse->requestId == Request->requestId
 *   - Rejects mismatched or corrupted responses
 *
 * Executes at IRQL <= APC_LEVEL.
 */
_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SentinalSendProtectionRequest(
    _In_  PFLT_FILTER                                   Filter,
    _In_  PFLT_PORT                                    *ClientPort,
    _In_  const SentinalDriverUnicodeProtectionRequest *Request,
    _Out_ SentinalDriverUnicodeProtectionResponse      *OutResponse,
    _In_  ULONG                                         TimeoutMilliseconds
);

#endif /* SENTINAL_MESSAGE_TRANSPORT_H */
