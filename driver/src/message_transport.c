/*
 * message_transport.c
 *
 * Kernel/User-Mode Message Transport Foundation for Sentinal AI minifilter.
 *
 * Phase 1.31 — Kernel/User-Mode Message Transport Foundation
 *
 * Responsibilities:
 *   - Implements SentinalGenerateRequestId (atomic monotonic non-zero generator)
 *   - Implements SentinalPortMessageNotify (Filter Manager message callback)
 *   - Implements SentinalSendProtectionRequest (kernel->user FltSendMessage helper)
 *
 * Strict isolation:
 *   - Pure transport boundary: no policy evaluation, no file blocking
 *   - Bounded timeout: transport failure or timeout is NEVER converted to ALLOW
 *   - Comprehensive contract validation on all incoming/outgoing messages
 */

#include "sentinal_message_transport.h"

/* =========================================================================
 * Request ID Generation
 * ========================================================================= */

static volatile LONG64 g_SentinalNextRequestId = 1;

uint64_t
SentinalGenerateRequestId(
    VOID
)
{
    LONG64 id = InterlockedIncrement64(&g_SentinalNextRequestId);
    if (id == 0) {
        id = InterlockedIncrement64(&g_SentinalNextRequestId);
    }
    return (uint64_t)id;
}

/* =========================================================================
 * Kernel Message Notification Callback (User -> Kernel)
 * ========================================================================= */

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
)
{
    const SentinalDriverUnicodeProtectionRequest* request;
    SentinalDriverUnicodeProtectionResponse       response;
    SentinalStatus                                validationStatus;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnOutputBufferLength = 0;

    /*
     * 1. Validate InputBuffer pointer and expected exact size.
     */
    if (InputBuffer == NULL || InputBufferLength != (ULONG)sizeof(SentinalDriverUnicodeProtectionRequest)) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (const SentinalDriverUnicodeProtectionRequest*)InputBuffer;

    /*
     * 2. Validate incoming request against authoritative Unicode contract.
     *    Never trust requestId, operation, source, pathLength, or reserved fields.
     */
    validationStatus = SentinalDriverUnicodeValidateProtectionRequest(request);
    if (validationStatus != SENTINAL_STATUS_SUCCESS) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 3. Construct deterministic transport test response if output buffer is provided.
     */
    if (OutputBuffer != NULL) {
        if (OutputBufferLength < (ULONG)sizeof(SentinalDriverUnicodeProtectionResponse)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(&response, sizeof(response));

        response.header.size         = (uint32_t)sizeof(SentinalDriverUnicodeProtectionResponse);
        response.header.majorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
        response.header.minorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
        response.header.messageType  = (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
        response.header.reserved     = 0;

        response.requestId = request->requestId;
        response.decision  = (uint32_t)SENTINAL_DECISION_ALLOW; /* Transport-test response only */
        response.status    = (uint32_t)SENTINAL_STATUS_SUCCESS;
        response.reserved  = 0;
        response.reserved1 = 0;

        /* Validate response before copying */
        validationStatus = SentinalDriverUnicodeValidateProtectionResponse(&response);
        if (validationStatus != SENTINAL_STATUS_SUCCESS) {
            return STATUS_INTERNAL_ERROR;
        }

        RtlCopyMemory(OutputBuffer, &response, sizeof(response));
        *ReturnOutputBufferLength = (ULONG)sizeof(response);
    }

    return STATUS_SUCCESS;
}

/* =========================================================================
 * Kernel -> User Message Transport Helper
 * ========================================================================= */

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SentinalSendProtectionRequest(
    _In_  PFLT_FILTER                                   Filter,
    _In_  PFLT_PORT                                    *ClientPort,
    _In_  const SentinalDriverUnicodeProtectionRequest *Request,
    _Out_ SentinalDriverUnicodeProtectionResponse      *OutResponse,
    _In_  ULONG                                         TimeoutMilliseconds
)
{
    NTSTATUS                                status;
    LARGE_INTEGER                           timeout;
    SentinalDriverUnicodeProtectionResponse replyBuffer;
    ULONG                                   replyLength;
    SentinalStatus                          validationStatus;

    if (Filter == NULL || ClientPort == NULL || *ClientPort == NULL ||
        Request == NULL || OutResponse == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 1. Validate complete request using shared contract validation.
     */
    validationStatus = SentinalDriverUnicodeValidateProtectionRequest(Request);
    if (validationStatus != SENTINAL_STATUS_SUCCESS) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 2. Zero-initialize reply buffer on local stack.
     */
    RtlZeroMemory(&replyBuffer, sizeof(replyBuffer));
    replyLength = (ULONG)sizeof(replyBuffer);

    /*
     * 3. Set up relative timeout in 100-nanosecond units.
     *    Negative value indicates relative time. 1 ms = 10,000 units.
     */
    timeout.QuadPart = -10000LL * (LONGLONG)TimeoutMilliseconds;

    /*
     * 4. Send message to user-mode via FltSendMessage.
     */
    status = FltSendMessage(
        Filter,
        ClientPort,
        (PVOID)Request,
        (ULONG)sizeof(SentinalDriverUnicodeProtectionRequest),
        (PVOID)&replyBuffer,
        &replyLength,
        &timeout
    );

    /*
     * 5. Explicitly handle timeout and transport errors.
     *    Never convert a transport failure into ALLOW.
     */
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * 6. Validate reply length.
     */
    if (replyLength != (ULONG)sizeof(SentinalDriverUnicodeProtectionResponse)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /*
     * 7. Validate reply content against Unicode contract.
     */
    validationStatus = SentinalDriverUnicodeValidateProtectionResponse(&replyBuffer);
    if (validationStatus != SENTINAL_STATUS_SUCCESS) {
        return STATUS_DATA_ERROR;
    }

    /*
     * 8. Verify request ID matching.
     */
    if (replyBuffer.requestId != Request->requestId) {
        return STATUS_DATA_ERROR;
    }

    /*
     * 9. Assign to output buffer only on complete success.
     */
    *OutResponse = replyBuffer;
    return STATUS_SUCCESS;
}
