/*
 * driver_unicode_contract_adapter.c
 *
 * Kernel-side Unicode contract adapter implementation.
 *
 * Phase 1.29 — Unicode Driver Communication Contract
 *
 * Pure C, non-paged, IRQL safe (IRQL <= DISPATCH_LEVEL).
 * No dynamic memory allocation, no user-buffer access, no filesystem calls.
 */

#include "sentinal_driver_unicode_contract_adapter.h"

NTSTATUS
SentinalObservationToUnicodeDriverRequest(
    _In_  const SENTINAL_OBSERVATION_EVENT*       Event,
    _In_  ULONGLONG                               RequestId,
    _Out_ SentinalDriverUnicodeProtectionRequest* Request
)
{
    NTSTATUS                             eventStatus;
    uint32_t                             mappedOp;
    SentinalDriverUnicodeProtectionRequest localRequest;
    SentinalStatus                       contractStatus;
    USHORT                               i;

    /* 1. Validate pointers and basic input requirements */
    if (Event == NULL || Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RequestId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 2. Validate the observation event structure */
    eventStatus = SentinalValidateObservationEvent(Event);
    if (!NT_SUCCESS(eventStatus)) {
        return eventStatus;
    }

    /*
     * 3. Operation mapping.
     *    SentinalObservedCreate         -> STATUS_NOT_SUPPORTED
     *      (IRP_MJ_CREATE does not inherently mean READ; reject.)
     *    SentinalObservedWrite          -> SENTINAL_OP_WRITE
     *    SentinalObservedSetInformation -> STATUS_NOT_SUPPORTED
     *      (no corresponding single-bit SentinalFileOp; reject.)
     */
    switch (Event->Operation) {
    case SentinalObservedCreate:
        return STATUS_NOT_SUPPORTED;

    case SentinalObservedWrite:
        mappedOp = (uint32_t)SENTINAL_OP_WRITE;
        break;

    case SentinalObservedSetInformation:
        return STATUS_NOT_SUPPORTED;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    /* 4. Build the Unicode contract message on a local stack buffer.
     *    Zero-initialize first so all reserved/padding bytes are zero. */
    RtlZeroMemory(&localRequest, sizeof(localRequest));

    /* Header */
    localRequest.header.size        = (uint32_t)sizeof(SentinalDriverUnicodeProtectionRequest);
    localRequest.header.majorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    localRequest.header.minorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    localRequest.header.messageType  = (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    localRequest.header.reserved     = 0;

    /* Payload */
    localRequest.requestId  = RequestId;
    localRequest.operation  = mappedOp;
    localRequest.source     = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
    localRequest.reserved0  = 0;
    localRequest.reserved   = 0;
    localRequest.reserved1  = 0;

    /*
     * 5. Copy the UTF-16 path losslessly.
     *    Event->PathLength is validated: > 0 and < SENTINAL_OBSERVATION_EVENT_MAX_PATH (1024).
     *    SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS is also 1024.
     *    The capacity check is therefore always satisfied, but we guard
     *    explicitly for defence-in-depth and ABI correctness.
     */
    if (Event->PathLength == 0 ||
        Event->PathLength >= SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < Event->PathLength; i++) {
        localRequest.path[i] = (uint16_t)Event->Path[i];
    }
    localRequest.path[Event->PathLength] = 0x0000u;
    localRequest.pathLength = (uint32_t)Event->PathLength;

    /* 6. Validate the resulting Unicode contract message */
    contractStatus = SentinalDriverUnicodeValidateProtectionRequest(&localRequest);
    if (contractStatus != SENTINAL_STATUS_SUCCESS) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 7. Assign to output only after complete success */
    *Request = localRequest;
    return STATUS_SUCCESS;
}
