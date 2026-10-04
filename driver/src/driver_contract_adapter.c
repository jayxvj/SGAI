/*
 * driver_contract_adapter.c
 *
 * Kernel-side contract adapter implementation.
 *
 * Phase 1.27 — Kernel Contract Adapter
 *
 * Pure C, non-paged, IRQL safe (IRQL <= DISPATCH_LEVEL).
 * No dynamic memory allocation, no user-buffer access, no filesystem calls.
 */

#include "sentinal_driver_contract_adapter.h"

NTSTATUS
SentinalObservationToDriverRequest(
    _In_  const SENTINAL_OBSERVATION_EVENT* Event,
    _In_  ULONGLONG                         RequestId,
    _Out_ SentinalDriverProtectionRequest*  Request
)
{
    NTSTATUS eventStatus;
    uint32_t mappedOp;
    SentinalDriverProtectionRequest localRequest;
    SentinalStatus contractStatus;

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
     * 3. Operation mapping:
     *    Map internal observation operation to existing SentinalFileOp values.
     *    - SentinalObservedCreate         -> IRP_MJ_CREATE does not inherently mean
     *      READ; it may represent open/create with any access mode. Reject safely.
     *    - SentinalObservedWrite          -> SENTINAL_OP_WRITE
     *    - SentinalObservedSetInformation -> Not representable in existing
     *      SentinalFileOp enum; reject safely with STATUS_NOT_SUPPORTED.
     */
    switch (Event->Operation) {
    case SentinalObservedCreate:
        /*
         * IRP_MJ_CREATE does not map inherently to SENTINAL_OP_READ.
         * Reject rather than invent READ semantics.
         */
        return STATUS_NOT_SUPPORTED;

    case SentinalObservedWrite:
        mappedOp = SENTINAL_OP_WRITE;
        break;

    case SentinalObservedSetInformation:
        /*
         * SET_INFORMATION has no corresponding single-bit operation in the
         * current shared SentinalFileOp definition (READ, WRITE, DELETE, RENAME, EXECUTE).
         * Must reject rather than invent non-existent semantics.
         */
        return STATUS_NOT_SUPPORTED;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    /* 4. Construct zero-initialized local request (no partial write to output) */
    RtlZeroMemory(&localRequest, sizeof(localRequest));

    /* Request header */
    localRequest.header.size = (uint32_t)sizeof(SentinalDriverProtectionRequest);
    localRequest.header.majorVersion = (uint16_t)SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    localRequest.header.minorVersion = (uint16_t)SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    localRequest.header.messageType = (uint32_t)SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST;
    localRequest.header.reserved = 0;

    /* Request payload */
    localRequest.requestId = RequestId;
    localRequest.operation = mappedOp;
    localRequest.source = SENTINAL_DRIVER_SOURCE_KERNEL;
    localRequest.reserved = 0;

    /*
     * 5. Path handling:
     *    SENTINAL_OBSERVATION_EVENT contains no path data at this phase.
     *    We must not invent placeholder paths. Because pathLength remains 0,
     *    the shared contract validator will reject the request.
     */
    localRequest.pathLength = 0;
    localRequest.path[0] = '\0';

    /* 6. Validate using the authoritative shared contract validator */
    contractStatus = SentinalDriverValidateProtectionRequest(&localRequest);
    if (contractStatus != SENTINAL_STATUS_SUCCESS) {
        /*
         * A valid protection request fundamentally requires a real path
         * (pathLength > 0), which is deferred to a future path-acquisition phase.
         * Reject conversion without mutating the caller's output.
         */
        return STATUS_NOT_SUPPORTED;
    }

    /* 7. Assign to output buffer only on complete validation success */
    *Request = localRequest;
    return STATUS_SUCCESS;
}
