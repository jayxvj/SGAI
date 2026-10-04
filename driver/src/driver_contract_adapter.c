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

    /* 4. Path: the only operation that reaches here is SentinalObservedWrite
     *    (SENTINAL_OP_WRITE). The kernel observation carries a UTF-16LE WCHAR
     *    path. The current shared contract defines path[] as char[], which is
     *    an ANSI/byte representation. There is no lossless encoding from
     *    UTF-16LE to char[] without an explicit, agreed Unicode contract that
     *    has not been designed yet.
     *
     *    Byte-narrowing (casting each WCHAR to char) silently corrupts any
     *    path with non-ASCII characters (Cyrillic, CJK, accented Latin, etc.).
     *    That is not acceptable.
     *
     *    Reject the conversion rather than corrupt the path.
     *    STATUS_NOT_SUPPORTED is consistent with the Phase 1.27 rejection
     *    policy for representations that cannot be faithfully expressed by the
     *    current contract ABI.
     *
     *    Upgrade path: introduce a Unicode-capable kernel/user contract
     *    (e.g. a wchar_t path[] field, or an agreed UTF-8 encoding step)
     *    before enabling this conversion path.
     */
    UNREFERENCED_PARAMETER(mappedOp);
    return STATUS_NOT_SUPPORTED;
}
