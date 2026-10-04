/*
 * sentinal_driver_unicode_contract_adapter.h
 *
 * Kernel-side adapter between SENTINAL_OBSERVATION_EVENT and
 * SentinalDriverUnicodeProtectionRequest.
 *
 * Phase 1.29 — Unicode Driver Communication Contract
 *
 * Non-paged. IRQL <= DISPATCH_LEVEL.
 * No dynamic allocation, no user-buffer access, no filesystem calls.
 */

#ifndef SENTINAL_DRIVER_UNICODE_CONTRACT_ADAPTER_H
#define SENTINAL_DRIVER_UNICODE_CONTRACT_ADAPTER_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_KERNEL_MODE)
#include <fltKernel.h>
#include "sentinal_observation_event.h"
#else
#include <windows.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_REVISION_MISMATCH
#define STATUS_REVISION_MISMATCH ((NTSTATUS)0xC0000059L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef RtlZeroMemory
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
#endif

#define SENTINAL_OBSERVATION_EVENT_VERSION_1 1
#define SENTINAL_OBSERVATION_EVENT_MAX_PATH 1024

typedef enum _SENTINAL_OBSERVED_OPERATION {
    SentinalObservedCreate         = 1,
    SentinalObservedWrite          = 2,
    SentinalObservedSetInformation = 3
} SENTINAL_OBSERVED_OPERATION;

typedef struct _SENTINAL_OBSERVATION_EVENT {
    ULONG                       Size;
    ULONG                       Version;
    SENTINAL_OBSERVED_OPERATION Operation;
    USHORT                      PathLength;   /* UTF-16 code unit count, excl. NUL terminator */
    WCHAR                       Path[SENTINAL_OBSERVATION_EVENT_MAX_PATH];
} SENTINAL_OBSERVATION_EVENT, *PSENTINAL_OBSERVATION_EVENT;

static inline NTSTATUS SentinalValidateObservationEvent(const SENTINAL_OBSERVATION_EVENT* Event) {
    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Event->Size != sizeof(SENTINAL_OBSERVATION_EVENT)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (Event->Version != SENTINAL_OBSERVATION_EVENT_VERSION_1) {
        return STATUS_REVISION_MISMATCH;
    }
    if (Event->Operation != SentinalObservedCreate &&
        Event->Operation != SentinalObservedWrite &&
        Event->Operation != SentinalObservedSetInformation) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Event->PathLength == 0 ||
        Event->PathLength >= SENTINAL_OBSERVATION_EVENT_MAX_PATH) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}
#endif

#include <sentinal/driver_unicode_contract.h>

/*
 * SentinalObservationToUnicodeDriverRequest
 *
 * Converts a validated kernel observation event into a
 * SentinalDriverUnicodeProtectionRequest suitable for transmission to
 * user mode once a communication channel is established.
 *
 * Steps:
 *   1. Validate pointers and RequestId.
 *   2. Validate the observation event.
 *   3. Map the observed operation to a SentinalFileOp value.
 *      SentinalObservedCreate         -> STATUS_NOT_SUPPORTED
 *      SentinalObservedWrite          -> SENTINAL_OP_WRITE
 *      SentinalObservedSetInformation -> STATUS_NOT_SUPPORTED
 *   4. Copy the UTF-16 path from the event directly into the contract
 *      without any lossy encoding step.
 *   5. Validate the resulting contract message.
 *   6. Write to *Request only on complete success.
 *
 * The output parameter is not modified on failure.
 *
 * Return values:
 *   STATUS_SUCCESS          - conversion succeeded; *Request is populated.
 *   STATUS_INVALID_PARAMETER - NULL pointer, RequestId == 0, or invalid event.
 *   STATUS_NOT_SUPPORTED     - operation has no valid Unicode contract mapping.
 */
NTSTATUS
SentinalObservationToUnicodeDriverRequest(
    _In_  const SENTINAL_OBSERVATION_EVENT*       Event,
    _In_  ULONGLONG                               RequestId,
    _Out_ SentinalDriverUnicodeProtectionRequest* Request
);

#ifdef __cplusplus
}
#endif

#endif /* SENTINAL_DRIVER_UNICODE_CONTRACT_ADAPTER_H */
