/*
 * observation_event.c
 *
 * Validation and lifecycle logic for kernel observation events.
 *
 * Phase 1.26 — Kernel Observation Event Model
 *
 * Non-paged: All code is safe to execute at IRQL <= DISPATCH_LEVEL.
 * No memory allocation, no user-buffer access, no blocking/synchronization.
 */

#include "sentinal_observation_event.h"

NTSTATUS
SentinalValidateObservationEvent(
    _In_ const SENTINAL_OBSERVATION_EVENT* Event
)
{
    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Event->Size != sizeof(SENTINAL_OBSERVATION_EVENT)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (Event->Version != SENTINAL_OBSERVATION_EVENT_VERSION_1) {
        return STATUS_REVISION_MISMATCH;
    }

    switch (Event->Operation) {
    case SentinalObservedCreate:
    case SentinalObservedWrite:
    case SentinalObservedSetInformation:
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}
