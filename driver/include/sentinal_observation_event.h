/*
 * sentinal_observation_event.h
 *
 * Internal kernel observation event model for the Sentinal AI minifilter.
 *
 * Phase 1.26 — Kernel Observation Event Model
 *
 * This header is kernel-mode only.
 * Defines a fixed-size, bounded, pointer-free event representation
 * constructed inside minifilter pre-operation observation callbacks.
 */

#ifndef SENTINAL_OBSERVATION_EVENT_H
#define SENTINAL_OBSERVATION_EVENT_H

#include <fltKernel.h>

#define SENTINAL_OBSERVATION_EVENT_VERSION_1 1

typedef enum _SENTINAL_OBSERVED_OPERATION {
    SentinalObservedCreate         = 1,
    SentinalObservedWrite          = 2,
    SentinalObservedSetInformation = 3
} SENTINAL_OBSERVED_OPERATION;

typedef struct _SENTINAL_OBSERVATION_EVENT {
    ULONG Size;
    ULONG Version;
    SENTINAL_OBSERVED_OPERATION Operation;
} SENTINAL_OBSERVATION_EVENT, *PSENTINAL_OBSERVATION_EVENT;

/*
 * Validates the integrity and bounds of a stack or buffer observation event.
 * Safe to call at IRQL <= DISPATCH_LEVEL.
 */
NTSTATUS
SentinalValidateObservationEvent(
    _In_ const SENTINAL_OBSERVATION_EVENT* Event
);

#endif /* SENTINAL_OBSERVATION_EVENT_H */
