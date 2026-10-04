/*
 * sentinal_observation_event.h
 *
 * Internal kernel observation event model for the Sentinal AI minifilter.
 *
 * Phase 1.28 — Kernel Path Acquisition
 *
 * This header is kernel-mode only.
 * Defines a fixed-size, bounded, pointer-free event representation
 * constructed inside minifilter pre-operation observation callbacks.
 *
 * PathLength is the count of meaningful WCHAR characters in Path[],
 * excluding the NUL terminator. The Path[] buffer is always NUL-terminated.
 * An event with PathLength == 0 is invalid.
 */

#ifndef SENTINAL_OBSERVATION_EVENT_H
#define SENTINAL_OBSERVATION_EVENT_H

#include <fltKernel.h>
#include <sentinal/driver_contract.h>

#define SENTINAL_OBSERVATION_EVENT_VERSION_1 1

/*
 * Maximum path buffer in WCHAR units (mirrors SENTINAL_DRIVER_MAX_PATH_CHARS,
 * which is the byte/char limit used by the shared contract's char path[]).
 * We store the wide form here; the adapter narrows to UTF-8/ANSI on export.
 */
#define SENTINAL_OBSERVATION_EVENT_MAX_PATH SENTINAL_DRIVER_MAX_PATH_CHARS

typedef enum _SENTINAL_OBSERVED_OPERATION {
    SentinalObservedCreate         = 1,
    SentinalObservedWrite          = 2,
    SentinalObservedSetInformation = 3
} SENTINAL_OBSERVED_OPERATION;

typedef struct _SENTINAL_OBSERVATION_EVENT {
    ULONG                       Size;
    ULONG                       Version;
    SENTINAL_OBSERVED_OPERATION Operation;
    USHORT                      PathLength;   /* WCHAR count, excl. NUL */
    WCHAR                       Path[SENTINAL_OBSERVATION_EVENT_MAX_PATH];
} SENTINAL_OBSERVATION_EVENT, *PSENTINAL_OBSERVATION_EVENT;

/*
 * Validates the integrity and bounds of a stack or buffer observation event.
 * Requires PathLength > 0 and PathLength < SENTINAL_OBSERVATION_EVENT_MAX_PATH.
 * Safe to call at IRQL <= DISPATCH_LEVEL.
 */
NTSTATUS
SentinalValidateObservationEvent(
    _In_ const SENTINAL_OBSERVATION_EVENT* Event
);

#endif /* SENTINAL_OBSERVATION_EVENT_H */
