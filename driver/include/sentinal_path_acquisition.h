/*
 * sentinal_path_acquisition.h
 *
 * Kernel-mode path acquisition for the Sentinal AI minifilter.
 *
 * Phase 1.28 — Kernel Path Acquisition
 *
 * Provides a single helper that attempts to acquire the normalized
 * file-system path from a Filter Manager callback data structure and
 * write it into a SENTINAL_OBSERVATION_EVENT.
 *
 * IRQL contract:
 *   FltGetFileNameInformation requires IRQL <= APC_LEVEL and that the
 *   call originates from a Filter Manager callback context.
 *   This helper checks KeGetCurrentIrql() and returns STATUS_UNSUCCESSFUL
 *   immediately if the IRQL constraint cannot be satisfied.
 *
 * Failure semantics:
 *   If a valid, complete path cannot be obtained, the function returns a
 *   failure NTSTATUS. The caller MUST discard the event and NOT proceed
 *   with an empty or partial path. No path is ever fabricated.
 */

#ifndef SENTINAL_PATH_ACQUISITION_H
#define SENTINAL_PATH_ACQUISITION_H

#include "sentinal_observation_event.h"

/*
 * SentinalAcquireObservationPath
 *
 * Acquires the normalized file-system path for the I/O operation described
 * by Data and writes it into Event->Path and Event->PathLength.
 *
 * Parameters:
 *   Data  - the callback data from the Filter Manager pre-operation callback.
 *           Must not be NULL.
 *   Event - the observation event to populate. Must not be NULL.
 *           On success, Event->Path is NUL-terminated and Event->PathLength
 *           holds the WCHAR count (excluding NUL).
 *           On failure, Event->Path and Event->PathLength are not modified.
 *
 * Return value:
 *   STATUS_SUCCESS          - path acquired and written into Event.
 *   STATUS_UNSUCCESSFUL     - IRQL too high; cannot call FltGetFileNameInformation.
 *   STATUS_BUFFER_TOO_SMALL - path exceeds SENTINAL_OBSERVATION_EVENT_MAX_PATH.
 *   Other NTSTATUS failures - FltGetFileNameInformation or FltParseFileNameInformation
 *                             returned an error.
 */
NTSTATUS
SentinalAcquireObservationPath(
    _In_    PFLT_CALLBACK_DATA          Data,
    _Inout_ SENTINAL_OBSERVATION_EVENT* Event
);

#endif /* SENTINAL_PATH_ACQUISITION_H */
