/*
 * path_acquisition.c
 *
 * Kernel-mode file-system path acquisition for the Sentinal AI minifilter.
 *
 * Phase 1.28 — Kernel Path Acquisition
 *
 * Non-paged: SentinalAcquireObservationPath is called from minifilter
 * pre-operation callbacks.  FltGetFileNameInformation requires IRQL <= APC_LEVEL.
 *
 * No dynamic allocation visible to callers: FLT_FILE_NAME_INFORMATION is
 * allocated by Filter Manager and released via FltReleaseFileNameInformation
 * before this function returns.
 */

#include "sentinal_path_acquisition.h"

NTSTATUS
SentinalAcquireObservationPath(
    _In_    PFLT_CALLBACK_DATA          Data,
    _Inout_ SENTINAL_OBSERVATION_EVENT* Event
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS                   status;
    USHORT                     charCount;

    if (Data == NULL || Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * FltGetFileNameInformation requires IRQL <= APC_LEVEL.
     * Reject at passive dispatch levels where it would be unsafe.
     *
     * ponytail: KeGetCurrentIrql() is a kernel intrinsic; no overhead.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Request the opened (post-open normalized) name where possible,
     * falling back to the normalized name.  The opened name is the most
     * accurate representation of the file that was actually targeted.
     *
     * FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT is the
     * standard safe choice inside a pre-operation callback.
     */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Parse the name information to populate individual components */
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    /*
     * nameInfo->Name is a UNICODE_STRING whose Length is in bytes.
     * Convert to WCHAR count.  Length is always even (UTF-16LE).
     */
    charCount = nameInfo->Name.Length / sizeof(WCHAR);

    if (charCount == 0) {
        /* Empty name — reject; do not fabricate a path */
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Enforce the bounded buffer: charCount must fit with a NUL terminator.
     * If the path is too long for the contract, reject rather than truncate.
     */
    if (charCount >= SENTINAL_OBSERVATION_EVENT_MAX_PATH) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Copy name into the event path buffer */
    RtlCopyMemory(
        Event->Path,
        nameInfo->Name.Buffer,
        charCount * sizeof(WCHAR)
    );
    Event->Path[charCount] = L'\0';
    Event->PathLength = charCount;

    FltReleaseFileNameInformation(nameInfo);
    return STATUS_SUCCESS;
}
