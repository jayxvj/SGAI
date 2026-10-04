#ifndef SENTINAL_DRIVER_UNICODE_CONTRACT_H
#define SENTINAL_DRIVER_UNICODE_CONTRACT_H

/*
 * Sentinal AI — Unicode Driver Communication Contract
 *
 * Phase 1.29 — Unicode Driver Communication Contract
 *
 * Defines a versioned, bounded, UTF-16 kernel<->user-mode protection message
 * contract that can faithfully represent arbitrary Windows filesystem paths.
 *
 * Encoding
 * --------
 *   path[] contains UTF-16 code units stored as uint16_t.
 *   uint16_t is used rather than wchar_t to make the width explicit and to
 *   avoid any platform-dependent sizeof(wchar_t) assumption.
 *   Each element is one UTF-16 code unit (2 bytes, little-endian on Windows).
 *   Surrogate pairs are permitted; validation does not enforce BMP-only.
 *
 * Path length semantics
 * ----------------------
 *   pathLength is measured in UTF-16 code units (uint16_t elements).
 *   pathLength excludes the NUL terminator.
 *   path[pathLength] must equal 0x0000 (NUL).
 *   No embedded NUL (0x0000) is permitted at index < pathLength.
 *   pathLength must be > 0 and < SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS.
 *   No truncation is permitted; oversized paths must be rejected by the sender.
 *
 * Version semantics
 * -----------------
 *   majorVersion must equal SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION exactly.
 *   minorVersion must be <= SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION.
 *   A future receiver with a higher minor version may accept messages with a
 *   lower minor version. A receiver with a lower minor version must reject
 *   messages with a higher minor version (unknown fields may be present).
 *
 * pathLength semantics
 * ---------------------
 *   pathLength is a count of UTF-16 code units stored as uint16_t elements.
 *   It is NOT a byte count (not pathLength * 2).
 *   It is NOT a wchar_t count (wchar_t width is compiler/platform dependent).
 *   It is exactly the number of uint16_t elements in path[] that carry
 *   meaningful UTF-16 data, excluding the terminating NUL code unit.
 *   Validation enforces: 0 < pathLength < SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS
 *   and: path[pathLength] == 0x0000u
 *   and: path[i] != 0x0000u for all i < pathLength
 *
 * ABI requirements
 * ----------------
 *   Fixed-width integer types only. No pointers. No STL. No dynamic allocation.
 *   No flexible array members. No function pointers. No platform-dependent types.
 *   Fields are naturally aligned; no global packing pragma is applied.
 *   All structure sizes are fully accounted for by named fields; there are no
 *   unnamed compiler-generated trailing padding bytes in either structure.
 *   This header is safe to include from both C and C++.
 */

#include <stdint.h>
#include <sentinal/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Contract version
 * ========================================================================= */

#define SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION 1U
#define SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION 0U

/* =========================================================================
 * Path buffer capacity
 *
 * 1024 UTF-16 code units, matching the kernel observation event buffer
 * (SENTINAL_OBSERVATION_EVENT_MAX_PATH = SENTINAL_DRIVER_MAX_PATH_CHARS = 1024).
 * The buffer holds up to 1023 meaningful code units plus one NUL terminator,
 * because pathLength must be < SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS.
 * ========================================================================= */

#define SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS 1024U

/* =========================================================================
 * Source identifiers
 *
 * Mirrors the source constants used in the existing ANSI contract.
 * Defined here so both the kernel-side adapter and user-mode consumers can
 * reference them without depending on the ANSI contract header.
 * ========================================================================= */

#define SENTINAL_DRIVER_UNICODE_SOURCE_UNKNOWN   0U
#define SENTINAL_DRIVER_UNICODE_SOURCE_USER_MODE 1U
#define SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL    2U

/* =========================================================================
 * Message types
 * ========================================================================= */

typedef enum SentinalDriverUnicodeMessageType {
    SENTINAL_DRIVER_UNICODE_MESSAGE_UNKNOWN             = 0,
    SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST  = 1,
    SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE = 2
} SentinalDriverUnicodeMessageType;

/* =========================================================================
 * Common message header
 *
 *   size        — total byte size of the enclosing message structure
 *   majorVersion — must equal SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION
 *   minorVersion — must be <= SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION
 *   messageType  — discriminates the payload (SentinalDriverUnicodeMessageType)
 *   reserved     — must be zero
 *
 * Layout: 4+2+2+4+4 = 16 bytes, naturally aligned.
 * ========================================================================= */

typedef struct SentinalDriverUnicodeMessageHeader {
    uint32_t size;           /* offset  0 */
    uint16_t majorVersion;   /* offset  4 */
    uint16_t minorVersion;   /* offset  6 */
    uint32_t messageType;    /* offset  8 */
    uint32_t reserved;       /* offset 12 */
                             /* total: 16 */
} SentinalDriverUnicodeMessageHeader;

/* =========================================================================
 * Unicode Protection Request (kernel -> user-mode)
 *
 *   header      — see SentinalDriverUnicodeMessageHeader
 *   requestId   — nonzero opaque identifier, echoed in the response
 *   operation   — exactly one SentinalFileOp single-operation value
 *   source      — originating source (SENTINAL_DRIVER_UNICODE_SOURCE_*)
 *   pathLength  — count of UTF-16 code units (uint16_t elements) in path[],
 *                 excluding the terminating NUL code unit (0x0000).
 *                 NOT a byte count. NOT a wchar_t count.
 *                 must satisfy: 0 < pathLength < SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS
 *   reserved0   — must be zero
 *   path        — UTF-16 code unit buffer; path[pathLength] == 0x0000
 *                 no embedded NUL permitted at index < pathLength
 *   reserved    — must be zero
 *   reserved1   — must be zero; explicit trailing field; ensures all bytes
 *                 in sizeof(SentinalDriverUnicodeProtectionRequest) are
 *                 accounted for by named fields with no implicit padding
 *
 * Field offsets (x64 and x86, no packing):
 *   header:      offset    0, size  16
 *   requestId:   offset   16, size   8
 *   operation:   offset   24, size   4
 *   source:      offset   28, size   4
 *   pathLength:  offset   32, size   4
 *   reserved0:   offset   36, size   4
 *   path:        offset   40, size 2048
 *   reserved:    offset 2088, size   4
 *   reserved1:   offset 2092, size   4
 *   sizeof:      2096  (fully accounted by named fields; no implicit padding)
 * ========================================================================= */

typedef struct SentinalDriverUnicodeProtectionRequest {
    SentinalDriverUnicodeMessageHeader header;     /* offset    0 */
    uint64_t                           requestId;  /* offset   16 */
    uint32_t                           operation;  /* offset   24 */
    uint32_t                           source;     /* offset   28 */
    uint32_t                           pathLength; /* offset   32, UTF-16 code unit count excl. NUL */
    uint32_t                           reserved0;  /* offset   36, must be zero */
    uint16_t                           path[SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS]; /* offset 40 */
    uint32_t                           reserved;   /* offset 2088, must be zero */
    uint32_t                           reserved1;  /* offset 2092, must be zero; no implicit trailing padding */
} SentinalDriverUnicodeProtectionRequest;

/* =========================================================================
 * Unicode Protection Response (user-mode -> kernel)
 *
 *   header      — see SentinalDriverUnicodeMessageHeader
 *   requestId   — must match the corresponding request; must be nonzero
 *   decision    — SentinalDecision value; must be ALLOW, DENY, or AUDIT
 *   status      — SentinalStatus value
 *   reserved    — must be zero
 *   reserved1   — must be zero; explicit trailing field; ensures all bytes
 *                 in sizeof(SentinalDriverUnicodeProtectionResponse) are
 *                 accounted for by named fields with no implicit padding
 *
 * Field offsets:
 *   header:    offset  0, size 16
 *   requestId: offset 16, size  8
 *   decision:  offset 24, size  4
 *   status:    offset 28, size  4
 *   reserved:  offset 32, size  4
 *   reserved1: offset 36, size  4
 *   sizeof:    40  (fully accounted by named fields; no implicit padding)
 * ========================================================================= */

typedef struct SentinalDriverUnicodeProtectionResponse {
    SentinalDriverUnicodeMessageHeader header;    /* offset  0 */
    uint64_t                           requestId; /* offset 16 */
    uint32_t                           decision;  /* offset 24 */
    uint32_t                           status;    /* offset 28 */
    uint32_t                           reserved;  /* offset 32, must be zero */
    uint32_t                           reserved1; /* offset 36, must be zero; no implicit trailing padding */
} SentinalDriverUnicodeProtectionResponse;

/* =========================================================================
 * Validation functions
 *
 * All functions return SENTINAL_STATUS_SUCCESS on success, or
 * SENTINAL_STATUS_INVALID_PARAMETER on any constraint violation.
 *
 * None of these functions access the filesystem, perform policy evaluation,
 * or call Windows APIs. They are deterministic and side-effect free.
 * ========================================================================= */

SentinalStatus SentinalDriverUnicodeValidateMessageHeader(
    const SentinalDriverUnicodeMessageHeader* header,
    uint32_t                                  expectedMessageType,
    uint32_t                                  minimumSize
);

SentinalStatus SentinalDriverUnicodeValidateProtectionRequest(
    const SentinalDriverUnicodeProtectionRequest* request
);

SentinalStatus SentinalDriverUnicodeValidateProtectionResponse(
    const SentinalDriverUnicodeProtectionResponse* response
);

#ifdef __cplusplus
}
#endif

#endif /* SENTINAL_DRIVER_UNICODE_CONTRACT_H */
