#ifndef SENTINAL_DRIVER_CONTRACT_H
#define SENTINAL_DRIVER_CONTRACT_H

#include <stdint.h>
#include <sentinal/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sentinal AI Driver Communication Contract
 *
 * Defines the fixed-size, bounded, C-compatible data structures used for
 * future kernel-driver <-> user-mode service communication.
 *
 * This header is safe to include from both C and C++.
 * It contains no pointers, no dynamic memory, no STL types, no Windows APIs.
 */

/* =========================================================================
 * Protocol Version
 * ========================================================================= */

#define SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION 1U
#define SENTINAL_DRIVER_CONTRACT_MINOR_VERSION 0U

/* =========================================================================
 * Path buffer constraint
 * ========================================================================= */

#define SENTINAL_DRIVER_MAX_PATH_CHARS 1024U

/* =========================================================================
 * Message Types
 * ========================================================================= */

typedef enum SentinalDriverMessageType {
    SENTINAL_DRIVER_MESSAGE_UNKNOWN             = 0,
    SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST  = 1,
    SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE = 2
} SentinalDriverMessageType;

/* =========================================================================
 * Common Message Header
 *
 * Precedes every message structure.
 * size     - total size of the enclosing message structure in bytes
 * majorVersion - must equal SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION
 * minorVersion - must be <= SENTINAL_DRIVER_CONTRACT_MINOR_VERSION
 * messageType  - discriminates the payload (SentinalDriverMessageType)
 * reserved     - must be zero
 * ========================================================================= */

typedef struct SentinalDriverMessageHeader {
    uint32_t size;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t messageType;
    uint32_t reserved;
} SentinalDriverMessageHeader;

/* =========================================================================
 * Protection Request (kernel -> user-mode)
 *
 * Describes one file-system operation that requires a policy decision.
 *
 * requestId   - opaque identifier supplied by the sender; echoed in response
 * operation   - one of the SentinalFileOp single-operation values (not a mask)
 * source      - originating request source (maps to ProtectionRequestSource)
 * pathLength  - number of meaningful bytes in path[], excluding NUL
 *               must be < SENTINAL_DRIVER_MAX_PATH_CHARS
 * path        - NUL-terminated UTF-8/byte path buffer
 * reserved    - must be zero
 * ========================================================================= */

typedef struct SentinalDriverProtectionRequest {
    SentinalDriverMessageHeader header;
    uint64_t                    requestId;
    uint32_t                    operation;
    uint32_t                    source;
    uint32_t                    pathLength;
    char                        path[SENTINAL_DRIVER_MAX_PATH_CHARS];
    uint32_t                    reserved;
} SentinalDriverProtectionRequest;

/* =========================================================================
 * Protection Response (user-mode -> kernel)
 *
 * Returns the policy decision for a previously received request.
 *
 * requestId - must match the corresponding SentinalDriverProtectionRequest
 * decision  - one of the SentinalDecision values
 * status    - one of the SentinalStatus values
 * reserved  - must be zero
 * ========================================================================= */

typedef struct SentinalDriverProtectionResponse {
    SentinalDriverMessageHeader header;
    uint64_t                    requestId;
    uint32_t                    decision;
    uint32_t                    status;
    uint32_t                    reserved;
} SentinalDriverProtectionResponse;

/* =========================================================================
 * Validation functions
 *
 * All functions return SENTINAL_STATUS_SUCCESS on success, or
 * SENTINAL_STATUS_INVALID_PARAMETER on any constraint violation.
 *
 * None of these functions access the filesystem, perform policy evaluation,
 * or call Windows APIs.
 * ========================================================================= */

SentinalStatus SentinalDriverValidateMessageHeader(
    const SentinalDriverMessageHeader* header,
    uint32_t                           expectedMessageType,
    uint32_t                           minimumSize
);

SentinalStatus SentinalDriverValidateProtectionRequest(
    const SentinalDriverProtectionRequest* request
);

SentinalStatus SentinalDriverValidateProtectionResponse(
    const SentinalDriverProtectionResponse* response
);

#ifdef __cplusplus
}
#endif

#endif /* SENTINAL_DRIVER_CONTRACT_H */
