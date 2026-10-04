/*
 * driver_unicode_contract.c
 *
 * Validation implementations for the Sentinal AI Unicode driver contract.
 *
 * Phase 1.29 — Unicode Driver Communication Contract
 *
 * Pure C. No Windows APIs, no filesystem access, no dynamic allocation.
 * Deterministic and side-effect free.
 */

#include "sentinal/driver_unicode_contract.h"

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static int sentinal_unicode_is_valid_single_operation(uint32_t op) {
    return (op == (uint32_t)SENTINAL_OP_READ    ||
            op == (uint32_t)SENTINAL_OP_WRITE   ||
            op == (uint32_t)SENTINAL_OP_DELETE  ||
            op == (uint32_t)SENTINAL_OP_RENAME  ||
            op == (uint32_t)SENTINAL_OP_EXECUTE);
}

static int sentinal_unicode_is_valid_source(uint32_t source) {
    return (source == SENTINAL_DRIVER_UNICODE_SOURCE_UNKNOWN   ||
            source == SENTINAL_DRIVER_UNICODE_SOURCE_USER_MODE ||
            source == SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL);
}

static int sentinal_unicode_is_valid_decision(uint32_t decision) {
    /* UNKNOWN is not a valid successful response decision per contract spec */
    return (decision == (uint32_t)SENTINAL_DECISION_ALLOW  ||
            decision == (uint32_t)SENTINAL_DECISION_DENY   ||
            decision == (uint32_t)SENTINAL_DECISION_AUDIT);
}

static int sentinal_unicode_is_valid_status(uint32_t status) {
    return (status == (uint32_t)SENTINAL_STATUS_SUCCESS             ||
            status == (uint32_t)SENTINAL_STATUS_UNSPECIFIED_ERROR   ||
            status == (uint32_t)SENTINAL_STATUS_INVALID_PARAMETER   ||
            status == (uint32_t)SENTINAL_STATUS_BUFFER_TOO_SMALL    ||
            status == (uint32_t)SENTINAL_STATUS_ACCESS_DENIED       ||
            status == (uint32_t)SENTINAL_STATUS_NOT_FOUND           ||
            status == (uint32_t)SENTINAL_STATUS_ALREADY_EXISTS);
}

/* =========================================================================
 * SentinalDriverUnicodeValidateMessageHeader
 * ========================================================================= */

SentinalStatus SentinalDriverUnicodeValidateMessageHeader(
    const SentinalDriverUnicodeMessageHeader* header,
    uint32_t                                  expectedMessageType,
    uint32_t                                  minimumSize
) {
    if (!header) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->size == 0 || header->size < minimumSize) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->majorVersion != SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->minorVersion > SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->messageType != expectedMessageType) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->reserved != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    return SENTINAL_STATUS_SUCCESS;
}

/* =========================================================================
 * SentinalDriverUnicodeValidateProtectionRequest
 * ========================================================================= */

SentinalStatus SentinalDriverUnicodeValidateProtectionRequest(
    const SentinalDriverUnicodeProtectionRequest* request
) {
    uint32_t i;

    if (!request) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (SentinalDriverUnicodeValidateMessageHeader(
            &request->header,
            (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST,
            (uint32_t)sizeof(SentinalDriverUnicodeProtectionRequest)
        ) != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* Size must equal the structure exactly — no extension bytes in v1.0 */
    if (request->header.size != (uint32_t)sizeof(SentinalDriverUnicodeProtectionRequest)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (request->requestId == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_unicode_is_valid_single_operation(request->operation)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_unicode_is_valid_source(request->source)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* pathLength > 0 and fits with NUL terminator */
    if (request->pathLength == 0 ||
        request->pathLength >= SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* NUL termination at path[pathLength] */
    if (request->path[request->pathLength] != 0x0000u) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* No embedded NUL before pathLength */
    for (i = 0; i < request->pathLength; ++i) {
        if (request->path[i] == 0x0000u) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }
    }
    if (request->reserved0 != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (request->reserved != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (request->reserved1 != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    return SENTINAL_STATUS_SUCCESS;
}

/* =========================================================================
 * SentinalDriverUnicodeValidateProtectionResponse
 * ========================================================================= */

SentinalStatus SentinalDriverUnicodeValidateProtectionResponse(
    const SentinalDriverUnicodeProtectionResponse* response
) {
    if (!response) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (SentinalDriverUnicodeValidateMessageHeader(
            &response->header,
            (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE,
            (uint32_t)sizeof(SentinalDriverUnicodeProtectionResponse)
        ) != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (response->header.size != (uint32_t)sizeof(SentinalDriverUnicodeProtectionResponse)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (response->requestId == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* UNKNOWN is not a valid response decision */
    if (!sentinal_unicode_is_valid_decision(response->decision)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_unicode_is_valid_status(response->status)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (response->reserved != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (response->reserved1 != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    return SENTINAL_STATUS_SUCCESS;
}
