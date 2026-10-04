#include "sentinal/driver_contract.h"

/*
 * Validation implementations for the Sentinal AI driver communication contract.
 * Pure C, no Windows APIs, no filesystem access.
 */

/*
 * Valid single-operation values for SentinalDriverProtectionRequest.operation.
 * These correspond to the single-bit SentinalFileOp values.
 */
static int sentinal_is_valid_single_operation(uint32_t op) {
    return (op == SENTINAL_OP_READ    ||
            op == SENTINAL_OP_WRITE   ||
            op == SENTINAL_OP_DELETE  ||
            op == SENTINAL_OP_RENAME  ||
            op == SENTINAL_OP_EXECUTE);
}

/* Source values that are defined as valid */
#define SENTINAL_DRIVER_SOURCE_UNKNOWN   0U
#define SENTINAL_DRIVER_SOURCE_USER_MODE 1U
#define SENTINAL_DRIVER_SOURCE_KERNEL    2U

static int sentinal_is_valid_source(uint32_t source) {
    return (source == SENTINAL_DRIVER_SOURCE_UNKNOWN   ||
            source == SENTINAL_DRIVER_SOURCE_USER_MODE ||
            source == SENTINAL_DRIVER_SOURCE_KERNEL);
}

static int sentinal_is_valid_decision(uint32_t decision) {
    return (decision == SENTINAL_DECISION_UNKNOWN ||
            decision == SENTINAL_DECISION_ALLOW   ||
            decision == SENTINAL_DECISION_DENY    ||
            decision == SENTINAL_DECISION_AUDIT);
}

static int sentinal_is_valid_status(uint32_t status) {
    return (status == SENTINAL_STATUS_SUCCESS             ||
            status == SENTINAL_STATUS_UNSPECIFIED_ERROR   ||
            status == SENTINAL_STATUS_INVALID_PARAMETER   ||
            status == SENTINAL_STATUS_BUFFER_TOO_SMALL    ||
            status == SENTINAL_STATUS_ACCESS_DENIED       ||
            status == SENTINAL_STATUS_NOT_FOUND           ||
            status == SENTINAL_STATUS_ALREADY_EXISTS);
}

SentinalStatus SentinalDriverValidateMessageHeader(
    const SentinalDriverMessageHeader* header,
    uint32_t                           expectedMessageType,
    uint32_t                           minimumSize
) {
    if (!header) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->size == 0 || header->size < minimumSize) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->majorVersion != SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (header->minorVersion > SENTINAL_DRIVER_CONTRACT_MINOR_VERSION) {
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

SentinalStatus SentinalDriverValidateProtectionRequest(
    const SentinalDriverProtectionRequest* request
) {
    uint32_t i;

    if (!request) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (SentinalDriverValidateMessageHeader(
            &request->header,
            SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
            (uint32_t)sizeof(SentinalDriverProtectionRequest)) != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (request->header.size != (uint32_t)sizeof(SentinalDriverProtectionRequest)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_is_valid_single_operation(request->operation)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_is_valid_source(request->source)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (request->pathLength == 0 || request->pathLength >= SENTINAL_DRIVER_MAX_PATH_CHARS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* Verify NUL termination at pathLength */
    if (request->path[request->pathLength] != '\0') {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    /* Scan for embedded NUL before pathLength */
    for (i = 0; i < request->pathLength; ++i) {
        if (request->path[i] == '\0') {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }
    }
    if (request->reserved != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus SentinalDriverValidateProtectionResponse(
    const SentinalDriverProtectionResponse* response
) {
    if (!response) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (SentinalDriverValidateMessageHeader(
            &response->header,
            SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE,
            (uint32_t)sizeof(SentinalDriverProtectionResponse)) != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (response->header.size != (uint32_t)sizeof(SentinalDriverProtectionResponse)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_is_valid_decision(response->decision)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (!sentinal_is_valid_status(response->status)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (response->reserved != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    return SENTINAL_STATUS_SUCCESS;
}
