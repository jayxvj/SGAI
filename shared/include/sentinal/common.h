#ifndef SENTINAL_COMMON_H
#define SENTINAL_COMMON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sentinal AI Common Definitions
 * Shared foundation definitions for user-mode components and future kernel-mode components.
 * Kept strictly C-compatible.
 */

#define SENTINAL_VERSION_MAJOR 0
#define SENTINAL_VERSION_MINOR 1
#define SENTINAL_VERSION_PATCH 0

/* Standard status and error codes */
typedef enum SentinalStatus {
    SENTINAL_STATUS_SUCCESS = 0,
    SENTINAL_STATUS_UNSPECIFIED_ERROR = 1,
    SENTINAL_STATUS_INVALID_PARAMETER = 2,
    SENTINAL_STATUS_BUFFER_TOO_SMALL = 3,
    SENTINAL_STATUS_ACCESS_DENIED = 4,
    SENTINAL_STATUS_NOT_FOUND = 5,
    SENTINAL_STATUS_ALREADY_EXISTS = 6
} SentinalStatus;

/* Target scope for protected paths */
typedef enum SentinalTargetType {
    SENTINAL_TARGET_UNKNOWN = 0,
    SENTINAL_TARGET_FILE = 1,
    SENTINAL_TARGET_DIRECTORY = 2,
    SENTINAL_TARGET_DIRECTORY_RECURSIVE = 3
} SentinalTargetType;

/* Monitored file-system operations (bitmask flags) */
typedef enum SentinalFileOp {
    SENTINAL_OP_NONE = 0x00,
    SENTINAL_OP_READ = 0x01,
    SENTINAL_OP_WRITE = 0x02,
    SENTINAL_OP_DELETE = 0x04,
    SENTINAL_OP_RENAME = 0x08,
    SENTINAL_OP_EXECUTE = 0x10
} SentinalFileOp;

/* Security enforcement decision verdict */
typedef enum SentinalDecision {
    SENTINAL_DECISION_UNKNOWN = 0,
    SENTINAL_DECISION_ALLOW = 1,
    SENTINAL_DECISION_DENY = 2,
    SENTINAL_DECISION_AUDIT = 3
} SentinalDecision;

#ifdef __cplusplus
}
#endif

#endif /* SENTINAL_COMMON_H */

