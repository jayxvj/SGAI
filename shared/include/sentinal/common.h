#ifndef SENTINAL_COMMON_H
#define SENTINAL_COMMON_H

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

typedef enum SentinalStatus {
    SENTINAL_STATUS_SUCCESS = 0,
    SENTINAL_STATUS_UNSPECIFIED_ERROR = 1
} SentinalStatus;

#ifdef __cplusplus
}
#endif

#endif /* SENTINAL_COMMON_H */
