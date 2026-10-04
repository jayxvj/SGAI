#include "service/target.h"

namespace sentinel::service {

SentinalStatus ProtectionTarget::validate() const {
    if (path.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    PathIdentity pi(path);
    if (!pi.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    // PolicyEngine protection targets reject relative paths because protection
    // policy must not depend on the process current working directory.
    if (pi.isRelative()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (type != SENTINAL_TARGET_FILE &&
        type != SENTINAL_TARGET_DIRECTORY &&
        type != SENTINAL_TARGET_DIRECTORY_RECURSIVE) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if ((opMask & ~SENTINAL_ALL_FILE_OPS) != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if ((opMask & SENTINAL_ALL_FILE_OPS) == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (decision != SENTINAL_DECISION_ALLOW &&
        decision != SENTINAL_DECISION_DENY &&
        decision != SENTINAL_DECISION_AUDIT) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return SENTINAL_STATUS_SUCCESS;
}

std::string normalizePath(const std::string& input) {
    PathIdentity pi(input);
    return pi.normalized();
}

} // namespace sentinel::service
