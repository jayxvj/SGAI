#include "service/target.h"

namespace sentinel::service {

SentinalStatus ProtectionTarget::validate() const {
    if (path.empty()) {
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
    if (input.empty()) {
        return "";
    }

    std::string result = input;
    for (char& c : result) {
        if (c == '\\') {
            c = '/';
        }
    }

    while (result.size() > 1 && result.back() == '/') {
        // Preserve drive root like "C:/"
        if (result.size() == 3 && result[1] == ':') {
            break;
        }
        result.pop_back();
    }

    return result;
}

} // namespace sentinel::service
