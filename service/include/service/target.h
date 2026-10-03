#pragma once

#include <string>
#include <cstdint>
#include <sentinal/common.h>

namespace sentinel::service {

constexpr uint32_t SENTINAL_ALL_FILE_OPS = 
    SENTINAL_OP_READ | 
    SENTINAL_OP_WRITE | 
    SENTINAL_OP_DELETE | 
    SENTINAL_OP_RENAME | 
    SENTINAL_OP_EXECUTE;

struct ProtectionTarget {
    SentinalTargetId id = SENTINAL_INVALID_TARGET_ID;
    std::string path;
    SentinalTargetType type = SENTINAL_TARGET_UNKNOWN;
    uint32_t opMask = SENTINAL_ALL_FILE_OPS;
    SentinalDecision decision = SENTINAL_DECISION_DENY;
    bool enabled = true;
    std::string description;

    SentinalStatus validate() const;
};

std::string normalizePath(const std::string& input);

} // namespace sentinel::service
