#pragma once

#include <sentinal/common.h>

namespace sentinel::service {

enum class ProtectionDecisionReason {
    DEFAULT_POLICY,
    EXACT_FILE,
    EXACT_DIRECTORY,
    DIRECT_CHILD_DIRECTORY,
    RECURSIVE_DIRECTORY,
    INVALID_REQUEST
};

class ProtectionDecision {
public:
    ProtectionDecision() = default;

    ProtectionDecision(
        SentinalDecision decision,
        ProtectionDecisionReason reason
    );

    SentinalDecision decision() const noexcept;
    ProtectionDecisionReason reason() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    SentinalDecision m_decision{SENTINAL_DECISION_UNKNOWN};
    ProtectionDecisionReason m_reason{ProtectionDecisionReason::DEFAULT_POLICY};
};

} // namespace sentinel::service
