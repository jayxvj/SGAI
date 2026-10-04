#include "service/protection_decision.h"

namespace sentinel::service {

ProtectionDecision::ProtectionDecision(
    SentinalDecision decision,
    ProtectionDecisionReason reason
)
    : m_decision(decision),
      m_reason(reason) {
}

SentinalDecision ProtectionDecision::decision() const noexcept {
    return m_decision;
}

ProtectionDecisionReason ProtectionDecision::reason() const noexcept {
    return m_reason;
}

SentinalStatus ProtectionDecision::validate() const noexcept {
    switch (m_decision) {
        case SENTINAL_DECISION_UNKNOWN:
        case SENTINAL_DECISION_ALLOW:
        case SENTINAL_DECISION_DENY:
        case SENTINAL_DECISION_AUDIT:
            break;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    switch (m_reason) {
        case ProtectionDecisionReason::DEFAULT_POLICY:
        case ProtectionDecisionReason::EXACT_FILE:
        case ProtectionDecisionReason::EXACT_DIRECTORY:
        case ProtectionDecisionReason::DIRECT_CHILD_DIRECTORY:
        case ProtectionDecisionReason::RECURSIVE_DIRECTORY:
        case ProtectionDecisionReason::INVALID_REQUEST:
            break;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return SENTINAL_STATUS_SUCCESS;
}

bool ProtectionDecision::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
