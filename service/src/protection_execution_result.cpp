#include "service/protection_execution_result.h"

namespace sentinel::service {

ProtectionExecutionResult::ProtectionExecutionResult(
    ProtectionExecutionResultStatus status,
    ProtectionEnforcementAction action
)
    : m_status(status),
      m_action(action) {
}

ProtectionExecutionResultStatus ProtectionExecutionResult::status() const noexcept {
    return m_status;
}

ProtectionEnforcementAction ProtectionExecutionResult::action() const noexcept {
    return m_action;
}

bool ProtectionExecutionResult::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus ProtectionExecutionResult::validate() const noexcept {
    switch (m_status) {
        case ProtectionExecutionResultStatus::PROCESSED:
            switch (m_action) {
                case ProtectionEnforcementAction::ALLOW:
                case ProtectionEnforcementAction::DENY:
                case ProtectionEnforcementAction::AUDIT:
                    return SENTINAL_STATUS_SUCCESS;
                default:
                    return SENTINAL_STATUS_INVALID_PARAMETER;
            }
        case ProtectionExecutionResultStatus::REJECTED:
            if (m_action == ProtectionEnforcementAction::DENY) {
                return SENTINAL_STATUS_SUCCESS;
            }
            return SENTINAL_STATUS_INVALID_PARAMETER;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }
}

} // namespace sentinel::service
