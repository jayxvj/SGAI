#pragma once

#include <sentinal/common.h>
#include "service/protection_enforcement.h"

namespace sentinel::service {

enum class ProtectionExecutionResultStatus {
    PROCESSED,
    REJECTED
};

class ProtectionExecutionResult {
public:
    ProtectionExecutionResult() = default;

    ProtectionExecutionResult(
        ProtectionExecutionResultStatus status,
        ProtectionEnforcementAction action
    );

    ProtectionExecutionResultStatus status() const noexcept;
    ProtectionEnforcementAction action() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    ProtectionExecutionResultStatus m_status{
        ProtectionExecutionResultStatus::REJECTED
    };

    ProtectionEnforcementAction m_action{
        ProtectionEnforcementAction::DENY
    };
};

} // namespace sentinel::service
