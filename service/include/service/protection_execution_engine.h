#pragma once

#include <sentinal/common.h>
#include "service/protection_enforcement.h"
#include "service/protection_operation.h"

namespace sentinel::service {

class ProtectionExecutionEngine {
public:
    explicit ProtectionExecutionEngine(
        const ProtectionEnforcement& enforcement
    );


    ProtectionEnforcementAction execute(
        const ProtectionOperation& operation,
        SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW
    ) const;

private:
    const ProtectionEnforcement& m_enforcement;
};

} // namespace sentinel::service
