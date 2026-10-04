#pragma once

#include <sentinal/common.h>

namespace sentinel::service {

class ProtectionEvaluationEngine;
class ProtectionRequest;

enum class ProtectionEnforcementAction {
    ALLOW,
    DENY,
    AUDIT
};

class ProtectionEnforcement {
public:
    explicit ProtectionEnforcement(
        const ProtectionEvaluationEngine& evaluationEngine
    );

    ProtectionEnforcementAction evaluate(
        const ProtectionRequest& request,
        SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW
    ) const;

private:
    const ProtectionEvaluationEngine& m_evaluationEngine;
};

} // namespace sentinel::service
