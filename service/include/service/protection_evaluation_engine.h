#pragma once

#include <sentinal/common.h>
#include "service/protection_decision.h"

namespace sentinel::service {

class PolicyEngine;
class ProtectionRequest;

class ProtectionEvaluationEngine {
public:
    explicit ProtectionEvaluationEngine(const PolicyEngine& policyEngine);

    ProtectionDecision evaluate(
        const ProtectionRequest& request,
        SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW
    ) const;

private:
    const PolicyEngine& m_policyEngine;
};

} // namespace sentinel::service
