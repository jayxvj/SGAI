#include "service/protection_evaluation_engine.h"
#include "service/policy_engine.h"
#include "service/protection_request.h"

namespace sentinel::service {

ProtectionEvaluationEngine::ProtectionEvaluationEngine(const PolicyEngine& policyEngine)
    : m_policyEngine(policyEngine) {
}

ProtectionDecision ProtectionEvaluationEngine::evaluate(
    const ProtectionRequest& request,
    SentinalDecision defaultDecision
) const {
    return m_policyEngine.evaluateDetailed(request, defaultDecision);
}

} // namespace sentinel::service
