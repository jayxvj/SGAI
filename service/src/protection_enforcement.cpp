#include "service/protection_enforcement.h"
#include "service/protection_evaluation_engine.h"
#include "service/protection_request.h"
#include "service/protection_decision.h"

namespace sentinel::service {

ProtectionEnforcement::ProtectionEnforcement(
    const ProtectionEvaluationEngine& evaluationEngine
)
    : m_evaluationEngine(evaluationEngine) {
}

ProtectionEnforcementAction ProtectionEnforcement::evaluate(
    const ProtectionRequest& request,
    SentinalDecision defaultDecision
) const {
    ProtectionDecision d = m_evaluationEngine.evaluate(request, defaultDecision);

    switch (d.decision()) {
        case SENTINAL_DECISION_ALLOW: return ProtectionEnforcementAction::ALLOW;
        case SENTINAL_DECISION_AUDIT: return ProtectionEnforcementAction::AUDIT;
        case SENTINAL_DECISION_DENY:  return ProtectionEnforcementAction::DENY;
        default:                      return ProtectionEnforcementAction::DENY; // fail closed
    }
}

} // namespace sentinel::service
