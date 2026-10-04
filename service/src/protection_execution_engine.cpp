#include "service/protection_execution_engine.h"
#include "service/protection_operation_adapter.h"
#include "service/protection_request.h"

namespace sentinel::service {

ProtectionExecutionEngine::ProtectionExecutionEngine(
    const ProtectionEnforcement& enforcement
)
    : m_enforcement(enforcement) {
}

ProtectionEnforcementAction ProtectionExecutionEngine::execute(
    const ProtectionOperation& operation,
    SentinalDecision defaultDecision
) const {
    ProtectionRequest request;
    if (ProtectionOperationAdapter::toRequest(operation, request) != SENTINAL_STATUS_SUCCESS) {
        return ProtectionEnforcementAction::DENY;
    }

    return m_enforcement.evaluate(request, defaultDecision);
}

} // namespace sentinel::service
