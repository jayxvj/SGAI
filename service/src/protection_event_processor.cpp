#include "service/protection_event_processor.h"
#include "service/protection_operation.h"
#include "service/windows_protection_event_adapter.h"

namespace sentinel::service {

ProtectionEventProcessor::ProtectionEventProcessor(
    const ProtectionExecutionEngine& executionEngine
)
    : m_executionEngine(executionEngine) {
}

ProtectionEnforcementAction ProtectionEventProcessor::process(
    const WindowsProtectionEvent& event,
    SentinalDecision defaultDecision
) const {
    ProtectionOperation operation;
    if (WindowsProtectionEventAdapter::toProtectionOperation(event, operation) != SENTINAL_STATUS_SUCCESS) {
        return ProtectionEnforcementAction::DENY;
    }
    return m_executionEngine.execute(operation, defaultDecision);
}

} // namespace sentinel::service
