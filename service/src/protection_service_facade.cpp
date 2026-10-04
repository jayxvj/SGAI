#include "service/protection_service_facade.h"

namespace sentinel::service {

ProtectionServiceFacade::ProtectionServiceFacade(
    ProtectionEventProcessor& eventProcessor
)
    : m_eventProcessor(eventProcessor) {
}

ProtectionEnforcementAction ProtectionServiceFacade::process(
    const WindowsProtectionEvent& event,
    SentinalDecision defaultDecision
) const {
    return m_eventProcessor.process(event, defaultDecision);
}

} // namespace sentinel::service
