#pragma once

#include <sentinal/common.h>
#include "service/protection_enforcement.h"
#include "service/protection_event_processor.h"
#include "service/windows_protection_event.h"

namespace sentinel::service {

class ProtectionServiceFacade {
public:
    explicit ProtectionServiceFacade(
        ProtectionEventProcessor& eventProcessor
    );

    ProtectionEnforcementAction process(
        const WindowsProtectionEvent& event,
        SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW
    ) const;

private:
    ProtectionEventProcessor& m_eventProcessor;
};

} // namespace sentinel::service
