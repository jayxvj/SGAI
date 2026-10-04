#pragma once

#include <sentinal/common.h>
#include "service/protection_enforcement.h"
#include "service/protection_execution_engine.h"
#include "service/windows_protection_event.h"

namespace sentinel::service {

class ProtectionEventProcessor {
public:
    explicit ProtectionEventProcessor(
        const ProtectionExecutionEngine& executionEngine
    );

    ProtectionEnforcementAction process(
        const WindowsProtectionEvent& event,
        SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW
    ) const;

private:
    const ProtectionExecutionEngine& m_executionEngine;
};

} // namespace sentinel::service
