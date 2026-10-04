#include "service/windows_protection_enforcement_adapter.h"

namespace sentinel::service {

SentinalStatus WindowsProtectionEnforcementAdapter::toWindowsResult(
    ProtectionEnforcementAction action,
    WindowsProtectionEnforcementResult& outResult
) noexcept {
    switch (action) {
        case ProtectionEnforcementAction::ALLOW:
            outResult = WindowsProtectionEnforcementResult::ALLOW;
            return SENTINAL_STATUS_SUCCESS;
        case ProtectionEnforcementAction::DENY:
            outResult = WindowsProtectionEnforcementResult::DENY;
            return SENTINAL_STATUS_SUCCESS;
        case ProtectionEnforcementAction::AUDIT:
            outResult = WindowsProtectionEnforcementResult::AUDIT;
            return SENTINAL_STATUS_SUCCESS;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }
}

} // namespace sentinel::service
