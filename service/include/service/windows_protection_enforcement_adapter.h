#pragma once

#include <sentinal/common.h>
#include "service/protection_enforcement.h"
#include "service/windows_protection_enforcement_result.h"

namespace sentinel::service {

class WindowsProtectionEnforcementAdapter {
public:
    static SentinalStatus toWindowsResult(
        ProtectionEnforcementAction action,
        WindowsProtectionEnforcementResult& outResult
    ) noexcept;
};

} // namespace sentinel::service
