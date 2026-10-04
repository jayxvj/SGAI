#pragma once

#include <sentinal/common.h>
#include "service/windows_protection_event.h"
#include "service/protection_operation.h"

namespace sentinel::service {

class WindowsProtectionEventAdapter {
public:
    static SentinalStatus toProtectionOperation(
        const WindowsProtectionEvent& event,
        ProtectionOperation& outOperation
    ) noexcept;
};

} // namespace sentinel::service
