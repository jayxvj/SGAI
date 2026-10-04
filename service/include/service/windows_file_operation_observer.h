#pragma once

#include <sentinal/common.h>
#include "service/windows_file_operation_observation.h"
#include "service/windows_protection_event.h"

namespace sentinel::service {

class WindowsFileOperationObserver {
public:
    static SentinalStatus toProtectionEvent(
        const WindowsFileOperationObservation& observation,
        WindowsProtectionEvent& outEvent
    ) noexcept;
};

} // namespace sentinel::service
