#include "service/windows_file_operation_observer.h"

namespace sentinel::service {

SentinalStatus WindowsFileOperationObserver::toProtectionEvent(
    const WindowsFileOperationObservation& observation,
    WindowsProtectionEvent& outEvent
) noexcept {
    if (!observation.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    WindowsProtectionEvent candidate(
        observation.windowsPath(),
        observation.operation()
    );

    if (!candidate.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outEvent = std::move(candidate);
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
