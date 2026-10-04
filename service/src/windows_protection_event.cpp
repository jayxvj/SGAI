#include "service/windows_protection_event.h"

namespace sentinel::service {

WindowsProtectionEvent::WindowsProtectionEvent(
    std::string windowsPath,
    WindowsProtectionOperation operation
)
    : m_windowsPath(std::move(windowsPath)),
      m_operation(operation) {
}

const std::string& WindowsProtectionEvent::windowsPath() const noexcept {
    return m_windowsPath;
}

WindowsProtectionOperation WindowsProtectionEvent::operation() const noexcept {
    return m_operation;
}

bool WindowsProtectionEvent::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus WindowsProtectionEvent::validate() const noexcept {
    if (m_windowsPath.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (m_windowsPath.find('\0') != std::string::npos) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    switch (m_operation) {
        case WindowsProtectionOperation::Read:
        case WindowsProtectionOperation::Write:
        case WindowsProtectionOperation::Delete:
        case WindowsProtectionOperation::Rename:
        case WindowsProtectionOperation::Execute:
            return SENTINAL_STATUS_SUCCESS;
        case WindowsProtectionOperation::Unknown:
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }
}

} // namespace sentinel::service
