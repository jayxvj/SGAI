#pragma once

#include <string>
#include <sentinal/common.h>
#include "service/windows_operation_adapter.h"

namespace sentinel::service {

class WindowsFileOperationObservation {
public:
    WindowsFileOperationObservation() = default;

    WindowsFileOperationObservation(
        std::string windowsPath,
        WindowsProtectionOperation operation
    );

    const std::string& windowsPath() const noexcept;
    WindowsProtectionOperation operation() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    std::string m_windowsPath;
    WindowsProtectionOperation m_operation{
        WindowsProtectionOperation::Unknown
    };
};

} // namespace sentinel::service
