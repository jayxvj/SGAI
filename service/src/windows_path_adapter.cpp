#include "service/windows_path_adapter.h"

namespace sentinel::service {

SentinalStatus WindowsPathAdapter::toPathIdentity(
    const std::string& windowsPath,
    PathIdentity& outIdentity
) noexcept {
    if (windowsPath.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (windowsPath.find('\0') != std::string::npos) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    PathIdentity pi(windowsPath);
    if (!pi.isValid() || !pi.isAbsolute()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outIdentity = std::move(pi);
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
