#pragma once

#include <string>
#include <sentinal/common.h>
#include "service/path_identity.h"

namespace sentinel::service {

class WindowsPathAdapter {
public:
    static SentinalStatus toPathIdentity(
        const std::string& windowsPath,
        PathIdentity& outIdentity
    ) noexcept;
};

} // namespace sentinel::service
