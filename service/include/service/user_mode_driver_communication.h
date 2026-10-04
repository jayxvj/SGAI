#pragma once

#include <sentinal/common.h>
#include "service/driver_protection_request.h"
#include "service/driver_protection_response.h"

namespace sentinel::service {

class IUserModeDriverCommunication {
public:
    virtual ~IUserModeDriverCommunication() = default;

    virtual SentinalStatus sendRequest(
        const DriverProtectionRequest& request,
        DriverProtectionResponse& outResponse
    ) = 0;
};

} // namespace sentinel::service
