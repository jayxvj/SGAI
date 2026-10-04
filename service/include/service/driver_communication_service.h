#pragma once

#include <sentinal/common.h>
#include "service/driver_protection_request.h"
#include "service/driver_protection_response.h"
#include "service/user_mode_driver_communication.h"

namespace sentinel::service {

class DriverCommunicationService {
public:
    explicit DriverCommunicationService(
        IUserModeDriverCommunication& communication
    );

    SentinalStatus requestProtectionDecision(
        const DriverProtectionRequest& request,
        DriverProtectionResponse& outResponse
    ) const;

private:
    IUserModeDriverCommunication& m_communication;
};

} // namespace sentinel::service
