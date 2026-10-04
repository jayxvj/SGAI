#pragma once

#include "service/user_mode_driver_communication.h"
#include "service/windows_driver_transport.h"

namespace sentinel::service {

class WindowsDriverCommunication final
    : public IUserModeDriverCommunication
{
public:
    explicit WindowsDriverCommunication(
        IWindowsDriverTransport& transport
    );

    SentinalStatus sendRequest(
        const DriverProtectionRequest& request,
        DriverProtectionResponse& outResponse
    ) override;

private:
    IWindowsDriverTransport& m_transport;
};

} // namespace sentinel::service
