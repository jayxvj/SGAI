#pragma once

#include "service/user_mode_driver_communication.h"

namespace sentinel::service {

class TestDriverCommunication final
    : public IUserModeDriverCommunication
{
public:
    TestDriverCommunication() = default;

    SentinalStatus sendRequest(
        const DriverProtectionRequest& request,
        DriverProtectionResponse& outResponse
    ) override;

    void setResponse(
        SentinalDecision decision,
        DriverProtectionResponseStatus status
    );

    void setFailure(SentinalStatus status);

    const DriverProtectionRequest& lastRequest() const noexcept;
    bool hasRequest() const noexcept;

private:
    bool m_hasRequest{false};
    DriverProtectionRequest m_lastRequest;
    DriverProtectionResponse m_response;
    SentinalStatus m_failure{SENTINAL_STATUS_SUCCESS};
};

} // namespace sentinel::service
