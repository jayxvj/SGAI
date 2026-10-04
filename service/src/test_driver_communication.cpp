#include "service/test_driver_communication.h"

namespace sentinel::service {

SentinalStatus TestDriverCommunication::sendRequest(
    const DriverProtectionRequest& request,
    DriverProtectionResponse& outResponse
) {
    if (!request.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (m_failure != SENTINAL_STATUS_SUCCESS) {
        return m_failure;
    }

    m_lastRequest = request;
    m_hasRequest = true;

    DriverProtectionResponse temp(
        request.requestId(),
        m_response.decision(),
        m_response.status()
    );

    if (!temp.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outResponse = temp;
    return SENTINAL_STATUS_SUCCESS;
}

void TestDriverCommunication::setResponse(
    SentinalDecision decision,
    DriverProtectionResponseStatus status
) {
    m_response = DriverProtectionResponse(0, decision, status);
}

void TestDriverCommunication::setFailure(SentinalStatus status) {
    m_failure = status;
}

const DriverProtectionRequest& TestDriverCommunication::lastRequest() const noexcept {
    return m_lastRequest;
}

bool TestDriverCommunication::hasRequest() const noexcept {
    return m_hasRequest;
}

} // namespace sentinel::service
