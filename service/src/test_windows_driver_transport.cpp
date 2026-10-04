#include "service/test_windows_driver_transport.h"
#include <cstring>

namespace sentinel::service {

SentinalStatus TestWindowsDriverTransport::connect() {
    m_connected = true;
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus TestWindowsDriverTransport::disconnect() {
    m_connected = false;
    return SENTINAL_STATUS_SUCCESS;
}

bool TestWindowsDriverTransport::isConnected() const noexcept {
    return m_connected;
}

SentinalStatus TestWindowsDriverTransport::exchange(
    const SentinalDriverProtectionRequest& request,
    SentinalDriverProtectionResponse& outResponse
) {
    if (!m_connected) {
        return SENTINAL_STATUS_ACCESS_DENIED;
    }

    SentinalStatus reqStatus = SentinalDriverValidateProtectionRequest(&request);
    if (reqStatus != SENTINAL_STATUS_SUCCESS) {
        return reqStatus;
    }

    if (m_failure != SENTINAL_STATUS_SUCCESS) {
        return m_failure;
    }

    SentinalStatus respStatus = SentinalDriverValidateProtectionResponse(&m_response);
    if (respStatus != SENTINAL_STATUS_SUCCESS) {
        return respStatus;
    }

    m_lastRequest = request;
    m_hasRequest = true;

    outResponse = m_response;
    return SENTINAL_STATUS_SUCCESS;
}

void TestWindowsDriverTransport::setResponse(
    uint64_t requestId,
    uint32_t decision,
    uint32_t status
) {
    std::memset(&m_response, 0, sizeof(m_response));
    m_response.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionResponse));
    m_response.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    m_response.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    m_response.header.messageType = SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE;
    m_response.header.reserved = 0;
    m_response.requestId = requestId;
    m_response.decision = decision;
    m_response.status = status;
    m_response.reserved = 0;
}

void TestWindowsDriverTransport::setFailure(SentinalStatus status) {
    m_failure = status;
}

const SentinalDriverProtectionRequest& TestWindowsDriverTransport::lastRequest() const noexcept {
    return m_lastRequest;
}

bool TestWindowsDriverTransport::hasRequest() const noexcept {
    return m_hasRequest;
}

} // namespace sentinel::service
