#include "service/driver_communication_service.h"

namespace sentinel::service {

DriverCommunicationService::DriverCommunicationService(
    IUserModeDriverCommunication& communication
)
    : m_communication(communication) {
}

SentinalStatus DriverCommunicationService::requestProtectionDecision(
    const DriverProtectionRequest& request,
    DriverProtectionResponse& outResponse
) const {
    if (!request.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    DriverProtectionResponse temp;
    SentinalStatus status = m_communication.sendRequest(request, temp);

    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    if (!temp.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outResponse = temp;
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
