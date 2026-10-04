#include "service/windows_driver_communication.h"
#include "service/driver_contract_adapter.h"

namespace sentinel::service {

WindowsDriverCommunication::WindowsDriverCommunication(
    IWindowsDriverTransport& transport
)
    : m_transport(transport) {
}

SentinalStatus WindowsDriverCommunication::sendRequest(
    const DriverProtectionRequest& request,
    DriverProtectionResponse& outResponse
) {
    // Step 1: Validate DriverProtectionRequest
    if (!request.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    // Step 2: Convert request using DriverContractAdapter::toContract()
    SentinalDriverProtectionRequest contractRequest;
    SentinalStatus status = DriverContractAdapter::toContract(request, contractRequest);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    // Step 3 & 4: Call m_transport.exchange() and propagate failure
    SentinalDriverProtectionResponse contractResponse;
    status = m_transport.exchange(contractRequest, contractResponse);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    // Step 5: Validate the received contract using existing contract validation
    status = SentinalDriverValidateProtectionResponse(&contractResponse);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    // Step 6: Verify request ID correlation
    if (contractResponse.requestId != request.requestId()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    // Step 7: Convert using DriverContractAdapter::fromContract()
    DriverProtectionResponse temporaryResponse;
    status = DriverContractAdapter::fromContract(contractResponse, temporaryResponse);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    // Step 8: Validate the resulting DriverProtectionResponse
    if (!temporaryResponse.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    // Step 9: Only after all validation succeeds, modify outResponse
    outResponse = temporaryResponse;

    // Step 10: Return success
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
