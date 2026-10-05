#include "service/driver_contract_adapter.h"
#include <cstring>

namespace sentinel::service {

SentinalStatus DriverContractAdapter::toContract(
    const DriverProtectionRequest& request,
    SentinalDriverProtectionRequest& outContract
) noexcept {
    if (!request.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    const auto& normPath = request.path().normalized();
    if (normPath.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (normPath.length() >= SENTINAL_DRIVER_MAX_PATH_CHARS) {
        return SENTINAL_STATUS_BUFFER_TOO_SMALL;
    }

    uint32_t contractSource = 0;
    switch (request.context().source()) {
        case ProtectionRequestSource::UNKNOWN:
            contractSource = 0U;
            break;
        case ProtectionRequestSource::USER_MODE:
            contractSource = 1U;
            break;
        case ProtectionRequestSource::KERNEL:
            contractSource = 2U;
            break;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalDriverProtectionRequest temp;
    std::memset(&temp, 0, sizeof(temp));

    temp.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest));
    temp.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    temp.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    temp.header.messageType = SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST;
    temp.header.reserved = 0;

    temp.requestId = request.requestId();
    temp.operation = static_cast<uint32_t>(request.operation());
    temp.source = contractSource;
    temp.pathLength = static_cast<uint32_t>(normPath.length());
    std::memcpy(temp.path, normPath.data(), normPath.length());
    temp.path[normPath.length()] = '\0';
    temp.reserved = 0;

    SentinalStatus status = SentinalDriverValidateProtectionRequest(&temp);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    outContract = temp;
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus DriverContractAdapter::fromContract(
    const SentinalDriverProtectionResponse& contract,
    DriverProtectionResponse& outResponse
) noexcept {
    SentinalStatus status = SentinalDriverValidateProtectionResponse(&contract);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    if (contract.requestId == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    DriverProtectionResponseStatus respStatus = DriverProtectionResponseStatus::REJECTED;
    if (contract.status == SENTINAL_STATUS_SUCCESS) {
        respStatus = DriverProtectionResponseStatus::SUCCESS;
    } else {
        respStatus = DriverProtectionResponseStatus::REJECTED;
    }

    auto decision = static_cast<SentinalDecision>(contract.decision);
    DriverProtectionResponse temp(contract.requestId, decision, respStatus);

    if (!temp.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outResponse = temp;
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus DriverContractAdapter::toUnicodeContract(
    const DriverProtectionRequest& request,
    SentinalDriverUnicodeProtectionRequest& outContract
) noexcept {
    if (!request.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    const auto& normPath = request.path().normalized();
    if (normPath.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (normPath.length() >= SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS) {
        return SENTINAL_STATUS_BUFFER_TOO_SMALL;
    }

    uint32_t contractSource = 0;
    switch (request.context().source()) {
        case ProtectionRequestSource::UNKNOWN:
            contractSource = SENTINAL_DRIVER_UNICODE_SOURCE_UNKNOWN;
            break;
        case ProtectionRequestSource::USER_MODE:
            contractSource = SENTINAL_DRIVER_UNICODE_SOURCE_USER_MODE;
            break;
        case ProtectionRequestSource::KERNEL:
            contractSource = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
            break;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalDriverUnicodeProtectionRequest temp;
    std::memset(&temp, 0, sizeof(temp));

    temp.header.size         = static_cast<uint32_t>(sizeof(SentinalDriverUnicodeProtectionRequest));
    temp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    temp.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    temp.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    temp.header.reserved     = 0;

    temp.requestId  = request.requestId();
    temp.operation  = static_cast<uint32_t>(request.operation());
    temp.source     = contractSource;
    temp.pathLength = static_cast<uint32_t>(normPath.length());
    temp.reserved0  = 0;

    for (size_t i = 0; i < normPath.length(); ++i) {
        temp.path[i] = static_cast<uint16_t>(normPath[i]);
    }
    temp.path[normPath.length()] = 0x0000u;
    temp.reserved  = 0;
    temp.reserved1 = 0;

    SentinalStatus status = SentinalDriverUnicodeValidateProtectionRequest(&temp);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    outContract = temp;
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus DriverContractAdapter::fromUnicodeContract(
    const SentinalDriverUnicodeProtectionResponse& contract,
    DriverProtectionResponse& outResponse
) noexcept {
    SentinalStatus status = SentinalDriverUnicodeValidateProtectionResponse(&contract);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    if (contract.requestId == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    DriverProtectionResponseStatus respStatus = DriverProtectionResponseStatus::REJECTED;
    if (contract.status == SENTINAL_STATUS_SUCCESS) {
        respStatus = DriverProtectionResponseStatus::SUCCESS;
    } else {
        respStatus = DriverProtectionResponseStatus::REJECTED;
    }

    auto decision = static_cast<SentinalDecision>(contract.decision);
    DriverProtectionResponse temp(contract.requestId, decision, respStatus);

    if (!temp.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outResponse = temp;
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
