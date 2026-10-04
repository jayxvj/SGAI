#pragma once

#include <sentinal/driver_contract.h>
#include "service/driver_protection_request.h"
#include "service/driver_protection_response.h"

namespace sentinel::service {

class DriverContractAdapter {
public:
    static SentinalStatus toContract(
        const DriverProtectionRequest& request,
        SentinalDriverProtectionRequest& outContract
    ) noexcept;

    static SentinalStatus fromContract(
        const SentinalDriverProtectionResponse& contract,
        DriverProtectionResponse& outResponse
    ) noexcept;
};

} // namespace sentinel::service
