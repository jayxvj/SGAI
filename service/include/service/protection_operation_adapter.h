#pragma once

#include <sentinal/common.h>
#include "service/protection_operation.h"
#include "service/protection_request.h"

namespace sentinel::service {

class ProtectionOperationAdapter {
public:
    static SentinalStatus toRequest(
        const ProtectionOperation& operation,
        ProtectionRequest& outRequest
    ) noexcept;
};

} // namespace sentinel::service
