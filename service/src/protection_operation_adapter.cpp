#include "service/protection_operation_adapter.h"

namespace sentinel::service {

SentinalStatus ProtectionOperationAdapter::toRequest(
    const ProtectionOperation& operation,
    ProtectionRequest& outRequest
) noexcept {
    if (!operation.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outRequest = ProtectionRequest(
        operation.path(),
        operation.operation(),
        operation.context()
    );

    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
