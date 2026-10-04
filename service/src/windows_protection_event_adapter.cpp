#include "service/windows_protection_event_adapter.h"
#include "service/windows_path_adapter.h"
#include "service/windows_operation_adapter.h"

namespace sentinel::service {

SentinalStatus WindowsProtectionEventAdapter::toProtectionOperation(
    const WindowsProtectionEvent& event,
    ProtectionOperation& outOperation
) noexcept {
    if (!event.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    PathIdentity pathIdentity;
    if (WindowsPathAdapter::toPathIdentity(event.windowsPath(), pathIdentity) != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalFileOp fileOp = SENTINAL_OP_NONE;
    if (WindowsOperationAdapter::toFileOperation(event.operation(), fileOp) != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    ProtectionOperation op(std::move(pathIdentity), fileOp);
    if (!op.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outOperation = std::move(op);
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
