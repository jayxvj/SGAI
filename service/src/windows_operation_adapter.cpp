#include "service/windows_operation_adapter.h"

namespace sentinel::service {

SentinalStatus WindowsOperationAdapter::toFileOperation(
    WindowsProtectionOperation operation,
    SentinalFileOp& outOperation
) noexcept {
    switch (operation) {
        case WindowsProtectionOperation::Read:
            outOperation = SENTINAL_OP_READ;
            return SENTINAL_STATUS_SUCCESS;
        case WindowsProtectionOperation::Write:
            outOperation = SENTINAL_OP_WRITE;
            return SENTINAL_STATUS_SUCCESS;
        case WindowsProtectionOperation::Delete:
            outOperation = SENTINAL_OP_DELETE;
            return SENTINAL_STATUS_SUCCESS;
        case WindowsProtectionOperation::Rename:
            outOperation = SENTINAL_OP_RENAME;
            return SENTINAL_STATUS_SUCCESS;
        case WindowsProtectionOperation::Execute:
            outOperation = SENTINAL_OP_EXECUTE;
            return SENTINAL_STATUS_SUCCESS;
        case WindowsProtectionOperation::Unknown:
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }
}

} // namespace sentinel::service
