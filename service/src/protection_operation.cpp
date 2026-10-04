#include "service/protection_operation.h"
#include "service/target.h"

namespace sentinel::service {

ProtectionOperation::ProtectionOperation(
    PathIdentity path,
    SentinalFileOp operation
)
    : m_path(std::move(path)),
      m_operation(operation) {
}

ProtectionOperation::ProtectionOperation(
    PathIdentity path,
    SentinalFileOp operation,
    ProtectionEvaluationContext context
)
    : m_path(std::move(path)),
      m_operation(operation),
      m_context(context) {
}

const PathIdentity& ProtectionOperation::path() const noexcept {
    return m_path;
}

SentinalFileOp ProtectionOperation::operation() const noexcept {
    return m_operation;
}

const ProtectionEvaluationContext& ProtectionOperation::context() const noexcept {
    return m_context;
}

bool ProtectionOperation::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus ProtectionOperation::validate() const noexcept {
    if (!m_path.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    auto opValue = static_cast<uint32_t>(m_operation);
    if (opValue == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if ((opValue & ~SENTINAL_ALL_FILE_OPS) != 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (!m_context.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
