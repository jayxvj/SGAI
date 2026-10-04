#include "service/protection_request.h"
#include "service/target.h"

namespace sentinel::service {

ProtectionRequest::ProtectionRequest(
    PathIdentity path,
    SentinalFileOp operation
)
    : m_path(std::move(path)),
      m_operation(operation) {
}

ProtectionRequest::ProtectionRequest(
    PathIdentity path,
    SentinalFileOp operation,
    ProtectionEvaluationContext context
)
    : m_path(std::move(path)),
      m_operation(operation),
      m_context(context) {
}

const PathIdentity& ProtectionRequest::path() const noexcept {
    return m_path;
}

SentinalFileOp ProtectionRequest::operation() const noexcept {
    return m_operation;
}

const ProtectionEvaluationContext& ProtectionRequest::context() const noexcept {
    return m_context;
}

bool ProtectionRequest::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus ProtectionRequest::validate() const noexcept {
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
