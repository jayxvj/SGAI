#include "service/driver_protection_request.h"
#include <utility>

namespace sentinel::service {

DriverProtectionRequest::DriverProtectionRequest(
    uint64_t requestId,
    PathIdentity path,
    SentinalFileOp operation,
    ProtectionEvaluationContext context
)
    : m_requestId(requestId),
      m_path(std::move(path)),
      m_operation(operation),
      m_context(std::move(context)) {
}

uint64_t DriverProtectionRequest::requestId() const noexcept {
    return m_requestId;
}

const PathIdentity& DriverProtectionRequest::path() const noexcept {
    return m_path;
}

SentinalFileOp DriverProtectionRequest::operation() const noexcept {
    return m_operation;
}

const ProtectionEvaluationContext& DriverProtectionRequest::context() const noexcept {
    return m_context;
}

bool DriverProtectionRequest::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus DriverProtectionRequest::validate() const noexcept {
    if (m_requestId == 0) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (!m_path.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    switch (m_operation) {
        case SENTINAL_OP_READ:
        case SENTINAL_OP_WRITE:
        case SENTINAL_OP_DELETE:
        case SENTINAL_OP_RENAME:
        case SENTINAL_OP_EXECUTE:
            break;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (!m_context.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
