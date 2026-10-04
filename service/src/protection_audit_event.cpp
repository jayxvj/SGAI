#include "service/protection_audit_event.h"

namespace sentinel::service {

ProtectionAuditEvent::ProtectionAuditEvent(
    PathIdentity path,
    SentinalFileOp operation,
    ProtectionEvaluationContext context,
    ProtectionExecutionResult result
)
    : m_path(std::move(path)),
      m_operation(operation),
      m_context(std::move(context)),
      m_result(result) {
}

const PathIdentity& ProtectionAuditEvent::path() const noexcept {
    return m_path;
}

SentinalFileOp ProtectionAuditEvent::operation() const noexcept {
    return m_operation;
}

const ProtectionEvaluationContext& ProtectionAuditEvent::context() const noexcept {
    return m_context;
}

const ProtectionExecutionResult& ProtectionAuditEvent::result() const noexcept {
    return m_result;
}

bool ProtectionAuditEvent::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus ProtectionAuditEvent::validate() const noexcept {
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

    if (!m_result.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
