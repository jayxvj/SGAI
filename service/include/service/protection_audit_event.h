#pragma once

#include <sentinal/common.h>
#include "service/path_identity.h"
#include "service/protection_evaluation_context.h"
#include "service/protection_execution_result.h"

namespace sentinel::service {

class ProtectionAuditEvent {
public:
    ProtectionAuditEvent() = default;

    ProtectionAuditEvent(
        PathIdentity path,
        SentinalFileOp operation,
        ProtectionEvaluationContext context,
        ProtectionExecutionResult result
    );

    const PathIdentity& path() const noexcept;
    SentinalFileOp operation() const noexcept;
    const ProtectionEvaluationContext& context() const noexcept;
    const ProtectionExecutionResult& result() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    PathIdentity m_path;
    SentinalFileOp m_operation{SENTINAL_OP_NONE};
    ProtectionEvaluationContext m_context;
    ProtectionExecutionResult m_result;
};

} // namespace sentinel::service
