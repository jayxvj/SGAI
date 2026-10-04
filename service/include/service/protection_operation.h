#pragma once

#include <sentinal/common.h>
#include "service/path_identity.h"
#include "service/protection_evaluation_context.h"

namespace sentinel::service {

class ProtectionOperation {
public:
    ProtectionOperation() = default;

    ProtectionOperation(
        PathIdentity path,
        SentinalFileOp operation
    );

    ProtectionOperation(
        PathIdentity path,
        SentinalFileOp operation,
        ProtectionEvaluationContext context
    );

    const PathIdentity& path() const noexcept;
    SentinalFileOp operation() const noexcept;
    const ProtectionEvaluationContext& context() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    PathIdentity m_path;
    SentinalFileOp m_operation{SENTINAL_OP_NONE};
    ProtectionEvaluationContext m_context;
};

} // namespace sentinel::service
