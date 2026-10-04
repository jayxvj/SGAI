#pragma once

#include <cstdint>
#include <sentinal/common.h>
#include "service/path_identity.h"
#include "service/protection_evaluation_context.h"

namespace sentinel::service {

class DriverProtectionRequest {
public:
    DriverProtectionRequest() = default;

    DriverProtectionRequest(
        uint64_t requestId,
        PathIdentity path,
        SentinalFileOp operation,
        ProtectionEvaluationContext context
    );

    uint64_t requestId() const noexcept;
    const PathIdentity& path() const noexcept;
    SentinalFileOp operation() const noexcept;
    const ProtectionEvaluationContext& context() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    uint64_t m_requestId{0};
    PathIdentity m_path;
    SentinalFileOp m_operation{SENTINAL_OP_NONE};
    ProtectionEvaluationContext m_context;
};

} // namespace sentinel::service
