#pragma once

#include <sentinal/common.h>
#include "service/path_identity.h"

namespace sentinel::service {

class ProtectionRequest {
public:
    ProtectionRequest() = default;

    ProtectionRequest(
        PathIdentity path,
        SentinalFileOp operation
    );

    const PathIdentity& path() const noexcept;
    SentinalFileOp operation() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    PathIdentity m_path;
    SentinalFileOp m_operation{SENTINAL_OP_NONE};
};

} // namespace sentinel::service
