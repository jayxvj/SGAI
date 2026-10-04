#pragma once

#include <sentinal/common.h>

namespace sentinel::service {

enum class WindowsProtectionOperation {
    Unknown,
    Read,
    Write,
    Delete,
    Rename,
    Execute
};

class WindowsOperationAdapter {
public:
    static SentinalStatus toFileOperation(
        WindowsProtectionOperation operation,
        SentinalFileOp& outOperation
    ) noexcept;
};

} // namespace sentinel::service
