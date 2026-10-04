#pragma once

#include <sentinal/common.h>

namespace sentinel::service {

enum class ProtectionRequestSource {
    UNKNOWN,
    USER_MODE,
    KERNEL
};

class ProtectionEvaluationContext {
public:
    ProtectionEvaluationContext() = default;

    explicit ProtectionEvaluationContext(ProtectionRequestSource source);

    ProtectionRequestSource source() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    ProtectionRequestSource m_source{ProtectionRequestSource::UNKNOWN};
};

} // namespace sentinel::service
