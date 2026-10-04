#include "service/protection_evaluation_context.h"

namespace sentinel::service {

ProtectionEvaluationContext::ProtectionEvaluationContext(ProtectionRequestSource source)
    : m_source(source) {
}

ProtectionRequestSource ProtectionEvaluationContext::source() const noexcept {
    return m_source;
}

SentinalStatus ProtectionEvaluationContext::validate() const noexcept {
    switch (m_source) {
        case ProtectionRequestSource::UNKNOWN:
        case ProtectionRequestSource::USER_MODE:
        case ProtectionRequestSource::KERNEL:
            return SENTINAL_STATUS_SUCCESS;
        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }
}

bool ProtectionEvaluationContext::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
