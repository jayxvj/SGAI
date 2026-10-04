#include "service/driver_protection_response.h"

namespace sentinel::service {

DriverProtectionResponse::DriverProtectionResponse(
    uint64_t requestId,
    SentinalDecision decision,
    DriverProtectionResponseStatus status
)
    : m_requestId(requestId),
      m_decision(decision),
      m_status(status) {
}

uint64_t DriverProtectionResponse::requestId() const noexcept {
    return m_requestId;
}

SentinalDecision DriverProtectionResponse::decision() const noexcept {
    return m_decision;
}

DriverProtectionResponseStatus DriverProtectionResponse::status() const noexcept {
    return m_status;
}

bool DriverProtectionResponse::isValid() const noexcept {
    return validate() == SENTINAL_STATUS_SUCCESS;
}

SentinalStatus DriverProtectionResponse::validate() const noexcept {
    switch (m_status) {
        case DriverProtectionResponseStatus::SUCCESS:
            if (m_requestId == 0) {
                return SENTINAL_STATUS_INVALID_PARAMETER;
            }
            switch (m_decision) {
                case SENTINAL_DECISION_ALLOW:
                case SENTINAL_DECISION_DENY:
                case SENTINAL_DECISION_AUDIT:
                    return SENTINAL_STATUS_SUCCESS;
                default:
                    return SENTINAL_STATUS_INVALID_PARAMETER;
            }

        case DriverProtectionResponseStatus::REJECTED:
            if (m_decision == SENTINAL_DECISION_DENY) {
                return SENTINAL_STATUS_SUCCESS;
            }
            return SENTINAL_STATUS_INVALID_PARAMETER;

        default:
            return SENTINAL_STATUS_INVALID_PARAMETER;
    }
}

} // namespace sentinel::service
