#pragma once

#include <cstdint>
#include <sentinal/common.h>

namespace sentinel::service {

enum class DriverProtectionResponseStatus {
    SUCCESS,
    REJECTED
};

class DriverProtectionResponse {
public:
    DriverProtectionResponse() = default;

    DriverProtectionResponse(
        uint64_t requestId,
        SentinalDecision decision,
        DriverProtectionResponseStatus status
    );

    uint64_t requestId() const noexcept;
    SentinalDecision decision() const noexcept;
    DriverProtectionResponseStatus status() const noexcept;

    bool isValid() const noexcept;
    SentinalStatus validate() const noexcept;

private:
    uint64_t m_requestId{0};
    SentinalDecision m_decision{SENTINAL_DECISION_DENY};
    DriverProtectionResponseStatus m_status{
        DriverProtectionResponseStatus::REJECTED
    };
};

} // namespace sentinel::service
