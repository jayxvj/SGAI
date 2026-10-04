#pragma once

#include <cstdint>
#include <sentinal/common.h>
#include <sentinal/driver_contract.h>
#include "service/windows_driver_transport.h"

namespace sentinel::service {

class TestWindowsDriverTransport final
    : public IWindowsDriverTransport
{
public:
    TestWindowsDriverTransport() = default;

    SentinalStatus connect() override;

    SentinalStatus disconnect() override;

    bool isConnected() const noexcept override;

    SentinalStatus exchange(
        const SentinalDriverProtectionRequest& request,
        SentinalDriverProtectionResponse& outResponse
    ) override;

    void setResponse(
        uint64_t requestId,
        uint32_t decision,
        uint32_t status
    );

    void setFailure(SentinalStatus status);

    const SentinalDriverProtectionRequest& lastRequest() const noexcept;

    bool hasRequest() const noexcept;

private:
    bool m_connected{false};
    bool m_hasRequest{false};

    SentinalDriverProtectionRequest m_lastRequest{};

    SentinalDriverProtectionResponse m_response{};

    SentinalStatus m_failure{
        SENTINAL_STATUS_SUCCESS
    };
};

} // namespace sentinel::service
