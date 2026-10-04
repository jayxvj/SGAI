#pragma once

#include <sentinal/common.h>
#include <sentinal/driver_contract.h>

namespace sentinel::service {

class IWindowsDriverTransport {
public:
    virtual ~IWindowsDriverTransport() = default;

    virtual SentinalStatus connect() = 0;

    virtual SentinalStatus disconnect() = 0;

    virtual bool isConnected() const noexcept = 0;

    virtual SentinalStatus exchange(
        const SentinalDriverProtectionRequest& request,
        SentinalDriverProtectionResponse& outResponse
    ) = 0;
};

} // namespace sentinel::service
