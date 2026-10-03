#pragma once

#include <string>
#include <sentinal/common.h>

namespace sentinel::service {

struct ServiceConfig {
    std::string serviceName = "SentinelService";
    SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW;
    bool verboseLogging = false;

    SentinalStatus validate() const;
};

} // namespace sentinel::service
