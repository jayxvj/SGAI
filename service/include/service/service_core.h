#pragma once

#include <memory>
#include <sentinal/common.h>
#include "service/config.h"
#include "service/logger.h"
#include "service/policy_engine.h"

namespace sentinel::service {

enum class ServiceState {
    Stopped,
    Initialized,
    Running,
    Stopping
};

class ServiceCore {
public:
    explicit ServiceCore(std::shared_ptr<ILogger> logger = std::make_shared<ConsoleLogger>());
    ~ServiceCore();

    SentinalStatus initialize(const ServiceConfig& config);
    SentinalStatus start();
    SentinalStatus stop();

    bool isRunning() const;
    ServiceState getState() const;

    PolicyEngine& getPolicyEngine();
    const PolicyEngine& getPolicyEngine() const;
    const ServiceConfig& getConfig() const;

private:
    ServiceState m_state{ServiceState::Stopped};
    ServiceConfig m_config;
    std::shared_ptr<ILogger> m_logger;
    PolicyEngine m_policyEngine;
};

} // namespace sentinel::service
