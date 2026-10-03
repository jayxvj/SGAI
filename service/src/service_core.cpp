#include "service/service_core.h"

namespace sentinel::service {

ServiceCore::ServiceCore(std::shared_ptr<ILogger> logger)
    : m_logger(std::move(logger)) {
    if (!m_logger) {
        m_logger = std::make_shared<ConsoleLogger>();
    }
}

ServiceCore::~ServiceCore() {
    if (m_state == ServiceState::Running) {
        stop();
    }
}

SentinalStatus ServiceCore::initialize(const ServiceConfig& config) {
    if (m_state == ServiceState::Running || m_state == ServiceState::Stopping) {
        m_logger->log(LogLevel::Error, "Cannot initialize while service is running or stopping");
        return SENTINAL_STATUS_UNSPECIFIED_ERROR;
    }

    SentinalStatus status = config.validate();
    if (status != SENTINAL_STATUS_SUCCESS) {
        m_logger->log(LogLevel::Error, "Service configuration validation failed");
        return status;
    }

    m_config = config;
    m_state = ServiceState::Initialized;
    m_logger->log(LogLevel::Info, "ServiceCore initialized: " + m_config.serviceName);
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus ServiceCore::start() {
    if (m_state == ServiceState::Running) {
        m_logger->log(LogLevel::Warning, "Service is already running");
        return SENTINAL_STATUS_ALREADY_EXISTS;
    }

    if (m_state != ServiceState::Initialized) {
        m_logger->log(LogLevel::Error, "Cannot start service: not initialized");
        return SENTINAL_STATUS_UNSPECIFIED_ERROR;
    }

    m_state = ServiceState::Running;
    m_logger->log(LogLevel::Info, "ServiceCore started successfully");
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus ServiceCore::stop() {
    if (m_state != ServiceState::Running) {
        m_logger->log(LogLevel::Warning, "Cannot stop service: not in running state");
        return SENTINAL_STATUS_UNSPECIFIED_ERROR;
    }

    m_state = ServiceState::Stopping;
    m_logger->log(LogLevel::Info, "ServiceCore stopping...");

    m_state = ServiceState::Stopped;
    m_logger->log(LogLevel::Info, "ServiceCore stopped cleanly");
    return SENTINAL_STATUS_SUCCESS;
}

bool ServiceCore::isRunning() const {
    return m_state == ServiceState::Running;
}

ServiceState ServiceCore::getState() const {
    return m_state;
}

PolicyEngine& ServiceCore::getPolicyEngine() {
    return m_policyEngine;
}

const PolicyEngine& ServiceCore::getPolicyEngine() const {
    return m_policyEngine;
}

const ServiceConfig& ServiceCore::getConfig() const {
    return m_config;
}

} // namespace sentinel::service
