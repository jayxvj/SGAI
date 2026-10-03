#include <cassert>
#include <iostream>
#include "service/service_core.h"

using namespace sentinel::service;

class TestLogger : public ILogger {
public:
    void log(LogLevel, const std::string&) override {}
};

static void test_initialization() {
    auto logger = std::make_shared<TestLogger>();
    ServiceCore core(logger);

    ServiceConfig validConfig;
    validConfig.serviceName = "SentinelTest";
    assert(core.initialize(validConfig) == SENTINAL_STATUS_SUCCESS);
    assert(core.getState() == ServiceState::Initialized);
    assert(!core.isRunning());

    // Invalid config (empty service name)
    ServiceConfig invalidConfig;
    invalidConfig.serviceName = "";
    ServiceCore core2(logger);
    assert(core2.initialize(invalidConfig) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(core2.getState() == ServiceState::Stopped);
}

static void test_lifecycle_flow() {
    auto logger = std::make_shared<TestLogger>();
    ServiceCore core(logger);

    ServiceConfig config;
    assert(core.initialize(config) == SENTINAL_STATUS_SUCCESS);

    // Start
    assert(core.start() == SENTINAL_STATUS_SUCCESS);
    assert(core.isRunning());
    assert(core.getState() == ServiceState::Running);

    // Stop
    assert(core.stop() == SENTINAL_STATUS_SUCCESS);
    assert(!core.isRunning());
    assert(core.getState() == ServiceState::Stopped);
}

static void test_invalid_transitions() {
    auto logger = std::make_shared<TestLogger>();
    ServiceCore core(logger);

    // Start before initialize
    assert(core.start() == SENTINAL_STATUS_UNSPECIFIED_ERROR);
    assert(!core.isRunning());

    // Stop before running
    assert(core.stop() == SENTINAL_STATUS_UNSPECIFIED_ERROR);

    // Normal init & start
    ServiceConfig config;
    assert(core.initialize(config) == SENTINAL_STATUS_SUCCESS);
    assert(core.start() == SENTINAL_STATUS_SUCCESS);

    // Double start while running
    assert(core.start() == SENTINAL_STATUS_ALREADY_EXISTS);

    // Re-initialize while running
    assert(core.initialize(config) == SENTINAL_STATUS_UNSPECIFIED_ERROR);

    assert(core.stop() == SENTINAL_STATUS_SUCCESS);
}

static void test_policy_engine() {
    auto logger = std::make_shared<TestLogger>();
    ServiceCore core(logger);

    ServiceConfig config;
    config.defaultDecision = SENTINAL_DECISION_ALLOW;
    assert(core.initialize(config) == SENTINAL_STATUS_SUCCESS);

    PolicyEngine& pe = core.getPolicyEngine();

    // Default decision for unprotected target
    assert(pe.evaluate("C:\\public\\doc.txt", SENTINAL_OP_READ, config.defaultDecision) == SENTINAL_DECISION_ALLOW);

    // Register a protected file target
    assert(pe.addTarget("C:\\protected\\secret.key", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(pe.getTargetCount() == 1);

    // Protected file target should return DENY
    assert(pe.evaluate("C:\\protected\\secret.key", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("c:/protected/secret.key", SENTINAL_OP_WRITE) == SENTINAL_DECISION_DENY);

    // Unrelated path should return configured default ALLOW
    assert(pe.evaluate("C:\\unprotected\\file.txt", SENTINAL_OP_WRITE, config.defaultDecision) == SENTINAL_DECISION_ALLOW);

    // Recursive directory target
    assert(pe.addTarget("C:\\protected\\folder", SENTINAL_TARGET_DIRECTORY_RECURSIVE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(pe.evaluate("C:\\protected\\folder\\sub\\nested.doc", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

int main() {
    test_initialization();
    test_lifecycle_flow();
    test_invalid_transitions();
    test_policy_engine();

    std::cout << "All SentinelServiceCore unit tests passed successfully." << std::endl;
    return 0;
}
