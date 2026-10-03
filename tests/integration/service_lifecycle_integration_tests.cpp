#include <cassert>
#include <iostream>
#include "service/service_core.h"
#include "service/config.h"
#include "service/logger.h"
#include "service/policy_engine.h"

using namespace sentinel::service;

int main() {
    std::cout << "[Integration Test] Starting ServiceCore real-component lifecycle test..." << std::endl;

    // 1. Instantiate real components: real ConsoleLogger via ServiceCore default constructor
    ServiceCore core;

    // 2. Configure with real ServiceConfig
    ServiceConfig config;
    config.serviceName = "SentinelIntegrationCore";
    config.defaultDecision = SENTINAL_DECISION_ALLOW;
    config.verboseLogging = true;

    assert(core.initialize(config) == SENTINAL_STATUS_SUCCESS);
    assert(core.getState() == ServiceState::Initialized);
    assert(!core.isRunning());

    // 3. Pre-configure policies on real PolicyEngine
    PolicyEngine& policyEngine = core.getPolicyEngine();
    assert(policyEngine.addTarget("C:/SecureStorage/keys.dat", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(policyEngine.addTarget("C:/AuditLogs", SENTINAL_TARGET_DIRECTORY_RECURSIVE, SENTINAL_DECISION_AUDIT) == SENTINAL_STATUS_SUCCESS);
    assert(policyEngine.getTargetCount() == 2);

    // 4. Start service lifecycle
    assert(core.start() == SENTINAL_STATUS_SUCCESS);
    assert(core.isRunning());
    assert(core.getState() == ServiceState::Running);

    // 5. Evaluate while running
    assert(policyEngine.evaluate("C:/SecureStorage/keys.dat", SENTINAL_OP_READ, config.defaultDecision) == SENTINAL_DECISION_DENY);
    assert(policyEngine.evaluate("C:/AuditLogs/2026/october.log", SENTINAL_OP_WRITE, config.defaultDecision) == SENTINAL_DECISION_AUDIT);
    assert(policyEngine.evaluate("C:/Public/readme.txt", SENTINAL_OP_READ, config.defaultDecision) == SENTINAL_DECISION_ALLOW);

    // 6. Dynamic policy update while running
    assert(policyEngine.addTarget("C:/Dynamic/confidential.txt", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(policyEngine.getTargetCount() == 3);
    assert(policyEngine.evaluate("C:/Dynamic/confidential.txt", SENTINAL_OP_READ, config.defaultDecision) == SENTINAL_DECISION_DENY);

    // 7. Dynamic policy removal while running
    assert(policyEngine.removeTarget("C:/SecureStorage/keys.dat") == SENTINAL_STATUS_SUCCESS);
    assert(policyEngine.getTargetCount() == 2);
    // Removed target should fall back to default decision
    assert(policyEngine.evaluate("C:/SecureStorage/keys.dat", SENTINAL_OP_READ, config.defaultDecision) == SENTINAL_DECISION_ALLOW);

    // 8. Clean service shutdown
    assert(core.stop() == SENTINAL_STATUS_SUCCESS);
    assert(!core.isRunning());
    assert(core.getState() == ServiceState::Stopped);

    std::cout << "[Integration Test] Completed successfully." << std::endl;
    return 0;
}
