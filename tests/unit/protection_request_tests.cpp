#include <cassert>
#include <iostream>
#include "service/protection_request.h"
#include "service/policy_engine.h"
#include "service/target.h"

using namespace sentinel::service;

static void test_default_constructor() {
    // 1. Default constructor produces an invalid request.
    ProtectionRequest req;
    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!req.path().isValid());
    assert(req.operation() == SENTINAL_OP_NONE);
}

static void test_valid_request() {
    // 2. Valid request: valid absolute PathIdentity, READ operation, validate() succeeds, isValid() is true.
    PathIdentity path("C:/Data/file.txt");
    assert(path.isValid());

    ProtectionRequest req(path, SENTINAL_OP_READ);
    assert(req.isValid());
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
    assert(req.operation() == SENTINAL_OP_READ);
    assert(req.path() == path);
}

static void test_invalid_path() {
    // 3. Invalid path: invalid PathIdentity, valid operation, validate() returns INVALID_PARAMETER.
    PathIdentity invalidPath("");
    assert(!invalidPath.isValid());

    ProtectionRequest req(invalidPath, SENTINAL_OP_WRITE);
    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_none_operation() {
    // 4. NONE operation: valid path, SENTINAL_OP_NONE, validate() returns INVALID_PARAMETER.
    PathIdentity path("C:/Data/file.txt");
    ProtectionRequest req(path, SENTINAL_OP_NONE);
    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_valid_combined_operation() {
    // 5. Valid combined operation: READ | WRITE, validate() succeeds.
    PathIdentity path("C:/Data/file.txt");
    auto combinedOp = static_cast<SentinalFileOp>(SENTINAL_OP_READ | SENTINAL_OP_WRITE);
    ProtectionRequest req(path, combinedOp);
    assert(req.isValid());
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
    assert(req.operation() == combinedOp);
}

static void test_invalid_operation_bits() {
    // 6. Invalid operation bits: use a bit outside defined SentinalFileOp values, validate() returns INVALID_PARAMETER.
    PathIdentity path("C:/Data/file.txt");

    auto invalidOpOnly = static_cast<SentinalFileOp>(0x80);
    ProtectionRequest req1(path, invalidOpOnly);
    assert(!req1.isValid());
    assert(req1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    auto mixedInvalidOp = static_cast<SentinalFileOp>(SENTINAL_OP_READ | 0x100);
    ProtectionRequest req2(path, mixedInvalidOp);
    assert(!req2.isValid());
    assert(req2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_accessors_preserve_values() {
    // 7. Accessors preserve the supplied PathIdentity and operation.
    PathIdentity path("C:/Folder/document.pdf");
    SentinalFileOp op = SENTINAL_OP_DELETE;
    ProtectionRequest req(path, op);

    assert(req.path() == path);
    assert(req.path().normalized() == "C:/Folder/document.pdf");
    assert(req.operation() == op);
}

static void test_policy_engine_evaluation() {
    // 8. PolicyEngine ProtectionRequest evaluation: valid request follows existing policy evaluation result.
    PolicyEngine pe;

    ProtectionTarget t1;
    t1.path = "C:/Sensitive";
    t1.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t1.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(t1) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget t2;
    t2.path = "C:/Sensitive/Finance";
    t2.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t2.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(t2) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget t3;
    t3.path = "C:/Sensitive/Finance/Payroll";
    t3.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t3.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(t3) == SENTINAL_STATUS_SUCCESS);

    // Evaluate via ProtectionRequest:
    // Root level -> DENY
    ProtectionRequest req1(PathIdentity("C:/Sensitive/misc.txt"), SENTINAL_OP_READ);
    assert(pe.evaluate(req1) == SENTINAL_DECISION_DENY);

    // Finance level -> ALLOW
    ProtectionRequest req2(PathIdentity("C:/Sensitive/Finance/budget.xlsx"), SENTINAL_OP_READ);
    assert(pe.evaluate(req2) == SENTINAL_DECISION_ALLOW);

    // Payroll level -> DENY
    ProtectionRequest req3(PathIdentity("C:/Sensitive/Finance/Payroll/slip.csv"), SENTINAL_OP_READ);
    assert(pe.evaluate(req3) == SENTINAL_DECISION_DENY);

    // Unrelated path -> default (ALLOW)
    ProtectionRequest req4(PathIdentity("C:/Public/readme.txt"), SENTINAL_OP_READ);
    assert(pe.evaluate(req4, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate(req4, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_DENY);
}

static void test_invalid_request_evaluation() {
    // 9. Invalid ProtectionRequest evaluation: returns the supplied default decision.
    PolicyEngine pe;

    ProtectionTarget target;
    target.path = "C:/Protected/vault.dat";
    target.type = SENTINAL_TARGET_FILE;
    target.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(target) == SENTINAL_STATUS_SUCCESS);

    // Default constructed (invalid) request
    ProtectionRequest invalidReq;
    assert(pe.evaluate(invalidReq, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate(invalidReq, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_DENY);

    // Request with SENTINAL_OP_NONE
    ProtectionRequest noneOpReq(PathIdentity("C:/Protected/vault.dat"), SENTINAL_OP_NONE);
    assert(pe.evaluate(noneOpReq, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate(noneOpReq, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_DENY);

    // Request with invalid path
    ProtectionRequest invalidPathReq(PathIdentity(""), SENTINAL_OP_READ);
    assert(pe.evaluate(invalidPathReq, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate(invalidPathReq, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_DENY);
}

int main() {
    std::cout << "[ProtectionRequest Tests] Running test suite..." << std::endl;

    test_default_constructor();
    test_valid_request();
    test_invalid_path();
    test_none_operation();
    test_valid_combined_operation();
    test_invalid_operation_bits();
    test_accessors_preserve_values();
    test_policy_engine_evaluation();
    test_invalid_request_evaluation();

    std::cout << "[ProtectionRequest Tests] All tests passed successfully." << std::endl;
    return 0;
}
