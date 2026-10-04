#include <cassert>
#include <iostream>
#include "service/protection_execution_engine.h"
#include "service/protection_enforcement.h"
#include "service/protection_evaluation_engine.h"
#include "service/policy_engine.h"
#include "service/protection_operation.h"
#include "service/protection_operation_adapter.h"
#include "service/protection_request.h"
#include "service/target.h"

using namespace sentinel::service;

static PolicyEngine makeSampleEngine() {
    PolicyEngine pe;

    ProtectionTarget allowTarget;
    allowTarget.path = "C:/Public";
    allowTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    allowTarget.decision = SENTINAL_DECISION_ALLOW;
    allowTarget.opMask = SENTINAL_OP_READ | SENTINAL_OP_WRITE;
    assert(pe.addTarget(allowTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget denyTarget;
    denyTarget.path = "C:/Secret";
    denyTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    denyTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(denyTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget auditTarget;
    auditTarget.path = "C:/Audit";
    auditTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    auditTarget.decision = SENTINAL_DECISION_AUDIT;
    assert(pe.addTarget(auditTarget) == SENTINAL_STATUS_SUCCESS);

    return pe;
}

static void test_valid_operation_allow() {
    // 1. Valid operation resulting in ALLOW
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Public/file.txt"), SENTINAL_OP_READ);
    assert(exec.execute(op) == ProtectionEnforcementAction::ALLOW);
}

static void test_valid_operation_deny() {
    // 2. Valid operation resulting in DENY
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Secret/data.bin"), SENTINAL_OP_READ);
    assert(exec.execute(op) == ProtectionEnforcementAction::DENY);
}

static void test_valid_operation_audit() {
    // 3. Valid operation resulting in AUDIT
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Audit/log.txt"), SENTINAL_OP_READ);
    assert(exec.execute(op) == ProtectionEnforcementAction::AUDIT);
}

static void test_default_policy_behavior() {
    // 4. Default policy behavior on unmatched paths
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Unmatched/file.txt"), SENTINAL_OP_READ);
    assert(exec.execute(op, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
    assert(exec.execute(op, SENTINAL_DECISION_DENY) == ProtectionEnforcementAction::DENY);
}

static void test_exact_file_policy() {
    // 5. Exact file policy takes precedence over recursive directory
    PolicyEngine pe;

    ProtectionTarget dirTarget;
    dirTarget.path = "C:/Folder";
    dirTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    dirTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget fileTarget;
    fileTarget.path = "C:/Folder/file.txt";
    fileTarget.type = SENTINAL_TARGET_FILE;
    fileTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(fileTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation opExact(PathIdentity("C:/Folder/file.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opExact) == ProtectionEnforcementAction::DENY);

    ProtectionOperation opOther(PathIdentity("C:/Folder/other.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opOther) == ProtectionEnforcementAction::ALLOW);
}

static void test_exact_directory_policy() {
    // 6. Exact directory policy matches the directory itself
    PolicyEngine pe;

    ProtectionTarget dirTarget;
    dirTarget.path = "C:/Folder";
    dirTarget.type = SENTINAL_TARGET_DIRECTORY;
    dirTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation opDir(PathIdentity("C:/Folder"), SENTINAL_OP_READ);
    assert(exec.execute(opDir) == ProtectionEnforcementAction::DENY);
}

static void test_direct_child_directory_policy() {
    // 7. Direct-child directory policy matches direct children but not deep descendants
    PolicyEngine pe;

    ProtectionTarget dirTarget;
    dirTarget.path = "C:/Folder";
    dirTarget.type = SENTINAL_TARGET_DIRECTORY;
    dirTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation opChild(PathIdentity("C:/Folder/child.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opChild, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    ProtectionOperation opDeep(PathIdentity("C:/Folder/sub/deep.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opDeep, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
}

static void test_recursive_directory_policy() {
    // 8. Recursive directory policy: deepest matching target wins
    PolicyEngine pe;

    ProtectionTarget rootTarget;
    rootTarget.path = "C:/Root";
    rootTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    rootTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(rootTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget subTarget;
    subTarget.path = "C:/Root/Sub";
    subTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    subTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(subTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation opRoot(PathIdentity("C:/Root/other.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opRoot) == ProtectionEnforcementAction::DENY);

    ProtectionOperation opSub(PathIdentity("C:/Root/Sub/deep.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opSub) == ProtectionEnforcementAction::ALLOW);
}

static void test_operation_mask_behavior() {
    // 9. Operation mask behavior
    PolicyEngine pe;

    ProtectionTarget target;
    target.path = "C:/Protected";
    target.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    target.decision = SENTINAL_DECISION_DENY;
    target.opMask = SENTINAL_OP_WRITE; // Only WRITE is denied
    assert(pe.addTarget(target) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation opRead(PathIdentity("C:/Protected/file.txt"), SENTINAL_OP_READ);
    assert(exec.execute(opRead, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);

    ProtectionOperation opWrite(PathIdentity("C:/Protected/file.txt"), SENTINAL_OP_WRITE);
    assert(exec.execute(opWrite, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

static void test_disabled_target_behavior() {
    // 10. Disabled target behavior: ignored during evaluation
    PolicyEngine pe;

    ProtectionTarget target;
    target.path = "C:/Disabled";
    target.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    target.decision = SENTINAL_DECISION_DENY;
    target.enabled = false;
    assert(pe.addTarget(target) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Disabled/file.txt"), SENTINAL_OP_READ);
    assert(exec.execute(op, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
}

static void test_invalid_protection_operation_results_in_deny() {
    // 11. Invalid ProtectionOperation results in safe DENY
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation invalidOp; // default invalid
    assert(exec.execute(invalidOp, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

static void test_invalid_path_results_in_deny() {
    // 12. Invalid path results in safe DENY
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity(""), SENTINAL_OP_READ);
    assert(exec.execute(op, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

static void test_invalid_operation_results_in_deny() {
    // 13. Invalid operation results in safe DENY
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    // SENTINAL_OP_NONE
    ProtectionOperation opNone(PathIdentity("C:/Public/file.txt"), SENTINAL_OP_NONE);
    assert(exec.execute(opNone, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    // Unrecognized operation bits
    ProtectionOperation opBadBits(PathIdentity("C:/Public/file.txt"), static_cast<SentinalFileOp>(0x80));
    assert(exec.execute(opBadBits, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

static void test_user_mode_evaluation_context_supported() {
    // 14. Valid USER_MODE evaluation context remains supported
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionOperation op(PathIdentity("C:/Secret/file.txt"), SENTINAL_OP_READ, ctx);
    assert(exec.execute(op) == ProtectionEnforcementAction::DENY);
}

static void test_kernel_evaluation_context_supported() {
    // 15. Valid KERNEL evaluation context remains supported
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionOperation op(PathIdentity("C:/Secret/file.txt"), SENTINAL_OP_READ, ctx);
    assert(exec.execute(op) == ProtectionEnforcementAction::DENY);
}

static void test_deterministic_evaluation() {
    // 16. Evaluation remains deterministic across repeated calls
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Secret/data.bin"), SENTINAL_OP_READ);
    ProtectionEnforcementAction a1 = exec.execute(op);
    ProtectionEnforcementAction a2 = exec.execute(op);
    ProtectionEnforcementAction a3 = exec.execute(op);

    assert(a1 == a2);
    assert(a2 == a3);
    assert(a1 == ProtectionEnforcementAction::DENY);
}

static void test_no_unexpected_state_mutation() {
    // 17. Existing engine state is not mutated unexpectedly
    PolicyEngine pe = makeSampleEngine();
    size_t countBefore = pe.getTargetCount();

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Public/file.txt"), SENTINAL_OP_READ);
    exec.execute(op);
    exec.execute(op);

    assert(pe.getTargetCount() == countBefore);
}

static void test_does_not_bypass_existing_adapters() {
    // 18. ProtectionExecutionEngine does not bypass existing adapters:
    // An operation with invalid context fails adapter conversion and is DENIED even if path matches an ALLOW target
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionEvaluationContext badCtx(static_cast<ProtectionRequestSource>(99));
    ProtectionOperation op(PathIdentity("C:/Public/file.txt"), SENTINAL_OP_READ, badCtx);

    // Verify ProtectionOperationAdapter rejects it
    ProtectionRequest req;
    assert(ProtectionOperationAdapter::toRequest(op, req) == SENTINAL_STATUS_INVALID_PARAMETER);

    // Execution must return safe DENY even with ALLOW default and ALLOW target
    assert(exec.execute(op, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

static void test_unknown_decision_maps_to_deny() {
    // 19. SENTINAL_DECISION_UNKNOWN is a valid enum value; ProtectionEnforcement maps it to DENY.
    PolicyEngine pe; // empty engine -> falls back to defaultDecision
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Unmatched/file.txt"), SENTINAL_OP_READ);
    assert(exec.execute(op, SENTINAL_DECISION_UNKNOWN) == ProtectionEnforcementAction::DENY);
}

static void test_invalid_decision_maps_to_deny() {
    // 20. An out-of-range SentinalDecision (e.g. 99) exercises the default branch
    //     of ProtectionEnforcement's switch and must return DENY (fail-closed).
    PolicyEngine pe;
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);

    ProtectionOperation op(PathIdentity("C:/Unmatched/file.txt"), SENTINAL_OP_READ);
    auto badDecision = static_cast<SentinalDecision>(99);
    assert(exec.execute(op, badDecision) == ProtectionEnforcementAction::DENY);
}

int main() {
    std::cout << "[ProtectionExecutionEngine Tests] Running test suite..." << std::endl;

    test_valid_operation_allow();
    test_valid_operation_deny();
    test_valid_operation_audit();
    test_default_policy_behavior();
    test_exact_file_policy();
    test_exact_directory_policy();
    test_direct_child_directory_policy();
    test_recursive_directory_policy();
    test_operation_mask_behavior();
    test_disabled_target_behavior();
    test_invalid_protection_operation_results_in_deny();
    test_invalid_path_results_in_deny();
    test_invalid_operation_results_in_deny();
    test_user_mode_evaluation_context_supported();
    test_kernel_evaluation_context_supported();
    test_deterministic_evaluation();
    test_no_unexpected_state_mutation();
    test_does_not_bypass_existing_adapters();
    test_unknown_decision_maps_to_deny();
    test_invalid_decision_maps_to_deny();

    std::cout << "[ProtectionExecutionEngine Tests] All tests passed successfully." << std::endl;
    return 0;
}
