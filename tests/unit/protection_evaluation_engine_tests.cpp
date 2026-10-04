#include <cassert>
#include <iostream>
#include "service/protection_evaluation_engine.h"
#include "service/policy_engine.h"
#include "service/protection_request.h"
#include "service/protection_decision.h"
#include "service/protection_evaluation_context.h"
#include "service/target.h"

using namespace sentinel::service;

// Helper: build a PolicyEngine with a standard set of targets for reuse.
static PolicyEngine makeSampleEngine() {
    PolicyEngine pe;

    ProtectionTarget recRoot;
    recRoot.path = "C:/Vault";
    recRoot.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    recRoot.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(recRoot) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget dirExact;
    dirExact.path = "C:/Vault/Public";
    dirExact.type = SENTINAL_TARGET_DIRECTORY;
    dirExact.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(dirExact) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget fileExact;
    fileExact.path = "C:/Vault/secret.txt";
    fileExact.type = SENTINAL_TARGET_FILE;
    fileExact.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(fileExact) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget audit;
    audit.path = "C:/Audit";
    audit.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    audit.decision = SENTINAL_DECISION_AUDIT;
    assert(pe.addTarget(audit) == SENTINAL_STATUS_SUCCESS);

    return pe;
}

static void test_valid_allow() {
    // 1. Valid request returning ALLOW (direct-child of ALLOW directory).
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/Public/readme.txt"), SENTINAL_OP_READ);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.decision() == SENTINAL_DECISION_ALLOW);
}

static void test_valid_deny() {
    // 2. Valid request returning DENY.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/data.bin"), SENTINAL_OP_WRITE);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.decision() == SENTINAL_DECISION_DENY);
}

static void test_valid_audit() {
    // 3. Valid request returning AUDIT.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Audit/log.txt"), SENTINAL_OP_READ);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.decision() == SENTINAL_DECISION_AUDIT);
}

static void test_reason_exact_file() {
    // 4. Exact file policy produces EXACT_FILE reason.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/secret.txt"), SENTINAL_OP_READ);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.reason() == ProtectionDecisionReason::EXACT_FILE);
}

static void test_reason_exact_directory() {
    // 5. Exact directory policy produces EXACT_DIRECTORY reason.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/Public"), SENTINAL_OP_READ);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.reason() == ProtectionDecisionReason::EXACT_DIRECTORY);
}

static void test_reason_direct_child_directory() {
    // 6. Direct-child directory policy produces DIRECT_CHILD_DIRECTORY reason.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/Public/readme.txt"), SENTINAL_OP_READ);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.reason() == ProtectionDecisionReason::DIRECT_CHILD_DIRECTORY);
}

static void test_reason_recursive_directory() {
    // 7. Recursive directory policy produces RECURSIVE_DIRECTORY reason.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/deep/nested/file.bin"), SENTINAL_OP_WRITE);
    ProtectionDecision d = eng.evaluate(req);
    assert(d.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

static void test_reason_default_policy() {
    // 8. No matching policy produces DEFAULT_POLICY reason.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Unrelated/file.txt"), SENTINAL_OP_READ);
    ProtectionDecision d = eng.evaluate(req, SENTINAL_DECISION_ALLOW);
    assert(d.reason() == ProtectionDecisionReason::DEFAULT_POLICY);
    assert(d.decision() == SENTINAL_DECISION_ALLOW);
}

static void test_reason_invalid_request() {
    // 9. Invalid request produces INVALID_REQUEST reason.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest invalid; // default = invalid
    ProtectionDecision d = eng.evaluate(invalid, SENTINAL_DECISION_ALLOW);
    assert(d.reason() == ProtectionDecisionReason::INVALID_REQUEST);
}

static void test_default_decision_preserved_for_invalid() {
    // 10. Supplied default decision is preserved for invalid requests.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest invalid;
    assert(eng.evaluate(invalid, SENTINAL_DECISION_ALLOW).decision() == SENTINAL_DECISION_ALLOW);
    assert(eng.evaluate(invalid, SENTINAL_DECISION_DENY).decision()  == SENTINAL_DECISION_DENY);
}

static void test_default_decision_preserved_for_no_match() {
    // 11. Supplied default decision is preserved when no policy matches.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Unrelated/file.txt"), SENTINAL_OP_READ);
    assert(eng.evaluate(req, SENTINAL_DECISION_ALLOW).decision() == SENTINAL_DECISION_ALLOW);
    assert(eng.evaluate(req, SENTINAL_DECISION_DENY).decision()  == SENTINAL_DECISION_DENY);
}

static void test_user_mode_same_as_unknown() {
    // 12. USER_MODE context produces the same result as UNKNOWN.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    PathIdentity path("C:/Vault/data.bin");
    ProtectionRequest umReq(path, SENTINAL_OP_READ,
                            ProtectionEvaluationContext(ProtectionRequestSource::USER_MODE));
    ProtectionRequest unknownReq(path, SENTINAL_OP_READ); // UNKNOWN

    ProtectionDecision um = eng.evaluate(umReq);
    ProtectionDecision uk = eng.evaluate(unknownReq);
    assert(um.decision() == uk.decision());
    assert(um.reason()   == uk.reason());
}

static void test_kernel_same_as_unknown() {
    // 13. KERNEL context produces the same result as UNKNOWN.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    PathIdentity path("C:/Vault/data.bin");
    ProtectionRequest kReq(path, SENTINAL_OP_READ,
                           ProtectionEvaluationContext(ProtectionRequestSource::KERNEL));
    ProtectionRequest unknownReq(path, SENTINAL_OP_READ);

    ProtectionDecision kd = eng.evaluate(kReq);
    ProtectionDecision uk = eng.evaluate(unknownReq);
    assert(kd.decision() == uk.decision());
    assert(kd.reason()   == uk.reason());
}

static void test_deterministic_repeated_evaluation() {
    // 14. Same request evaluated repeatedly produces the same result.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eng(pe);

    ProtectionRequest req(PathIdentity("C:/Vault/data.bin"), SENTINAL_OP_WRITE);
    ProtectionDecision first  = eng.evaluate(req);
    ProtectionDecision second = eng.evaluate(req);
    ProtectionDecision third  = eng.evaluate(req);
    assert(first.decision() == second.decision() && second.decision() == third.decision());
    assert(first.reason()   == second.reason()   && second.reason()   == third.reason());
}

static void test_engine_does_not_alter_policy_engine() {
    // 15. Engine does not alter the existing PolicyEngine behavior.
    PolicyEngine pe = makeSampleEngine();
    size_t countBefore = pe.getTargetCount();

    ProtectionEvaluationEngine eng(pe);
    ProtectionRequest req(PathIdentity("C:/Vault/data.bin"), SENTINAL_OP_READ);
    eng.evaluate(req);
    eng.evaluate(req);

    // PolicyEngine must be unchanged
    assert(pe.getTargetCount() == countBefore);

    // Direct PolicyEngine evaluation must match engine evaluation
    ProtectionDecision direct = pe.evaluateDetailed(req);
    ProtectionDecision via    = eng.evaluate(req);
    assert(direct.decision() == via.decision());
    assert(direct.reason()   == via.reason());
}

int main() {
    std::cout << "[ProtectionEvaluationEngine Tests] Running test suite..." << std::endl;

    test_valid_allow();
    test_valid_deny();
    test_valid_audit();
    test_reason_exact_file();
    test_reason_exact_directory();
    test_reason_direct_child_directory();
    test_reason_recursive_directory();
    test_reason_default_policy();
    test_reason_invalid_request();
    test_default_decision_preserved_for_invalid();
    test_default_decision_preserved_for_no_match();
    test_user_mode_same_as_unknown();
    test_kernel_same_as_unknown();
    test_deterministic_repeated_evaluation();
    test_engine_does_not_alter_policy_engine();

    std::cout << "[ProtectionEvaluationEngine Tests] All tests passed successfully." << std::endl;
    return 0;
}
