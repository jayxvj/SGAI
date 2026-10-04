#include <cassert>
#include <iostream>
#include "service/protection_enforcement.h"
#include "service/protection_evaluation_engine.h"
#include "service/policy_engine.h"
#include "service/protection_request.h"
#include "service/protection_decision.h"
#include "service/protection_evaluation_context.h"
#include "service/target.h"

using namespace sentinel::service;

// Build a standard PolicyEngine for most tests.
static PolicyEngine makeSampleEngine() {
    PolicyEngine pe;

    ProtectionTarget allow;
    allow.path = "C:/Public";
    allow.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    allow.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(allow) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget deny;
    deny.path = "C:/Vault";
    deny.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    deny.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(deny) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget audit;
    audit.path = "C:/Audit";
    audit.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    audit.decision = SENTINAL_DECISION_AUDIT;
    assert(pe.addTarget(audit) == SENTINAL_STATUS_SUCCESS);

    return pe;
}

static void test_allow_decision_gives_allow_action() {
    // 1. ALLOW decision -> ALLOW action.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Public/readme.txt"), SENTINAL_OP_READ);
    assert(enf.evaluate(req) == ProtectionEnforcementAction::ALLOW);
}

static void test_deny_decision_gives_deny_action() {
    // 2. DENY decision -> DENY action.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Vault/secret.bin"), SENTINAL_OP_WRITE);
    assert(enf.evaluate(req) == ProtectionEnforcementAction::DENY);
}

static void test_audit_decision_gives_audit_action() {
    // 3. AUDIT decision -> AUDIT action.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Audit/log.txt"), SENTINAL_OP_READ);
    assert(enf.evaluate(req) == ProtectionEnforcementAction::AUDIT);
}

static void test_unknown_decision_gives_deny_action() {
    // 4. UNKNOWN decision -> DENY action (fail closed).
    // Construct a ProtectionDecision with UNKNOWN directly to test the mapping.
    PolicyEngine pe;
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    // An empty engine with SENTINAL_DECISION_UNKNOWN as default produces UNKNOWN.
    ProtectionRequest req(PathIdentity("C:/Any/file.txt"), SENTINAL_OP_READ);
    ProtectionEnforcementAction action = enf.evaluate(req, SENTINAL_DECISION_UNKNOWN);
    assert(action == ProtectionEnforcementAction::DENY);
}

static void test_invalid_enum_decision_gives_deny_action() {
    // 5. Invalid/unrecognized SentinalDecision cast -> DENY action.
    PolicyEngine pe;
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Any/file.txt"), SENTINAL_OP_READ);
    auto invalidDecision = static_cast<SentinalDecision>(99);
    ProtectionEnforcementAction action = enf.evaluate(req, invalidDecision);
    assert(action == ProtectionEnforcementAction::DENY);
}

static void test_invalid_request_follows_evaluation_semantics() {
    // 6. Invalid ProtectionRequest follows existing evaluation semantics.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest invalid; // default-constructed = invalid

    // With ALLOW default: PolicyEngine produces ALLOW + INVALID_REQUEST -> maps to ALLOW
    assert(enf.evaluate(invalid, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);

    // With DENY default: PolicyEngine produces DENY + INVALID_REQUEST -> maps to DENY
    assert(enf.evaluate(invalid, SENTINAL_DECISION_DENY) == ProtectionEnforcementAction::DENY);
}

static void test_default_allow_preserved_on_no_match() {
    // 7. Caller-supplied default ALLOW is preserved when PolicyEngine produces DEFAULT_POLICY + ALLOW.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Unrelated/file.txt"), SENTINAL_OP_READ);
    assert(enf.evaluate(req, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
}

static void test_default_deny_preserved_on_no_match() {
    // 8. Caller-supplied default DENY is preserved when PolicyEngine produces DEFAULT_POLICY + DENY.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Unrelated/file.txt"), SENTINAL_OP_READ);
    assert(enf.evaluate(req, SENTINAL_DECISION_DENY) == ProtectionEnforcementAction::DENY);
}

static void test_user_mode_same_as_unknown_context() {
    // 9. USER_MODE context produces the same action as UNKNOWN.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    PathIdentity path("C:/Vault/data.bin");
    ProtectionRequest umReq(path, SENTINAL_OP_READ,
                            ProtectionEvaluationContext(ProtectionRequestSource::USER_MODE));
    ProtectionRequest ukReq(path, SENTINAL_OP_READ); // UNKNOWN

    assert(enf.evaluate(umReq) == enf.evaluate(ukReq));
}

static void test_kernel_same_as_unknown_context() {
    // 10. KERNEL context produces the same action as UNKNOWN.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    PathIdentity path("C:/Vault/data.bin");
    ProtectionRequest kReq(path, SENTINAL_OP_READ,
                           ProtectionEvaluationContext(ProtectionRequestSource::KERNEL));
    ProtectionRequest ukReq(path, SENTINAL_OP_READ);

    assert(enf.evaluate(kReq) == enf.evaluate(ukReq));
}

static void test_deterministic_repeated_evaluation() {
    // 11. Repeated evaluation is deterministic.
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Vault/secret.bin"), SENTINAL_OP_WRITE);
    ProtectionEnforcementAction a1 = enf.evaluate(req);
    ProtectionEnforcementAction a2 = enf.evaluate(req);
    ProtectionEnforcementAction a3 = enf.evaluate(req);
    assert(a1 == a2 && a2 == a3);
}

static void test_enforcement_does_not_modify_engine_state() {
    // 12. ProtectionEnforcement does not modify the underlying evaluation engine or policy state.
    PolicyEngine pe = makeSampleEngine();
    size_t countBefore = pe.getTargetCount();

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);

    ProtectionRequest req(PathIdentity("C:/Vault/secret.bin"), SENTINAL_OP_READ);
    enf.evaluate(req);
    enf.evaluate(req);

    assert(pe.getTargetCount() == countBefore);

    // Direct evaluation must still agree after enforcement calls
    ProtectionDecision direct = pe.evaluateDetailed(req);
    ProtectionEnforcementAction action = enf.evaluate(req);

    ProtectionEnforcementAction expected =
        (direct.decision() == SENTINAL_DECISION_ALLOW) ? ProtectionEnforcementAction::ALLOW :
        (direct.decision() == SENTINAL_DECISION_AUDIT) ? ProtectionEnforcementAction::AUDIT :
                                                         ProtectionEnforcementAction::DENY;
    assert(action == expected);
}

int main() {
    std::cout << "[ProtectionEnforcement Tests] Running test suite..." << std::endl;

    test_allow_decision_gives_allow_action();
    test_deny_decision_gives_deny_action();
    test_audit_decision_gives_audit_action();
    test_unknown_decision_gives_deny_action();
    test_invalid_enum_decision_gives_deny_action();
    test_invalid_request_follows_evaluation_semantics();
    test_default_allow_preserved_on_no_match();
    test_default_deny_preserved_on_no_match();
    test_user_mode_same_as_unknown_context();
    test_kernel_same_as_unknown_context();
    test_deterministic_repeated_evaluation();
    test_enforcement_does_not_modify_engine_state();

    std::cout << "[ProtectionEnforcement Tests] All tests passed successfully." << std::endl;
    return 0;
}
