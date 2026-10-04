#include <cassert>
#include <iostream>
#include <climits>
#include "service/protection_decision.h"
#include "service/policy_engine.h"
#include "service/protection_request.h"
#include "service/target.h"

using namespace sentinel::service;

// ---------------------------------------------------------------------------
// ProtectionDecision model tests
// ---------------------------------------------------------------------------

static void test_default_construction() {
    // 1. Default: UNKNOWN + DEFAULT_POLICY, both are valid enum values so isValid() == true.
    ProtectionDecision pd;
    assert(pd.decision() == SENTINAL_DECISION_UNKNOWN);
    assert(pd.reason() == ProtectionDecisionReason::DEFAULT_POLICY);
    assert(pd.isValid());
    assert(pd.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_allow_default_policy() {
    // 2. Valid ALLOW + DEFAULT_POLICY
    ProtectionDecision pd(SENTINAL_DECISION_ALLOW, ProtectionDecisionReason::DEFAULT_POLICY);
    assert(pd.decision() == SENTINAL_DECISION_ALLOW);
    assert(pd.reason() == ProtectionDecisionReason::DEFAULT_POLICY);
    assert(pd.isValid());
    assert(pd.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_deny_exact_file() {
    // 3. Valid DENY + EXACT_FILE
    ProtectionDecision pd(SENTINAL_DECISION_DENY, ProtectionDecisionReason::EXACT_FILE);
    assert(pd.decision() == SENTINAL_DECISION_DENY);
    assert(pd.reason() == ProtectionDecisionReason::EXACT_FILE);
    assert(pd.isValid());
}

static void test_allow_exact_directory() {
    // 4. Valid ALLOW + EXACT_DIRECTORY
    ProtectionDecision pd(SENTINAL_DECISION_ALLOW, ProtectionDecisionReason::EXACT_DIRECTORY);
    assert(pd.decision() == SENTINAL_DECISION_ALLOW);
    assert(pd.reason() == ProtectionDecisionReason::EXACT_DIRECTORY);
    assert(pd.isValid());
}

static void test_deny_direct_child_directory() {
    // 5. Valid DENY + DIRECT_CHILD_DIRECTORY
    ProtectionDecision pd(SENTINAL_DECISION_DENY, ProtectionDecisionReason::DIRECT_CHILD_DIRECTORY);
    assert(pd.decision() == SENTINAL_DECISION_DENY);
    assert(pd.reason() == ProtectionDecisionReason::DIRECT_CHILD_DIRECTORY);
    assert(pd.isValid());
}

static void test_deny_recursive_directory() {
    // 6. Valid DENY + RECURSIVE_DIRECTORY
    ProtectionDecision pd(SENTINAL_DECISION_DENY, ProtectionDecisionReason::RECURSIVE_DIRECTORY);
    assert(pd.decision() == SENTINAL_DECISION_DENY);
    assert(pd.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
    assert(pd.isValid());
}

static void test_default_decision_invalid_request() {
    // 7. Valid default decision + INVALID_REQUEST
    ProtectionDecision pd(SENTINAL_DECISION_DENY, ProtectionDecisionReason::INVALID_REQUEST);
    assert(pd.decision() == SENTINAL_DECISION_DENY);
    assert(pd.reason() == ProtectionDecisionReason::INVALID_REQUEST);
    assert(pd.isValid());

    ProtectionDecision pd2(SENTINAL_DECISION_ALLOW, ProtectionDecisionReason::INVALID_REQUEST);
    assert(pd2.decision() == SENTINAL_DECISION_ALLOW);
    assert(pd2.reason() == ProtectionDecisionReason::INVALID_REQUEST);
    assert(pd2.isValid());
}

static void test_invalid_sentinal_decision() {
    // 8. Invalid SentinalDecision value is rejected.
    auto badDecision = static_cast<SentinalDecision>(99);
    ProtectionDecision pd(badDecision, ProtectionDecisionReason::DEFAULT_POLICY);
    assert(!pd.isValid());
    assert(pd.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_reason() {
    // 9. Invalid ProtectionDecisionReason value is rejected.
    auto badReason = static_cast<ProtectionDecisionReason>(999);
    ProtectionDecision pd(SENTINAL_DECISION_ALLOW, badReason);
    assert(!pd.isValid());
    assert(pd.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_accessors_preserve_values() {
    // 10. Accessors preserve decision and reason.
    ProtectionDecision pd(SENTINAL_DECISION_AUDIT, ProtectionDecisionReason::RECURSIVE_DIRECTORY);
    assert(pd.decision() == SENTINAL_DECISION_AUDIT);
    assert(pd.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

// ---------------------------------------------------------------------------
// PolicyEngine detailed evaluation tests
// ---------------------------------------------------------------------------

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

    return pe;
}

static void test_detailed_exact_file() {
    // 1. Exact FILE returns EXACT_FILE reason.
    PolicyEngine pe = makeSampleEngine();

    auto result = pe.evaluateDetailed(PathIdentity("C:/Vault/secret.txt"), SENTINAL_OP_READ);
    assert(result.decision() == SENTINAL_DECISION_DENY);
    assert(result.reason() == ProtectionDecisionReason::EXACT_FILE);
}

static void test_detailed_exact_directory() {
    // 2. Exact DIRECTORY returns EXACT_DIRECTORY reason.
    PolicyEngine pe = makeSampleEngine();

    auto result = pe.evaluateDetailed(PathIdentity("C:/Vault/Public"), SENTINAL_OP_READ);
    assert(result.decision() == SENTINAL_DECISION_ALLOW);
    assert(result.reason() == ProtectionDecisionReason::EXACT_DIRECTORY);
}

static void test_detailed_direct_child_directory() {
    // 3. Direct-child DIRECTORY returns DIRECT_CHILD_DIRECTORY reason.
    PolicyEngine pe = makeSampleEngine();

    // "C:/Vault/Public" is a DIRECTORY target; direct children of it are covered.
    auto result = pe.evaluateDetailed(PathIdentity("C:/Vault/Public/readme.txt"), SENTINAL_OP_READ);
    assert(result.decision() == SENTINAL_DECISION_ALLOW);
    assert(result.reason() == ProtectionDecisionReason::DIRECT_CHILD_DIRECTORY);
}

static void test_detailed_recursive_directory() {
    // 4. Recursive directory returns RECURSIVE_DIRECTORY reason.
    PolicyEngine pe = makeSampleEngine();

    auto result = pe.evaluateDetailed(PathIdentity("C:/Vault/other/data.bin"), SENTINAL_OP_READ);
    assert(result.decision() == SENTINAL_DECISION_DENY);
    assert(result.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

static void test_detailed_deepest_recursive() {
    // 5. Deepest recursive directory wins and returns RECURSIVE_DIRECTORY.
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

    auto r1 = pe.evaluateDetailed(PathIdentity("C:/Sensitive/misc.txt"), SENTINAL_OP_READ);
    assert(r1.decision() == SENTINAL_DECISION_DENY);
    assert(r1.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);

    auto r2 = pe.evaluateDetailed(PathIdentity("C:/Sensitive/Finance/budget.xlsx"), SENTINAL_OP_READ);
    assert(r2.decision() == SENTINAL_DECISION_ALLOW);
    assert(r2.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);

    auto r3 = pe.evaluateDetailed(PathIdentity("C:/Sensitive/Finance/Payroll/slip.csv"), SENTINAL_OP_READ);
    assert(r3.decision() == SENTINAL_DECISION_DENY);
    assert(r3.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

static void test_detailed_no_match_default_policy() {
    // 6. No matching target returns DEFAULT_POLICY.
    PolicyEngine pe = makeSampleEngine();

    auto result = pe.evaluateDetailed(PathIdentity("C:/Other/file.txt"), SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW);
    assert(result.decision() == SENTINAL_DECISION_ALLOW);
    assert(result.reason() == ProtectionDecisionReason::DEFAULT_POLICY);
}

static void test_detailed_disabled_target_fallthrough() {
    // 7. Disabled matching target falls through to the next applicable target.
    PolicyEngine pe;

    ProtectionTarget broad;
    broad.path = "C:/Vault";
    broad.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    broad.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(broad) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget specific;
    specific.path = "C:/Vault/safe.txt";
    specific.type = SENTINAL_TARGET_FILE;
    specific.decision = SENTINAL_DECISION_ALLOW;
    specific.enabled = false;
    assert(pe.addTarget(specific) == SENTINAL_STATUS_SUCCESS);

    // Disabled FILE target doesn't win; falls through to recursive DENY.
    auto result = pe.evaluateDetailed(PathIdentity("C:/Vault/safe.txt"), SENTINAL_OP_READ);
    assert(result.decision() == SENTINAL_DECISION_DENY);
    assert(result.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

static void test_detailed_operation_mismatch_fallthrough() {
    // 8. Operation mismatch falls through to broader applicable policy.
    PolicyEngine pe;

    ProtectionTarget broad;
    broad.path = "C:/Vault";
    broad.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    broad.opMask = SENTINAL_OP_WRITE | SENTINAL_OP_DELETE;
    broad.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(broad) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget specific;
    specific.path = "C:/Vault/a.txt";
    specific.type = SENTINAL_TARGET_FILE;
    specific.opMask = SENTINAL_OP_READ;
    specific.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(specific) == SENTINAL_STATUS_SUCCESS);

    // READ matches specific FILE -> ALLOW + EXACT_FILE
    auto r1 = pe.evaluateDetailed(PathIdentity("C:/Vault/a.txt"), SENTINAL_OP_READ);
    assert(r1.decision() == SENTINAL_DECISION_ALLOW);
    assert(r1.reason() == ProtectionDecisionReason::EXACT_FILE);

    // WRITE mismatches specific FILE, falls through to recursive -> DENY + RECURSIVE_DIRECTORY
    auto r2 = pe.evaluateDetailed(PathIdentity("C:/Vault/a.txt"), SENTINAL_OP_WRITE);
    assert(r2.decision() == SENTINAL_DECISION_DENY);
    assert(r2.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

static void test_detailed_invalid_request() {
    // 9. Invalid ProtectionRequest returns INVALID_REQUEST.
    PolicyEngine pe;

    ProtectionRequest invalid;
    auto r1 = pe.evaluateDetailed(invalid, SENTINAL_DECISION_ALLOW);
    assert(r1.decision() == SENTINAL_DECISION_ALLOW);
    assert(r1.reason() == ProtectionDecisionReason::INVALID_REQUEST);

    auto r2 = pe.evaluateDetailed(invalid, SENTINAL_DECISION_DENY);
    assert(r2.decision() == SENTINAL_DECISION_DENY);
    assert(r2.reason() == ProtectionDecisionReason::INVALID_REQUEST);
}

static void test_evaluate_matches_evaluateDetailed() {
    // 10. Existing evaluate() returns the same decision as evaluateDetailed().decision().
    PolicyEngine pe = makeSampleEngine();

    struct TestCase { const char* path; SentinalFileOp op; };
    TestCase cases[] = {
        {"C:/Vault/secret.txt", SENTINAL_OP_READ},
        {"C:/Vault/Public", SENTINAL_OP_READ},
        {"C:/Vault/Public/readme.txt", SENTINAL_OP_READ},
        {"C:/Vault/other/data.bin", SENTINAL_OP_WRITE},
        {"C:/Other/file.txt", SENTINAL_OP_READ},
    };

    for (auto& tc : cases) {
        PathIdentity pi(tc.path);
        SentinalDecision simple = pe.evaluate(pi, tc.op, SENTINAL_DECISION_ALLOW);
        ProtectionDecision detailed = pe.evaluateDetailed(pi, tc.op, SENTINAL_DECISION_ALLOW);
        assert(simple == detailed.decision());
    }
}

static void test_insertion_order_detailed_consistency() {
    // 11. Insertion-order independence for detailed evaluation.
    ProtectionTarget t1;
    t1.path = "C:/Sensitive";
    t1.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t1.decision = SENTINAL_DECISION_DENY;

    ProtectionTarget t2;
    t2.path = "C:/Sensitive/Finance";
    t2.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t2.decision = SENTINAL_DECISION_ALLOW;

    PolicyEngine fwd, rev;
    assert(fwd.addTarget(t1) == SENTINAL_STATUS_SUCCESS);
    assert(fwd.addTarget(t2) == SENTINAL_STATUS_SUCCESS);
    assert(rev.addTarget(t2) == SENTINAL_STATUS_SUCCESS);
    assert(rev.addTarget(t1) == SENTINAL_STATUS_SUCCESS);

    const char* paths[] = {
        "C:/Sensitive/readme.txt",
        "C:/Sensitive/Finance/budget.pdf",
    };
    for (auto* p : paths) {
        auto rf = fwd.evaluateDetailed(PathIdentity(p), SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW);
        auto rr = rev.evaluateDetailed(PathIdentity(p), SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW);
        assert(rf.decision() == rr.decision());
        assert(rf.reason() == rr.reason());
    }
}

int main() {
    std::cout << "[ProtectionDecision Tests] Running test suite..." << std::endl;

    // ProtectionDecision model
    test_default_construction();
    test_allow_default_policy();
    test_deny_exact_file();
    test_allow_exact_directory();
    test_deny_direct_child_directory();
    test_deny_recursive_directory();
    test_default_decision_invalid_request();
    test_invalid_sentinal_decision();
    test_invalid_reason();
    test_accessors_preserve_values();

    // PolicyEngine detailed evaluation
    test_detailed_exact_file();
    test_detailed_exact_directory();
    test_detailed_direct_child_directory();
    test_detailed_recursive_directory();
    test_detailed_deepest_recursive();
    test_detailed_no_match_default_policy();
    test_detailed_disabled_target_fallthrough();
    test_detailed_operation_mismatch_fallthrough();
    test_detailed_invalid_request();
    test_evaluate_matches_evaluateDetailed();
    test_insertion_order_detailed_consistency();

    std::cout << "[ProtectionDecision Tests] All tests passed successfully." << std::endl;
    return 0;
}
