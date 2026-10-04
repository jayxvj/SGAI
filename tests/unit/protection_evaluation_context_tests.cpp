#include <cassert>
#include <iostream>
#include <climits>
#include "service/protection_evaluation_context.h"
#include "service/protection_request.h"
#include "service/policy_engine.h"
#include "service/target.h"

using namespace sentinel::service;

// ---------------------------------------------------------------------------
// ProtectionEvaluationContext model tests
// ---------------------------------------------------------------------------

static void test_default_context() {
    // 1. Default context is valid and source == UNKNOWN.
    ProtectionEvaluationContext ctx;
    assert(ctx.source() == ProtectionRequestSource::UNKNOWN);
    assert(ctx.isValid());
    assert(ctx.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_user_mode_context() {
    // 2. USER_MODE context is valid.
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    assert(ctx.source() == ProtectionRequestSource::USER_MODE);
    assert(ctx.isValid());
    assert(ctx.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_kernel_context() {
    // 3. KERNEL context is valid.
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    assert(ctx.source() == ProtectionRequestSource::KERNEL);
    assert(ctx.isValid());
    assert(ctx.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_invalid_enum_cast() {
    // 4. Invalid enum cast is rejected.
    auto badSource = static_cast<ProtectionRequestSource>(999);
    ProtectionEvaluationContext ctx(badSource);
    assert(!ctx.isValid());
    assert(ctx.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_accessor_preserves_source() {
    // 5. Accessor preserves source.
    ProtectionEvaluationContext u(ProtectionRequestSource::USER_MODE);
    assert(u.source() == ProtectionRequestSource::USER_MODE);

    ProtectionEvaluationContext k(ProtectionRequestSource::KERNEL);
    assert(k.source() == ProtectionRequestSource::KERNEL);
}

// ---------------------------------------------------------------------------
// ProtectionRequest + context integration tests
// ---------------------------------------------------------------------------

static void test_two_arg_constructor_has_unknown_source() {
    // 6. Existing two-argument constructor produces a valid request with UNKNOWN source.
    PathIdentity path("C:/Data/file.txt");
    ProtectionRequest req(path, SENTINAL_OP_READ);
    assert(req.isValid());
    assert(req.context().source() == ProtectionRequestSource::UNKNOWN);
    assert(req.context().isValid());
}

static void test_three_arg_constructor_preserves_context() {
    // 7. Three-argument constructor preserves the supplied context.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionRequest req(path, SENTINAL_OP_READ, ctx);
    assert(req.isValid());
    assert(req.context().source() == ProtectionRequestSource::USER_MODE);
}

static void test_invalid_context_invalidates_request() {
    // 8. Invalid context makes ProtectionRequest invalid.
    PathIdentity path("C:/Data/file.txt");
    auto badCtx = ProtectionEvaluationContext(static_cast<ProtectionRequestSource>(999));
    ProtectionRequest req(path, SENTINAL_OP_READ, badCtx);
    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_user_mode_request_validates() {
    // 9. USER_MODE request validates.
    PathIdentity path("C:/Secure/report.pdf");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionRequest req(path, SENTINAL_OP_READ, ctx);
    assert(req.isValid());
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_kernel_request_validates() {
    // 10. KERNEL request validates.
    PathIdentity path("C:/Secure/report.pdf");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionRequest req(path, SENTINAL_OP_WRITE, ctx);
    assert(req.isValid());
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_path_validation_unchanged() {
    // 11. Existing path validation behavior remains unchanged.
    PathIdentity invalid("");
    ProtectionRequest req(invalid, SENTINAL_OP_READ);
    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_operation_validation_unchanged() {
    // 12. Existing operation validation behavior remains unchanged.
    PathIdentity path("C:/Data/file.txt");

    ProtectionRequest noneOp(path, SENTINAL_OP_NONE);
    assert(!noneOp.isValid());

    auto badOp = static_cast<SentinalFileOp>(0x80);
    ProtectionRequest badOpReq(path, badOp);
    assert(!badOpReq.isValid());
}

// ---------------------------------------------------------------------------
// PolicyEngine regression tests
// ---------------------------------------------------------------------------

static PolicyEngine makeSampleEngine() {
    PolicyEngine pe;

    ProtectionTarget t;
    t.path = "C:/Vault";
    t.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(t) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget t2;
    t2.path = "C:/Vault/secret.txt";
    t2.type = SENTINAL_TARGET_FILE;
    t2.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(t2) == SENTINAL_STATUS_SUCCESS);

    return pe;
}

static void test_user_mode_kernel_same_decision() {
    // 1. USER_MODE and KERNEL with identical path/op produce identical ProtectionDecision.
    PolicyEngine pe = makeSampleEngine();
    PathIdentity path("C:/Vault/data.bin");

    ProtectionRequest umReq(path, SENTINAL_OP_READ, ProtectionEvaluationContext(ProtectionRequestSource::USER_MODE));
    ProtectionRequest kReq(path, SENTINAL_OP_READ, ProtectionEvaluationContext(ProtectionRequestSource::KERNEL));

    ProtectionDecision umResult = pe.evaluateDetailed(umReq);
    ProtectionDecision kResult  = pe.evaluateDetailed(kReq);

    // 1 + 2: same decision and same reason
    assert(umResult.decision() == kResult.decision());
    assert(umResult.reason()   == kResult.reason());
    assert(umResult.decision() == SENTINAL_DECISION_DENY);
}

static void test_no_context_request_unchanged() {
    // 3. Existing requests without explicit context continue to behave exactly as before.
    PolicyEngine pe = makeSampleEngine();
    PathIdentity path("C:/Vault/data.bin");

    ProtectionRequest req(path, SENTINAL_OP_READ);   // two-arg, UNKNOWN source
    assert(pe.evaluate(req) == SENTINAL_DECISION_DENY);
    assert(pe.evaluateDetailed(req).decision() == SENTINAL_DECISION_DENY);
    assert(pe.evaluateDetailed(req).reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

static void test_insertion_order_independence_regression() {
    // 4. Phase 1.3 insertion-order independence remains unchanged.
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
        "C:/Sensitive/misc.txt",
        "C:/Sensitive/Finance/report.xlsx",
    };
    for (auto* p : paths) {
        ProtectionRequest req(PathIdentity(p), SENTINAL_OP_READ,
                              ProtectionEvaluationContext(ProtectionRequestSource::USER_MODE));
        assert(fwd.evaluate(req) == rev.evaluate(req));
        assert(fwd.evaluateDetailed(req).reason() == rev.evaluateDetailed(req).reason());
    }
}

static void test_phase15_reason_mapping_unchanged() {
    // 5. Phase 1.5 reason mapping remains unchanged.
    PolicyEngine pe = makeSampleEngine();

    // Exact FILE -> EXACT_FILE
    ProtectionRequest fileReq(PathIdentity("C:/Vault/secret.txt"), SENTINAL_OP_READ,
                              ProtectionEvaluationContext(ProtectionRequestSource::KERNEL));
    auto fd = pe.evaluateDetailed(fileReq);
    assert(fd.reason() == ProtectionDecisionReason::EXACT_FILE);

    // Recursive -> RECURSIVE_DIRECTORY
    ProtectionRequest recReq(PathIdentity("C:/Vault/other.bin"), SENTINAL_OP_READ,
                             ProtectionEvaluationContext(ProtectionRequestSource::USER_MODE));
    auto rd = pe.evaluateDetailed(recReq);
    assert(rd.reason() == ProtectionDecisionReason::RECURSIVE_DIRECTORY);
}

int main() {
    std::cout << "[ProtectionEvaluationContext Tests] Running test suite..." << std::endl;

    // Context model
    test_default_context();
    test_user_mode_context();
    test_kernel_context();
    test_invalid_enum_cast();
    test_accessor_preserves_source();

    // ProtectionRequest integration
    test_two_arg_constructor_has_unknown_source();
    test_three_arg_constructor_preserves_context();
    test_invalid_context_invalidates_request();
    test_user_mode_request_validates();
    test_kernel_request_validates();
    test_path_validation_unchanged();
    test_operation_validation_unchanged();

    // PolicyEngine regression
    test_user_mode_kernel_same_decision();
    test_no_context_request_unchanged();
    test_insertion_order_independence_regression();
    test_phase15_reason_mapping_unchanged();

    std::cout << "[ProtectionEvaluationContext Tests] All tests passed successfully." << std::endl;
    return 0;
}
