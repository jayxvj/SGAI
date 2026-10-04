#include <cassert>
#include <iostream>
#include "service/protection_operation_adapter.h"
#include "service/protection_operation.h"
#include "service/protection_request.h"

using namespace sentinel::service;

static void test_valid_operation_converts_successfully() {
    // 1. Valid operation converts successfully.
    PathIdentity path("C:/Folder/test.txt");
    ProtectionOperation op(path, SENTINAL_OP_READ);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_SUCCESS);
}

static void test_path_identity_preserved_exactly() {
    // 2. PathIdentity is preserved exactly.
    PathIdentity path("C:/Directory/sub/data.bin");
    ProtectionOperation op(path, SENTINAL_OP_WRITE);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(req.path() == path);
    assert(req.path().original() == path.original());
    assert(req.path().normalized() == path.normalized());
    assert(req.path().getType() == path.getType());
}

static void test_operation_preserved_exactly() {
    // 3. SentinalFileOp is preserved exactly.
    PathIdentity path("C:/Data/file.txt");
    auto combinedOp = static_cast<SentinalFileOp>(SENTINAL_OP_READ | SENTINAL_OP_WRITE);
    ProtectionOperation op(path, combinedOp);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(req.operation() == combinedOp);
}

static void test_context_preserved_exactly() {
    // 4. ProtectionEvaluationContext is preserved exactly.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionOperation op(path, SENTINAL_OP_READ, ctx);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(req.context().source() == ctx.source());
    assert(req.context().isValid() == ctx.isValid());
}

static void test_user_mode_context_preserved() {
    // 5. USER_MODE context is preserved.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionOperation op(path, SENTINAL_OP_READ, ctx);
    ProtectionRequest req;

    assert(ProtectionOperationAdapter::toRequest(op, req) == SENTINAL_STATUS_SUCCESS);
    assert(req.context().source() == ProtectionRequestSource::USER_MODE);
}

static void test_kernel_context_preserved() {
    // 6. KERNEL context is preserved.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionOperation op(path, SENTINAL_OP_READ, ctx);
    ProtectionRequest req;

    assert(ProtectionOperationAdapter::toRequest(op, req) == SENTINAL_STATUS_SUCCESS);
    assert(req.context().source() == ProtectionRequestSource::KERNEL);
}

static void test_unknown_context_preserved() {
    // 7. UNKNOWN context is preserved.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::UNKNOWN);
    ProtectionOperation op(path, SENTINAL_OP_READ, ctx);
    ProtectionRequest req;

    assert(ProtectionOperationAdapter::toRequest(op, req) == SENTINAL_STATUS_SUCCESS);
    assert(req.context().source() == ProtectionRequestSource::UNKNOWN);
}

static void test_invalid_default_operation_returns_invalid_parameter() {
    // 8. Invalid default ProtectionOperation returns INVALID_PARAMETER.
    ProtectionOperation op;
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_path_operation_returns_invalid_parameter() {
    // 9. Invalid path operation returns INVALID_PARAMETER.
    PathIdentity badPath("");
    ProtectionOperation op(badPath, SENTINAL_OP_READ);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_none_operation_returns_invalid_parameter() {
    // 10. NONE operation returns INVALID_PARAMETER.
    PathIdentity path("C:/Data/file.txt");
    ProtectionOperation op(path, SENTINAL_OP_NONE);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_operation_bits_return_invalid_parameter() {
    // 11. Invalid operation bits return INVALID_PARAMETER.
    PathIdentity path("C:/Data/file.txt");
    auto badOp = static_cast<SentinalFileOp>(0x80);
    ProtectionOperation op(path, badOp);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_context_returns_invalid_parameter() {
    // 12. Invalid context returns INVALID_PARAMETER.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext badCtx(static_cast<ProtectionRequestSource>(99));
    ProtectionOperation op(path, SENTINAL_OP_READ, badCtx);
    ProtectionRequest req;

    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_input_does_not_modify_existing_out_request() {
    // 13. Invalid input does not modify an existing outRequest.
    PathIdentity validPath("C:/Original/valid.txt");
    ProtectionRequest req(validPath, SENTINAL_OP_DELETE, ProtectionEvaluationContext(ProtectionRequestSource::KERNEL));

    ProtectionOperation invalidOp; // default invalid
    SentinalStatus status = ProtectionOperationAdapter::toRequest(invalidOp, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);

    // Verify req was untouched
    assert(req.isValid());
    assert(req.path() == validPath);
    assert(req.operation() == SENTINAL_OP_DELETE);
    assert(req.context().source() == ProtectionRequestSource::KERNEL);

    // Also test with invalid path
    ProtectionOperation invalidPathOp(PathIdentity(""), SENTINAL_OP_READ);
    status = ProtectionOperationAdapter::toRequest(invalidPathOp, req);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(req.path() == validPath);
    assert(req.operation() == SENTINAL_OP_DELETE);
    assert(req.context().source() == ProtectionRequestSource::KERNEL);
}

static void test_conversion_is_deterministic() {
    // 14. Conversion is deterministic.
    PathIdentity path("C:/Data/file.txt");
    ProtectionOperation op(path, SENTINAL_OP_READ, ProtectionEvaluationContext(ProtectionRequestSource::USER_MODE));

    ProtectionRequest req1;
    ProtectionRequest req2;

    SentinalStatus s1 = ProtectionOperationAdapter::toRequest(op, req1);
    SentinalStatus s2 = ProtectionOperationAdapter::toRequest(op, req2);

    assert(s1 == s2);
    assert(s1 == SENTINAL_STATUS_SUCCESS);
    assert(req1.path() == req2.path());
    assert(req1.operation() == req2.operation());
    assert(req1.context().source() == req2.context().source());
    assert(req1.isValid() == req2.isValid());
}

static void test_successful_conversion_produces_valid_protection_request() {
    // 15. Successful conversion produces a valid ProtectionRequest.
    PathIdentity path("C:/Data/valid_file.txt");
    ProtectionOperation op(path, SENTINAL_OP_READ);
    ProtectionRequest req;

    assert(!req.isValid());
    SentinalStatus status = ProtectionOperationAdapter::toRequest(op, req);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(req.isValid());
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
}

int main() {
    std::cout << "[ProtectionOperationAdapter Tests] Running test suite..." << std::endl;

    test_valid_operation_converts_successfully();
    test_path_identity_preserved_exactly();
    test_operation_preserved_exactly();
    test_context_preserved_exactly();
    test_user_mode_context_preserved();
    test_kernel_context_preserved();
    test_unknown_context_preserved();
    test_invalid_default_operation_returns_invalid_parameter();
    test_invalid_path_operation_returns_invalid_parameter();
    test_none_operation_returns_invalid_parameter();
    test_invalid_operation_bits_return_invalid_parameter();
    test_invalid_context_returns_invalid_parameter();
    test_invalid_input_does_not_modify_existing_out_request();
    test_conversion_is_deterministic();
    test_successful_conversion_produces_valid_protection_request();

    std::cout << "[ProtectionOperationAdapter Tests] All tests passed successfully." << std::endl;
    return 0;
}
