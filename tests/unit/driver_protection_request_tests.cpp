#include <cassert>
#include <iostream>
#include "service/driver_protection_request.h"

using namespace sentinel::service;

static void test_default_invalid() {
    DriverProtectionRequest req;
    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(req.requestId() == 0);
    assert(!req.path().isValid());
    assert(req.operation() == SENTINAL_OP_NONE);
}

static void test_valid_request() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(101, path, SENTINAL_OP_READ, ctx);

    assert(req.isValid());
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
    assert(req.requestId() == 101);
    assert(req.path().normalized() == "C:/Data/file.txt");
    assert(req.operation() == SENTINAL_OP_READ);
    assert(req.context().source() == ProtectionRequestSource::USER_MODE);
}

static void test_request_id_zero_rejected() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(0, path, SENTINAL_OP_READ, ctx);

    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_path_rejected() {
    PathIdentity invalidPath;
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(101, invalidPath, SENTINAL_OP_READ, ctx);

    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_none_operation_rejected() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(101, path, SENTINAL_OP_NONE, ctx);

    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_operation_bits_rejected() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);

    // Compound mask (multiple operations)
    auto compoundOp = static_cast<SentinalFileOp>(
        static_cast<uint32_t>(SENTINAL_OP_READ) | static_cast<uint32_t>(SENTINAL_OP_WRITE)
    );
    DriverProtectionRequest req1(101, path, compoundOp, ctx);
    assert(!req1.isValid());
    assert(req1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Out of range operation
    auto badOp = static_cast<SentinalFileOp>(0x80);
    DriverProtectionRequest req2(101, path, badOp, ctx);
    assert(!req2.isValid());
    assert(req2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_context_rejected() {
    PathIdentity path("C:/Data/file.txt");
    auto badSource = static_cast<ProtectionRequestSource>(99);
    ProtectionEvaluationContext badCtx(badSource);
    DriverProtectionRequest req(101, path, SENTINAL_OP_READ, badCtx);

    assert(!req.isValid());
    assert(req.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_deterministic_validation() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(101, path, SENTINAL_OP_READ, ctx);

    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
    assert(req.validate() == SENTINAL_STATUS_SUCCESS);
    assert(req.isValid());
    assert(req.isValid());

    DriverProtectionRequest badReq(0, path, SENTINAL_OP_READ, ctx);
    assert(badReq.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(badReq.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!badReq.isValid());
    assert(!badReq.isValid());
}

static void test_getters_preserve_values() {
    PathIdentity path("C:/Data/test.dat");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    DriverProtectionRequest req(0xABCDEF0123456789ULL, path, SENTINAL_OP_DELETE, ctx);

    assert(req.requestId() == 0xABCDEF0123456789ULL);
    assert(req.path().normalized() == "C:/Data/test.dat");
    assert(req.operation() == SENTINAL_OP_DELETE);
    assert(req.context().source() == ProtectionRequestSource::KERNEL);
}

static void test_all_single_supported_operations() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);

    const SentinalFileOp ops[] = {
        SENTINAL_OP_READ,
        SENTINAL_OP_WRITE,
        SENTINAL_OP_DELETE,
        SENTINAL_OP_RENAME,
        SENTINAL_OP_EXECUTE
    };

    for (auto op : ops) {
        DriverProtectionRequest req(200, path, op, ctx);
        assert(req.isValid());
        assert(req.validate() == SENTINAL_STATUS_SUCCESS);
        assert(req.operation() == op);
    }
}

int main() {
    std::cout << "[DriverProtectionRequest Tests] Running..." << std::endl;

    test_default_invalid();
    test_valid_request();
    test_request_id_zero_rejected();
    test_invalid_path_rejected();
    test_none_operation_rejected();
    test_invalid_operation_bits_rejected();
    test_invalid_context_rejected();
    test_deterministic_validation();
    test_getters_preserve_values();
    test_all_single_supported_operations();

    std::cout << "[DriverProtectionRequest Tests] All tests passed." << std::endl;
    return 0;
}
