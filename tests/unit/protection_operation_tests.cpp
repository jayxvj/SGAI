#include <cassert>
#include <iostream>
#include "service/protection_operation.h"

using namespace sentinel::service;

static void test_default_construction_is_invalid() {
    // 1. Default construction is invalid.
    ProtectionOperation op;
    assert(!op.isValid());
    assert(op.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!op.path().isValid());
    assert(op.operation() == SENTINAL_OP_NONE);
}

static void test_valid_two_argument_construction() {
    // 2. Valid two-argument construction.
    PathIdentity path("C:/Data/file.txt");
    ProtectionOperation op(path, SENTINAL_OP_READ);
    assert(op.isValid());
    assert(op.validate() == SENTINAL_STATUS_SUCCESS);
    assert(op.path() == path);
    assert(op.operation() == SENTINAL_OP_READ);
}

static void test_valid_three_argument_unknown_context() {
    // 3. Valid three-argument construction with UNKNOWN context.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::UNKNOWN);
    ProtectionOperation op(path, SENTINAL_OP_WRITE, ctx);
    assert(op.isValid());
    assert(op.validate() == SENTINAL_STATUS_SUCCESS);
    assert(op.context().source() == ProtectionRequestSource::UNKNOWN);
}

static void test_valid_user_mode_context() {
    // 4. Valid USER_MODE context.
    PathIdentity path("C:/Secure/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionOperation op(path, SENTINAL_OP_READ, ctx);
    assert(op.isValid());
    assert(op.context().source() == ProtectionRequestSource::USER_MODE);
}

static void test_valid_kernel_context() {
    // 5. Valid KERNEL context.
    PathIdentity path("C:/Secure/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionOperation op(path, SENTINAL_OP_READ, ctx);
    assert(op.isValid());
    assert(op.context().source() == ProtectionRequestSource::KERNEL);
}

static void test_invalid_path_makes_operation_invalid() {
    // 6. Invalid PathIdentity makes operation invalid.
    PathIdentity invalidPath("");
    assert(!invalidPath.isValid());
    ProtectionOperation op(invalidPath, SENTINAL_OP_READ);
    assert(!op.isValid());
    assert(op.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_op_none_makes_operation_invalid() {
    // 7. SENTINAL_OP_NONE makes operation invalid.
    PathIdentity path("C:/Data/file.txt");
    ProtectionOperation op(path, SENTINAL_OP_NONE);
    assert(!op.isValid());
    assert(op.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_unrecognized_bits_make_operation_invalid() {
    // 8. Unrecognized operation bits make operation invalid.
    PathIdentity path("C:/Data/file.txt");

    auto invalidOnly = static_cast<SentinalFileOp>(0x80);
    ProtectionOperation op1(path, invalidOnly);
    assert(!op1.isValid());
    assert(op1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    auto mixedInvalid = static_cast<SentinalFileOp>(SENTINAL_OP_READ | 0x100);
    ProtectionOperation op2(path, mixedInvalid);
    assert(!op2.isValid());
    assert(op2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_context_makes_operation_invalid() {
    // 9. Invalid context makes operation invalid.
    // ProtectionEvaluationContext with an out-of-range source is invalid.
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext badCtx(static_cast<ProtectionRequestSource>(99));
    assert(!badCtx.isValid());
    ProtectionOperation op(path, SENTINAL_OP_READ, badCtx);
    assert(!op.isValid());
    assert(op.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_accessors_preserve_values() {
    // 10. Accessors preserve path, operation, and context.
    PathIdentity path("C:/Folder/document.pdf");
    SentinalFileOp op = SENTINAL_OP_DELETE;
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionOperation pop(path, op, ctx);

    assert(pop.path() == path);
    assert(pop.path().normalized() == "C:/Folder/document.pdf");
    assert(pop.operation() == op);
    assert(pop.context().source() == ProtectionRequestSource::KERNEL);
}

static void test_two_arg_constructor_defaults_context_to_unknown() {
    // 11. Two-argument constructor defaults context to UNKNOWN.
    PathIdentity path("C:/Data/file.txt");
    ProtectionOperation op(path, SENTINAL_OP_READ);
    assert(op.context().source() == ProtectionRequestSource::UNKNOWN);
}

static void test_validation_is_deterministic() {
    // 12. Validation is deterministic and does not mutate the object.
    PathIdentity path("C:/Data/file.txt");
    ProtectionOperation op(path, SENTINAL_OP_WRITE);

    SentinalStatus s1 = op.validate();
    bool v1 = op.isValid();
    SentinalStatus s2 = op.validate();
    bool v2 = op.isValid();

    assert(s1 == s2);
    assert(v1 == v2);
    assert(s1 == SENTINAL_STATUS_SUCCESS);
    // Path and operation unchanged after validation.
    assert(op.path() == path);
    assert(op.operation() == SENTINAL_OP_WRITE);
}

int main() {
    std::cout << "[ProtectionOperation Tests] Running test suite..." << std::endl;

    test_default_construction_is_invalid();
    test_valid_two_argument_construction();
    test_valid_three_argument_unknown_context();
    test_valid_user_mode_context();
    test_valid_kernel_context();
    test_invalid_path_makes_operation_invalid();
    test_op_none_makes_operation_invalid();
    test_unrecognized_bits_make_operation_invalid();
    test_invalid_context_makes_operation_invalid();
    test_accessors_preserve_values();
    test_two_arg_constructor_defaults_context_to_unknown();
    test_validation_is_deterministic();

    std::cout << "[ProtectionOperation Tests] All tests passed successfully." << std::endl;
    return 0;
}
