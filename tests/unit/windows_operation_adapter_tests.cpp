#include <cassert>
#include <iostream>
#include "service/windows_operation_adapter.h"

using namespace sentinel::service;

static void test_read_mapping() {
    // 1. Read mapping
    SentinalFileOp out = SENTINAL_OP_NONE;
    SentinalStatus status = WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Read, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out == SENTINAL_OP_READ);
}

static void test_write_mapping() {
    // 2. Write mapping
    SentinalFileOp out = SENTINAL_OP_NONE;
    SentinalStatus status = WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Write, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out == SENTINAL_OP_WRITE);
}

static void test_delete_mapping() {
    // 3. Delete mapping
    SentinalFileOp out = SENTINAL_OP_NONE;
    SentinalStatus status = WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Delete, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out == SENTINAL_OP_DELETE);
}

static void test_rename_mapping() {
    // 4. Rename mapping
    SentinalFileOp out = SENTINAL_OP_NONE;
    SentinalStatus status = WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Rename, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out == SENTINAL_OP_RENAME);
}

static void test_execute_mapping() {
    // 5. Execute mapping
    SentinalFileOp out = SENTINAL_OP_NONE;
    SentinalStatus status = WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Execute, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out == SENTINAL_OP_EXECUTE);
}

static void test_unknown_rejection() {
    // 6. Unknown rejection
    SentinalFileOp out = SENTINAL_OP_READ;
    SentinalStatus status = WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Unknown, out);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == SENTINAL_OP_READ);
}

static void test_invalid_unrecognized_enum_rejection() {
    // 7. Invalid/unrecognized enum value rejection
    SentinalFileOp out = SENTINAL_OP_WRITE;

    auto badVal1 = static_cast<WindowsProtectionOperation>(99);
    assert(WindowsOperationAdapter::toFileOperation(badVal1, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == SENTINAL_OP_WRITE);

    auto badVal2 = static_cast<WindowsProtectionOperation>(-1);
    assert(WindowsOperationAdapter::toFileOperation(badVal2, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == SENTINAL_OP_WRITE);
}

static void test_existing_output_unchanged_on_failure() {
    // 8. Existing output remains unchanged on failure
    SentinalFileOp preserved = SENTINAL_OP_DELETE;

    SentinalFileOp out = preserved;
    assert(WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Unknown, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == preserved);

    assert(WindowsOperationAdapter::toFileOperation(static_cast<WindowsProtectionOperation>(1234), out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == preserved);
}

static void test_deterministic_mapping() {
    // 9. Deterministic mapping
    const WindowsProtectionOperation ops[] = {
        WindowsProtectionOperation::Read,
        WindowsProtectionOperation::Write,
        WindowsProtectionOperation::Delete,
        WindowsProtectionOperation::Rename,
        WindowsProtectionOperation::Execute
    };

    for (auto op : ops) {
        SentinalFileOp out1 = SENTINAL_OP_NONE;
        SentinalFileOp out2 = SENTINAL_OP_NONE;
        SentinalStatus s1 = WindowsOperationAdapter::toFileOperation(op, out1);
        SentinalStatus s2 = WindowsOperationAdapter::toFileOperation(op, out2);
        assert(s1 == s2);
        assert(s1 == SENTINAL_STATUS_SUCCESS);
        assert(out1 == out2);
    }
}

static void test_every_valid_mapping_produces_exactly_one_operation_bit() {
    // 10. Every valid mapping produces exactly one operation bit
    const WindowsProtectionOperation ops[] = {
        WindowsProtectionOperation::Read,
        WindowsProtectionOperation::Write,
        WindowsProtectionOperation::Delete,
        WindowsProtectionOperation::Rename,
        WindowsProtectionOperation::Execute
    };

    for (auto op : ops) {
        SentinalFileOp out = SENTINAL_OP_NONE;
        SentinalStatus status = WindowsOperationAdapter::toFileOperation(op, out);
        assert(status == SENTINAL_STATUS_SUCCESS);
        auto raw = static_cast<uint32_t>(out);
        assert(raw != 0);
        // Exactly one bit set: (raw & (raw - 1)) == 0
        assert((raw & (raw - 1)) == 0);
    }
}

static void test_no_successful_mapping_produces_sentinal_op_none() {
    // 11. No successful mapping produces SENTINAL_OP_NONE
    const WindowsProtectionOperation ops[] = {
        WindowsProtectionOperation::Read,
        WindowsProtectionOperation::Write,
        WindowsProtectionOperation::Delete,
        WindowsProtectionOperation::Rename,
        WindowsProtectionOperation::Execute
    };

    for (auto op : ops) {
        SentinalFileOp out = SENTINAL_OP_NONE;
        SentinalStatus status = WindowsOperationAdapter::toFileOperation(op, out);
        assert(status == SENTINAL_STATUS_SUCCESS);
        assert(out != SENTINAL_OP_NONE);
    }
}

static void test_all_five_valid_operations_return_success() {
    // 12. All five valid operations return SENTINAL_STATUS_SUCCESS
    SentinalFileOp out = SENTINAL_OP_NONE;
    assert(WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Read, out) == SENTINAL_STATUS_SUCCESS);
    assert(WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Write, out) == SENTINAL_STATUS_SUCCESS);
    assert(WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Delete, out) == SENTINAL_STATUS_SUCCESS);
    assert(WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Rename, out) == SENTINAL_STATUS_SUCCESS);
    assert(WindowsOperationAdapter::toFileOperation(WindowsProtectionOperation::Execute, out) == SENTINAL_STATUS_SUCCESS);
}

int main() {
    std::cout << "[WindowsOperationAdapter Tests] Running test suite..." << std::endl;

    test_read_mapping();
    test_write_mapping();
    test_delete_mapping();
    test_rename_mapping();
    test_execute_mapping();
    test_unknown_rejection();
    test_invalid_unrecognized_enum_rejection();
    test_existing_output_unchanged_on_failure();
    test_deterministic_mapping();
    test_every_valid_mapping_produces_exactly_one_operation_bit();
    test_no_successful_mapping_produces_sentinal_op_none();
    test_all_five_valid_operations_return_success();

    std::cout << "[WindowsOperationAdapter Tests] All tests passed successfully." << std::endl;
    return 0;
}
