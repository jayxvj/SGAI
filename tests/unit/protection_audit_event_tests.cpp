#include <cassert>
#include <iostream>
#include "service/protection_audit_event.h"

using namespace sentinel::service;

static void test_default_construction() {
    ProtectionAuditEvent event;
    assert(!event.path().isValid());
    assert(event.operation() == SENTINAL_OP_NONE);
    assert(event.context().source() == ProtectionRequestSource::UNKNOWN);
    assert(event.result().isValid());
}

static void test_default_validation_failure() {
    ProtectionAuditEvent event;
    assert(!event.isValid());
    assert(event.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_valid_read_event() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_READ, ctx, res);
    assert(event.isValid());
    assert(event.validate() == SENTINAL_STATUS_SUCCESS);
    assert(event.operation() == SENTINAL_OP_READ);
}

static void test_valid_write_event() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::DENY
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_WRITE, ctx, res);
    assert(event.isValid());
    assert(event.validate() == SENTINAL_STATUS_SUCCESS);
    assert(event.operation() == SENTINAL_OP_WRITE);
}

static void test_valid_delete_event() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::AUDIT
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_DELETE, ctx, res);
    assert(event.isValid());
    assert(event.validate() == SENTINAL_STATUS_SUCCESS);
    assert(event.operation() == SENTINAL_OP_DELETE);
}

static void test_valid_rename_event() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::DENY
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_RENAME, ctx, res);
    assert(event.isValid());
    assert(event.validate() == SENTINAL_STATUS_SUCCESS);
    assert(event.operation() == SENTINAL_OP_RENAME);
}

static void test_valid_execute_event() {
    PathIdentity path("C:/Data/app.exe");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_EXECUTE, ctx, res);
    assert(event.isValid());
    assert(event.validate() == SENTINAL_STATUS_SUCCESS);
    assert(event.operation() == SENTINAL_OP_EXECUTE);
}

static void test_invalid_path() {
    PathIdentity invalidPath("");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event(invalidPath, SENTINAL_OP_READ, ctx, res);
    assert(!event.isValid());
    assert(event.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_operation() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event1(
        path,
        static_cast<SentinalFileOp>(999),
        ctx,
        res
    );
    assert(!event1.isValid());
    assert(event1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    ProtectionAuditEvent event2(
        path,
        static_cast<SentinalFileOp>(0x80000000u),
        ctx,
        res
    );
    assert(!event2.isValid());
    assert(event2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_none_operation_rejected() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_NONE, ctx, res);
    assert(!event.isValid());
    assert(event.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_combined_operation_mask_rejected() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    auto combined = static_cast<SentinalFileOp>(
        static_cast<uint32_t>(SENTINAL_OP_READ) | static_cast<uint32_t>(SENTINAL_OP_WRITE)
    );
    ProtectionAuditEvent event(path, combined, ctx, res);
    assert(!event.isValid());
    assert(event.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_context() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext invalidCtx(static_cast<ProtectionRequestSource>(999));
    assert(!invalidCtx.isValid());
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_READ, invalidCtx, res);
    assert(!event.isValid());
    assert(event.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_execution_result() {
    PathIdentity path("C:/Data/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult invalidRes(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_READ, ctx, invalidRes);
    assert(!event.isValid());
    assert(event.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_accessor_preservation() {
    PathIdentity path("C:/Data/secure/document.docx");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::AUDIT
    );

    ProtectionAuditEvent event(path, SENTINAL_OP_WRITE, ctx, res);
    assert(event.path() == path);
    assert(event.operation() == SENTINAL_OP_WRITE);
    assert(event.context().source() == ProtectionRequestSource::KERNEL);
    assert(event.result().status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(event.result().action() == ProtectionEnforcementAction::AUDIT);
}

static void test_deterministic_validation() {
    PathIdentity path("C:/Data/deterministic.bin");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    ProtectionAuditEvent validEvent(path, SENTINAL_OP_DELETE, ctx, res);
    assert(validEvent.validate() == SENTINAL_STATUS_SUCCESS);
    assert(validEvent.validate() == SENTINAL_STATUS_SUCCESS);
    assert(validEvent.isValid());
    assert(validEvent.isValid());

    ProtectionAuditEvent invalidEvent(path, SENTINAL_OP_NONE, ctx, res);
    assert(invalidEvent.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(invalidEvent.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!invalidEvent.isValid());
    assert(!invalidEvent.isValid());
}

static void test_no_mutation_during_validation() {
    PathIdentity path("C:/Data/const_test.dat");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    ProtectionExecutionResult res(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::DENY
    );

    const ProtectionAuditEvent event(path, SENTINAL_OP_EXECUTE, ctx, res);
    assert(event.path() == path);
    assert(event.operation() == SENTINAL_OP_EXECUTE);
    assert(event.context().source() == ProtectionRequestSource::USER_MODE);
    assert(event.result().status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(event.result().action() == ProtectionEnforcementAction::DENY);

    SentinalStatus s = event.validate();
    assert(s == SENTINAL_STATUS_SUCCESS);
    assert(event.path() == path);
    assert(event.operation() == SENTINAL_OP_EXECUTE);

    bool v = event.isValid();
    assert(v);
    assert(event.path() == path);
    assert(event.operation() == SENTINAL_OP_EXECUTE);
}

int main() {
    std::cout << "[ProtectionAuditEvent Tests] Running test suite..." << std::endl;

    test_default_construction();
    test_default_validation_failure();
    test_valid_read_event();
    test_valid_write_event();
    test_valid_delete_event();
    test_valid_rename_event();
    test_valid_execute_event();
    test_invalid_path();
    test_invalid_operation();
    test_none_operation_rejected();
    test_combined_operation_mask_rejected();
    test_invalid_context();
    test_invalid_execution_result();
    test_accessor_preservation();
    test_deterministic_validation();
    test_no_mutation_during_validation();

    std::cout << "[ProtectionAuditEvent Tests] All 16 tests passed successfully." << std::endl;
    return 0;
}
