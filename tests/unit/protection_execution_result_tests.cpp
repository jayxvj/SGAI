#include <cassert>
#include <iostream>
#include "service/protection_execution_result.h"

using namespace sentinel::service;

static void test_default_construction() {
    ProtectionExecutionResult result;
    assert(result.status() == ProtectionExecutionResultStatus::REJECTED);
    assert(result.action() == ProtectionEnforcementAction::DENY);
}

static void test_default_result_validation() {
    ProtectionExecutionResult result;
    assert(result.isValid());
    assert(result.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_processed_allow() {
    ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );
    assert(result.isValid());
    assert(result.validate() == SENTINAL_STATUS_SUCCESS);
    assert(result.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(result.action() == ProtectionEnforcementAction::ALLOW);
}

static void test_processed_deny() {
    ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::DENY
    );
    assert(result.isValid());
    assert(result.validate() == SENTINAL_STATUS_SUCCESS);
    assert(result.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(result.action() == ProtectionEnforcementAction::DENY);
}

static void test_processed_audit() {
    ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::AUDIT
    );
    assert(result.isValid());
    assert(result.validate() == SENTINAL_STATUS_SUCCESS);
    assert(result.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(result.action() == ProtectionEnforcementAction::AUDIT);
}

static void test_rejected_deny() {
    ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::DENY
    );
    assert(result.isValid());
    assert(result.validate() == SENTINAL_STATUS_SUCCESS);
    assert(result.status() == ProtectionExecutionResultStatus::REJECTED);
    assert(result.action() == ProtectionEnforcementAction::DENY);
}

static void test_rejected_allow_rejected() {
    ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::ALLOW
    );
    assert(!result.isValid());
    assert(result.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_rejected_audit_rejected() {
    ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::AUDIT
    );
    assert(!result.isValid());
    assert(result.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_status_rejected() {
    ProtectionExecutionResult result1(
        static_cast<ProtectionExecutionResultStatus>(999),
        ProtectionEnforcementAction::DENY
    );
    assert(!result1.isValid());
    assert(result1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    ProtectionExecutionResult result2(
        static_cast<ProtectionExecutionResultStatus>(-1),
        ProtectionEnforcementAction::DENY
    );
    assert(!result2.isValid());
    assert(result2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_action_rejected() {
    ProtectionExecutionResult result1(
        ProtectionExecutionResultStatus::PROCESSED,
        static_cast<ProtectionEnforcementAction>(999)
    );
    assert(!result1.isValid());
    assert(result1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    ProtectionExecutionResult result2(
        ProtectionExecutionResultStatus::REJECTED,
        static_cast<ProtectionEnforcementAction>(999)
    );
    assert(!result2.isValid());
    assert(result2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_accessors() {
    ProtectionExecutionResult res1(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::AUDIT
    );
    assert(res1.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(res1.action() == ProtectionEnforcementAction::AUDIT);

    ProtectionExecutionResult res2(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::DENY
    );
    assert(res2.status() == ProtectionExecutionResultStatus::REJECTED);
    assert(res2.action() == ProtectionEnforcementAction::DENY);
}

static void test_deterministic_validation() {
    ProtectionExecutionResult validRes(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );
    assert(validRes.validate() == SENTINAL_STATUS_SUCCESS);
    assert(validRes.validate() == SENTINAL_STATUS_SUCCESS);
    assert(validRes.isValid());
    assert(validRes.isValid());

    ProtectionExecutionResult invalidRes(
        ProtectionExecutionResultStatus::REJECTED,
        ProtectionEnforcementAction::ALLOW
    );
    assert(invalidRes.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(invalidRes.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!invalidRes.isValid());
    assert(!invalidRes.isValid());
}

static void test_no_mutation_during_validation() {
    const ProtectionExecutionResult result(
        ProtectionExecutionResultStatus::PROCESSED,
        ProtectionEnforcementAction::ALLOW
    );

    assert(result.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(result.action() == ProtectionEnforcementAction::ALLOW);

    SentinalStatus s1 = result.validate();
    assert(s1 == SENTINAL_STATUS_SUCCESS);
    assert(result.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(result.action() == ProtectionEnforcementAction::ALLOW);

    bool v1 = result.isValid();
    assert(v1);
    assert(result.status() == ProtectionExecutionResultStatus::PROCESSED);
    assert(result.action() == ProtectionEnforcementAction::ALLOW);
}

int main() {
    std::cout << "[ProtectionExecutionResult Tests] Running test suite..." << std::endl;

    test_default_construction();
    test_default_result_validation();
    test_processed_allow();
    test_processed_deny();
    test_processed_audit();
    test_rejected_deny();
    test_rejected_allow_rejected();
    test_rejected_audit_rejected();
    test_invalid_status_rejected();
    test_invalid_action_rejected();
    test_accessors();
    test_deterministic_validation();
    test_no_mutation_during_validation();

    std::cout << "[ProtectionExecutionResult Tests] All 13 tests passed successfully." << std::endl;
    return 0;
}
