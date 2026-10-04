#include <cassert>
#include <iostream>
#include "service/driver_protection_response.h"

using namespace sentinel::service;

static void test_default_rejected_deny_valid() {
    DriverProtectionResponse resp;
    assert(resp.status() == DriverProtectionResponseStatus::REJECTED);
    assert(resp.decision() == SENTINAL_DECISION_DENY);
    assert(resp.requestId() == 0);
    assert(resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_valid_success_allow() {
    DriverProtectionResponse resp(42, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);
    assert(resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId() == 42);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_valid_success_deny() {
    DriverProtectionResponse resp(42, SENTINAL_DECISION_DENY, DriverProtectionResponseStatus::SUCCESS);
    assert(resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId() == 42);
    assert(resp.decision() == SENTINAL_DECISION_DENY);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_valid_success_audit() {
    DriverProtectionResponse resp(42, SENTINAL_DECISION_AUDIT, DriverProtectionResponseStatus::SUCCESS);
    assert(resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId() == 42);
    assert(resp.decision() == SENTINAL_DECISION_AUDIT);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_valid_rejected_deny() {
    DriverProtectionResponse resp(42, SENTINAL_DECISION_DENY, DriverProtectionResponseStatus::REJECTED);
    assert(resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId() == 42);
    assert(resp.decision() == SENTINAL_DECISION_DENY);
    assert(resp.status() == DriverProtectionResponseStatus::REJECTED);
}

static void test_invalid_request_id_rejected() {
    DriverProtectionResponse resp(0, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);
    assert(!resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_status_rejected() {
    auto badStatus = static_cast<DriverProtectionResponseStatus>(99);
    DriverProtectionResponse resp(42, SENTINAL_DECISION_ALLOW, badStatus);
    assert(!resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_rejected_allow_rejected() {
    DriverProtectionResponse resp(42, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::REJECTED);
    assert(!resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_rejected_audit_rejected() {
    DriverProtectionResponse resp(42, SENTINAL_DECISION_AUDIT, DriverProtectionResponseStatus::REJECTED);
    assert(!resp.isValid());
    assert(resp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_decision_rejected() {
    auto badDecision = static_cast<SentinalDecision>(99);
    DriverProtectionResponse resp1(42, badDecision, DriverProtectionResponseStatus::SUCCESS);
    assert(!resp1.isValid());
    assert(resp1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    DriverProtectionResponse resp2(42, badDecision, DriverProtectionResponseStatus::REJECTED);
    assert(!resp2.isValid());
    assert(resp2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_deterministic_validation() {
    DriverProtectionResponse validResp(42, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);
    assert(validResp.validate() == SENTINAL_STATUS_SUCCESS);
    assert(validResp.validate() == SENTINAL_STATUS_SUCCESS);
    assert(validResp.isValid());
    assert(validResp.isValid());

    DriverProtectionResponse invalidResp(42, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::REJECTED);
    assert(invalidResp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(invalidResp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!invalidResp.isValid());
    assert(!invalidResp.isValid());
}

int main() {
    std::cout << "[DriverProtectionResponse Tests] Running..." << std::endl;

    test_default_rejected_deny_valid();
    test_valid_success_allow();
    test_valid_success_deny();
    test_valid_success_audit();
    test_valid_rejected_deny();
    test_invalid_request_id_rejected();
    test_invalid_status_rejected();
    test_rejected_allow_rejected();
    test_rejected_audit_rejected();
    test_invalid_decision_rejected();
    test_deterministic_validation();

    std::cout << "[DriverProtectionResponse Tests] All tests passed." << std::endl;
    return 0;
}
