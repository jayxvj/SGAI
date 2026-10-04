#include <cassert>
#include <iostream>
#include "service/windows_protection_enforcement_adapter.h"
#include "service/windows_protection_enforcement_result.h"
#include "service/protection_enforcement.h"

using namespace sentinel::service;

static void test_allow_conversion() {
    WindowsProtectionEnforcementResult result = WindowsProtectionEnforcementResult::DENY;
    SentinalStatus status = WindowsProtectionEnforcementAdapter::toWindowsResult(
        ProtectionEnforcementAction::ALLOW,
        result
    );
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(result == WindowsProtectionEnforcementResult::ALLOW);
}

static void test_deny_conversion() {
    WindowsProtectionEnforcementResult result = WindowsProtectionEnforcementResult::ALLOW;
    SentinalStatus status = WindowsProtectionEnforcementAdapter::toWindowsResult(
        ProtectionEnforcementAction::DENY,
        result
    );
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(result == WindowsProtectionEnforcementResult::DENY);
}

static void test_audit_conversion() {
    WindowsProtectionEnforcementResult result = WindowsProtectionEnforcementResult::ALLOW;
    SentinalStatus status = WindowsProtectionEnforcementAdapter::toWindowsResult(
        ProtectionEnforcementAction::AUDIT,
        result
    );
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(result == WindowsProtectionEnforcementResult::AUDIT);
}

static void test_invalid_enum_conversion() {
    WindowsProtectionEnforcementResult result = WindowsProtectionEnforcementResult::ALLOW;
    SentinalStatus status1 = WindowsProtectionEnforcementAdapter::toWindowsResult(
        static_cast<ProtectionEnforcementAction>(999),
        result
    );
    assert(status1 == SENTINAL_STATUS_INVALID_PARAMETER);

    SentinalStatus status2 = WindowsProtectionEnforcementAdapter::toWindowsResult(
        static_cast<ProtectionEnforcementAction>(-1),
        result
    );
    assert(status2 == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_output_remains_unchanged_on_failure() {
    WindowsProtectionEnforcementResult resAllow = WindowsProtectionEnforcementResult::ALLOW;
    assert(WindowsProtectionEnforcementAdapter::toWindowsResult(
        static_cast<ProtectionEnforcementAction>(123),
        resAllow
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(resAllow == WindowsProtectionEnforcementResult::ALLOW);

    WindowsProtectionEnforcementResult resDeny = WindowsProtectionEnforcementResult::DENY;
    assert(WindowsProtectionEnforcementAdapter::toWindowsResult(
        static_cast<ProtectionEnforcementAction>(456),
        resDeny
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(resDeny == WindowsProtectionEnforcementResult::DENY);

    WindowsProtectionEnforcementResult resAudit = WindowsProtectionEnforcementResult::AUDIT;
    assert(WindowsProtectionEnforcementAdapter::toWindowsResult(
        static_cast<ProtectionEnforcementAction>(789),
        resAudit
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(resAudit == WindowsProtectionEnforcementResult::AUDIT);
}

static void test_exact_result_preservation() {
    WindowsProtectionEnforcementResult out;

    assert(WindowsProtectionEnforcementAdapter::toWindowsResult(ProtectionEnforcementAction::ALLOW, out) == SENTINAL_STATUS_SUCCESS);
    assert(out == WindowsProtectionEnforcementResult::ALLOW);

    assert(WindowsProtectionEnforcementAdapter::toWindowsResult(ProtectionEnforcementAction::DENY, out) == SENTINAL_STATUS_SUCCESS);
    assert(out == WindowsProtectionEnforcementResult::DENY);

    assert(WindowsProtectionEnforcementAdapter::toWindowsResult(ProtectionEnforcementAction::AUDIT, out) == SENTINAL_STATUS_SUCCESS);
    assert(out == WindowsProtectionEnforcementResult::AUDIT);
}

static void test_deterministic_repeated_conversion() {
    WindowsProtectionEnforcementResult r1 = WindowsProtectionEnforcementResult::DENY;
    WindowsProtectionEnforcementResult r2 = WindowsProtectionEnforcementResult::DENY;

    SentinalStatus s1 = WindowsProtectionEnforcementAdapter::toWindowsResult(ProtectionEnforcementAction::ALLOW, r1);
    SentinalStatus s2 = WindowsProtectionEnforcementAdapter::toWindowsResult(ProtectionEnforcementAction::ALLOW, r2);

    assert(s1 == s2);
    assert(s1 == SENTINAL_STATUS_SUCCESS);
    assert(r1 == r2);
    assert(r1 == WindowsProtectionEnforcementResult::ALLOW);

    WindowsProtectionEnforcementResult invalid1 = WindowsProtectionEnforcementResult::ALLOW;
    WindowsProtectionEnforcementResult invalid2 = WindowsProtectionEnforcementResult::ALLOW;
    SentinalStatus err1 = WindowsProtectionEnforcementAdapter::toWindowsResult(static_cast<ProtectionEnforcementAction>(99), invalid1);
    SentinalStatus err2 = WindowsProtectionEnforcementAdapter::toWindowsResult(static_cast<ProtectionEnforcementAction>(99), invalid2);

    assert(err1 == err2);
    assert(err1 == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(invalid1 == WindowsProtectionEnforcementResult::ALLOW);
    assert(invalid2 == WindowsProtectionEnforcementResult::ALLOW);
}

static void test_all_valid_enum_values() {
    const ProtectionEnforcementAction validActions[] = {
        ProtectionEnforcementAction::ALLOW,
        ProtectionEnforcementAction::DENY,
        ProtectionEnforcementAction::AUDIT
    };

    for (auto action : validActions) {
        WindowsProtectionEnforcementResult res;
        SentinalStatus s = WindowsProtectionEnforcementAdapter::toWindowsResult(action, res);
        assert(s == SENTINAL_STATUS_SUCCESS);
    }
}

static void test_no_side_effects_or_unrelated_mutation() {
    int unrelatedVariable = 42;
    WindowsProtectionEnforcementResult res = WindowsProtectionEnforcementResult::ALLOW;

    SentinalStatus s = WindowsProtectionEnforcementAdapter::toWindowsResult(
        ProtectionEnforcementAction::DENY,
        res
    );
    assert(s == SENTINAL_STATUS_SUCCESS);
    assert(res == WindowsProtectionEnforcementResult::DENY);
    assert(unrelatedVariable == 42);
}

int main() {
    std::cout << "[WindowsProtectionEnforcementAdapter Tests] Running test suite..." << std::endl;

    test_allow_conversion();
    test_deny_conversion();
    test_audit_conversion();
    test_invalid_enum_conversion();
    test_output_remains_unchanged_on_failure();
    test_exact_result_preservation();
    test_deterministic_repeated_conversion();
    test_all_valid_enum_values();
    test_no_side_effects_or_unrelated_mutation();

    std::cout << "[WindowsProtectionEnforcementAdapter Tests] All 9 tests passed successfully." << std::endl;
    return 0;
}
