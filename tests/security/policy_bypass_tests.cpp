#include <cassert>
#include <iostream>
#include "service/policy_engine.h"

using namespace sentinel::service;

static void test_protected_target_invariant() {
    PolicyEngine pe;
    assert(pe.addTarget("C:/Vault/secret.key", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);

    // Invariant: Exact protected target returns DENY for valid operations
    assert(pe.evaluate("C:/Vault/secret.key", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("C:/Vault/secret.key", SENTINAL_OP_WRITE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("C:/Vault/secret.key", SENTINAL_OP_DELETE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);
}

static void test_unprotected_target_invariant() {
    PolicyEngine pe;
    assert(pe.addTarget("C:/Vault/secret.key", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);

    // Invariant: Unprotected target returns the configured default decision
    assert(pe.evaluate("C:/Public/open.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate("C:/Public/open.txt", SENTINAL_OP_WRITE, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("C:/Public/open.txt", SENTINAL_OP_EXECUTE, SENTINAL_DECISION_AUDIT) == SENTINAL_DECISION_AUDIT);
}

static void test_unrelated_target_boundary_invariant() {
    PolicyEngine pe;
    assert(pe.addTarget("C:/Target.txt", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(pe.addTarget("C:/Dir", SENTINAL_TARGET_DIRECTORY, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);

    // Suffix extension must not accidentally match file target
    assert(pe.evaluate("C:/Target.txt.backup", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate("C:/Target.txt2", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);

    // Sibling directory must not accidentally match directory target
    assert(pe.evaluate("C:/Dir_sibling/file.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);

    // Subdirectory must not match flat (non-recursive) directory target
    assert(pe.evaluate("C:/Dir/sub/nested.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);

    // Direct child must match flat directory target
    assert(pe.evaluate("C:/Dir/child.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);
}

static void test_multiple_target_determinism_invariant() {
    PolicyEngine pe;
    assert(pe.addTarget("C:/Path/A", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(pe.addTarget("C:/Path/B", SENTINAL_TARGET_FILE, SENTINAL_DECISION_AUDIT) == SENTINAL_STATUS_SUCCESS);
    assert(pe.addTarget("C:/Path/C", SENTINAL_TARGET_DIRECTORY_RECURSIVE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(pe.getTargetCount() == 3);

    // Deterministic lookup
    assert(pe.evaluate("C:/Path/A", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("C:/Path/B", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_AUDIT);
    assert(pe.evaluate("C:/Path/C/nested/file.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);

    // Updating existing target replaces decision cleanly without duplicating rule
    assert(pe.addTarget("C:/Path/A", SENTINAL_TARGET_FILE, SENTINAL_DECISION_ALLOW) == SENTINAL_STATUS_SUCCESS);
    assert(pe.getTargetCount() == 3);
    assert(pe.evaluate("C:/Path/A", SENTINAL_OP_READ, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_ALLOW);

    // Clear targets empties rule set
    pe.clearTargets();
    assert(pe.getTargetCount() == 0);
    assert(pe.evaluate("C:/Path/B", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
}

static void test_invalid_input_safety_invariant() {
    PolicyEngine pe;

    // Empty path handling
    assert(pe.addTarget("", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(pe.removeTarget("") == SENTINAL_STATUS_INVALID_PARAMETER);

    // Unknown target type
    assert(pe.addTarget("C:/valid", SENTINAL_TARGET_UNKNOWN, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_INVALID_PARAMETER);

    // Removing non-existent path
    assert(pe.removeTarget("C:/nonexistent") == SENTINAL_STATUS_NOT_FOUND);

    // Evaluating empty path returns default decision safely
    assert(pe.evaluate("", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);

    // Evaluating SENTINAL_OP_NONE returns default decision safely
    assert(pe.addTarget("C:/file.txt", SENTINAL_TARGET_FILE, SENTINAL_DECISION_DENY) == SENTINAL_STATUS_SUCCESS);
    assert(pe.evaluate("C:/file.txt", SENTINAL_OP_NONE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
}

int main() {
    std::cout << "[Security Suite] Running policy invariant tests..." << std::endl;

    test_protected_target_invariant();
    test_unprotected_target_invariant();
    test_unrelated_target_boundary_invariant();
    test_multiple_target_determinism_invariant();
    test_invalid_input_safety_invariant();

    std::cout << "[Security Suite] All policy invariant tests passed successfully." << std::endl;
    return 0;
}
