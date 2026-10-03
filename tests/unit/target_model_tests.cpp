#include <cassert>
#include <iostream>
#include "service/target.h"
#include "service/policy_engine.h"

using namespace sentinel::service;

static void test_validation() {
    // Valid target
    ProtectionTarget validTarget;
    validTarget.path = "C:/Secure/file.txt";
    validTarget.type = SENTINAL_TARGET_FILE;
    validTarget.opMask = SENTINAL_OP_READ | SENTINAL_OP_WRITE;
    validTarget.decision = SENTINAL_DECISION_DENY;
    assert(validTarget.validate() == SENTINAL_STATUS_SUCCESS);

    // Empty path rejection
    ProtectionTarget emptyPath = validTarget;
    emptyPath.path = "";
    assert(emptyPath.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Invalid target type
    ProtectionTarget invalidType = validTarget;
    invalidType.type = SENTINAL_TARGET_UNKNOWN;
    assert(invalidType.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Invalid operation mask (zero ops)
    ProtectionTarget zeroOps = validTarget;
    zeroOps.opMask = 0;
    assert(zeroOps.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Invalid operation mask (unknown bit)
    ProtectionTarget unknownOp = validTarget;
    unknownOp.opMask = validTarget.opMask | 0x8000;
    assert(unknownOp.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Invalid decision
    ProtectionTarget invalidDecision = validTarget;
    invalidDecision.decision = SENTINAL_DECISION_UNKNOWN;
    assert(invalidDecision.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_target_ids_and_duplicates() {
    PolicyEngine pe;

    ProtectionTarget t1;
    t1.path = "C:/Test/target1.txt";
    t1.type = SENTINAL_TARGET_FILE;
    t1.opMask = SENTINAL_OP_READ;
    t1.decision = SENTINAL_DECISION_DENY;

    SentinalTargetId id1 = SENTINAL_INVALID_TARGET_ID;
    assert(pe.addTarget(t1, &id1) == SENTINAL_STATUS_SUCCESS);
    assert(id1 == 1);

    ProtectionTarget t2;
    t2.path = "C:/Test/target2.txt";
    t2.type = SENTINAL_TARGET_FILE;
    t2.opMask = SENTINAL_OP_READ;
    t2.decision = SENTINAL_DECISION_DENY;

    SentinalTargetId id2 = SENTINAL_INVALID_TARGET_ID;
    assert(pe.addTarget(t2, &id2) == SENTINAL_STATUS_SUCCESS);
    assert(id2 == 2);

    // Sequential ID assignment check
    assert(id2 == id1 + 1);

    // Duplicate path rejection (exact)
    ProtectionTarget dupExact = t1;
    assert(pe.addTarget(dupExact) == SENTINAL_STATUS_ALREADY_EXISTS);

    // Duplicate path rejection (normalized: backslashes and trailing slash)
    ProtectionTarget dupNorm;
    dupNorm.path = "C:\\Test\\target1.txt\\";
    dupNorm.type = SENTINAL_TARGET_FILE;
    dupNorm.opMask = SENTINAL_OP_WRITE;
    dupNorm.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(dupNorm) == SENTINAL_STATUS_ALREADY_EXISTS);

    assert(pe.getTargetCount() == 2);
}

static void test_lookups_and_updates() {
    PolicyEngine pe;

    ProtectionTarget t1;
    t1.path = "C:\\Folder\\Data.bin";
    t1.type = SENTINAL_TARGET_FILE;
    t1.opMask = SENTINAL_OP_READ;
    t1.decision = SENTINAL_DECISION_DENY;

    SentinalTargetId id1 = 0;
    assert(pe.addTarget(t1, &id1) == SENTINAL_STATUS_SUCCESS);

    // Lookup by ID
    assert(pe.hasTarget(id1));
    assert(!pe.hasTarget(9999));

    ProtectionTarget fetched;
    assert(pe.getTarget(id1, fetched) == SENTINAL_STATUS_SUCCESS);
    assert(fetched.id == id1);
    assert(fetched.path == "C:/Folder/Data.bin");

    // Lookup by normalized path
    assert(pe.hasTarget("C:/Folder/Data.bin"));
    assert(pe.hasTarget("C:\\Folder\\Data.bin\\"));
    assert(!pe.hasTarget("C:/Other.bin"));

    ProtectionTarget fetchedByPath;
    assert(pe.getTarget("C:\\Folder\\Data.bin", fetchedByPath) == SENTINAL_STATUS_SUCCESS);
    assert(fetchedByPath.id == id1);

    // Update preserving ID
    fetched.decision = SENTINAL_DECISION_AUDIT;
    fetched.opMask = SENTINAL_OP_WRITE;
    fetched.description = "Updated description";
    assert(pe.updateTarget(fetched) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget updated;
    assert(pe.getTarget(id1, updated) == SENTINAL_STATUS_SUCCESS);
    assert(updated.id == id1);
    assert(updated.decision == SENTINAL_DECISION_AUDIT);
    assert(updated.opMask == SENTINAL_OP_WRITE);
    assert(updated.description == "Updated description");

    // Disallow path change during updateTarget
    updated.path = "C:/Folder/Renamed.bin";
    assert(pe.updateTarget(updated) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_removal() {
    PolicyEngine pe;

    ProtectionTarget t1;
    t1.path = "C:/Remove/Me.txt";
    t1.type = SENTINAL_TARGET_FILE;
    t1.opMask = SENTINAL_OP_READ;
    t1.decision = SENTINAL_DECISION_DENY;

    SentinalTargetId id = 0;
    assert(pe.addTarget(t1, &id) == SENTINAL_STATUS_SUCCESS);
    assert(pe.getTargetCount() == 1);

    // Removal by ID
    assert(pe.removeTarget(id) == SENTINAL_STATUS_SUCCESS);
    assert(pe.getTargetCount() == 0);
    assert(!pe.hasTarget(id));
    assert(pe.removeTarget(id) == SENTINAL_STATUS_NOT_FOUND);

    // Removal by Path
    assert(pe.addTarget(t1, &id) == SENTINAL_STATUS_SUCCESS);
    assert(pe.removeTarget("C:\\Remove\\Me.txt\\") == SENTINAL_STATUS_SUCCESS);
    assert(pe.getTargetCount() == 0);
    assert(pe.removeTarget("C:/Remove/Me.txt") == SENTINAL_STATUS_NOT_FOUND);
}

static void test_matching_semantics() {
    PolicyEngine pe;

    // FILE matching
    ProtectionTarget f;
    f.path = "C:/Files/secret.key";
    f.type = SENTINAL_TARGET_FILE;
    f.opMask = SENTINAL_OP_READ;
    f.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(f) == SENTINAL_STATUS_SUCCESS);

    assert(pe.evaluate("C:/Files/secret.key", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("C:/Files/secret.key.bak", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // DIRECTORY exact/direct-child behavior
    ProtectionTarget d;
    d.path = "C:/Directory";
    d.type = SENTINAL_TARGET_DIRECTORY;
    d.opMask = SENTINAL_OP_READ;
    d.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(d) == SENTINAL_STATUS_SUCCESS);

    // Exact directory match
    assert(pe.evaluate("C:/Directory", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    // Direct immediate child match
    assert(pe.evaluate("C:/Directory/direct.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    // Sibling directory does not match
    assert(pe.evaluate("C:/Directory_sibling/direct.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);
    // Nested subdirectory descendant does NOT match flat directory
    assert(pe.evaluate("C:/Directory/nested/deep.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // DIRECTORY_RECURSIVE descendant behavior
    ProtectionTarget r;
    r.path = "C:/Recursive";
    r.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    r.opMask = SENTINAL_OP_READ;
    r.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(r) == SENTINAL_STATUS_SUCCESS);

    // Exact match
    assert(pe.evaluate("C:/Recursive", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    // Immediate child match
    assert(pe.evaluate("C:/Recursive/child.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    // Deep descendant match
    assert(pe.evaluate("C:/Recursive/a/b/c/nested.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    // Sibling does not match
    assert(pe.evaluate("C:/Recursive_other/file.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);
}

static void test_operation_mask_and_disabled_fallback() {
    PolicyEngine pe;

    ProtectionTarget t;
    t.path = "C:/Protected/write_only.txt";
    t.type = SENTINAL_TARGET_FILE;
    t.opMask = SENTINAL_OP_WRITE | SENTINAL_OP_DELETE;
    t.decision = SENTINAL_DECISION_DENY;
    t.enabled = true;

    SentinalTargetId id = 0;
    assert(pe.addTarget(t, &id) == SENTINAL_STATUS_SUCCESS);

    // Operation-mask filtering:
    // READ is not in opMask -> should fall back to default decision (ALLOW)
    assert(pe.evaluate("C:/Protected/write_only.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    // WRITE is in opMask -> returns DENY
    assert(pe.evaluate("C:/Protected/write_only.txt", SENTINAL_OP_WRITE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);
    // DELETE is in opMask -> returns DENY
    assert(pe.evaluate("C:/Protected/write_only.txt", SENTINAL_OP_DELETE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);

    // Disabled target fallback:
    t.id = id;
    t.enabled = false;
    assert(pe.updateTarget(t) == SENTINAL_STATUS_SUCCESS);

    // When disabled, even WRITE should fall back to default decision (ALLOW)
    assert(pe.evaluate("C:/Protected/write_only.txt", SENTINAL_OP_WRITE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);

    // Unrelated target does not match
    assert(pe.evaluate("C:/Unrelated/file.txt", SENTINAL_OP_WRITE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
}

int main() {
    std::cout << "[Target Model Tests] Running test suite..." << std::endl;

    test_validation();
    test_target_ids_and_duplicates();
    test_lookups_and_updates();
    test_removal();
    test_matching_semantics();
    test_operation_mask_and_disabled_fallback();

    std::cout << "[Target Model Tests] All tests passed successfully." << std::endl;
    return 0;
}
