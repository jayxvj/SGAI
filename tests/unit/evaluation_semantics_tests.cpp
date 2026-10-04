#include <cassert>
#include <iostream>
#include "service/policy_engine.h"
#include "service/target.h"

using namespace sentinel::service;

static void test_exact_file_beats_recursive_directory() {
    PolicyEngine pe;

    // A. Exact FILE beats recursive DIRECTORY
    ProtectionTarget recursiveTarget;
    recursiveTarget.path = "C:/Vault";
    recursiveTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    recursiveTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(recursiveTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget fileTarget;
    fileTarget.path = "C:/Vault/a.txt";
    fileTarget.type = SENTINAL_TARGET_FILE;
    fileTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(fileTarget) == SENTINAL_STATUS_SUCCESS);

    // a.txt must resolve to ALLOW (exact FILE beats recursive directory)
    assert(pe.evaluate("C:/Vault/a.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // Other files under C:/Vault resolve to DENY
    assert(pe.evaluate("C:/Vault/b.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

static void test_exact_file_beats_direct_child_directory() {
    PolicyEngine pe;

    // B. Exact FILE beats direct-child DIRECTORY
    ProtectionTarget dirTarget;
    dirTarget.path = "C:/Dir";
    dirTarget.type = SENTINAL_TARGET_DIRECTORY;
    dirTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget fileTarget;
    fileTarget.path = "C:/Dir/a.txt";
    fileTarget.type = SENTINAL_TARGET_FILE;
    fileTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(fileTarget) == SENTINAL_STATUS_SUCCESS);

    // a.txt matches both as exact FILE (prec 4) and direct child of C:/Dir (prec 2)
    assert(pe.evaluate("C:/Dir/a.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // Other direct child in C:/Dir matches direct-child DIRECTORY -> DENY
    assert(pe.evaluate("C:/Dir/other.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

static void test_exact_directory_beats_recursive_directory() {
    PolicyEngine pe;

    // C. Exact DIRECTORY beats recursive DIRECTORY
    ProtectionTarget rootRec;
    rootRec.path = "C:/Root";
    rootRec.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    rootRec.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(rootRec) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget subDir;
    subDir.path = "C:/Root/SubDir";
    subDir.type = SENTINAL_TARGET_DIRECTORY;
    subDir.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(subDir) == SENTINAL_STATUS_SUCCESS);

    // Request on the directory itself matches exact DIRECTORY (prec 3) vs recursive (prec 1)
    assert(pe.evaluate("C:/Root/SubDir", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // Request on another branch matches recursive root -> DENY
    assert(pe.evaluate("C:/Root/OtherBranch", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

static void test_direct_child_directory_beats_recursive_directory() {
    PolicyEngine pe;

    // D. Direct-child DIRECTORY beats recursive DIRECTORY
    ProtectionTarget rootRec;
    rootRec.path = "C:/Root";
    rootRec.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    rootRec.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(rootRec) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget folder;
    folder.path = "C:/Root/Folder";
    folder.type = SENTINAL_TARGET_DIRECTORY;
    folder.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(folder) == SENTINAL_STATUS_SUCCESS);

    // Direct child of C:/Root/Folder: matches direct-child (prec 2) vs recursive (prec 1) -> ALLOW
    assert(pe.evaluate("C:/Root/Folder/file.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // Deep descendant of C:/Root/Folder: not direct child of Folder, falls through to Root recursive -> DENY
    assert(pe.evaluate("C:/Root/Folder/sub/deep.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

static void test_deepest_recursive_target_wins() {
    PolicyEngine pe;

    // E. Deepest recursive target wins
    ProtectionTarget t1;
    t1.path = "C:/Sensitive";
    t1.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t1.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(t1) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget t2;
    t2.path = "C:/Sensitive/Finance";
    t2.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t2.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(t2) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget t3;
    t3.path = "C:/Sensitive/Finance/Payroll";
    t3.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t3.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(t3) == SENTINAL_STATUS_SUCCESS);

    // Depth 2: Sensitive
    assert(pe.evaluate("C:/Sensitive/misc.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);

    // Depth 3: Finance
    assert(pe.evaluate("C:/Sensitive/Finance/budget.xlsx", SENTINAL_OP_READ) == SENTINAL_DECISION_ALLOW);

    // Depth 4: Payroll
    assert(pe.evaluate("C:/Sensitive/Finance/Payroll/october.csv", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
    assert(pe.evaluate("C:/Sensitive/Finance/Payroll/sub/data.dat", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

static void test_insertion_order_independence() {
    // F. Insertion-order independence
    ProtectionTarget t1;
    t1.path = "C:/Sensitive";
    t1.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t1.decision = SENTINAL_DECISION_DENY;

    ProtectionTarget t2;
    t2.path = "C:/Sensitive/Finance";
    t2.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t2.decision = SENTINAL_DECISION_ALLOW;

    ProtectionTarget t3;
    t3.path = "C:/Sensitive/Finance/Payroll";
    t3.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    t3.decision = SENTINAL_DECISION_DENY;

    ProtectionTarget tFile;
    tFile.path = "C:/Sensitive/Finance/Payroll/override.txt";
    tFile.type = SENTINAL_TARGET_FILE;
    tFile.decision = SENTINAL_DECISION_ALLOW;

    // Forward order
    PolicyEngine peForward;
    assert(peForward.addTarget(t1) == SENTINAL_STATUS_SUCCESS);
    assert(peForward.addTarget(t2) == SENTINAL_STATUS_SUCCESS);
    assert(peForward.addTarget(t3) == SENTINAL_STATUS_SUCCESS);
    assert(peForward.addTarget(tFile) == SENTINAL_STATUS_SUCCESS);

    // Reverse order
    PolicyEngine peReverse;
    assert(peReverse.addTarget(tFile) == SENTINAL_STATUS_SUCCESS);
    assert(peReverse.addTarget(t3) == SENTINAL_STATUS_SUCCESS);
    assert(peReverse.addTarget(t2) == SENTINAL_STATUS_SUCCESS);
    assert(peReverse.addTarget(t1) == SENTINAL_STATUS_SUCCESS);

    const char* testPaths[] = {
        "C:/Sensitive/readme.txt",
        "C:/Sensitive/Finance/report.pdf",
        "C:/Sensitive/Finance/Payroll/slip.csv",
        "C:/Sensitive/Finance/Payroll/override.txt",
        "C:/Unrelated/file.txt"
    };

    for (const char* p : testPaths) {
        SentinalDecision fwd = peForward.evaluate(p, SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW);
        SentinalDecision rev = peReverse.evaluate(p, SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW);
        assert(fwd == rev);
    }
}

static void test_operation_mask_fall_through() {
    PolicyEngine pe;

    // G. Operation-mask fall-through
    ProtectionTarget broadTarget;
    broadTarget.path = "C:/Vault";
    broadTarget.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    broadTarget.opMask = SENTINAL_OP_WRITE | SENTINAL_OP_DELETE;
    broadTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(broadTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget specificTarget;
    specificTarget.path = "C:/Vault/a.txt";
    specificTarget.type = SENTINAL_TARGET_FILE;
    specificTarget.opMask = SENTINAL_OP_READ;
    specificTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(specificTarget) == SENTINAL_STATUS_SUCCESS);

    // READ operation matches specific target -> ALLOW
    assert(pe.evaluate("C:/Vault/a.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);

    // WRITE operation does not match specific target, falls through to broad target -> DENY
    assert(pe.evaluate("C:/Vault/a.txt", SENTINAL_OP_WRITE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_DENY);

    // EXECUTE operation matches neither target -> returns default (ALLOW)
    assert(pe.evaluate("C:/Vault/a.txt", SENTINAL_OP_EXECUTE, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
}

static void test_disabled_target_fall_through() {
    PolicyEngine pe;

    // H. Disabled-target fall-through
    ProtectionTarget broad;
    broad.path = "C:/Vault";
    broad.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    broad.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(broad) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget specific;
    specific.path = "C:/Vault/a.txt";
    specific.type = SENTINAL_TARGET_FILE;
    specific.decision = SENTINAL_DECISION_ALLOW;
    specific.enabled = false;
    assert(pe.addTarget(specific) == SENTINAL_STATUS_SUCCESS);

    // Disabled specific target does not participate; falls through to broader target -> DENY
    assert(pe.evaluate("C:/Vault/a.txt", SENTINAL_OP_READ) == SENTINAL_DECISION_DENY);
}

static void test_unrelated_path_default() {
    PolicyEngine pe;

    // I. Unrelated path remains default
    ProtectionTarget target;
    target.path = "C:/Protected/Path";
    target.type = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    target.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(target) == SENTINAL_STATUS_SUCCESS);

    assert(pe.evaluate("C:/Other/Unrelated/file.txt", SENTINAL_OP_READ, SENTINAL_DECISION_ALLOW) == SENTINAL_DECISION_ALLOW);
    assert(pe.evaluate("C:/Other/Unrelated/file.txt", SENTINAL_OP_READ, SENTINAL_DECISION_DENY) == SENTINAL_DECISION_DENY);
}

int main() {
    std::cout << "[Evaluation Semantics Tests] Running test suite..." << std::endl;

    test_exact_file_beats_recursive_directory();
    test_exact_file_beats_direct_child_directory();
    test_exact_directory_beats_recursive_directory();
    test_direct_child_directory_beats_recursive_directory();
    test_deepest_recursive_target_wins();
    test_insertion_order_independence();
    test_operation_mask_fall_through();
    test_disabled_target_fall_through();
    test_unrelated_path_default();

    std::cout << "[Evaluation Semantics Tests] All tests passed successfully." << std::endl;
    return 0;
}
