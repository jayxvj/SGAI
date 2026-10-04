#include <cassert>
#include <iostream>
#include "service/protection_event_processor.h"
#include "service/protection_evaluation_engine.h"
#include "service/policy_engine.h"
#include "service/target.h"
#include "service/windows_protection_event.h"
#include "service/windows_protection_event_adapter.h"
#include "service/protection_operation.h"
#include "service/protection_operation_adapter.h"

using namespace sentinel::service;

// ---------------------------------------------------------------------------
// Helper: a sample policy with ALLOW/DENY/AUDIT targets for varied testing.
// ---------------------------------------------------------------------------
static PolicyEngine makeSampleEngine() {
    PolicyEngine pe;

    ProtectionTarget allowTarget;
    allowTarget.path     = "C:/Public";
    allowTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    allowTarget.decision = SENTINAL_DECISION_ALLOW;
    allowTarget.opMask   = SENTINAL_OP_READ | SENTINAL_OP_WRITE;
    assert(pe.addTarget(allowTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget denyTarget;
    denyTarget.path     = "C:/Secret";
    denyTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    denyTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(denyTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget auditTarget;
    auditTarget.path     = "C:/Audit";
    auditTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    auditTarget.decision = SENTINAL_DECISION_AUDIT;
    assert(pe.addTarget(auditTarget) == SENTINAL_STATUS_SUCCESS);

    return pe;
}

static ProtectionEventProcessor makeProcessor(
    const PolicyEngine& pe,
    ProtectionEvaluationEngine& eval,
    ProtectionEnforcement& enf,
    ProtectionExecutionEngine& exec
) {
    // eval/enf/exec are constructed by the caller with matching lifetimes.
    (void)pe;
    return ProtectionEventProcessor(exec);
}

// ---------------------------------------------------------------------------
// 1. Valid Windows read event resulting in ALLOW.
// ---------------------------------------------------------------------------
static void test_read_event_allows() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    assert(proc.process(ev) == ProtectionEnforcementAction::ALLOW);
}

// ---------------------------------------------------------------------------
// 2. Valid Windows write event resulting in DENY.
// ---------------------------------------------------------------------------
static void test_write_event_denies() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Secret\\data.bin", WindowsProtectionOperation::Write);
    assert(proc.process(ev) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 3. Valid Windows delete event resulting in AUDIT.
// ---------------------------------------------------------------------------
static void test_delete_event_audits() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Audit\\log.txt", WindowsProtectionOperation::Delete);
    assert(proc.process(ev) == ProtectionEnforcementAction::AUDIT);
}

// ---------------------------------------------------------------------------
// 4. Valid Windows rename event.
// ---------------------------------------------------------------------------
static void test_rename_event_flows_through() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // Secret path -> DENY regardless of operation type
    WindowsProtectionEvent ev("C:\\Secret\\report.docx", WindowsProtectionOperation::Rename);
    assert(proc.process(ev) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 5. Valid Windows execute event.
// ---------------------------------------------------------------------------
static void test_execute_event_flows_through() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // Secret path -> DENY
    WindowsProtectionEvent ev("C:\\Secret\\tool.exe", WindowsProtectionOperation::Execute);
    assert(proc.process(ev) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 6. Default policy behavior (unmatched path).
// ---------------------------------------------------------------------------
static void test_default_policy_behavior() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Unmatched\\file.txt", WindowsProtectionOperation::Read);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
    assert(proc.process(ev, SENTINAL_DECISION_DENY)  == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 7. Exact file policy.
// ---------------------------------------------------------------------------
static void test_exact_file_policy() {
    PolicyEngine pe;

    ProtectionTarget dirTarget;
    dirTarget.path     = "C:/Folder";
    dirTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    dirTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget fileTarget;
    fileTarget.path     = "C:/Folder/secret.txt";
    fileTarget.type     = SENTINAL_TARGET_FILE;
    fileTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(fileTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent evExact("C:\\Folder\\secret.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evExact) == ProtectionEnforcementAction::DENY);

    WindowsProtectionEvent evOther("C:\\Folder\\other.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evOther) == ProtectionEnforcementAction::ALLOW);
}

// ---------------------------------------------------------------------------
// 8. Exact directory policy.
// ---------------------------------------------------------------------------
static void test_exact_directory_policy() {
    PolicyEngine pe;

    ProtectionTarget dirTarget;
    dirTarget.path     = "C:/Locked";
    dirTarget.type     = SENTINAL_TARGET_DIRECTORY;
    dirTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent evDir("C:\\Locked", WindowsProtectionOperation::Read);
    assert(proc.process(evDir) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 9. Direct-child directory policy.
// ---------------------------------------------------------------------------
static void test_direct_child_directory_policy() {
    PolicyEngine pe;

    ProtectionTarget dirTarget;
    dirTarget.path     = "C:/Parent";
    dirTarget.type     = SENTINAL_TARGET_DIRECTORY;
    dirTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(dirTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // Direct child -> DENY
    WindowsProtectionEvent evChild("C:\\Parent\\child.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evChild, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    // Deep descendant -> not matched by DIRECTORY type -> falls back to default ALLOW
    WindowsProtectionEvent evDeep("C:\\Parent\\sub\\deep.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evDeep, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
}

// ---------------------------------------------------------------------------
// 10. Recursive directory policy.
// ---------------------------------------------------------------------------
static void test_recursive_directory_policy() {
    PolicyEngine pe;

    ProtectionTarget rootTarget;
    rootTarget.path     = "C:/Root";
    rootTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    rootTarget.decision = SENTINAL_DECISION_DENY;
    assert(pe.addTarget(rootTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionTarget subTarget;
    subTarget.path     = "C:/Root/Safe";
    subTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    subTarget.decision = SENTINAL_DECISION_ALLOW;
    assert(pe.addTarget(subTarget) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent evRoot("C:\\Root\\other.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evRoot) == ProtectionEnforcementAction::DENY);

    WindowsProtectionEvent evSafe("C:\\Root\\Safe\\deep.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evSafe) == ProtectionEnforcementAction::ALLOW);
}

// ---------------------------------------------------------------------------
// 11. Operation mask behavior.
// ---------------------------------------------------------------------------
static void test_operation_mask_behavior() {
    PolicyEngine pe;

    ProtectionTarget target;
    target.path     = "C:/Protected";
    target.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    target.decision = SENTINAL_DECISION_DENY;
    target.opMask   = SENTINAL_OP_WRITE; // Only WRITE denied
    assert(pe.addTarget(target) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent evRead("C:\\Protected\\file.txt", WindowsProtectionOperation::Read);
    assert(proc.process(evRead, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);

    WindowsProtectionEvent evWrite("C:\\Protected\\file.txt", WindowsProtectionOperation::Write);
    assert(proc.process(evWrite, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 12. Disabled target behavior.
// ---------------------------------------------------------------------------
static void test_disabled_target_behavior() {
    PolicyEngine pe;

    ProtectionTarget target;
    target.path     = "C:/Disabled";
    target.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    target.decision = SENTINAL_DECISION_DENY;
    target.enabled  = false;
    assert(pe.addTarget(target) == SENTINAL_STATUS_SUCCESS);

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Disabled\\file.txt", WindowsProtectionOperation::Read);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
}

// ---------------------------------------------------------------------------
// 13. Invalid/default-constructed event returns DENY.
// ---------------------------------------------------------------------------
static void test_invalid_default_event_returns_deny() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev; // default: empty path, Unknown operation
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 14. Empty Windows path returns DENY.
// ---------------------------------------------------------------------------
static void test_empty_path_returns_deny() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("", WindowsProtectionOperation::Read);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 15. Embedded NUL path returns DENY.
// ---------------------------------------------------------------------------
static void test_embedded_nul_path_returns_deny() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    std::string nulPath("C:\\Public\0\\file.txt", 19);
    WindowsProtectionEvent ev(nulPath, WindowsProtectionOperation::Read);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 16. Unknown Windows operation returns DENY.
// ---------------------------------------------------------------------------
static void test_unknown_operation_returns_deny() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Unknown);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 17. Unrecognized Windows operation enum value returns DENY.
// ---------------------------------------------------------------------------
static void test_unrecognized_operation_enum_returns_deny() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev(
        "C:\\Public\\file.txt",
        static_cast<WindowsProtectionOperation>(99)
    );
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 18. Context propagation: WindowsProtectionEvent has no context constructor.
//     The adapter produces a USER_MODE context by default; the processor
//     passes it through to ProtectionExecutionEngine unchanged. Verify the
//     policy decision still evaluates correctly — no new event-context API
//     is needed or invented here.
// ---------------------------------------------------------------------------
static void test_default_context_evaluates_correctly() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // A DENY target path must still be DENIED through the default context.
    WindowsProtectionEvent ev("C:\\Secret\\data.bin", WindowsProtectionOperation::Read);
    assert(proc.process(ev) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 19. Repeated processing is deterministic.
// ---------------------------------------------------------------------------
static void test_repeated_processing_is_deterministic() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Secret\\data.bin", WindowsProtectionOperation::Read);
    ProtectionEnforcementAction a1 = proc.process(ev);
    ProtectionEnforcementAction a2 = proc.process(ev);
    ProtectionEnforcementAction a3 = proc.process(ev);

    assert(a1 == a2);
    assert(a2 == a3);
    assert(a1 == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 20. Processing does not mutate policy state.
// ---------------------------------------------------------------------------
static void test_processing_does_not_mutate_policy() {
    PolicyEngine pe = makeSampleEngine();
    size_t countBefore = pe.getTargetCount();

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    proc.process(ev);
    proc.process(ev);

    assert(pe.getTargetCount() == countBefore);
}

// ---------------------------------------------------------------------------
// 21. Caller-supplied defaultDecision is preserved for valid unmatched events.
// ---------------------------------------------------------------------------
static void test_caller_default_decision_preserved_for_unmatched() {
    PolicyEngine pe; // empty -> always falls to defaultDecision
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    WindowsProtectionEvent ev("C:\\Anywhere\\file.txt", WindowsProtectionOperation::Read);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
    assert(proc.process(ev, SENTINAL_DECISION_DENY)  == ProtectionEnforcementAction::DENY);
    assert(proc.process(ev, SENTINAL_DECISION_AUDIT) == ProtectionEnforcementAction::AUDIT);
}

// ---------------------------------------------------------------------------
// 22. Invalid event cannot override safe DENY behavior with an ALLOW default.
// ---------------------------------------------------------------------------
static void test_invalid_event_cannot_become_allow() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // Empty path -> adapter fails -> DENY, even though caller asked for ALLOW default
    WindowsProtectionEvent ev("", WindowsProtectionOperation::Read);
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    // Default-constructed -> DENY
    WindowsProtectionEvent evDef;
    assert(proc.process(evDef, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 23. The processor does not bypass the existing Windows event adapter.
//     Verify: an event that the adapter rejects is never passed to the
//     execution engine as a successful conversion.
// ---------------------------------------------------------------------------
static void test_processor_does_not_bypass_event_adapter() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // Confirm the adapter itself rejects this event
    WindowsProtectionEvent ev("", WindowsProtectionOperation::Read);
    ProtectionOperation op;
    assert(WindowsProtectionEventAdapter::toProtectionOperation(ev, op) == SENTINAL_STATUS_INVALID_PARAMETER);

    // Processor must agree: DENY (not ALLOW)
    assert(proc.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

// ---------------------------------------------------------------------------
// 24. The processor does not bypass ProtectionExecutionEngine.
//     A valid event on a DENY target must pass through the full evaluation
//     stack and be denied — not short-circuited before reaching the engine.
// ---------------------------------------------------------------------------
static void test_processor_does_not_bypass_execution_engine() {
    PolicyEngine pe = makeSampleEngine();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    // Verify the execution engine gives DENY for this path directly
    ProtectionOperation op(
        PathIdentity("C:/Secret/data.bin"), SENTINAL_OP_READ
    );
    assert(exec.execute(op) == ProtectionEnforcementAction::DENY);

    // Processor on the equivalent Windows event must give the same result
    WindowsProtectionEvent ev("C:\\Secret\\data.bin", WindowsProtectionOperation::Read);
    assert(proc.process(ev) == ProtectionEnforcementAction::DENY);
}

int main() {
    std::cout << "[ProtectionEventProcessor Tests] Running test suite..." << std::endl;

    test_read_event_allows();
    test_write_event_denies();
    test_delete_event_audits();
    test_rename_event_flows_through();
    test_execute_event_flows_through();
    test_default_policy_behavior();
    test_exact_file_policy();
    test_exact_directory_policy();
    test_direct_child_directory_policy();
    test_recursive_directory_policy();
    test_operation_mask_behavior();
    test_disabled_target_behavior();
    test_invalid_default_event_returns_deny();
    test_empty_path_returns_deny();
    test_embedded_nul_path_returns_deny();
    test_unknown_operation_returns_deny();
    test_unrecognized_operation_enum_returns_deny();
    test_default_context_evaluates_correctly();
    test_repeated_processing_is_deterministic();
    test_processing_does_not_mutate_policy();
    test_caller_default_decision_preserved_for_unmatched();
    test_invalid_event_cannot_become_allow();
    test_processor_does_not_bypass_event_adapter();
    test_processor_does_not_bypass_execution_engine();

    std::cout << "[ProtectionEventProcessor Tests] All tests passed successfully." << std::endl;
    return 0;
}
