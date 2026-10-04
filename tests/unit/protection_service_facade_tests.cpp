#include <cassert>
#include <iostream>
#include "service/protection_service_facade.h"
#include "service/protection_event_processor.h"
#include "service/protection_execution_engine.h"
#include "service/protection_enforcement.h"
#include "service/protection_evaluation_engine.h"
#include "service/policy_engine.h"
#include "service/target.h"
#include "service/windows_protection_event.h"

using namespace sentinel::service;

static PolicyEngine makeSamplePolicy() {
    PolicyEngine pe;

    ProtectionTarget allowTarget;
    allowTarget.path     = "C:/Public";
    allowTarget.type     = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    allowTarget.decision = SENTINAL_DECISION_ALLOW;
    allowTarget.opMask   = SENTINAL_OP_READ;
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

static void test_construction_with_valid_processor() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);

    ProtectionServiceFacade facade(proc);
    WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    assert(facade.process(ev) == ProtectionEnforcementAction::ALLOW);
}

static void test_valid_read_event_delegation() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    assert(facade.process(ev) == ProtectionEnforcementAction::ALLOW);
    assert(facade.process(ev) == proc.process(ev));
}

static void test_valid_write_event_delegation() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Secret\\write.bin", WindowsProtectionOperation::Write);
    assert(facade.process(ev) == ProtectionEnforcementAction::DENY);
    assert(facade.process(ev) == proc.process(ev));
}

static void test_valid_delete_event_delegation() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Audit\\delete.log", WindowsProtectionOperation::Delete);
    assert(facade.process(ev) == ProtectionEnforcementAction::AUDIT);
    assert(facade.process(ev) == proc.process(ev));
}

static void test_valid_rename_event_delegation() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Secret\\rename.txt", WindowsProtectionOperation::Rename);
    assert(facade.process(ev) == ProtectionEnforcementAction::DENY);
    assert(facade.process(ev) == proc.process(ev));
}

static void test_valid_execute_event_delegation() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Secret\\app.exe", WindowsProtectionOperation::Execute);
    assert(facade.process(ev) == ProtectionEnforcementAction::DENY);
    assert(facade.process(ev) == proc.process(ev));
}

static void test_valid_event_with_explicit_allow_default() {
    PolicyEngine pe;
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Unmatched\\test.txt", WindowsProtectionOperation::Read);
    assert(facade.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
}

static void test_valid_unmatched_event_preserving_supplied_default() {
    PolicyEngine pe;
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Unmatched\\test.txt", WindowsProtectionOperation::Read);
    assert(facade.process(ev, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::ALLOW);
    assert(facade.process(ev, SENTINAL_DECISION_DENY)  == ProtectionEnforcementAction::DENY);
    assert(facade.process(ev, SENTINAL_DECISION_AUDIT) == ProtectionEnforcementAction::AUDIT);
}

static void test_invalid_event_producing_deny() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    // Empty path
    WindowsProtectionEvent emptyPath("", WindowsProtectionOperation::Read);
    assert(facade.process(emptyPath, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    // Embedded NUL
    std::string nulPath("C:\\Public\0\\file.txt", 19);
    WindowsProtectionEvent embeddedNul(nulPath, WindowsProtectionOperation::Read);
    assert(facade.process(embeddedNul, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    // Unknown operation
    WindowsProtectionEvent unknownOp("C:\\Public\\file.txt", WindowsProtectionOperation::Unknown);
    assert(facade.process(unknownOp, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);

    // Default constructed
    WindowsProtectionEvent defaultEv;
    assert(facade.process(defaultEv, SENTINAL_DECISION_ALLOW) == ProtectionEnforcementAction::DENY);
}

static void test_deterministic_repeated_processing() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Secret\\data.bin", WindowsProtectionOperation::Read);
    ProtectionEnforcementAction a1 = facade.process(ev);
    ProtectionEnforcementAction a2 = facade.process(ev);
    ProtectionEnforcementAction a3 = facade.process(ev);

    assert(a1 == a2);
    assert(a2 == a3);
    assert(a1 == ProtectionEnforcementAction::DENY);
}

static void test_facade_does_not_mutate_supplied_event() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    const WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    assert(ev.windowsPath() == "C:\\Public\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Read);

    ProtectionEnforcementAction action = facade.process(ev);
    assert(action == ProtectionEnforcementAction::ALLOW);

    assert(ev.windowsPath() == "C:\\Public\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Read);
}

static void test_facade_does_not_mutate_processor_state() {
    PolicyEngine pe = makeSamplePolicy();
    size_t countBefore = pe.getTargetCount();

    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent ev("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    facade.process(ev);
    facade.process(ev);

    assert(pe.getTargetCount() == countBefore);
}

static void test_delegation_preserves_processor_result_exactly() {
    PolicyEngine pe = makeSamplePolicy();
    ProtectionEvaluationEngine eval(pe);
    ProtectionEnforcement enf(eval);
    ProtectionExecutionEngine exec(enf);
    ProtectionEventProcessor proc(exec);
    ProtectionServiceFacade facade(proc);

    WindowsProtectionEvent evAllow("C:\\Public\\file.txt", WindowsProtectionOperation::Read);
    WindowsProtectionEvent evDeny("C:\\Secret\\file.txt", WindowsProtectionOperation::Write);
    WindowsProtectionEvent evAudit("C:\\Audit\\file.txt", WindowsProtectionOperation::Delete);
    WindowsProtectionEvent evUnmatched("C:\\Other\\file.txt", WindowsProtectionOperation::Read);
    WindowsProtectionEvent evInvalid("", WindowsProtectionOperation::Read);

    assert(facade.process(evAllow) == proc.process(evAllow));
    assert(facade.process(evDeny) == proc.process(evDeny));
    assert(facade.process(evAudit) == proc.process(evAudit));
    assert(facade.process(evUnmatched, SENTINAL_DECISION_ALLOW) == proc.process(evUnmatched, SENTINAL_DECISION_ALLOW));
    assert(facade.process(evUnmatched, SENTINAL_DECISION_DENY) == proc.process(evUnmatched, SENTINAL_DECISION_DENY));
    assert(facade.process(evUnmatched, SENTINAL_DECISION_AUDIT) == proc.process(evUnmatched, SENTINAL_DECISION_AUDIT));
    assert(facade.process(evInvalid, SENTINAL_DECISION_ALLOW) == proc.process(evInvalid, SENTINAL_DECISION_ALLOW));
}

int main() {
    std::cout << "[ProtectionServiceFacade Tests] Running test suite..." << std::endl;

    test_construction_with_valid_processor();
    test_valid_read_event_delegation();
    test_valid_write_event_delegation();
    test_valid_delete_event_delegation();
    test_valid_rename_event_delegation();
    test_valid_execute_event_delegation();
    test_valid_event_with_explicit_allow_default();
    test_valid_unmatched_event_preserving_supplied_default();
    test_invalid_event_producing_deny();
    test_deterministic_repeated_processing();
    test_facade_does_not_mutate_supplied_event();
    test_facade_does_not_mutate_processor_state();
    test_delegation_preserves_processor_result_exactly();

    std::cout << "[ProtectionServiceFacade Tests] All 13 tests passed successfully." << std::endl;
    return 0;
}
