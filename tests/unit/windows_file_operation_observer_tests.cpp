#include <cassert>
#include <iostream>
#include <string>
#include "service/windows_file_operation_observation.h"
#include "service/windows_file_operation_observer.h"
#include "service/windows_protection_event.h"
#include "service/windows_protection_event_adapter.h"
#include "service/protection_operation.h"

using namespace sentinel::service;

// 1. Valid Read observation converts successfully.
static void test_valid_read_conversion() {
    WindowsFileOperationObservation obs("C:\\Data\\file.txt", WindowsProtectionOperation::Read);
    assert(obs.isValid());
    assert(obs.validate() == SENTINAL_STATUS_SUCCESS);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Read);
}

// 2. Valid Write observation converts successfully.
static void test_valid_write_conversion() {
    WindowsFileOperationObservation obs("C:\\Data\\file.txt", WindowsProtectionOperation::Write);
    assert(obs.isValid());

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Write);
}

// 3. Valid Delete observation converts successfully.
static void test_valid_delete_conversion() {
    WindowsFileOperationObservation obs("C:\\Data\\file.txt", WindowsProtectionOperation::Delete);
    assert(obs.isValid());

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Delete);
}

// 4. Valid Rename observation converts successfully.
static void test_valid_rename_conversion() {
    WindowsFileOperationObservation obs("C:\\Data\\file.txt", WindowsProtectionOperation::Rename);
    assert(obs.isValid());

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Rename);
}

// 5. Valid Execute observation converts successfully.
static void test_valid_execute_conversion() {
    WindowsFileOperationObservation obs("C:\\Data\\app.exe", WindowsProtectionOperation::Execute);
    assert(obs.isValid());

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Data\\app.exe");
    assert(ev.operation() == WindowsProtectionOperation::Execute);
}

// 6. Windows path is preserved.
static void test_windows_path_is_preserved() {
    const std::string originalPath = "C:\\Deeply\\Nested\\Directory\\Path\\File_2026.log";
    WindowsFileOperationObservation obs(originalPath, WindowsProtectionOperation::Read);
    assert(obs.windowsPath() == originalPath);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.windowsPath() == originalPath);
}

// 7. Windows operation is preserved.
static void test_windows_operation_is_preserved() {
    WindowsFileOperationObservation obs("C:\\Data\\file.bin", WindowsProtectionOperation::Delete);
    assert(obs.operation() == WindowsProtectionOperation::Delete);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.operation() == WindowsProtectionOperation::Delete);
}

// 8. Default observation is invalid.
static void test_default_observation_is_invalid() {
    WindowsFileOperationObservation obs;
    assert(!obs.isValid());
    assert(obs.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(obs.windowsPath().empty());
    assert(obs.operation() == WindowsProtectionOperation::Unknown);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

// 9. Empty path is rejected.
static void test_empty_path_is_rejected() {
    WindowsFileOperationObservation obs("", WindowsProtectionOperation::Read);
    assert(!obs.isValid());
    assert(obs.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

// 10. Embedded NUL path is rejected.
static void test_embedded_nul_path_is_rejected() {
    std::string nulPath("C:\\Data\0\\file.txt", 17);
    WindowsFileOperationObservation obs(nulPath, WindowsProtectionOperation::Write);
    assert(!obs.isValid());
    assert(obs.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

// 11. Unknown operation is rejected.
static void test_unknown_operation_is_rejected() {
    WindowsFileOperationObservation obs("C:\\Data\\file.txt", WindowsProtectionOperation::Unknown);
    assert(!obs.isValid());
    assert(obs.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

// 12. Unrecognized operation enum is rejected.
static void test_unrecognized_operation_enum_is_rejected() {
    WindowsFileOperationObservation obs1(
        "C:\\Data\\file.txt",
        static_cast<WindowsProtectionOperation>(999)
    );
    assert(!obs1.isValid());
    assert(obs1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent ev1;
    assert(WindowsFileOperationObserver::toProtectionEvent(obs1, ev1) == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsFileOperationObservation obs2(
        "C:\\Data\\file.txt",
        static_cast<WindowsProtectionOperation>(-1)
    );
    assert(!obs2.isValid());
    assert(obs2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent ev2;
    assert(WindowsFileOperationObserver::toProtectionEvent(obs2, ev2) == SENTINAL_STATUS_INVALID_PARAMETER);
}

// 13. Invalid observation leaves output event unchanged.
static void test_invalid_observation_leaves_output_event_unchanged() {
    const WindowsProtectionEvent preserved(
        "C:\\Initial\\Kept.txt",
        WindowsProtectionOperation::Execute
    );
    WindowsProtectionEvent ev = preserved;

    // Empty path
    WindowsFileOperationObservation emptyPath("", WindowsProtectionOperation::Read);
    assert(WindowsFileOperationObserver::toProtectionEvent(emptyPath, ev) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(ev.windowsPath() == "C:\\Initial\\Kept.txt");
    assert(ev.operation() == WindowsProtectionOperation::Execute);

    // Embedded NUL
    std::string nulPath("C:\\Bad\0\\Path.txt", 16);
    WindowsFileOperationObservation nulObs(nulPath, WindowsProtectionOperation::Write);
    assert(WindowsFileOperationObserver::toProtectionEvent(nulObs, ev) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(ev.windowsPath() == "C:\\Initial\\Kept.txt");
    assert(ev.operation() == WindowsProtectionOperation::Execute);

    // Unknown operation
    WindowsFileOperationObservation unknownOp("C:\\Valid\\Path.txt", WindowsProtectionOperation::Unknown);
    assert(WindowsFileOperationObserver::toProtectionEvent(unknownOp, ev) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(ev.windowsPath() == "C:\\Initial\\Kept.txt");
    assert(ev.operation() == WindowsProtectionOperation::Execute);

    // Default observation
    WindowsFileOperationObservation defaultObs;
    assert(WindowsFileOperationObserver::toProtectionEvent(defaultObs, ev) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(ev.windowsPath() == "C:\\Initial\\Kept.txt");
    assert(ev.operation() == WindowsProtectionOperation::Execute);

    // Invalid enum
    WindowsFileOperationObservation invalidEnum("C:\\Valid\\Path.txt", static_cast<WindowsProtectionOperation>(123));
    assert(WindowsFileOperationObserver::toProtectionEvent(invalidEnum, ev) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(ev.windowsPath() == "C:\\Initial\\Kept.txt");
    assert(ev.operation() == WindowsProtectionOperation::Execute);
}

// 14. Valid observation produces valid WindowsProtectionEvent.
static void test_valid_observation_produces_valid_protection_event() {
    WindowsFileOperationObservation obs("C:\\Data\\config.json", WindowsProtectionOperation::Write);
    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_SUCCESS);
}

// 15. Conversion is deterministic.
static void test_conversion_is_deterministic() {
    WindowsFileOperationObservation obs("C:\\Data\\deterministic.txt", WindowsProtectionOperation::Rename);
    WindowsProtectionEvent ev1;
    WindowsProtectionEvent ev2;

    SentinalStatus s1 = WindowsFileOperationObserver::toProtectionEvent(obs, ev1);
    SentinalStatus s2 = WindowsFileOperationObserver::toProtectionEvent(obs, ev2);

    assert(s1 == SENTINAL_STATUS_SUCCESS);
    assert(s2 == SENTINAL_STATUS_SUCCESS);
    assert(ev1.windowsPath() == ev2.windowsPath());
    assert(ev1.operation() == ev2.operation());
    assert(ev1.isValid() == ev2.isValid());
}

// 16. Nonexistent path is accepted because this layer does not access the filesystem.
static void test_nonexistent_path_is_accepted() {
    const std::string phantom = "C:\\PhantomDirectory_XYZ_987\\NonExistentFile_12345.dat";
    WindowsFileOperationObservation obs(phantom, WindowsProtectionOperation::Delete);
    assert(obs.isValid());

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == phantom);
    assert(ev.operation() == WindowsProtectionOperation::Delete);
}

// 17. Observer does not evaluate policy.
static void test_observer_does_not_evaluate_policy() {
    // Operations on high-risk system paths (e.g. deletion of system file)
    // are translated faithfully without any policy evaluation, allow, deny, or rejection.
    WindowsFileOperationObservation obs(
        "C:\\Windows\\System32\\ntoskrnl.exe",
        WindowsProtectionOperation::Delete
    );
    assert(obs.isValid());

    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Windows\\System32\\ntoskrnl.exe");
    assert(ev.operation() == WindowsProtectionOperation::Delete);
}

// 18. Observer does not perform enforcement.
static void test_observer_does_not_perform_enforcement() {
    // WindowsFileOperationObserver produces only WindowsProtectionEvent.
    // It does not output ProtectionEnforcementAction, does not modify any state,
    // and does not block or execute any action.
    WindowsFileOperationObservation obs("C:\\Restricted\\secret.docx", WindowsProtectionOperation::Read);
    WindowsProtectionEvent ev;
    SentinalStatus status = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(ev.isValid());
    assert(ev.windowsPath() == "C:\\Restricted\\secret.docx");
    assert(ev.operation() == WindowsProtectionOperation::Read);
}

// 19. Repeated conversion produces equivalent events.
static void test_repeated_conversion_produces_equivalent_events() {
    WindowsFileOperationObservation obs("C:\\Folder\\batch.bat", WindowsProtectionOperation::Execute);
    WindowsProtectionEvent evA;
    WindowsProtectionEvent evB;

    assert(WindowsFileOperationObserver::toProtectionEvent(obs, evA) == SENTINAL_STATUS_SUCCESS);
    assert(WindowsFileOperationObserver::toProtectionEvent(obs, evB) == SENTINAL_STATUS_SUCCESS);

    assert(evA.windowsPath() == evB.windowsPath());
    assert(evA.operation() == evB.operation());
    assert(evA.isValid() == evB.isValid());
    assert(evA.validate() == evB.validate());
}

// 20. Existing WindowsProtectionEvent semantics remain unchanged.
static void test_existing_windows_protection_event_semantics_remain_unchanged() {
    // The event produced by observer must integrate seamlessly with
    // WindowsProtectionEventAdapter -> ProtectionOperation.
    WindowsFileOperationObservation obs("C:\\Integrate\\File.txt", WindowsProtectionOperation::Write);
    WindowsProtectionEvent ev;
    SentinalStatus obsStatus = WindowsFileOperationObserver::toProtectionEvent(obs, ev);
    assert(obsStatus == SENTINAL_STATUS_SUCCESS);

    ProtectionOperation op;
    SentinalStatus adapterStatus = WindowsProtectionEventAdapter::toProtectionOperation(ev, op);
    assert(adapterStatus == SENTINAL_STATUS_SUCCESS);
    assert(op.isValid());
    assert(op.operation() == SENTINAL_OP_WRITE);
    assert(op.path().normalized() == "C:/Integrate/File.txt");
    assert(op.path().isAbsolute());
}

int main() {
    std::cout << "[WindowsFileOperationObserver Tests] Running test suite..." << std::endl;

    test_valid_read_conversion();
    test_valid_write_conversion();
    test_valid_delete_conversion();
    test_valid_rename_conversion();
    test_valid_execute_conversion();
    test_windows_path_is_preserved();
    test_windows_operation_is_preserved();
    test_default_observation_is_invalid();
    test_empty_path_is_rejected();
    test_embedded_nul_path_is_rejected();
    test_unknown_operation_is_rejected();
    test_unrecognized_operation_enum_is_rejected();
    test_invalid_observation_leaves_output_event_unchanged();
    test_valid_observation_produces_valid_protection_event();
    test_conversion_is_deterministic();
    test_nonexistent_path_is_accepted();
    test_observer_does_not_evaluate_policy();
    test_observer_does_not_perform_enforcement();
    test_repeated_conversion_produces_equivalent_events();
    test_existing_windows_protection_event_semantics_remain_unchanged();

    std::cout << "[WindowsFileOperationObserver Tests] All 20 tests passed successfully." << std::endl;
    return 0;
}
