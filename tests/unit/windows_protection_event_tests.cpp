#include <cassert>
#include <iostream>
#include "service/windows_protection_event.h"
#include "service/windows_protection_event_adapter.h"
#include "service/protection_operation.h"
#include "service/windows_operation_adapter.h"

using namespace sentinel::service;

// ==========================================
// WindowsProtectionEvent tests (1-10)
// ==========================================

static void test_event_valid_read() {
    // 1. Valid Read event
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Read);
    assert(ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_SUCCESS);
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Read);
}

static void test_event_valid_write() {
    // 2. Valid Write event
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Write);
    assert(ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_SUCCESS);
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Write);
}

static void test_event_valid_delete() {
    // 3. Valid Delete event
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Delete);
    assert(ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_SUCCESS);
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Delete);
}

static void test_event_valid_rename() {
    // 4. Valid Rename event
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Rename);
    assert(ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_SUCCESS);
    assert(ev.windowsPath() == "C:\\Data\\file.txt");
    assert(ev.operation() == WindowsProtectionOperation::Rename);
}

static void test_event_valid_execute() {
    // 5. Valid Execute event
    WindowsProtectionEvent ev("C:\\Data\\app.exe", WindowsProtectionOperation::Execute);
    assert(ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_SUCCESS);
    assert(ev.windowsPath() == "C:\\Data\\app.exe");
    assert(ev.operation() == WindowsProtectionOperation::Execute);
}

static void test_event_empty_path_rejection() {
    // 6. Empty path rejection
    WindowsProtectionEvent ev("", WindowsProtectionOperation::Read);
    assert(!ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_event_embedded_nul_rejection() {
    // 7. Embedded NUL rejection
    std::string nulPath("C:\\Data\0\\file.txt", 17);
    WindowsProtectionEvent ev(nulPath, WindowsProtectionOperation::Read);
    assert(!ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_event_unknown_operation_rejection() {
    // 8. Unknown operation rejection
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Unknown);
    assert(!ev.isValid());
    assert(ev.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Default constructed event has Unknown operation
    WindowsProtectionEvent def;
    assert(!def.isValid());
    assert(def.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_event_invalid_enum_rejection() {
    // 9. Invalid enum rejection
    WindowsProtectionEvent ev1("C:\\Data\\file.txt", static_cast<WindowsProtectionOperation>(99));
    assert(!ev1.isValid());
    assert(ev1.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent ev2("C:\\Data\\file.txt", static_cast<WindowsProtectionOperation>(-1));
    assert(!ev2.isValid());
    assert(ev2.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_event_deterministic_validation() {
    // 10. Deterministic validation
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Read);
    assert(ev.validate() == ev.validate());
    assert(ev.isValid() == ev.isValid());

    WindowsProtectionEvent badEv("", WindowsProtectionOperation::Unknown);
    assert(badEv.validate() == badEv.validate());
    assert(badEv.isValid() == badEv.isValid());
}

// ==========================================
// WindowsProtectionEventAdapter tests (11-24)
// ==========================================

static void test_adapter_valid_read_conversion() {
    // 11. Valid Read conversion
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Read);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.operation() == SENTINAL_OP_READ);
    assert(out.path().normalized() == "C:/Data/file.txt");
}

static void test_adapter_valid_write_conversion() {
    // 12. Valid Write conversion
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Write);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.operation() == SENTINAL_OP_WRITE);
    assert(out.path().normalized() == "C:/Data/file.txt");
}

static void test_adapter_valid_delete_conversion() {
    // 13. Valid Delete conversion
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Delete);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.operation() == SENTINAL_OP_DELETE);
    assert(out.path().normalized() == "C:/Data/file.txt");
}

static void test_adapter_valid_rename_conversion() {
    // 14. Valid Rename conversion
    WindowsProtectionEvent ev("C:\\Data\\file.txt", WindowsProtectionOperation::Rename);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.operation() == SENTINAL_OP_RENAME);
    assert(out.path().normalized() == "C:/Data/file.txt");
}

static void test_adapter_valid_execute_conversion() {
    // 15. Valid Execute conversion
    WindowsProtectionEvent ev("C:\\Data\\app.exe", WindowsProtectionOperation::Execute);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.operation() == SENTINAL_OP_EXECUTE);
    assert(out.path().normalized() == "C:/Data/app.exe");
}

static void test_adapter_path_conversion_is_preserved() {
    // 16. Path conversion is preserved (normalized, original, and absolute)
    WindowsProtectionEvent ev("C:\\Folder\\SubDir\\File.TXT", WindowsProtectionOperation::Read);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.path().normalized() == "C:/Folder/SubDir/File.TXT");
    assert(out.path().original() == "C:\\Folder\\SubDir\\File.TXT");
    assert(out.path().isAbsolute());
}

static void test_adapter_operation_conversion_is_preserved() {
    // 17. Operation conversion is preserved
    WindowsProtectionEvent ev("C:\\Folder\\file.txt", WindowsProtectionOperation::Write);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.operation() == SENTINAL_OP_WRITE);
}

static void test_adapter_invalid_event_rejection() {
    // 18. Invalid event rejection
    WindowsProtectionEvent invalidEv("", WindowsProtectionOperation::Read);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(invalidEv, out);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_adapter_existing_output_remains_unchanged_on_failure() {
    // 19. Existing ProtectionOperation remains unchanged on failure
    PathIdentity preservedPath("C:/Original/valid.txt");
    ProtectionOperation preserved(preservedPath, SENTINAL_OP_DELETE);
    ProtectionOperation out = preserved;

    // Failure: invalid event (empty path)
    WindowsProtectionEvent ev1("", WindowsProtectionOperation::Read);
    assert(WindowsProtectionEventAdapter::toProtectionOperation(ev1, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out.path() == preservedPath);
    assert(out.operation() == SENTINAL_OP_DELETE);

    // Failure: invalid path (relative path passes event validation but fails path adapter)
    WindowsProtectionEvent ev2("rel/path.txt", WindowsProtectionOperation::Read);
    assert(WindowsProtectionEventAdapter::toProtectionOperation(ev2, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out.path() == preservedPath);
    assert(out.operation() == SENTINAL_OP_DELETE);

    // Failure: invalid operation
    WindowsProtectionEvent ev3("C:\\valid\\path.txt", WindowsProtectionOperation::Unknown);
    assert(WindowsProtectionEventAdapter::toProtectionOperation(ev3, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out.path() == preservedPath);
    assert(out.operation() == SENTINAL_OP_DELETE);
}

static void test_adapter_invalid_path_rejection() {
    // 20. Invalid path rejection (e.g. relative path, bare drive, malformed UNC)
    WindowsProtectionEvent evRel("relative\\file.txt", WindowsProtectionOperation::Read);
    assert(evRel.isValid()); // valid as event
    ProtectionOperation out;
    assert(WindowsProtectionEventAdapter::toProtectionOperation(evRel, out) == SENTINAL_STATUS_INVALID_PARAMETER);

    WindowsProtectionEvent evBare("C:", WindowsProtectionOperation::Read);
    assert(evBare.isValid());
    assert(WindowsProtectionEventAdapter::toProtectionOperation(evBare, out) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_adapter_invalid_operation_rejection() {
    // 21. Invalid operation rejection
    WindowsProtectionEvent evUnknown("C:\\valid\\path.txt", WindowsProtectionOperation::Unknown);
    ProtectionOperation out;
    assert(WindowsProtectionEventAdapter::toProtectionOperation(evUnknown, out) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_adapter_resulting_operation_is_valid() {
    // 22. Resulting ProtectionOperation is valid
    WindowsProtectionEvent ev("C:\\valid\\file.txt", WindowsProtectionOperation::Read);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_adapter_deterministic_conversion() {
    // 23. Deterministic conversion
    WindowsProtectionEvent ev("C:\\Folder\\file.txt", WindowsProtectionOperation::Execute);
    ProtectionOperation out1;
    ProtectionOperation out2;

    SentinalStatus s1 = WindowsProtectionEventAdapter::toProtectionOperation(ev, out1);
    SentinalStatus s2 = WindowsProtectionEventAdapter::toProtectionOperation(ev, out2);

    assert(s1 == s2);
    assert(s1 == SENTINAL_STATUS_SUCCESS);
    assert(out1.path() == out2.path());
    assert(out1.operation() == out2.operation());
    assert(out1.context().source() == out2.context().source());
    assert(out1.isValid() == out2.isValid());
}

static void test_adapter_nonexistent_filesystem_path_accepted() {
    // 24. Nonexistent filesystem path is accepted because no filesystem access is performed
    WindowsProtectionEvent ev("C:\\Phantom\\NonExistent_112233\\GhostFile_445566.xyz", WindowsProtectionOperation::Write);
    ProtectionOperation out;
    SentinalStatus status = WindowsProtectionEventAdapter::toProtectionOperation(ev, out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.path().normalized() == "C:/Phantom/NonExistent_112233/GhostFile_445566.xyz");
}

int main() {
    std::cout << "[WindowsProtectionEvent Tests] Running test suite..." << std::endl;

    test_event_valid_read();
    test_event_valid_write();
    test_event_valid_delete();
    test_event_valid_rename();
    test_event_valid_execute();
    test_event_empty_path_rejection();
    test_event_embedded_nul_rejection();
    test_event_unknown_operation_rejection();
    test_event_invalid_enum_rejection();
    test_event_deterministic_validation();

    test_adapter_valid_read_conversion();
    test_adapter_valid_write_conversion();
    test_adapter_valid_delete_conversion();
    test_adapter_valid_rename_conversion();
    test_adapter_valid_execute_conversion();
    test_adapter_path_conversion_is_preserved();
    test_adapter_operation_conversion_is_preserved();
    test_adapter_invalid_event_rejection();
    test_adapter_existing_output_remains_unchanged_on_failure();
    test_adapter_invalid_path_rejection();
    test_adapter_invalid_operation_rejection();
    test_adapter_resulting_operation_is_valid();
    test_adapter_deterministic_conversion();
    test_adapter_nonexistent_filesystem_path_accepted();

    std::cout << "[WindowsProtectionEvent Tests] All tests passed successfully." << std::endl;
    return 0;
}
