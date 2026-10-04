#include <cassert>
#include <iostream>
#include "service/windows_path_adapter.h"
#include "service/path_identity.h"

using namespace sentinel::service;

static void test_valid_drive_absolute_path() {
    // 1. Valid drive-absolute path
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\Windows\\System32\\notepad.exe", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.getType() == PathType::DriveAbsolute);
    assert(out.isAbsolute());
    assert(out.normalized() == "C:/Windows/System32/notepad.exe");
}

static void test_valid_drive_root_path() {
    // 2. Valid drive-root path
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.getType() == PathType::DriveRoot);
    assert(out.isAbsolute());
    assert(out.isDriveRoot());
    assert(out.normalized() == "C:/");

    PathIdentity outSlash;
    assert(WindowsPathAdapter::toPathIdentity("D:/", outSlash) == SENTINAL_STATUS_SUCCESS);
    assert(outSlash.getType() == PathType::DriveRoot);
    assert(outSlash.normalized() == "D:/");
}

static void test_valid_unc_path() {
    // 3. Valid UNC path
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("\\\\server\\share\\data\\file.txt", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.getType() == PathType::Unc);
    assert(out.isAbsolute());
    assert(out.isUnc());
    assert(out.normalized() == "//server/share/data/file.txt");

    PathIdentity outRoot;
    assert(WindowsPathAdapter::toPathIdentity("\\\\server\\share\\", outRoot) == SENTINAL_STATUS_SUCCESS);
    assert(outRoot.getType() == PathType::Unc);
    assert(outRoot.normalized() == "//server/share");
}

static void test_case_preservation() {
    // 4. Case preservation
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\MyFolder\\SubDir\\Document.TXT", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.normalized() == "C:/MyFolder/SubDir/Document.TXT");
    assert(out.original() == "C:\\MyFolder\\SubDir\\Document.TXT");
}

static void test_separator_normalization() {
    // 5. Separator normalization
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\\\Folder\\\\Sub\\\\file.txt", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.normalized() == "C:/Folder/Sub/file.txt");

    PathIdentity outMixed;
    assert(WindowsPathAdapter::toPathIdentity("C:\\Folder/Sub\\file.txt", outMixed) == SENTINAL_STATUS_SUCCESS);
    assert(outMixed.normalized() == "C:/Folder/Sub/file.txt");

    PathIdentity outTrailing;
    assert(WindowsPathAdapter::toPathIdentity("C:\\Folder\\Sub\\", outTrailing) == SENTINAL_STATUS_SUCCESS);
    assert(outTrailing.normalized() == "C:/Folder/Sub");
}

static void test_relative_path_rejection() {
    // 6. Relative path rejection
    PathIdentity out;
    assert(WindowsPathAdapter::toPathIdentity("relative\\path\\file.txt", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(WindowsPathAdapter::toPathIdentity("file.txt", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(WindowsPathAdapter::toPathIdentity("sub/dir", out) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_empty_path_rejection() {
    // 7. Empty path rejection
    PathIdentity out;
    assert(WindowsPathAdapter::toPathIdentity("", out) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_embedded_nul_rejection() {
    // 8. Embedded NUL rejection
    PathIdentity out;
    std::string nulStr("C:\\Data\0\\file.txt", 17);
    assert(WindowsPathAdapter::toPathIdentity(nulStr, out) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_path_identity_rejection() {
    // 9. Invalid PathIdentity rejection if representable
    PathIdentity out;
    // Bare drive syntax is ambiguous/drive-relative
    assert(WindowsPathAdapter::toPathIdentity("C:", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    // Drive-relative without slash
    assert(WindowsPathAdapter::toPathIdentity("C:file.txt", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    // Malformed colons
    assert(WindowsPathAdapter::toPathIdentity("C::/foo", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(WindowsPathAdapter::toPathIdentity("C:/foo:bar", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(WindowsPathAdapter::toPathIdentity("1:/foo", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    // Malformed UNC
    assert(WindowsPathAdapter::toPathIdentity("///server/share", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(WindowsPathAdapter::toPathIdentity("//server", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(WindowsPathAdapter::toPathIdentity("//", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    // Ambiguous single-slash root
    assert(WindowsPathAdapter::toPathIdentity("/root/file.txt", out) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_existing_out_identity_remains_unchanged_on_failure() {
    // 10. Existing outIdentity remains unchanged on failure
    PathIdentity original("C:/Preserved/Existing.dat");
    assert(original.isValid());

    PathIdentity out = original;

    // Failure: empty path
    assert(WindowsPathAdapter::toPathIdentity("", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == original);
    assert(out.normalized() == "C:/Preserved/Existing.dat");

    // Failure: relative path
    assert(WindowsPathAdapter::toPathIdentity("relative\\file.txt", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == original);

    // Failure: embedded NUL
    std::string nulStr("C:\\Bad\0\\Path", 13);
    assert(WindowsPathAdapter::toPathIdentity(nulStr, out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == original);

    // Failure: invalid syntax
    assert(WindowsPathAdapter::toPathIdentity("C:drive_rel", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(out == original);
}

static void test_successful_output_is_valid() {
    // 11. Successful output is valid
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\Valid\\Path.dat", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.validate() == SENTINAL_STATUS_SUCCESS);
}

static void test_successful_output_is_absolute() {
    // 12. Successful output is absolute
    PathIdentity out;

    assert(WindowsPathAdapter::toPathIdentity("C:\\Folder\\file.txt", out) == SENTINAL_STATUS_SUCCESS);
    assert(out.isAbsolute());
    assert(!out.isRelative());

    assert(WindowsPathAdapter::toPathIdentity("C:\\", out) == SENTINAL_STATUS_SUCCESS);
    assert(out.isAbsolute());
    assert(!out.isRelative());

    assert(WindowsPathAdapter::toPathIdentity("\\\\server\\share\\data", out) == SENTINAL_STATUS_SUCCESS);
    assert(out.isAbsolute());
    assert(!out.isRelative());
}

static void test_deterministic_conversion() {
    // 13. Deterministic conversion
    PathIdentity out1;
    PathIdentity out2;

    SentinalStatus s1 = WindowsPathAdapter::toPathIdentity("C:\\Users\\User\\Documents\\file.txt", out1);
    SentinalStatus s2 = WindowsPathAdapter::toPathIdentity("C:\\Users\\User\\Documents\\file.txt", out2);

    assert(s1 == s2);
    assert(s1 == SENTINAL_STATUS_SUCCESS);
    assert(out1 == out2);
    assert(out1.original() == out2.original());
    assert(out1.normalized() == out2.normalized());
    assert(out1.getType() == out2.getType());
    assert(out1.depth() == out2.depth());
}

static void test_no_filesystem_existence_requirement() {
    // 14. No filesystem existence requirement
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\Definitively\\NonExistent_999888\\phantom_file_12345.xyz", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.normalized() == "C:/Definitively/NonExistent_999888/phantom_file_12345.xyz");
}

static void test_path_containing_dot_remains_structurally_unchanged() {
    // 15. Path containing '.' remains structurally unchanged except for existing separator normalization
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\Folder\\.\\sub\\file.txt", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.normalized() == "C:/Folder/./sub/file.txt");
}

static void test_path_containing_dotdot_remains_structurally_unchanged() {
    // 16. Path containing '..' remains structurally unchanged except for existing separator normalization
    PathIdentity out;
    SentinalStatus status = WindowsPathAdapter::toPathIdentity("C:\\Folder\\..\\sub\\file.txt", out);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.normalized() == "C:/Folder/../sub/file.txt");
}

int main() {
    std::cout << "[WindowsPathAdapter Tests] Running test suite..." << std::endl;

    test_valid_drive_absolute_path();
    test_valid_drive_root_path();
    test_valid_unc_path();
    test_case_preservation();
    test_separator_normalization();
    test_relative_path_rejection();
    test_empty_path_rejection();
    test_embedded_nul_rejection();
    test_invalid_path_identity_rejection();
    test_existing_out_identity_remains_unchanged_on_failure();
    test_successful_output_is_valid();
    test_successful_output_is_absolute();
    test_deterministic_conversion();
    test_no_filesystem_existence_requirement();
    test_path_containing_dot_remains_structurally_unchanged();
    test_path_containing_dotdot_remains_structurally_unchanged();

    std::cout << "[WindowsPathAdapter Tests] All tests passed successfully." << std::endl;
    return 0;
}
