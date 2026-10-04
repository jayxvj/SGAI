#include <cassert>
#include <iostream>
#include "service/path_identity.h"
#include "service/target.h"
#include "service/policy_engine.h"

using namespace sentinel::service;

static void test_empty_and_nul_input() {
    PathIdentity empty("");
    assert(!empty.isValid());
    assert(empty.getType() == PathType::Invalid);
    assert(empty.validate() == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(empty.original().empty());
    assert(empty.normalized().empty());

    // Embedded NUL character
    std::string nulStr("C:/Data\0/file.txt", 16);
    PathIdentity withNul(nulStr);
    assert(!withNul.isValid());
    assert(withNul.getType() == PathType::Invalid);
    assert(withNul.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    // Factory method check
    PathIdentity out;
    assert(PathIdentity::create("", out) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(PathIdentity::create("C:/Valid/Path.txt", out) == SENTINAL_STATUS_SUCCESS);
    assert(out.isValid());
    assert(out.normalized() == "C:/Valid/Path.txt");
}

static void test_drive_syntax_validation() {
    // Bare drive syntax is ambiguous/drive-relative -> must be rejected
    PathIdentity bareC("C:");
    assert(!bareC.isValid());
    assert(bareC.getType() == PathType::Invalid);

    PathIdentity bareD("d:");
    assert(!bareD.isValid());

    // Drive-relative without slash
    PathIdentity driveRel("C:file.txt");
    assert(!driveRel.isValid());

    PathIdentity driveRelDir("C:dir/sub");
    assert(!driveRelDir.isValid());

    // Malformed drive colons
    PathIdentity mal1("::/foo");
    assert(!mal1.isValid());

    PathIdentity mal2("1:/foo");
    assert(!mal2.isValid());

    PathIdentity mal3("C::/foo");
    assert(!mal3.isValid());

    PathIdentity mal4("C:D:/foo");
    assert(!mal4.isValid());

    PathIdentity mal5("C:/foo:bar");
    assert(!mal5.isValid());
}

static void test_classification_and_forms() {
    // DriveAbsolute
    PathIdentity da("C:/Data/file.txt");
    assert(da.isValid());
    assert(da.getType() == PathType::DriveAbsolute);
    assert(da.isAbsolute());
    assert(!da.isRelative());
    assert(!da.isDriveRoot());
    assert(!da.isUnc());

    // DriveRoot
    PathIdentity dr("C:/");
    assert(dr.isValid());
    assert(dr.getType() == PathType::DriveRoot);
    assert(dr.isAbsolute());
    assert(dr.isDriveRoot());
    assert(!dr.isRelative());
    assert(!dr.isUnc());
    assert(dr.normalized() == "C:/");

    PathIdentity drBackslash("D:\\");
    assert(drBackslash.isValid());
    assert(drBackslash.getType() == PathType::DriveRoot);
    assert(drBackslash.normalized() == "D:/");

    // UNC paths
    PathIdentity unc("\\\\server\\share\\data");
    assert(unc.isValid());
    assert(unc.getType() == PathType::Unc);
    assert(unc.isAbsolute());
    assert(unc.isUnc());
    assert(!unc.isRelative());
    assert(!unc.isDriveRoot());
    assert(unc.normalized() == "//server/share/data");

    PathIdentity uncRoot("\\\\server\\share\\");
    assert(uncRoot.isValid());
    assert(uncRoot.getType() == PathType::Unc);
    assert(uncRoot.normalized() == "//server/share");

    // Malformed UNC paths
    PathIdentity uncBad1("///server/share");
    assert(!uncBad1.isValid());

    PathIdentity uncBad2("//server");
    assert(!uncBad2.isValid());

    PathIdentity uncBad3("//server/");
    assert(!uncBad3.isValid());

    PathIdentity uncBad4("//");
    assert(!uncBad4.isValid());

    // Relative paths
    PathIdentity rel("data/file.txt");
    assert(rel.isValid());
    assert(rel.getType() == PathType::Relative);
    assert(rel.isRelative());
    assert(!rel.isAbsolute());
    assert(rel.normalized() == "data/file.txt");

    PathIdentity relBack("sub\\folder\\doc.pdf");
    assert(relBack.isValid());
    assert(relBack.getType() == PathType::Relative);
    assert(relBack.normalized() == "sub/folder/doc.pdf");
}

static void test_normalization_and_separators() {
    // Slashes converted
    PathIdentity p("C:\\Folder\\Sub\\file.txt");
    assert(p.normalized() == "C:/Folder/Sub/file.txt");
    assert(p.original() == "C:\\Folder\\Sub\\file.txt");
    assert(std::string(p.c_str()) == "C:/Folder/Sub/file.txt");

    // Redundant consecutive slashes collapsed
    PathIdentity pRedundant("C:////Folder///Sub//file.txt");
    assert(pRedundant.normalized() == "C:/Folder/Sub/file.txt");

    // Trailing separators removed
    PathIdentity pTrailing("C:\\Folder\\Sub\\");
    assert(pTrailing.normalized() == "C:/Folder/Sub");

    // Drive root preserves trailing slash
    PathIdentity pRoot("C:\\");
    assert(pRoot.normalized() == "C:/");

    PathIdentity pRootSlash("C:/");
    assert(pRootSlash.normalized() == "C:/");
}

static void test_case_preservation_and_equality() {
    // Case preserved in normalized output
    PathIdentity pCase("C:/MyFolder/MyFile.TXT");
    assert(pCase.normalized() == "C:/MyFolder/MyFile.TXT");

    // Equality with normalized variations
    PathIdentity p1("C:\\A\\B");
    PathIdentity p2("C:/A/B/");
    assert(p1 == p2);
    assert(!(p1 != p2));

    // Case is significant for ==
    PathIdentity pUpper("C:/FOLDER/FILE.TXT");
    PathIdentity pLower("C:/folder/file.txt");
    assert(pUpper != pLower);
    assert(!(pUpper == pLower));

    // Case-insensitive helper
    assert(pUpper.equalsCaseInsensitive(pLower));
    assert(!pUpper.equalsCaseInsensitive(PathIdentity("C:/folder/other.txt")));

    // Ordering (<)
    assert(PathIdentity("C:/A") < PathIdentity("C:/B"));
    assert(!(PathIdentity("C:/B") < PathIdentity("C:/A")));
}

static void test_hierarchy() {
    PathIdentity parent("C:/Folder");
    PathIdentity child("C:/Folder/file.txt");
    PathIdentity deep("C:/Folder/sub/file.txt");
    PathIdentity sibling("C:/Folder_sibling/file.txt");
    PathIdentity self("C:/Folder");

    // Direct parent verification
    assert(parent.isDirectParentOf(child));
    assert(!parent.isDirectParentOf(deep));
    assert(!parent.isDirectParentOf(sibling));
    assert(!parent.isDirectParentOf(self));

    // Descendant verification
    assert(child.isDescendantOf(parent));
    assert(deep.isDescendantOf(parent));
    assert(!sibling.isDescendantOf(parent));
    assert(!self.isDescendantOf(parent));

    // DriveRoot hierarchy
    PathIdentity root("C:/");
    PathIdentity rootChild("C:/file.txt");
    PathIdentity rootDeep("C:/Folder/file.txt");
    PathIdentity otherDrive("D:/file.txt");

    assert(root.isDirectParentOf(rootChild));
    assert(!root.isDirectParentOf(rootDeep));
    assert(rootChild.isDescendantOf(root));
    assert(rootDeep.isDescendantOf(root));
    assert(!root.isDirectParentOf(otherDrive));
    assert(!otherDrive.isDescendantOf(root));

    // Cross-type / boundary isolation
    PathIdentity uncPath("//server/share/file.txt");
    PathIdentity relPath("Folder/file.txt");
    assert(!parent.isDirectParentOf(uncPath));
    assert(!parent.isDirectParentOf(relPath));
    assert(!child.isDescendantOf(uncPath));
    assert(!child.isDescendantOf(relPath));
}

static void test_protection_target_relative_rejection() {
    // Relative paths must be rejected by ProtectionTarget and PolicyEngine
    ProtectionTarget relTarget;
    relTarget.path = "relative/path/target.txt";
    relTarget.type = SENTINAL_TARGET_FILE;
    relTarget.opMask = SENTINAL_OP_READ;
    relTarget.decision = SENTINAL_DECISION_DENY;

    assert(relTarget.validate() == SENTINAL_STATUS_INVALID_PARAMETER);

    PolicyEngine pe;
    assert(pe.addTarget(relTarget) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(pe.addTarget("relative/path/target.txt", SENTINAL_TARGET_FILE) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_depth() {
    // Invalid
    assert(PathIdentity("").depth() == 0);
    assert(PathIdentity("C:").depth() == 0);

    // Drive root
    assert(PathIdentity("C:/").depth() == 1);
    assert(PathIdentity("D:\\").depth() == 1);

    // Drive absolute & nested
    assert(PathIdentity("C:/Sensitive").depth() == 2);
    assert(PathIdentity("C:\\Sensitive\\Finance").depth() == 3);
    assert(PathIdentity("C:/Sensitive/Finance/Payroll").depth() == 4);
    assert(PathIdentity("C:/A/B/C/D/E/file.txt").depth() == 7);

    // UNC
    assert(PathIdentity("\\\\server\\share").depth() == 2);
    assert(PathIdentity("//server/share/folder").depth() == 3);
    assert(PathIdentity("//server/share/folder/sub").depth() == 4);

    // Relative
    assert(PathIdentity("file.txt").depth() == 1);
    assert(PathIdentity("data/file.txt").depth() == 2);
    assert(PathIdentity("a/b/c/d").depth() == 4);
}

int main() {
    std::cout << "[PathIdentity Tests] Running test suite..." << std::endl;

    test_empty_and_nul_input();
    test_drive_syntax_validation();
    test_classification_and_forms();
    test_normalization_and_separators();
    test_case_preservation_and_equality();
    test_hierarchy();
    test_protection_target_relative_rejection();
    test_depth();

    std::cout << "[PathIdentity Tests] All tests passed successfully." << std::endl;
    return 0;
}
