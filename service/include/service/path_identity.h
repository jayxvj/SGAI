#pragma once

#include <string>
#include <sentinal/common.h>

namespace sentinel::service {

enum class PathType {
    Invalid,
    Relative,
    DriveAbsolute,
    DriveRoot,
    Unc
};

class PathIdentity {
public:
    PathIdentity() = default;
    explicit PathIdentity(std::string rawPath);

    bool isValid() const noexcept;
    PathType getType() const noexcept;
    bool isAbsolute() const noexcept;
    bool isRelative() const noexcept;
    bool isDriveRoot() const noexcept;
    bool isUnc() const noexcept;

    const std::string& original() const noexcept;
    const std::string& normalized() const noexcept;
    const char* c_str() const noexcept;

    bool isDirectParentOf(const PathIdentity& other) const;
    bool isDescendantOf(const PathIdentity& other) const;

    bool operator==(const PathIdentity& other) const noexcept;
    bool operator!=(const PathIdentity& other) const noexcept;
    bool operator<(const PathIdentity& other) const noexcept;

    bool equalsCaseInsensitive(const PathIdentity& other) const noexcept;

    SentinalStatus validate() const noexcept;

    static SentinalStatus create(
        std::string rawPath,
        PathIdentity& outIdentity);

private:
    std::string m_original;
    std::string m_normalized;
    PathType m_type{PathType::Invalid};
    bool m_isValid{false};

    void parseAndNormalize();
};

} // namespace sentinel::service
