#include "service/path_identity.h"
#include <algorithm>
#include <cctype>

namespace sentinel::service {

PathIdentity::PathIdentity(std::string rawPath)
    : m_original(std::move(rawPath)) {
    parseAndNormalize();
}

bool PathIdentity::isValid() const noexcept {
    return m_isValid && m_type != PathType::Invalid;
}

PathType PathIdentity::getType() const noexcept {
    return m_type;
}

bool PathIdentity::isAbsolute() const noexcept {
    return m_type == PathType::DriveAbsolute ||
           m_type == PathType::DriveRoot ||
           m_type == PathType::Unc;
}

bool PathIdentity::isRelative() const noexcept {
    return m_type == PathType::Relative;
}

bool PathIdentity::isDriveRoot() const noexcept {
    return m_type == PathType::DriveRoot;
}

bool PathIdentity::isUnc() const noexcept {
    return m_type == PathType::Unc;
}

const std::string& PathIdentity::original() const noexcept {
    return m_original;
}

const std::string& PathIdentity::normalized() const noexcept {
    return m_normalized;
}

const char* PathIdentity::c_str() const noexcept {
    return m_normalized.c_str();
}

bool PathIdentity::isDirectParentOf(const PathIdentity& other) const {
    if (!isValid() || !other.isValid()) {
        return false;
    }

    if (m_type == PathType::DriveRoot) {
        if (other.m_type != PathType::DriveAbsolute) {
            return false;
        }
        if (m_normalized.size() != 3 || other.m_normalized.size() <= 3) {
            return false;
        }
        if (m_normalized[0] != other.m_normalized[0] || m_normalized[1] != ':') {
            return false;
        }
        std::string remainder = other.m_normalized.substr(3);
        return remainder.find('/') == std::string::npos;
    }

    if (m_type != other.m_type) {
        return false;
    }

    std::string prefix = m_normalized + "/";
    if (other.m_normalized.size() <= prefix.size()) {
        return false;
    }

    if (other.m_normalized.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }

    std::string remainder = other.m_normalized.substr(prefix.size());
    return !remainder.empty() && remainder.find('/') == std::string::npos;
}

bool PathIdentity::isDescendantOf(const PathIdentity& other) const {
    if (!isValid() || !other.isValid()) {
        return false;
    }

    if (other.m_type == PathType::DriveRoot) {
        if (m_type != PathType::DriveAbsolute) {
            return false;
        }
        if (other.m_normalized.size() != 3 || m_normalized.size() <= 3) {
            return false;
        }
        if (m_normalized[0] != other.m_normalized[0] || m_normalized[1] != ':') {
            return false;
        }
        return true;
    }

    if (m_type != other.m_type) {
        return false;
    }

    std::string prefix = other.m_normalized + "/";
    if (m_normalized.size() <= prefix.size()) {
        return false;
    }

    return m_normalized.compare(0, prefix.size(), prefix) == 0;
}

bool PathIdentity::operator==(const PathIdentity& other) const noexcept {
    if (m_isValid != other.m_isValid) {
        return false;
    }
    if (!m_isValid) {
        return true;
    }
    return m_normalized == other.m_normalized;
}

bool PathIdentity::operator!=(const PathIdentity& other) const noexcept {
    return !(*this == other);
}

bool PathIdentity::operator<(const PathIdentity& other) const noexcept {
    if (m_isValid != other.m_isValid) {
        return !m_isValid && other.m_isValid;
    }
    return m_normalized < other.m_normalized;
}

bool PathIdentity::equalsCaseInsensitive(const PathIdentity& other) const noexcept {
    if (!isValid() || !other.isValid()) {
        return false;
    }
    if (m_normalized.size() != other.m_normalized.size()) {
        return false;
    }
    for (size_t i = 0; i < m_normalized.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(m_normalized[i])) !=
            std::tolower(static_cast<unsigned char>(other.m_normalized[i]))) {
            return false;
        }
    }
    return true;
}

SentinalStatus PathIdentity::validate() const noexcept {
    return isValid() ? SENTINAL_STATUS_SUCCESS : SENTINAL_STATUS_INVALID_PARAMETER;
}

SentinalStatus PathIdentity::create(std::string rawPath, PathIdentity& outIdentity) {
    PathIdentity id(std::move(rawPath));
    if (!id.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    outIdentity = std::move(id);
    return SENTINAL_STATUS_SUCCESS;
}

void PathIdentity::parseAndNormalize() {
    m_isValid = false;
    m_type = PathType::Invalid;
    m_normalized.clear();

    if (m_original.empty()) {
        return;
    }

    // Reject embedded NUL characters
    if (m_original.find('\0') != std::string::npos) {
        return;
    }

    // Convert all backslashes to forward slashes
    std::string s = m_original;
    for (char& c : s) {
        if (c == '\\') {
            c = '/';
        }
    }

    // Check for UNC path
    if (s.size() >= 2 && s[0] == '/' && s[1] == '/') {
        if (s.size() >= 3 && s[2] == '/') {
            // Triple slash or more is invalid
            return;
        }

        size_t serverStart = 2;
        size_t slashAfterServer = s.find('/', serverStart);
        if (slashAfterServer == std::string::npos || slashAfterServer == serverStart) {
            return;
        }

        std::string server = s.substr(serverStart, slashAfterServer - serverStart);
        size_t shareStart = slashAfterServer + 1;
        if (shareStart >= s.size()) {
            return;
        }

        size_t slashAfterShare = s.find('/', shareStart);
        std::string share = (slashAfterShare == std::string::npos)
                                ? s.substr(shareStart)
                                : s.substr(shareStart, slashAfterShare - shareStart);

        if (share.empty()) {
            return;
        }

        if (server.find(':') != std::string::npos || share.find(':') != std::string::npos) {
            return;
        }

        std::string norm = "//" + server + "/" + share;
        if (slashAfterShare != std::string::npos) {
            std::string rest = s.substr(slashAfterShare);
            std::string normRest;
            for (char c : rest) {
                if (c == '/') {
                    if (normRest.empty() || normRest.back() != '/') {
                        normRest += '/';
                    }
                } else {
                    normRest += c;
                }
            }
            while (normRest.size() > 1 && normRest.back() == '/') {
                normRest.pop_back();
            }
            if (normRest != "/") {
                norm += normRest;
            }
        }

        m_normalized = std::move(norm);
        m_type = PathType::Unc;
        m_isValid = true;
        return;
    }

    // Check for drive letter syntax: e.g. "C:/"
    size_t colonPos = s.find(':');
    if (colonPos != std::string::npos) {
        if (colonPos != 1) {
            // Colon must be at index 1 for drive letters
            return;
        }

        char d = s[0];
        if (!((d >= 'A' && d <= 'Z') || (d >= 'a' && d <= 'z'))) {
            // Drive letter must be ASCII alphabetic
            return;
        }

        if (s.find(':', 2) != std::string::npos) {
            // No secondary colons allowed
            return;
        }

        if (s.size() == 2) {
            // Bare drive syntax like "C:" is ambiguous/drive-relative -> invalid
            return;
        }

        if (s[2] != '/') {
            // e.g. "C:foo" is drive-relative -> invalid
            return;
        }

        // Collapse redundant slashes
        std::string norm;
        norm += d;
        norm += ':';
        norm += '/';

        for (size_t i = 3; i < s.size(); ++i) {
            if (s[i] == '/') {
                if (norm.back() != '/') {
                    norm += '/';
                }
            } else {
                norm += s[i];
            }
        }

        // Remove redundant trailing slashes, preserving root "C:/"
        while (norm.size() > 3 && norm.back() == '/') {
            norm.pop_back();
        }

        if (norm.size() == 3) {
            m_type = PathType::DriveRoot;
        } else {
            m_type = PathType::DriveAbsolute;
        }

        m_normalized = std::move(norm);
        m_isValid = true;
        return;
    }

    // If it starts with single '/', without drive or UNC, it is an ambiguous rooted path in Windows
    if (s[0] == '/') {
        return;
    }

    // Relative path
    std::string norm;
    for (char c : s) {
        if (c == '/') {
            if (norm.empty() || norm.back() != '/') {
                norm += '/';
            }
        } else {
            norm += c;
        }
    }

    while (norm.size() > 1 && norm.back() == '/') {
        norm.pop_back();
    }

    if (norm.empty() || norm == "/") {
        return;
    }

    m_normalized = std::move(norm);
    m_type = PathType::Relative;
    m_isValid = true;
}

} // namespace sentinel::service
