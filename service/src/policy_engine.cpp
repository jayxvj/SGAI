#include "service/policy_engine.h"
#include <algorithm>

namespace sentinel::service {

namespace {

bool startsWith(const std::string& str, const std::string& prefix) {
    if (str.size() < prefix.size()) return false;
    return str.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

SentinalStatus PolicyEngine::addTarget(const ProtectionTarget& target, SentinalTargetId* outId) {
    if (target.path.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalStatus status = target.validate();
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    std::string normPath = normalizePath(target.path);
    if (hasTarget(normPath)) {
        return SENTINAL_STATUS_ALREADY_EXISTS;
    }

    ProtectionTarget t = target;
    t.id = m_nextId++;
    t.path = normPath;

    if (outId) {
        *outId = t.id;
    }

    m_targets.push_back(t);
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus PolicyEngine::addTarget(const std::string& path, SentinalTargetType type, SentinalDecision decision) {
    if (path.empty() || type == SENTINAL_TARGET_UNKNOWN) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    std::string normPath = normalizePath(path);
    for (auto& t : m_targets) {
        if (t.path == normPath) {
            t.type = type;
            t.decision = decision;
            return SENTINAL_STATUS_SUCCESS;
        }
    }

    ProtectionTarget t;
    t.path = path;
    t.type = type;
    t.decision = decision;
    t.opMask = SENTINAL_ALL_FILE_OPS;
    t.enabled = true;

    return addTarget(t);
}

SentinalStatus PolicyEngine::updateTarget(const ProtectionTarget& target) {
    SentinalStatus status = target.validate();
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.id == target.id;
    });

    if (it == m_targets.end()) {
        return SENTINAL_STATUS_NOT_FOUND;
    }

    std::string normPath = normalizePath(target.path);
    if (normPath != it->path) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    it->type = target.type;
    it->opMask = target.opMask;
    it->decision = target.decision;
    it->enabled = target.enabled;
    it->description = target.description;

    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus PolicyEngine::removeTarget(SentinalTargetId id) {
    if (id == SENTINAL_INVALID_TARGET_ID) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.id == id;
    });

    if (it == m_targets.end()) {
        return SENTINAL_STATUS_NOT_FOUND;
    }

    m_targets.erase(it);
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus PolicyEngine::removeTarget(const std::string& path) {
    if (path.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    std::string normPath = normalizePath(path);
    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.path == normPath;
    });

    if (it == m_targets.end()) {
        return SENTINAL_STATUS_NOT_FOUND;
    }

    m_targets.erase(it);
    return SENTINAL_STATUS_SUCCESS;
}

bool PolicyEngine::hasTarget(SentinalTargetId id) const {
    if (id == SENTINAL_INVALID_TARGET_ID) {
        return false;
    }

    return std::any_of(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.id == id;
    });
}

bool PolicyEngine::hasTarget(const std::string& path) const {
    if (path.empty()) {
        return false;
    }

    std::string normPath = normalizePath(path);
    return std::any_of(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.path == normPath;
    });
}

SentinalStatus PolicyEngine::getTarget(SentinalTargetId id, ProtectionTarget& outTarget) const {
    if (id == SENTINAL_INVALID_TARGET_ID) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.id == id;
    });

    if (it == m_targets.end()) {
        return SENTINAL_STATUS_NOT_FOUND;
    }

    outTarget = *it;
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus PolicyEngine::getTarget(const std::string& path, ProtectionTarget& outTarget) const {
    if (path.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    std::string normPath = normalizePath(path);
    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.path == normPath;
    });

    if (it == m_targets.end()) {
        return SENTINAL_STATUS_NOT_FOUND;
    }

    outTarget = *it;
    return SENTINAL_STATUS_SUCCESS;
}

std::vector<ProtectionTarget> PolicyEngine::listTargets() const {
    return m_targets;
}

void PolicyEngine::clearTargets() {
    m_targets.clear();
}

size_t PolicyEngine::getTargetCount() const {
    return m_targets.size();
}

SentinalDecision PolicyEngine::evaluate(const std::string& path, SentinalFileOp op, SentinalDecision defaultDecision) const {
    if (op == SENTINAL_OP_NONE || path.empty()) {
        return defaultDecision;
    }

    std::string normPath = normalizePath(path);

    for (const auto& target : m_targets) {
        if (!target.enabled) {
            continue;
        }

        if ((static_cast<uint32_t>(op) & target.opMask) == 0) {
            continue;
        }

        if (target.type == SENTINAL_TARGET_FILE) {
            if (normPath == target.path) {
                return target.decision;
            }
        } else if (target.type == SENTINAL_TARGET_DIRECTORY) {
            if (normPath == target.path) {
                return target.decision;
            }
            std::string prefix = target.path + "/";
            if (startsWith(normPath, prefix)) {
                std::string remainder = normPath.substr(prefix.size());
                if (remainder.find('/') == std::string::npos) {
                    return target.decision;
                }
            }
        } else if (target.type == SENTINAL_TARGET_DIRECTORY_RECURSIVE) {
            if (normPath == target.path) {
                return target.decision;
            }
            std::string prefix = target.path + "/";
            if (startsWith(normPath, prefix)) {
                return target.decision;
            }
        }
    }

    return defaultDecision;
}

} // namespace sentinel::service
