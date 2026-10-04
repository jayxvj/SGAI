#include "service/policy_engine.h"
#include <algorithm>

namespace sentinel::service {

SentinalStatus PolicyEngine::addTarget(const ProtectionTarget& target, SentinalTargetId* outId) {
    if (target.path.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalStatus status = target.validate();
    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    PathIdentity pi(target.path);
    if (!pi.isValid() || pi.isRelative()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (hasTarget(pi)) {
        return SENTINAL_STATUS_ALREADY_EXISTS;
    }

    ProtectionTarget t = target;
    t.id = m_nextId++;
    t.path = pi.normalized();
    t.pathIdentity = pi;

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

    PathIdentity pi(path);
    if (!pi.isValid() || pi.isRelative()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    for (auto& t : m_targets) {
        if (t.pathIdentity == pi) {
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

    PathIdentity pi(target.path);
    if (!pi.isValid() || pi != it->pathIdentity) {
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

SentinalStatus PolicyEngine::removeTarget(const PathIdentity& path) {
    if (!path.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.pathIdentity == path;
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

    PathIdentity pi(path);
    if (!pi.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return removeTarget(pi);
}

bool PolicyEngine::hasTarget(SentinalTargetId id) const {
    if (id == SENTINAL_INVALID_TARGET_ID) {
        return false;
    }

    return std::any_of(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.id == id;
    });
}

bool PolicyEngine::hasTarget(const PathIdentity& path) const {
    if (!path.isValid()) {
        return false;
    }

    return std::any_of(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.pathIdentity == path;
    });
}

bool PolicyEngine::hasTarget(const std::string& path) const {
    if (path.empty()) {
        return false;
    }

    PathIdentity pi(path);
    if (!pi.isValid()) {
        return false;
    }

    return hasTarget(pi);
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

SentinalStatus PolicyEngine::getTarget(const PathIdentity& path, ProtectionTarget& outTarget) const {
    if (!path.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    auto it = std::find_if(m_targets.begin(), m_targets.end(), [&](const ProtectionTarget& t) {
        return t.pathIdentity == path;
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

    PathIdentity pi(path);
    if (!pi.isValid()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    return getTarget(pi, outTarget);
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

SentinalDecision PolicyEngine::evaluate(const PathIdentity& path, SentinalFileOp op, SentinalDecision defaultDecision) const {
    if (op == SENTINAL_OP_NONE || !path.isValid()) {
        return defaultDecision;
    }

    int bestPrecedence = 0; // 0 = No match, 1 = Recursive, 2 = Direct-child, 3 = Exact Dir, 4 = Exact File
    size_t bestDepth = 0;
    SentinalDecision bestDecision = defaultDecision;

    for (const auto& target : m_targets) {
        if (!target.enabled) {
            continue;
        }

        if ((static_cast<uint32_t>(op) & target.opMask) == 0) {
            continue;
        }

        int precedence = 0;

        if (target.type == SENTINAL_TARGET_FILE) {
            if (path == target.pathIdentity) {
                precedence = 4; // Exact FILE
            }
        } else if (target.type == SENTINAL_TARGET_DIRECTORY) {
            if (path == target.pathIdentity) {
                precedence = 3; // Exact DIRECTORY
            } else if (target.pathIdentity.isDirectParentOf(path)) {
                precedence = 2; // Direct-child DIRECTORY
            }
        } else if (target.type == SENTINAL_TARGET_DIRECTORY_RECURSIVE) {
            if (path == target.pathIdentity || path.isDescendantOf(target.pathIdentity)) {
                precedence = 1; // Recursive DIRECTORY
            }
        }

        if (precedence == 0) {
            continue;
        }

        size_t targetDepth = target.pathIdentity.depth();

        if (precedence > bestPrecedence) {
            bestPrecedence = precedence;
            bestDepth = targetDepth;
            bestDecision = target.decision;
        } else if (precedence == bestPrecedence && precedence == 1) {
            // For multiple Recursive DIRECTORY matches, the target with the greatest depth wins
            if (targetDepth > bestDepth) {
                bestDepth = targetDepth;
                bestDecision = target.decision;
            }
        }
    }

    return (bestPrecedence > 0) ? bestDecision : defaultDecision;
}

SentinalDecision PolicyEngine::evaluate(const std::string& path, SentinalFileOp op, SentinalDecision defaultDecision) const {
    if (op == SENTINAL_OP_NONE || path.empty()) {
        return defaultDecision;
    }

    PathIdentity pi(path);
    return evaluate(pi, op, defaultDecision);
}

} // namespace sentinel::service
