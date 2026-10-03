#include "service/policy_engine.h"
#include <algorithm>
#include <cctype>

namespace sentinel::service {

namespace {

std::string normalizePath(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        if (c == '\\') return '/';
        return static_cast<char>(std::tolower(c));
    });
    while (result.size() > 1 && result.back() == '/') {
        result.pop_back();
    }
    return result;
}

bool startsWith(const std::string& str, const std::string& prefix) {
    if (str.size() < prefix.size()) return false;
    return str.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

SentinalStatus PolicyEngine::addTarget(const std::string& path, SentinalTargetType type, SentinalDecision decision) {
    if (path.empty() || type == SENTINAL_TARGET_UNKNOWN) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    std::string norm = normalizePath(path);
    for (auto& rule : m_rules) {
        if (normalizePath(rule.path) == norm) {
            rule.type = type;
            rule.decisionOnMatch = decision;
            return SENTINAL_STATUS_SUCCESS;
        }
    }

    m_rules.push_back({path, type, decision});
    return SENTINAL_STATUS_SUCCESS;
}

SentinalStatus PolicyEngine::removeTarget(const std::string& path) {
    if (path.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    std::string norm = normalizePath(path);
    auto it = std::remove_if(m_rules.begin(), m_rules.end(), [&](const TargetRule& rule) {
        return normalizePath(rule.path) == norm;
    });

    if (it == m_rules.end()) {
        return SENTINAL_STATUS_NOT_FOUND;
    }

    m_rules.erase(it, m_rules.end());
    return SENTINAL_STATUS_SUCCESS;
}

void PolicyEngine::clearTargets() {
    m_rules.clear();
}

size_t PolicyEngine::getTargetCount() const {
    return m_rules.size();
}

SentinalDecision PolicyEngine::evaluate(const std::string& path, SentinalFileOp op, SentinalDecision defaultDecision) const {
    if (op == SENTINAL_OP_NONE || path.empty()) {
        return defaultDecision;
    }

    std::string normPath = normalizePath(path);

    for (const auto& rule : m_rules) {
        std::string normRule = normalizePath(rule.path);

        if (rule.type == SENTINAL_TARGET_FILE) {
            if (normPath == normRule) {
                return rule.decisionOnMatch;
            }
        } else if (rule.type == SENTINAL_TARGET_DIRECTORY) {
            if (normPath == normRule) {
                return rule.decisionOnMatch;
            }
            std::string prefix = normRule + "/";
            if (startsWith(normPath, prefix)) {
                // Must be directly in the directory (no additional slashes)
                std::string remainder = normPath.substr(prefix.size());
                if (remainder.find('/') == std::string::npos) {
                    return rule.decisionOnMatch;
                }
            }
        } else if (rule.type == SENTINAL_TARGET_DIRECTORY_RECURSIVE) {
            if (normPath == normRule) {
                return rule.decisionOnMatch;
            }
            std::string prefix = normRule + "/";
            if (startsWith(normPath, prefix)) {
                return rule.decisionOnMatch;
            }
        }
    }

    return defaultDecision;
}

} // namespace sentinel::service
