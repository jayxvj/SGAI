#pragma once

#include <string>
#include <vector>
#include <cstddef>
#include <sentinal/common.h>

namespace sentinel::service {

struct TargetRule {
    std::string path;
    SentinalTargetType type;
    SentinalDecision decisionOnMatch;
};

class PolicyEngine {
public:
    PolicyEngine() = default;

    SentinalStatus addTarget(const std::string& path, SentinalTargetType type, SentinalDecision decision = SENTINAL_DECISION_DENY);
    SentinalStatus removeTarget(const std::string& path);
    void clearTargets();

    size_t getTargetCount() const;

    SentinalDecision evaluate(const std::string& path, SentinalFileOp op, SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW) const;

private:
    std::vector<TargetRule> m_rules;
};

} // namespace sentinel::service
