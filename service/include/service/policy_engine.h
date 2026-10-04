#pragma once

#include <string>
#include <vector>
#include <cstddef>
#include <sentinal/common.h>
#include "service/target.h"
#include "service/path_identity.h"

namespace sentinel::service {

class PolicyEngine {
public:
    PolicyEngine() = default;

    // Phase 1 Target API
    SentinalStatus addTarget(const ProtectionTarget& target, SentinalTargetId* outId = nullptr);
    SentinalStatus updateTarget(const ProtectionTarget& target);
    SentinalStatus removeTarget(SentinalTargetId id);
    SentinalStatus removeTarget(const std::string& path);
    SentinalStatus removeTarget(const PathIdentity& path);

    bool hasTarget(SentinalTargetId id) const;
    bool hasTarget(const std::string& path) const;
    bool hasTarget(const PathIdentity& path) const;

    SentinalStatus getTarget(SentinalTargetId id, ProtectionTarget& outTarget) const;
    SentinalStatus getTarget(const std::string& path, ProtectionTarget& outTarget) const;
    SentinalStatus getTarget(const PathIdentity& path, ProtectionTarget& outTarget) const;

    std::vector<ProtectionTarget> listTargets() const;
    void clearTargets();
    size_t getTargetCount() const;

    // Evaluation API
    SentinalDecision evaluate(const std::string& path, SentinalFileOp op,
                             SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW) const;
    SentinalDecision evaluate(const PathIdentity& path, SentinalFileOp op,
                             SentinalDecision defaultDecision = SENTINAL_DECISION_ALLOW) const;

    // Phase 0 convenience API
    SentinalStatus addTarget(const std::string& path, SentinalTargetType type,
                             SentinalDecision decision = SENTINAL_DECISION_DENY);

private:
    std::vector<ProtectionTarget> m_targets;
    SentinalTargetId m_nextId = 1;
};

} // namespace sentinel::service
