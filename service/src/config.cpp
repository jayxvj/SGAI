#include "service/config.h"

namespace sentinel::service {

SentinalStatus ServiceConfig::validate() const {
    if (serviceName.empty()) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    if (defaultDecision != SENTINAL_DECISION_ALLOW && 
        defaultDecision != SENTINAL_DECISION_DENY && 
        defaultDecision != SENTINAL_DECISION_AUDIT) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }
    return SENTINAL_STATUS_SUCCESS;
}

} // namespace sentinel::service
