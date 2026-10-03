#include <sentinal/common.h>

int main(void) {
    volatile SentinalStatus status = SENTINAL_STATUS_SUCCESS;
    volatile SentinalTargetType target = SENTINAL_TARGET_DIRECTORY_RECURSIVE;
    volatile SentinalFileOp op = SENTINAL_OP_WRITE;
    volatile SentinalDecision decision = SENTINAL_DECISION_DENY;

    if (SENTINAL_VERSION_MAJOR != 0) {
        return 1;
    }

    if (status != 0 || target != 3 || op != 0x02 || decision != 2) {
        return 2;
    }

    return 0;
}
