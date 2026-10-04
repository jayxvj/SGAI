#include <sentinal/driver_contract.h>

int main(void) {
    /* Verify all enums and macros are accessible from C */
    volatile SentinalDriverMessageType msgType = SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST;
    volatile uint32_t major = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    volatile uint32_t minor = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    volatile uint32_t maxPath = SENTINAL_DRIVER_MAX_PATH_CHARS;

    SentinalDriverMessageHeader hdr;
    SentinalDriverProtectionRequest req;
    SentinalDriverProtectionResponse resp;
    SentinalStatus status;

    if (msgType != 1 || major != 1U || minor != 0U || maxPath != 1024U) {
        return 1;
    }

    hdr.size        = 0;
    hdr.majorVersion = 0;
    hdr.minorVersion = 0;
    hdr.messageType  = 0;
    hdr.reserved     = 0;

    /* Confirm struct members are accessible */
    req.requestId  = 0;
    req.operation  = 0;
    req.source     = 0;
    req.pathLength = 0;
    req.reserved   = 0;

    resp.requestId = 0;
    resp.decision  = 0;
    resp.status    = 0;
    resp.reserved  = 0;

    /* Validation functions callable from C */
    status = SentinalDriverValidateMessageHeader(NULL, 0, 0);
    if (status != SENTINAL_STATUS_INVALID_PARAMETER) {
        return 2;
    }

    status = SentinalDriverValidateProtectionRequest(NULL);
    if (status != SENTINAL_STATUS_INVALID_PARAMETER) {
        return 3;
    }

    status = SentinalDriverValidateProtectionResponse(NULL);
    if (status != SENTINAL_STATUS_INVALID_PARAMETER) {
        return 4;
    }

    (void)hdr; (void)req; (void)resp;
    return 0;
}
