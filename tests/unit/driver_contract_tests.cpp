#include <cassert>
#include <cstring>
#include <iostream>
#include <sentinal/driver_contract.h>

/* =========================================================================
 * Helpers to build valid structures
 * ========================================================================= */

static SentinalDriverProtectionRequest make_valid_request(uint64_t requestId = 42) {
    SentinalDriverProtectionRequest req;
    std::memset(&req, 0, sizeof(req));

    req.header.size        = static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest));
    req.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    req.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    req.header.messageType  = SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST;
    req.header.reserved     = 0;

    req.requestId  = requestId;
    req.operation  = SENTINAL_OP_READ;
    req.source     = 1U; /* USER_MODE */
    req.pathLength = 12;
    std::memcpy(req.path, "C:/test/file", 12);
    req.path[12]   = '\0';
    req.reserved   = 0;

    return req;
}

static SentinalDriverProtectionResponse make_valid_response(uint64_t requestId = 42) {
    SentinalDriverProtectionResponse resp;
    std::memset(&resp, 0, sizeof(resp));

    resp.header.size        = static_cast<uint32_t>(sizeof(SentinalDriverProtectionResponse));
    resp.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    resp.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    resp.header.messageType  = SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE;
    resp.header.reserved     = 0;

    resp.requestId = requestId;
    resp.decision  = SENTINAL_DECISION_ALLOW;
    resp.status    = SENTINAL_STATUS_SUCCESS;
    resp.reserved  = 0;

    return resp;
}

static SentinalDriverMessageHeader make_valid_header(uint32_t msgType, uint32_t size) {
    SentinalDriverMessageHeader hdr;
    std::memset(&hdr, 0, sizeof(hdr));
    hdr.size        = size;
    hdr.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    hdr.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    hdr.messageType  = msgType;
    hdr.reserved     = 0;
    return hdr;
}

/* =========================================================================
 * Message header tests
 * ========================================================================= */

static void test_valid_header() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    );
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_SUCCESS);
}

static void test_null_header() {
    assert(SentinalDriverValidateMessageHeader(
        nullptr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        4
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_zero_size_header() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST, 0
    );
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_undersized_header() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        4U
    );
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_incorrect_major_version() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    );
    hdr.majorVersion = 99;
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_unsupported_minor_version() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    );
    hdr.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION + 1;
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_incorrect_message_type() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    );
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_nonzero_reserved_field_in_header() {
    SentinalDriverMessageHeader hdr = make_valid_header(
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    );
    hdr.reserved = 1;
    assert(SentinalDriverValidateMessageHeader(
        &hdr,
        SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
}

/* =========================================================================
 * Protection request tests
 * ========================================================================= */

static void test_valid_request() {
    SentinalDriverProtectionRequest req = make_valid_request();
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_SUCCESS);
}

static void test_null_request() {
    assert(SentinalDriverValidateProtectionRequest(nullptr) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_incorrect_request_size() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest)) - 1;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_request_operation() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.operation = 0xFF;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_none_operation_request() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.operation = SENTINAL_OP_NONE;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_request_source() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.source = 99U;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_path_length_zero() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.pathLength = 0;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_path_length_too_large() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.pathLength = SENTINAL_DRIVER_MAX_PATH_CHARS; /* must be < max */
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_path_not_nul_terminated() {
    SentinalDriverProtectionRequest req = make_valid_request();
    /* pathLength = 12, so path[12] must be '\0' */
    req.path[12] = 'X';
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_request_reserved_nonzero() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.reserved = 7U;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_request_id_preservation() {
    SentinalDriverProtectionRequest req = make_valid_request(0xDEADBEEFCAFEBABEULL);
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_SUCCESS);
    assert(req.requestId == 0xDEADBEEFCAFEBABEULL);
}

/* =========================================================================
 * Protection response tests
 * ========================================================================= */

static void test_valid_response() {
    SentinalDriverProtectionResponse resp = make_valid_response();
    assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_SUCCESS);
}

static void test_null_response() {
    assert(SentinalDriverValidateProtectionResponse(nullptr) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_incorrect_response_size() {
    SentinalDriverProtectionResponse resp = make_valid_response();
    resp.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionResponse)) + 1;
    assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_response_decision() {
    SentinalDriverProtectionResponse resp = make_valid_response();
    resp.decision = 99U;
    assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_invalid_response_status() {
    SentinalDriverProtectionResponse resp = make_valid_response();
    resp.status = 99U;
    assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_response_reserved_nonzero() {
    SentinalDriverProtectionResponse resp = make_valid_response();
    resp.reserved = 1U;
    assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_response_id_preservation() {
    SentinalDriverProtectionResponse resp = make_valid_response(0x1234567890ABCDEFULL);
    assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId == 0x1234567890ABCDEFULL);
}

/* =========================================================================
 * Determinism + no mutation
 * ========================================================================= */

static void test_repeated_validation_is_deterministic() {
    SentinalDriverProtectionRequest req = make_valid_request();
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_SUCCESS);
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_SUCCESS);

    req.operation = 0xFF;
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_validation_does_not_mutate_structures() {
    SentinalDriverProtectionRequest req = make_valid_request(77);
    SentinalDriverProtectionRequest copy = req;

    SentinalDriverValidateProtectionRequest(&req);

    assert(req.requestId == copy.requestId);
    assert(req.operation == copy.operation);
    assert(req.source    == copy.source);
    assert(req.pathLength == copy.pathLength);
    assert(req.reserved  == copy.reserved);
    assert(req.header.size == copy.header.size);

    SentinalDriverProtectionResponse resp = make_valid_response(99);
    SentinalDriverProtectionResponse rcopy = resp;

    SentinalDriverValidateProtectionResponse(&resp);

    assert(resp.requestId == rcopy.requestId);
    assert(resp.decision  == rcopy.decision);
    assert(resp.status    == rcopy.status);
    assert(resp.reserved  == rcopy.reserved);
}

/* =========================================================================
 * All valid operations / decisions
 * ========================================================================= */

static void test_all_valid_single_operations() {
    const uint32_t ops[] = {
        SENTINAL_OP_READ, SENTINAL_OP_WRITE, SENTINAL_OP_DELETE,
        SENTINAL_OP_RENAME, SENTINAL_OP_EXECUTE
    };
    for (int i = 0; i < 5; ++i) {
        SentinalDriverProtectionRequest req = make_valid_request();
        req.operation = ops[i];
        assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_SUCCESS);
    }
}

static void test_all_valid_decisions_in_response() {
    const uint32_t decisions[] = {
        SENTINAL_DECISION_UNKNOWN, SENTINAL_DECISION_ALLOW,
        SENTINAL_DECISION_DENY, SENTINAL_DECISION_AUDIT
    };
    for (int i = 0; i < 4; ++i) {
        SentinalDriverProtectionResponse resp = make_valid_response();
        resp.decision = decisions[i];
        assert(SentinalDriverValidateProtectionResponse(&resp) == SENTINAL_STATUS_SUCCESS);
    }
}

static void test_combined_operation_mask_rejected() {
    SentinalDriverProtectionRequest req = make_valid_request();
    req.operation = static_cast<uint32_t>(SENTINAL_OP_READ) | static_cast<uint32_t>(SENTINAL_OP_WRITE);
    assert(SentinalDriverValidateProtectionRequest(&req) == SENTINAL_STATUS_INVALID_PARAMETER);
}

int main() {
    std::cout << "[DriverContract Tests] Running test suite..." << std::endl;

    /* Header tests */
    test_valid_header();
    test_null_header();
    test_zero_size_header();
    test_undersized_header();
    test_incorrect_major_version();
    test_unsupported_minor_version();
    test_incorrect_message_type();
    test_nonzero_reserved_field_in_header();

    /* Request tests */
    test_valid_request();
    test_null_request();
    test_incorrect_request_size();
    test_invalid_request_operation();
    test_none_operation_request();
    test_invalid_request_source();
    test_invalid_path_length_zero();
    test_invalid_path_length_too_large();
    test_path_not_nul_terminated();
    test_request_reserved_nonzero();
    test_request_id_preservation();

    /* Response tests */
    test_valid_response();
    test_null_response();
    test_incorrect_response_size();
    test_invalid_response_decision();
    test_invalid_response_status();
    test_response_reserved_nonzero();
    test_response_id_preservation();

    /* Determinism + mutation */
    test_repeated_validation_is_deterministic();
    test_validation_does_not_mutate_structures();

    /* Enum coverage */
    test_all_valid_single_operations();
    test_all_valid_decisions_in_response();
    test_combined_operation_mask_rejected();

    std::cout << "[DriverContract Tests] All 31 tests passed successfully." << std::endl;
    return 0;
}
