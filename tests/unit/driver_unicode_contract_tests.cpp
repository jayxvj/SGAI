/*
 * driver_unicode_contract_tests.cpp
 *
 * ABI layout, validation, and adapter tests for the Sentinal AI
 * Unicode Driver Communication Contract.
 *
 * Phase 1.29 — Unicode Driver Communication Contract
 *
 * All 25 required test cases plus ABI offset/sizeof assertions.
 * No test framework dependency: assert + main pattern.
 */

#include <cassert>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sentinal/driver_unicode_contract.h>
#include "sentinal_driver_unicode_contract_adapter.h"

/* =========================================================================
 * ABI layout assertions (compile-time where possible)
 * ========================================================================= */

static void test_abi_layout() {
    /* Header: 4+2+2+4+4 = 16 bytes, no trailing padding */
    static_assert(offsetof(SentinalDriverUnicodeMessageHeader, size)         ==  0, "header.size offset");
    static_assert(offsetof(SentinalDriverUnicodeMessageHeader, majorVersion) ==  4, "header.majorVersion offset");
    static_assert(offsetof(SentinalDriverUnicodeMessageHeader, minorVersion) ==  6, "header.minorVersion offset");
    static_assert(offsetof(SentinalDriverUnicodeMessageHeader, messageType)  ==  8, "header.messageType offset");
    static_assert(offsetof(SentinalDriverUnicodeMessageHeader, reserved)     == 12, "header.reserved offset");
    static_assert(sizeof(SentinalDriverUnicodeMessageHeader)                 == 16, "header size");

    /* Request: all 2096 bytes accounted by named fields; no implicit trailing padding */
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, header)     ==    0, "req.header offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, requestId)  ==   16, "req.requestId offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, operation)  ==   24, "req.operation offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, source)     ==   28, "req.source offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, pathLength) ==   32, "req.pathLength offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, reserved0)  ==   36, "req.reserved0 offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, path)       ==   40, "req.path offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, reserved)   == 2088, "req.reserved offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, reserved1)  == 2092, "req.reserved1 offset");
    static_assert(sizeof(SentinalDriverUnicodeProtectionRequest)               == 2096, "req size");
    /* Verify: offset(reserved1) + sizeof(uint32_t) == sizeof(struct) — no trailing bytes */
    static_assert(offsetof(SentinalDriverUnicodeProtectionRequest, reserved1) + sizeof(uint32_t)
                  == sizeof(SentinalDriverUnicodeProtectionRequest), "req no trailing padding");

    /* Response: all 40 bytes accounted by named fields; no implicit trailing padding */
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, header)    ==  0, "resp.header offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, requestId) == 16, "resp.requestId offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, decision)  == 24, "resp.decision offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, status)    == 28, "resp.status offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, reserved)  == 32, "resp.reserved offset");
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, reserved1) == 36, "resp.reserved1 offset");
    static_assert(sizeof(SentinalDriverUnicodeProtectionResponse)              == 40, "resp size");
    /* Verify: offset(reserved1) + sizeof(uint32_t) == sizeof(struct) — no trailing bytes */
    static_assert(offsetof(SentinalDriverUnicodeProtectionResponse, reserved1) + sizeof(uint32_t)
                  == sizeof(SentinalDriverUnicodeProtectionResponse), "resp no trailing padding");

    /* Path capacity constant */
    static_assert(SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS == 1024u, "path capacity");

    /* pathLength semantics: element width is uint16_t (2 bytes), not wchar_t */
    static_assert(sizeof(uint16_t) == 2, "code unit width is 2 bytes");

    std::cout << "ABI layout: PASS\n";
    std::cout << "  sizeof request  = " << sizeof(SentinalDriverUnicodeProtectionRequest)  << "\n";
    std::cout << "  sizeof response = " << sizeof(SentinalDriverUnicodeProtectionResponse) << "\n";
    std::cout << "  sizeof header   = " << sizeof(SentinalDriverUnicodeMessageHeader)      << "\n";
    std::cout << "  req.reserved1 offset = " << offsetof(SentinalDriverUnicodeProtectionRequest, reserved1)  << "\n";
    std::cout << "  resp.reserved1 offset = " << offsetof(SentinalDriverUnicodeProtectionResponse, reserved1) << "\n";
}

/* =========================================================================
 * Builder helpers
 * ========================================================================= */

static SentinalDriverUnicodeProtectionRequest make_valid_request(uint64_t id = 42) {
    SentinalDriverUnicodeProtectionRequest r;
    std::memset(&r, 0, sizeof(r)); /* zeroes reserved0, reserved, reserved1 */
    r.header.size        = static_cast<uint32_t>(sizeof(r));
    r.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    r.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    r.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    r.requestId  = id;
    r.operation  = SENTINAL_OP_WRITE;
    r.source     = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
    /* ASCII path: \Device\HarddiskVolume3\test.txt (28 uint16_t code units) */
    const char* ascii = "\\Device\\HarddiskVolume3\\test.txt";
    uint32_t len = 0;
    while (ascii[len]) { r.path[len] = static_cast<uint16_t>(ascii[len]); len++; }
    r.pathLength = len;  /* count of uint16_t code units, not bytes */
    r.path[len] = 0x0000u;
    return r;
}

static SentinalDriverUnicodeProtectionResponse make_valid_response(uint64_t id = 42) {
    SentinalDriverUnicodeProtectionResponse r;
    std::memset(&r, 0, sizeof(r)); /* zeroes reserved, reserved1 */
    r.header.size        = static_cast<uint32_t>(sizeof(r));
    r.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    r.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    r.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    r.requestId = id;
    r.decision  = SENTINAL_DECISION_ALLOW;
    r.status    = SENTINAL_STATUS_SUCCESS;
    return r;
}

/* =========================================================================
 * TC01 — Valid header
 * ========================================================================= */
static void tc01_valid_header() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    assert(SentinalDriverUnicodeValidateMessageHeader(
        &r.header,
        SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(r))
    ) == SENTINAL_STATUS_SUCCESS);
    std::cout << "TC01 valid header: PASS\n";
}

/* TC02 — Wrong major version */
static void tc02_wrong_major() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.header.majorVersion = 99;
    assert(SentinalDriverUnicodeValidateMessageHeader(
        &r.header,
        SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(r))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC02 wrong major version: PASS\n";
}

/* TC03 — Future minor version rejected */
static void tc03_future_minor() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.header.minorVersion = static_cast<uint16_t>(SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION + 1u);
    assert(SentinalDriverUnicodeValidateMessageHeader(
        &r.header,
        SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(r))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC03 future minor version: PASS\n";
}

/* TC04 — Wrong message type */
static void tc04_wrong_type() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    assert(SentinalDriverUnicodeValidateMessageHeader(
        &r.header,
        SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(r))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC04 wrong message type: PASS\n";
}

/* TC05 — Invalid size (too small) */
static void tc05_invalid_size() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.header.size = 1;
    assert(SentinalDriverUnicodeValidateMessageHeader(
        &r.header,
        SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST,
        static_cast<uint32_t>(sizeof(r))
    ) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC05 invalid size: PASS\n";
}

/* TC06 — Valid request */
static void tc06_valid_request() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);
    std::cout << "TC06 valid request: PASS\n";
}

/* TC07 — Zero requestId rejected */
static void tc07_zero_request_id() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request(0);
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC07 zero requestId: PASS\n";
}

/* TC08 — Invalid operation */
static void tc08_invalid_operation() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.operation = 0x00; /* NONE is not a single valid op */
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    r.operation = 0xFF; /* unknown */
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC08 invalid operation: PASS\n";
}

/* TC09 — Invalid source */
static void tc09_invalid_source() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.source = 99;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC09 invalid source: PASS\n";
}

/* TC10 — Empty path (pathLength == 0) */
static void tc10_empty_path() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.pathLength = 0;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC10 empty path: PASS\n";
}

/* TC11 — Maximum valid path (pathLength == capacity - 1) */
static void tc11_max_valid_path() {
    SentinalDriverUnicodeProtectionRequest r;
    std::memset(&r, 0, sizeof(r));
    r.header.size        = static_cast<uint32_t>(sizeof(r));
    r.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    r.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    r.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    r.requestId  = 1;
    r.operation  = SENTINAL_OP_WRITE;
    r.source     = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
    r.pathLength = SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS - 1u;
    for (uint32_t i = 0; i < r.pathLength; i++) r.path[i] = 0x0041u; /* 'A' */
    r.path[r.pathLength] = 0x0000u;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);
    std::cout << "TC11 maximum valid path: PASS\n";
}

/* TC12 — Oversized path (pathLength >= capacity) */
static void tc12_oversized_path() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.pathLength = SENTINAL_DRIVER_UNICODE_MAX_PATH_CODE_UNITS;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC12 oversized path: PASS\n";
}

/* TC13 — Missing NUL at path[pathLength] */
static void tc13_missing_nul() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    /* Overwrite the NUL position with a non-zero value */
    r.path[r.pathLength] = 0x0041u;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC13 missing NUL: PASS\n";
}

/* TC14 — Embedded NUL before pathLength */
static void tc14_embedded_nul() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    /* Plant a NUL in the middle of the path */
    r.path[2] = 0x0000u;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC14 embedded NUL: PASS\n";
}

/* TC15 — Non-ASCII UTF-16 paths (Cyrillic, CJK, accented Latin) */
static void tc15_unicode_paths() {
    SentinalDriverUnicodeProtectionRequest r;

    /* Cyrillic: \Device\Volume\Документы\файл.txt
     * We encode the Unicode code points directly as uint16_t values. */
    const uint16_t cyrillic_path[] = {
        /* \Device\Volume\ — ASCII prefix */
        0x005Cu, 0x0044u, 0x0065u, 0x0076u, 0x0069u, 0x0063u, 0x0065u,
        0x005Cu, 0x0056u, 0x006Fu, 0x006Cu, 0x0075u, 0x006Du, 0x0065u, 0x005Cu,
        /* Д о к у м е н т ы */
        0x0414u, 0x043Eu, 0x043Au, 0x0443u, 0x043Cu, 0x0435u, 0x043Du, 0x0442u, 0x044Bu,
        /* \ ф а й л . t x t */
        0x005Cu, 0x0444u, 0x0430u, 0x0439u, 0x043Bu, 0x002Eu,
        0x0074u, 0x0078u, 0x0074u
    };
    const uint32_t cyrillic_len = sizeof(cyrillic_path) / sizeof(cyrillic_path[0]);

    std::memset(&r, 0, sizeof(r));
    r.header.size        = static_cast<uint32_t>(sizeof(r));
    r.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    r.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    r.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    r.requestId  = 100;
    r.operation  = SENTINAL_OP_WRITE;
    r.source     = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
    r.pathLength = cyrillic_len;
    std::memcpy(r.path, cyrillic_path, cyrillic_len * sizeof(uint16_t));
    r.path[cyrillic_len] = 0x0000u;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);

    /* CJK: \Device\Volume\文件.txt */
    const uint16_t cjk_path[] = {
        0x005Cu, 0x0044u, 0x0065u, 0x0076u, 0x0069u, 0x0063u, 0x0065u,
        0x005Cu, 0x0056u, 0x006Fu, 0x006Cu, 0x0075u, 0x006Du, 0x0065u, 0x005Cu,
        0x6587u, 0x4EF6u, /* 文件 */
        0x002Eu, 0x0074u, 0x0078u, 0x0074u
    };
    const uint32_t cjk_len = sizeof(cjk_path) / sizeof(cjk_path[0]);

    std::memset(&r, 0, sizeof(r));
    r.header.size        = static_cast<uint32_t>(sizeof(r));
    r.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    r.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    r.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    r.requestId  = 101;
    r.operation  = SENTINAL_OP_WRITE;
    r.source     = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
    r.pathLength = cjk_len;
    std::memcpy(r.path, cjk_path, cjk_len * sizeof(uint16_t));
    r.path[cjk_len] = 0x0000u;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);

    /* Accented Latin: \Device\Volume\Ärger\naïveté.txt */
    const uint16_t accented_path[] = {
        0x005Cu, 0x0044u, 0x0065u, 0x0076u, 0x0069u, 0x0063u, 0x0065u,
        0x005Cu, 0x0056u, 0x006Fu, 0x006Cu, 0x0075u, 0x006Du, 0x0065u, 0x005Cu,
        0x00C4u, 0x0072u, 0x0067u, 0x0065u, 0x0072u, /* Ärger */
        0x005Cu,
        0x006Eu, 0x0061u, 0x00EFu, 0x0076u, 0x0065u, 0x0074u, 0x00E9u, /* naïveté */
        0x002Eu, 0x0074u, 0x0078u, 0x0074u
    };
    const uint32_t accented_len = sizeof(accented_path) / sizeof(accented_path[0]);

    std::memset(&r, 0, sizeof(r));
    r.header.size        = static_cast<uint32_t>(sizeof(r));
    r.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    r.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    r.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    r.requestId  = 102;
    r.operation  = SENTINAL_OP_WRITE;
    r.source     = SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL;
    r.pathLength = accented_len;
    std::memcpy(r.path, accented_path, accented_len * sizeof(uint16_t));
    r.path[accented_len] = 0x0000u;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);

    std::cout << "TC15 non-ASCII UTF-16 paths (Cyrillic, CJK, accented): PASS\n";
}

/* TC16 — All reserved fields in request must be zero */
static void tc16_reserved_nonzero() {
    SentinalDriverUnicodeProtectionRequest r = make_valid_request();
    r.reserved = 1;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    r.reserved = 0;
    r.reserved0 = 1;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    r.reserved0 = 0;
    r.reserved1 = 1;
    assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC16 reserved nonzero: PASS\n";
}

/* TC17 — Valid response */
static void tc17_valid_response() {
    SentinalDriverUnicodeProtectionResponse r = make_valid_response();
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_SUCCESS);
    std::cout << "TC17 valid response: PASS\n";
}

/* TC18 — Invalid response requestId (zero) */
static void tc18_response_zero_id() {
    SentinalDriverUnicodeProtectionResponse r = make_valid_response(0);
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC18 response zero requestId: PASS\n";
}

/* TC19 — Invalid response decision (UNKNOWN rejected) */
static void tc19_response_invalid_decision() {
    SentinalDriverUnicodeProtectionResponse r = make_valid_response();
    r.decision = SENTINAL_DECISION_UNKNOWN;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    r.decision = 99;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC19 invalid response decision: PASS\n";
}

/* TC20 — Invalid response status */
static void tc20_response_invalid_status() {
    SentinalDriverUnicodeProtectionResponse r = make_valid_response();
    r.status = 99;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC20 invalid response status: PASS\n";
}

/* TC21 — All reserved fields in response must be zero */
static void tc21_response_reserved_nonzero() {
    SentinalDriverUnicodeProtectionResponse r = make_valid_response();
    r.reserved = 1;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    r.reserved = 0;
    r.reserved1 = 1;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC21 response reserved nonzero: PASS\n";
}

/* TC22 — CREATE mapping rejected */
static void tc22_create_rejected() {
    SENTINAL_OBSERVATION_EVENT event;
    std::memset(&event, 0, sizeof(event));
    event.Size = sizeof(event);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedCreate;
    event.PathLength = 4;
    event.Path[0] = L't'; event.Path[1] = L'e'; event.Path[2] = L's'; event.Path[3] = L't'; event.Path[4] = 0;

    SentinalDriverUnicodeProtectionRequest req;
    std::memset(&req, 0xCC, sizeof(req));
    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&event, 1, &req);
    assert(status == STATUS_NOT_SUPPORTED);
    std::cout << "TC22 CREATE mapping rejected: PASS\n";
}

/* TC23 — WRITE mapping succeeds */
static void tc23_write_succeeds() {
    SENTINAL_OBSERVATION_EVENT event;
    std::memset(&event, 0, sizeof(event));
    event.Size = sizeof(event);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedWrite;
    event.PathLength = 4;
    event.Path[0] = L't'; event.Path[1] = L'e'; event.Path[2] = L's'; event.Path[3] = L't'; event.Path[4] = 0;

    SentinalDriverUnicodeProtectionRequest req;
    std::memset(&req, 0, sizeof(req));
    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&event, 42, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.operation == SENTINAL_OP_WRITE);
    assert(req.requestId == 42);
    assert(req.source == SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL);
    assert(req.pathLength == 4);
    assert(req.path[0] == static_cast<uint16_t>(L't'));
    assert(req.path[4] == 0);
    assert(SentinalDriverUnicodeValidateProtectionRequest(&req) == SENTINAL_STATUS_SUCCESS);
    std::cout << "TC23 WRITE mapping succeeds: PASS\n";
}

/* TC24 — SET_INFORMATION mapping rejected */
static void tc24_set_info_rejected() {
    SENTINAL_OBSERVATION_EVENT event;
    std::memset(&event, 0, sizeof(event));
    event.Size = sizeof(event);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedSetInformation;
    event.PathLength = 4;
    event.Path[0] = L't'; event.Path[1] = L'e'; event.Path[2] = L's'; event.Path[3] = L't'; event.Path[4] = 0;

    SentinalDriverUnicodeProtectionRequest req;
    std::memset(&req, 0xCC, sizeof(req));
    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&event, 1, &req);
    assert(status == STATUS_NOT_SUPPORTED);
    std::cout << "TC24 SET_INFORMATION mapping rejected: PASS\n";
}

/* TC25 — output remains unchanged on adapter failure */
static void tc25_output_unchanged_on_failure() {
    SENTINAL_OBSERVATION_EVENT event;
    std::memset(&event, 0, sizeof(event));
    event.Size = sizeof(event);
    event.Version = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    event.Operation = SentinalObservedCreate; /* Will fail with STATUS_NOT_SUPPORTED */
    event.PathLength = 4;
    event.Path[0] = L't'; event.Path[1] = L'e'; event.Path[2] = L's'; event.Path[3] = L't'; event.Path[4] = 0;

    SentinalDriverUnicodeProtectionRequest req;
    std::memset(&req, 0xAA, sizeof(req));
    SentinalDriverUnicodeProtectionRequest before = req;

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&event, 1, &req);
    assert(status == STATUS_NOT_SUPPORTED);
    assert(std::memcmp(&req, &before, sizeof(req)) == 0);

    /* Also test with NULL event */
    status = SentinalObservationToUnicodeDriverRequest(nullptr, 1, &req);
    assert(status == STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&req, &before, sizeof(req)) == 0);

    /* Also test with zero RequestId */
    event.Operation = SentinalObservedWrite;
    status = SentinalObservationToUnicodeDriverRequest(&event, 0, &req);
    assert(status == STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&req, &before, sizeof(req)) == 0);

    std::cout << "TC25 output remains unchanged on adapter failure: PASS\n";
}

/* TC26 — All valid SentinalFileOp single operations are accepted */
static void tc26_all_operations() {
    const uint32_t ops[] = {
        SENTINAL_OP_READ, SENTINAL_OP_WRITE, SENTINAL_OP_DELETE,
        SENTINAL_OP_RENAME, SENTINAL_OP_EXECUTE
    };
    for (uint32_t op : ops) {
        SentinalDriverUnicodeProtectionRequest r = make_valid_request();
        r.operation = op;
        assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);
    }
    std::cout << "TC26 all valid operations accepted: PASS\n";
}

/* TC27 — All valid sources accepted */
static void tc27_all_sources() {
    const uint32_t sources[] = {
        SENTINAL_DRIVER_UNICODE_SOURCE_UNKNOWN,
        SENTINAL_DRIVER_UNICODE_SOURCE_USER_MODE,
        SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL
    };
    for (uint32_t src : sources) {
        SentinalDriverUnicodeProtectionRequest r = make_valid_request();
        r.source = src;
        assert(SentinalDriverUnicodeValidateProtectionRequest(&r) == SENTINAL_STATUS_SUCCESS);
    }
    std::cout << "TC27 all valid sources accepted: PASS\n";
}

/* TC28 — All valid decisions accepted (ALLOW, DENY, AUDIT) */
static void tc28_all_decisions() {
    const uint32_t decisions[] = {
        SENTINAL_DECISION_ALLOW, SENTINAL_DECISION_DENY, SENTINAL_DECISION_AUDIT
    };
    for (uint32_t d : decisions) {
        SentinalDriverUnicodeProtectionResponse r = make_valid_response();
        r.decision = d;
        assert(SentinalDriverUnicodeValidateProtectionResponse(&r) == SENTINAL_STATUS_SUCCESS);
    }
    std::cout << "TC28 all valid decisions accepted: PASS\n";
}

/* TC29 — NULL pointer rejected in all validators */
static void tc29_null_rejected() {
    assert(SentinalDriverUnicodeValidateMessageHeader(nullptr,
        SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST, 1)
        == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(SentinalDriverUnicodeValidateProtectionRequest(nullptr)
        == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(SentinalDriverUnicodeValidateProtectionResponse(nullptr)
        == SENTINAL_STATUS_INVALID_PARAMETER);
    std::cout << "TC29 NULL rejected: PASS\n";
}

/* =========================================================================
 * main
 * ========================================================================= */

int main() {
    std::cout << "=== driver_unicode_contract_tests ===\n";

    test_abi_layout();

    tc01_valid_header();
    tc02_wrong_major();
    tc03_future_minor();
    tc04_wrong_type();
    tc05_invalid_size();
    tc06_valid_request();
    tc07_zero_request_id();
    tc08_invalid_operation();
    tc09_invalid_source();
    tc10_empty_path();
    tc11_max_valid_path();
    tc12_oversized_path();
    tc13_missing_nul();
    tc14_embedded_nul();
    tc15_unicode_paths();
    tc16_reserved_nonzero();
    tc17_valid_response();
    tc18_response_zero_id();
    tc19_response_invalid_decision();
    tc20_response_invalid_status();
    tc21_response_reserved_nonzero();
    tc22_create_rejected();
    tc23_write_succeeds();
    tc24_set_info_rejected();
    tc25_output_unchanged_on_failure();
    tc26_all_operations();
    tc27_all_sources();
    tc28_all_decisions();
    tc29_null_rejected();

    std::cout << "=== All tests PASSED ===\n";
    return 0;
}
