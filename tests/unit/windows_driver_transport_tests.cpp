#include <cassert>
#include <cstring>
#include <iostream>
#include "service/test_windows_driver_transport.h"

using namespace sentinel::service;

static SentinalDriverProtectionRequest make_valid_contract_request(uint64_t requestId = 100) {
    SentinalDriverProtectionRequest req;
    std::memset(&req, 0, sizeof(req));
    req.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionRequest));
    req.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    req.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    req.header.messageType = SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST;
    req.header.reserved = 0;
    req.requestId = requestId;
    req.operation = SENTINAL_OP_READ;
    req.source = 1U; // USER_MODE
    req.pathLength = 12;
    std::memcpy(req.path, "C:/test/file", 12);
    req.path[12] = '\0';
    req.reserved = 0;
    return req;
}

static SentinalDriverProtectionResponse make_canary_response() {
    SentinalDriverProtectionResponse resp;
    std::memset(&resp, 0xEE, sizeof(resp));
    return resp;
}

static void test_initial_state_disconnected() {
    TestWindowsDriverTransport transport;
    assert(!transport.isConnected());
    assert(!transport.hasRequest());
}

static void test_connect_lifecycle() {
    TestWindowsDriverTransport transport;

    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());

    // Repeated connect deterministic
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());
}

static void test_disconnect_lifecycle() {
    TestWindowsDriverTransport transport;

    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());

    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());

    // Repeated disconnect deterministic
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
}

static void test_exchange_while_disconnected_rejected() {
    TestWindowsDriverTransport transport;
    assert(!transport.isConnected());

    SentinalDriverProtectionRequest req = make_valid_contract_request(201);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    SentinalStatus status = transport.exchange(req, resp);
    assert(status == SENTINAL_STATUS_ACCESS_DENIED);
    assert(!transport.hasRequest());

    // Output unchanged on failure
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

static void test_configured_transport_failure_returned() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    transport.setFailure(SENTINAL_STATUS_UNSPECIFIED_ERROR);
    transport.setResponse(301, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    SentinalDriverProtectionRequest req = make_valid_contract_request(301);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    SentinalStatus status = transport.exchange(req, resp);
    assert(status == SENTINAL_STATUS_UNSPECIFIED_ERROR);

    // Request stored only when accepted (failure means not accepted)
    assert(!transport.hasRequest());

    // Output unchanged on failure
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

static void test_invalid_request_rejected() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(401, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    SentinalDriverProtectionRequest badReq;
    std::memset(&badReq, 0, sizeof(badReq)); // invalid header size, zero path

    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    SentinalStatus status = transport.exchange(badReq, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!transport.hasRequest());
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

static void test_successful_exchange() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    transport.setResponse(501, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    SentinalDriverProtectionRequest req = make_valid_contract_request(501);
    SentinalDriverProtectionResponse resp = make_canary_response();

    assert(!transport.hasRequest());

    SentinalStatus status = transport.exchange(req, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);

    // Request stored when accepted
    assert(transport.hasRequest());
    assert(transport.lastRequest().requestId == 501);
    assert(transport.lastRequest().operation == SENTINAL_OP_READ);

    // Output updated
    assert(resp.header.size == sizeof(SentinalDriverProtectionResponse));
    assert(resp.header.messageType == SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE);
    assert(resp.requestId == 501);
    assert(resp.decision == SENTINAL_DECISION_ALLOW);
    assert(resp.status == SENTINAL_STATUS_SUCCESS);
}

static void test_invalid_configured_response_rejected() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    // 99 is invalid decision in driver contract
    transport.setResponse(601, 99, SENTINAL_STATUS_SUCCESS);

    SentinalDriverProtectionRequest req = make_valid_contract_request(601);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    SentinalStatus status = transport.exchange(req, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!transport.hasRequest());

    // Output unchanged on invalid response
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

int main() {
    std::cout << "[WindowsDriverTransport Tests] Running..." << std::endl;

    test_initial_state_disconnected();
    test_connect_lifecycle();
    test_disconnect_lifecycle();
    test_exchange_while_disconnected_rejected();
    test_configured_transport_failure_returned();
    test_invalid_request_rejected();
    test_successful_exchange();
    test_invalid_configured_response_rejected();

    std::cout << "[WindowsDriverTransport Tests] All tests passed." << std::endl;
    return 0;
}
