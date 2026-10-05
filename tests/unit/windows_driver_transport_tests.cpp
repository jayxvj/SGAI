/*
 * windows_driver_transport_tests.cpp
 *
 * Unit tests for WindowsDriverTransport and TestWindowsDriverTransport.
 *
 * Phase 1.31 — Kernel/User-Mode Message Transport Foundation (corrected)
 *
 * All tests are mock-based; no loaded driver is required.
 *
 * Transport direction notes:
 *   exchange()       -> FilterSendMessage  -> user -> kernel
 *   receiveAndReply() -> FilterGetMessage +
 *                        FilterReplyMessage -> kernel -> user
 */

#include <cassert>
#include <cstring>
#include <iostream>
#include "service/test_windows_driver_transport.h"

using namespace sentinel::service;

/* =========================================================================
 * Helpers
 * ========================================================================= */

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

static SentinalDriverUnicodeProtectionRequest make_valid_unicode_request(uint64_t requestId = 200) {
    SentinalDriverUnicodeProtectionRequest req;
    std::memset(&req, 0, sizeof(req));
    req.header.size         = sizeof(req);
    req.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    req.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    req.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    req.requestId           = requestId;
    req.operation           = SENTINAL_OP_WRITE;
    req.source              = SENTINAL_DRIVER_UNICODE_SOURCE_USER_MODE;
    req.pathLength          = 7;
    const wchar_t* p = L"C:\\test";
    for (int i = 0; i < 7; ++i) req.path[i] = static_cast<uint16_t>(p[i]);
    req.path[7]             = 0x0000u;
    return req;
}

static void make_valid_unicode_response(
    SentinalDriverUnicodeProtectionResponse& resp,
    uint64_t requestId,
    uint32_t decision = SENTINAL_DECISION_ALLOW,
    uint32_t status = SENTINAL_STATUS_SUCCESS
) {
    std::memset(&resp, 0, sizeof(resp));
    resp.header.size         = sizeof(resp);
    resp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    resp.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.requestId           = requestId;
    resp.decision            = decision;
    resp.status              = status;
    resp.reserved            = 0;
    resp.reserved1           = 0;
}

/* =========================================================================
 * TestWindowsDriverTransport tests (mock stub)
 * ========================================================================= */

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

    assert(!transport.hasRequest());

    // Output unchanged on failure
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

static void test_invalid_request_rejected() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(401, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    SentinalDriverProtectionRequest badReq;
    std::memset(&badReq, 0, sizeof(badReq)); // invalid: zero header size, zero path

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

    assert(transport.hasRequest());
    assert(transport.lastRequest().requestId == 501);
    assert(transport.lastRequest().operation == SENTINAL_OP_READ);

    assert(resp.header.size == sizeof(SentinalDriverProtectionResponse));
    assert(resp.header.messageType == SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE);
    assert(resp.requestId == 501);
    assert(resp.decision == SENTINAL_DECISION_ALLOW);
    assert(resp.status == SENTINAL_STATUS_SUCCESS);
}

static void test_invalid_configured_response_rejected() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    transport.setResponse(601, 99, SENTINAL_STATUS_SUCCESS); // 99 = invalid decision

    SentinalDriverProtectionRequest req = make_valid_contract_request(601);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    SentinalStatus status = transport.exchange(req, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!transport.hasRequest());

    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

/* =========================================================================
 * MockFilterPortDevice — simulates IFilterPortDevice for WindowsDriverTransport tests
 *
 * Simulates all four operations:
 *   connectPort    — returns fake handle on success
 *   sendMessage    — user->kernel (FilterSendMessage) simulation
 *   getKernelMessage — kernel->user (FilterGetMessage) simulation
 *   replyToKernel  — user->kernel reply (FilterReplyMessage) simulation
 * ========================================================================= */

class MockFilterPortDevice : public IFilterPortDevice {
public:
    /* connect/close state */
    bool connectSuccess{true};
    bool connected{false};

    /* sendMessage (user->kernel) config */
    SentinalStatus sendStatus{SENTINAL_STATUS_SUCCESS};
    SentinalDriverUnicodeProtectionResponse cannedSendResponse{};
    bool hasCannedSendResponse{false};
    uint32_t simulatedSendReturnedBytes{sizeof(SentinalDriverUnicodeProtectionResponse)};
    SentinalDriverUnicodeProtectionRequest lastSentRequest{};
    bool hasSentRequest{false};

    /* getKernelMessage (kernel->user) config */
    SentinalStatus getMessageStatus{SENTINAL_STATUS_SUCCESS};
    SentinalDriverUnicodeProtectionRequest cannedKernelRequest{};
    bool hasCannedKernelRequest{false};
    uint64_t cannedMessageId{0xABCD1234ULL};
    uint32_t cannedReplyLength{
        static_cast<uint32_t>(sizeof(SentinalFltReplyHeader) +
                               sizeof(SentinalDriverUnicodeProtectionResponse))
    };

    /* replyToKernel (user->kernel reply) config */
    SentinalStatus replyStatus{SENTINAL_STATUS_SUCCESS};
    SentinalReplyBuffer lastReply{};
    bool hasReply{false};

    /* ------------------------------------------------------------------ */

    SentinalStatus connectPort(const wchar_t* portName, void** outHandle) override {
        (void)portName;
        if (!connectSuccess) {
            return SENTINAL_STATUS_NOT_FOUND;
        }
        connected = true;
        *outHandle = reinterpret_cast<void*>(0x1234);
        return SENTINAL_STATUS_SUCCESS;
    }

    /*
     * sendMessage — simulates FilterSendMessage (user -> kernel).
     * Populates the canned send response if configured.
     */
    SentinalStatus sendMessage(
        void* portHandle,
        const void* inBuffer,
        uint32_t inSize,
        void* outBuffer,
        uint32_t outSize,
        uint32_t* bytesReturned
    ) override {
        (void)portHandle;
        if (inSize == sizeof(SentinalDriverUnicodeProtectionRequest)) {
            std::memcpy(&lastSentRequest, inBuffer, sizeof(lastSentRequest));
            hasSentRequest = true;
        }
        if (sendStatus != SENTINAL_STATUS_SUCCESS) {
            return sendStatus;
        }
        if (hasCannedSendResponse && outBuffer != nullptr &&
            outSize >= sizeof(cannedSendResponse)) {
            std::memcpy(outBuffer, &cannedSendResponse, sizeof(cannedSendResponse));
        }
        if (bytesReturned != nullptr) {
            *bytesReturned = simulatedSendReturnedBytes;
        }
        return SENTINAL_STATUS_SUCCESS;
    }

    /*
     * getKernelMessage — simulates FilterGetMessage (kernel -> user).
     *
     * shutdownEvent is ignored by the mock (synchronous simulation; no
     * blocking occurs). The real DefaultFilterPortDevice uses shutdownEvent
     * in WaitForMultipleObjects to support disconnect cancellation.
     *
     * Writes a SentinalKernelMessageBuffer into messageBuffer:
     *   header.messageId   = cannedMessageId  (for reply correlation)
     *   header.replyLength = cannedReplyLength (Filter Manager sets this)
     *   payload            = cannedKernelRequest
     */
    SentinalStatus getKernelMessage(
        void* portHandle,
        void* messageBuffer,
        uint32_t messageBufferSize,
        void* shutdownEvent  /* ignored by mock — synchronous simulation */
    ) override {
        (void)shutdownEvent;
        (void)portHandle;

        if (getMessageStatus != SENTINAL_STATUS_SUCCESS) {
            return getMessageStatus;
        }

        if (!hasCannedKernelRequest ||
            messageBuffer == nullptr ||
            messageBufferSize < static_cast<uint32_t>(sizeof(SentinalKernelMessageBuffer))) {
            return SENTINAL_STATUS_UNSPECIFIED_ERROR;
        }

        SentinalKernelMessageBuffer* buf =
            static_cast<SentinalKernelMessageBuffer*>(messageBuffer);

        std::memset(buf, 0, sizeof(*buf));
        buf->header.messageId   = cannedMessageId;
        buf->header.replyLength = cannedReplyLength;
        buf->payload            = cannedKernelRequest;

        return SENTINAL_STATUS_SUCCESS;
    }

    /*
     * replyToKernel — simulates FilterReplyMessage (user -> kernel reply).
     * Captures the reply buffer for test inspection.
     */
    SentinalStatus replyToKernel(
        void* portHandle,
        const void* replyBuffer,
        uint32_t replyBufferSize
    ) override {
        (void)portHandle;

        if (replyStatus != SENTINAL_STATUS_SUCCESS) {
            return replyStatus;
        }

        if (replyBuffer == nullptr ||
            replyBufferSize < static_cast<uint32_t>(sizeof(SentinalReplyBuffer))) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        std::memcpy(&lastReply, replyBuffer, sizeof(lastReply));
        hasReply = true;
        return SENTINAL_STATUS_SUCCESS;
    }

    void closePort(void* portHandle) override {
        (void)portHandle;
        connected = false;
    }
};

/* =========================================================================
 * WindowsDriverTransport — lifecycle tests
 * ========================================================================= */

static void test_real_transport_lifecycle() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    assert(!transport.isConnected());
    assert(transport.state() == TransportState::Disconnected);

    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());
    assert(transport.state() == TransportState::Connected);

    // Repeated connect is idempotent
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());

    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
    assert(transport.state() == TransportState::Disconnected);

    // Repeated disconnect is safe
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
}

static void test_real_transport_connect_failure() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    mock->connectSuccess = false;
    WindowsDriverTransport transport(mock);

    assert(transport.connect() == SENTINAL_STATUS_NOT_FOUND);
    assert(!transport.isConnected());
    assert(transport.state() == TransportState::Disconnected);
}

/* =========================================================================
 * WindowsDriverTransport — exchange() (user->kernel via FilterSendMessage)
 * ========================================================================= */

static void test_real_transport_exchange_while_disconnected() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    SentinalDriverProtectionRequest req = make_valid_contract_request(101);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    assert(transport.exchange(req, resp) == SENTINAL_STATUS_ACCESS_DENIED);
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0); // Output unchanged
}

static void test_real_transport_successful_exchange() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    make_valid_unicode_response(mock->cannedSendResponse, 505);
    mock->hasCannedSendResponse = true;

    SentinalDriverProtectionRequest req = make_valid_contract_request(505);
    SentinalDriverProtectionResponse resp = make_canary_response();

    assert(transport.exchange(req, resp) == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId == 505);
    assert(resp.decision == SENTINAL_DECISION_ALLOW);
    assert(resp.status == SENTINAL_STATUS_SUCCESS);
}

static void test_real_transport_mismatched_request_id_rejected() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    make_valid_unicode_response(mock->cannedSendResponse, 999); // mismatched
    mock->hasCannedSendResponse = true;

    SentinalDriverProtectionRequest req = make_valid_contract_request(505);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    assert(transport.exchange(req, resp) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0); // Output unchanged
}

static void test_real_transport_malformed_response_rejected() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    make_valid_unicode_response(mock->cannedSendResponse, 505, 99); // invalid decision
    mock->hasCannedSendResponse = true;

    SentinalDriverProtectionRequest req = make_valid_contract_request(505);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    assert(transport.exchange(req, resp) == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

static void test_real_transport_timeout_failure_propagated() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    mock->sendStatus = SENTINAL_STATUS_UNSPECIFIED_ERROR;

    SentinalDriverProtectionRequest req = make_valid_contract_request(505);
    SentinalDriverProtectionResponse resp = make_canary_response();
    SentinalDriverProtectionResponse copy = resp;

    assert(transport.exchange(req, resp) == SENTINAL_STATUS_UNSPECIFIED_ERROR);
    // CRITICAL: Transport failure must NEVER be converted to ALLOW!
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);
}

static void test_real_transport_exchange_unicode_direct() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    SentinalDriverUnicodeProtectionRequest req = make_valid_unicode_request(707);
    SentinalDriverUnicodeProtectionResponse resp;
    std::memset(&resp, 0xEE, sizeof(resp));
    SentinalDriverUnicodeProtectionResponse copy = resp;

    // 1. Exchange while disconnected
    assert(transport.exchangeUnicode(req, resp) == SENTINAL_STATUS_ACCESS_DENIED);
    assert(std::memcmp(&resp, &copy, sizeof(resp)) == 0);

    // 2. Connect
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    // 3. Successful exchange
    make_valid_unicode_response(mock->cannedSendResponse, 707);
    mock->hasCannedSendResponse = true;

    assert(transport.exchangeUnicode(req, resp) == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId == 707);
    assert(resp.decision == SENTINAL_DECISION_ALLOW);
    assert(resp.status == SENTINAL_STATUS_SUCCESS);

    // 4. Mismatched requestId
    make_valid_unicode_response(mock->cannedSendResponse, 888);
    assert(transport.exchangeUnicode(req, resp) == SENTINAL_STATUS_INVALID_PARAMETER);

    // 5. Transport error is NOT converted to ALLOW
    mock->sendStatus = SENTINAL_STATUS_UNSPECIFIED_ERROR;
    assert(transport.exchangeUnicode(req, resp) == SENTINAL_STATUS_UNSPECIFIED_ERROR);
}

/* =========================================================================
 * WindowsDriverTransport — receiveAndReply()
 *
 * Tests the KERNEL -> USER path:
 *   FilterGetMessage (getKernelMessage) -> validate -> FilterReplyMessage (replyToKernel)
 *
 * These tests verify:
 *   A. receiveAndReply() while disconnected -> ACCESS_DENIED
 *   B. FilterGetMessage failure -> explicit error, no ALLOW
 *   C. Malformed kernel message (invalid application payload) -> INVALID_PARAMETER
 *   D. Valid kernel message -> deterministic ALLOW response, correct messageId correlation
 *   E. FilterReplyMessage failure -> explicit error
 *   F. requestId echoed exactly in response
 *   G. Output buffers optionally populated
 * ========================================================================= */

static SentinalDriverUnicodeProtectionRequest make_valid_kernel_request(uint64_t requestId) {
    return make_valid_unicode_request(requestId);
}

static void test_receive_and_reply_while_disconnected() {
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    assert(!transport.isConnected());

    SentinalStatus status = transport.receiveAndReply();
    assert(status == SENTINAL_STATUS_ACCESS_DENIED);
    assert(!mock->hasReply); // No reply was sent
}

static void test_receive_and_reply_get_message_failure() {
    /*
     * FilterGetMessage fails (e.g. port closed while waiting).
     * Must return explicit error, NEVER ALLOW.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    mock->getMessageStatus = SENTINAL_STATUS_UNSPECIFIED_ERROR;
    mock->hasCannedKernelRequest = false;

    SentinalStatus status = transport.receiveAndReply();
    assert(status == SENTINAL_STATUS_UNSPECIFIED_ERROR);
    assert(!mock->hasReply); // No reply on receive failure
}

static void test_receive_and_reply_malformed_payload_rejected() {
    /*
     * FilterGetMessage succeeds but payload fails contract validation.
     * Must reject without sending a reply.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    // Canned request is zero-initialized -> invalid (zero requestId, zero pathLength)
    SentinalDriverUnicodeProtectionRequest bad;
    std::memset(&bad, 0, sizeof(bad));
    mock->cannedKernelRequest = bad;
    mock->hasCannedKernelRequest = true;

    SentinalStatus status = transport.receiveAndReply();
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(!mock->hasReply); // Malformed message must not receive a reply
}

static void test_receive_and_reply_successful_round_trip() {
    /*
     * Happy path:
     *   - FilterGetMessage delivers valid kernel request
     *   - receiveAndReply validates it, builds ALLOW response, sends it
     *   - reply messageId matches received messageId (kernel correlation)
     *   - response requestId matches request requestId
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    mock->cannedKernelRequest = make_valid_kernel_request(42ULL);
    mock->hasCannedKernelRequest = true;
    mock->cannedMessageId = 0xDEADBEEF1234ULL;

    SentinalDriverUnicodeProtectionRequest  receivedReq;
    SentinalDriverUnicodeProtectionResponse sentResp;
    std::memset(&receivedReq, 0, sizeof(receivedReq));
    std::memset(&sentResp, 0, sizeof(sentResp));

    SentinalStatus status = transport.receiveAndReply(&receivedReq, &sentResp);
    assert(status == SENTINAL_STATUS_SUCCESS);

    // A reply must have been sent
    assert(mock->hasReply);

    // Reply transport header: messageId must match received messageId (kernel correlation)
    assert(mock->lastReply.header.messageId == 0xDEADBEEF1234ULL);
    assert(mock->lastReply.header.status == 0); // STATUS_SUCCESS

    // Application payload: requestId echoed from kernel request
    assert(mock->lastReply.payload.requestId == 42ULL);
    assert(mock->lastReply.payload.decision == SENTINAL_DECISION_ALLOW);
    assert(mock->lastReply.payload.status == SENTINAL_STATUS_SUCCESS);
    assert(mock->lastReply.payload.reserved == 0);
    assert(mock->lastReply.payload.reserved1 == 0);

    // Out params populated
    assert(receivedReq.requestId == 42ULL);
    assert(sentResp.requestId == 42ULL);
    assert(sentResp.decision == SENTINAL_DECISION_ALLOW);
}

static void test_receive_and_reply_request_id_echoed_exactly() {
    /*
     * requestId from the kernel request must be echoed exactly in the response.
     * Different requestId -> different echo.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    for (uint64_t id : {1ULL, 0xFFFFFFFFULL, 0x123456789ABCULL}) {
        mock->cannedKernelRequest = make_valid_kernel_request(id);
        mock->hasCannedKernelRequest = true;
        mock->hasReply = false;

        SentinalDriverUnicodeProtectionResponse sentResp;
        SentinalStatus status = transport.receiveAndReply(nullptr, &sentResp);
        assert(status == SENTINAL_STATUS_SUCCESS);
        assert(mock->lastReply.payload.requestId == id);
        assert(sentResp.requestId == id);
    }
}

static void test_receive_and_reply_transport_failure_not_allow() {
    /*
     * FilterReplyMessage fails.
     * Must return explicit failure, NEVER silently succeed.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    mock->cannedKernelRequest = make_valid_kernel_request(77ULL);
    mock->hasCannedKernelRequest = true;
    mock->replyStatus = SENTINAL_STATUS_UNSPECIFIED_ERROR;

    SentinalStatus status = transport.receiveAndReply();
    assert(status == SENTINAL_STATUS_UNSPECIFIED_ERROR);
    // hasReply is false because replyToKernel returned an error
    assert(!mock->hasReply);
}

static void test_receive_and_reply_response_validation() {
    /*
     * The response built internally must pass contract validation.
     * This is an internal correctness check: valid kernel request ->
     * valid response constructed -> passes validation -> reply sent.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    mock->cannedKernelRequest = make_valid_kernel_request(999ULL);
    mock->hasCannedKernelRequest = true;

    SentinalDriverUnicodeProtectionResponse sentResp;
    assert(transport.receiveAndReply(nullptr, &sentResp) == SENTINAL_STATUS_SUCCESS);

    // The response that was sent must itself pass contract validation
    SentinalStatus vs = SentinalDriverUnicodeValidateProtectionResponse(&sentResp);
    assert(vs == SENTINAL_STATUS_SUCCESS);
}

static void test_receive_and_reply_no_allow_on_get_failure() {
    /*
     * CRITICAL SAFETY: FilterGetMessage failure must NEVER result in
     * any decision being communicated (no spurious ALLOW/DENY/AUDIT).
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    mock->getMessageStatus = SENTINAL_STATUS_UNSPECIFIED_ERROR;

    SentinalDriverUnicodeProtectionResponse sentResp;
    std::memset(&sentResp, 0xEE, sizeof(sentResp));
    SentinalDriverUnicodeProtectionResponse copy = sentResp;

    SentinalStatus status = transport.receiveAndReply(nullptr, &sentResp);
    assert(status != SENTINAL_STATUS_SUCCESS);
    // outResponse must NOT be modified on failure
    assert(std::memcmp(&sentResp, &copy, sizeof(sentResp)) == 0);
    assert(!mock->hasReply);
}

/* =========================================================================
 * Disconnect / receive lifecycle invariant tests (Phase 1.31 correction)
 *
 * These tests verify the single-threaded observable behavior guaranteed by
 * the two-mutex design. The actual disconnect-during-receive race cannot be
 * deterministically reproduced in a single-threaded unit test; concurrent
 * safety is verified by design review (see windows_driver_transport.cpp file
 * header and disconnect() inline comments) and requires integration testing
 * with a real driver for full validation.
 * ========================================================================= */

static void test_disconnect_from_disconnected_is_safe() {
    /*
     * Calling disconnect() on an already-disconnected transport must be
     * idempotent and never crash or deadlock.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    assert(!transport.isConnected());
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
}

static void test_receive_and_reply_after_disconnect_returns_access_denied() {
    /*
     * After disconnect(), receiveAndReply() must return ACCESS_DENIED immediately
     * without attempting any FilterGetMessage call.
     *
     * Verifies: m_state check in the brief m_mutex critical section sees
     * Disconnected / nullptr handle and returns early.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());

    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
    assert(transport.state() == TransportState::Disconnected);

    /* Mock's getKernelMessage should NOT be called after disconnect */
    mock->hasCannedKernelRequest = true; /* would succeed if called */
    mock->cannedKernelRequest = make_valid_kernel_request(1ULL);

    SentinalStatus status = transport.receiveAndReply();
    assert(status == SENTINAL_STATUS_ACCESS_DENIED);
    assert(!mock->hasReply); /* No reply was sent */
}

static void test_reconnect_after_disconnect() {
    /*
     * connect() -> disconnect() -> connect() must succeed.
     * Verifies: shutdown event is properly reset by connect() so the
     * second session can receive messages.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    /* First connect/disconnect cycle */
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(!transport.isConnected());
    assert(transport.state() == TransportState::Disconnected);

    /* Second connect */
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.isConnected());
    assert(transport.state() == TransportState::Connected);

    /* Second session can receive messages normally */
    mock->cannedKernelRequest = make_valid_kernel_request(77ULL);
    mock->hasCannedKernelRequest = true;

    SentinalDriverUnicodeProtectionResponse resp;
    assert(transport.receiveAndReply(nullptr, &resp) == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId == 77ULL);

    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
}

static void test_double_disconnect_is_safe() {
    /*
     * disconnect() called twice in succession must be safe and idempotent.
     * Verifies: state guard in disconnect() (Disconnected → return immediately).
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);

    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS);
    assert(transport.disconnect() == SENTINAL_STATUS_SUCCESS); /* second call */
    assert(!transport.isConnected());
    assert(transport.state() == TransportState::Disconnected);
}

static void test_no_m_mutex_held_during_receive_by_design() {
    /*
     * Verifies the single-threaded observable consequence of the design:
     * receiveAndReply() returns correct results whether or not exchange()
     * was called previously (both use m_mutex, but neither holds it across
     * a blocking operation).
     *
     * If m_mutex were held during FilterGetMessage, exchange() would also
     * deadlock if called concurrently — this test verifies the sequential
     * behavior is correct, ensuring the implementation at least compiles
     * and runs with the two-mutex design.
     */
    auto mock = std::make_shared<MockFilterPortDevice>();
    WindowsDriverTransport transport(mock);
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    /* exchange() — user->kernel */
    make_valid_unicode_response(mock->cannedSendResponse, 10ULL);
    mock->hasCannedSendResponse = true;
    SentinalDriverProtectionRequest req = make_valid_contract_request(10ULL);
    SentinalDriverProtectionResponse resp = make_canary_response();
    assert(transport.exchange(req, resp) == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId == 10ULL);

    /* receiveAndReply() — kernel->user (called after exchange, same thread) */
    mock->cannedKernelRequest = make_valid_kernel_request(11ULL);
    mock->hasCannedKernelRequest = true;
    SentinalDriverUnicodeProtectionResponse kresp;
    assert(transport.receiveAndReply(nullptr, &kresp) == SENTINAL_STATUS_SUCCESS);
    assert(kresp.requestId == 11ULL);

    /* isConnected() works throughout (m_mutex accessible) */
    assert(transport.isConnected());
}

/* =========================================================================
 * Layout verification tests
 * ========================================================================= */

static void test_transport_buffer_layout() {
    /*
     * Verify the buffer sizes match the documented Phase 1.31 spec:
     *
     *   SentinalKernelMessageBuffer:
     *     SentinalFltMessageHeader (16) + SentinalDriverUnicodeProtectionRequest (2096)
     *     = 2112 bytes
     *
     *   SentinalReplyBuffer:
     *     SentinalFltReplyHeader (16) + SentinalDriverUnicodeProtectionResponse (40)
     *     = 56 bytes
     */
    static_assert(sizeof(SentinalFltMessageHeader) == 16,
        "SentinalFltMessageHeader must be 16 bytes");
    static_assert(sizeof(SentinalFltReplyHeader) == 16,
        "SentinalFltReplyHeader must be 16 bytes");
    static_assert(sizeof(SentinalKernelMessageBuffer) ==
                  sizeof(SentinalFltMessageHeader) +
                  sizeof(SentinalDriverUnicodeProtectionRequest),
        "SentinalKernelMessageBuffer size mismatch");
    static_assert(sizeof(SentinalReplyBuffer) ==
                  sizeof(SentinalFltReplyHeader) +
                  sizeof(SentinalDriverUnicodeProtectionResponse),
        "SentinalReplyBuffer size mismatch");

    assert(sizeof(SentinalFltMessageHeader) == 16);
    assert(sizeof(SentinalFltReplyHeader) == 16);
    assert(sizeof(SentinalKernelMessageBuffer) == 16 + 2096);
    assert(sizeof(SentinalReplyBuffer) == 16 + 40);
}

/* =========================================================================
 * main
 * ========================================================================= */

int main() {
    std::cout << "[WindowsDriverTransport Tests] Running..." << std::endl;

    /* TestWindowsDriverTransport stub tests */
    test_initial_state_disconnected();
    test_connect_lifecycle();
    test_disconnect_lifecycle();
    test_exchange_while_disconnected_rejected();
    test_configured_transport_failure_returned();
    test_invalid_request_rejected();
    test_successful_exchange();
    test_invalid_configured_response_rejected();

    /* WindowsDriverTransport lifecycle */
    test_real_transport_lifecycle();
    test_real_transport_connect_failure();

    /* exchange() — user->kernel (FilterSendMessage path) */
    test_real_transport_exchange_while_disconnected();
    test_real_transport_successful_exchange();
    test_real_transport_mismatched_request_id_rejected();
    test_real_transport_malformed_response_rejected();
    test_real_transport_timeout_failure_propagated();
    test_real_transport_exchange_unicode_direct();

    /* receiveAndReply() — kernel->user (FilterGetMessage + FilterReplyMessage path) */
    test_receive_and_reply_while_disconnected();
    test_receive_and_reply_get_message_failure();
    test_receive_and_reply_malformed_payload_rejected();
    test_receive_and_reply_successful_round_trip();
    test_receive_and_reply_request_id_echoed_exactly();
    test_receive_and_reply_transport_failure_not_allow();
    test_receive_and_reply_response_validation();
    test_receive_and_reply_no_allow_on_get_failure();

    /* Disconnect / receive lifecycle invariants (Phase 1.31 correction) */
    test_disconnect_from_disconnected_is_safe();
    test_receive_and_reply_after_disconnect_returns_access_denied();
    test_reconnect_after_disconnect();
    test_double_disconnect_is_safe();
    test_no_m_mutex_held_during_receive_by_design();

    /* Layout verification */
    test_transport_buffer_layout();

    std::cout << "[WindowsDriverTransport Tests] All tests passed." << std::endl;
    return 0;
}
