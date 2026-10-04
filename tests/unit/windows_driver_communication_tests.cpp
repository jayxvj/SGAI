#include <cassert>
#include <iostream>
#include "service/windows_driver_communication.h"
#include "service/test_windows_driver_transport.h"
#include "service/driver_communication_service.h"

using namespace sentinel::service;

static DriverProtectionResponse make_canary_response() {
    return DriverProtectionResponse(9999, SENTINAL_DECISION_AUDIT, DriverProtectionResponseStatus::SUCCESS);
}

static void test_invalid_request_rejected() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(101, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    WindowsDriverCommunication comm(transport);

    DriverProtectionRequest invalidReq; // default invalid
    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(invalidReq, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);

    // Transport called only for valid requests
    assert(!transport.hasRequest());

    // Output unchanged on failure
    assert(resp.requestId() == 9999);
    assert(resp.decision() == SENTINAL_DECISION_AUDIT);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_successful_request_response_round_trip() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(201, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/MyFolder/sub/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(201, path, SENTINAL_OP_WRITE, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);

    // Transport received converted contract
    assert(transport.hasRequest());
    const auto& lastReq = transport.lastRequest();
    assert(lastReq.requestId == 201);
    assert(lastReq.operation == SENTINAL_OP_WRITE);
    assert(lastReq.source == 1U); // USER_MODE
    assert(std::string(lastReq.path) == "C:/MyFolder/sub/file.txt");

    // Output changed only after complete success
    assert(resp.requestId() == 201);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_request_contract_conversion_preserves_path_and_operation() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(301, SENTINAL_DECISION_DENY, SENTINAL_STATUS_ACCESS_DENIED);

    WindowsDriverCommunication comm(transport);

    // Path normalization test: backslashes should normalize to forward slashes without truncation
    PathIdentity path("C:\\Windows\\System32\\drivers\\test.sys");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    DriverProtectionRequest req(301, path, SENTINAL_OP_DELETE, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);

    assert(transport.hasRequest());
    const auto& lastReq = transport.lastRequest();
    assert(lastReq.requestId == 301);
    assert(lastReq.operation == SENTINAL_OP_DELETE);
    assert(lastReq.source == 2U); // KERNEL
    assert(std::string(lastReq.path) == "C:/Windows/System32/drivers/test.sys");
    assert(lastReq.pathLength == std::string("C:/Windows/System32/drivers/test.sys").length());

    // Response conversion preserved
    assert(resp.requestId() == 301);
    assert(resp.decision() == SENTINAL_DECISION_DENY);
    assert(resp.status() == DriverProtectionResponseStatus::REJECTED);
}

static void test_mismatched_request_id_rejected() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);

    // Transport returns response with mismatched requestId (999 instead of 401)
    transport.setResponse(999, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/Data/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(401, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);

    // Output unchanged on correlation failure
    assert(resp.requestId() == 9999);
    assert(resp.decision() == SENTINAL_DECISION_AUDIT);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_transport_disconnected_failure_propagated() {
    TestWindowsDriverTransport transport; // disconnected
    assert(!transport.isConnected());

    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/Data/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(501, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_ACCESS_DENIED);

    // Output unchanged on transport failure
    assert(resp.requestId() == 9999);
}

static void test_transport_failure_propagated() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setFailure(SENTINAL_STATUS_UNSPECIFIED_ERROR);

    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/Data/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(601, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_UNSPECIFIED_ERROR);

    // Output unchanged on transport failure
    assert(resp.requestId() == 9999);
}

static void test_adapter_failure_overlong_path() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(701, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    WindowsDriverCommunication comm(transport);

    std::string longPath = "C:/" + std::string(1025, 'a');
    PathIdentity path(longPath);
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(701, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_BUFFER_TOO_SMALL);

    // Output unchanged on adapter failure
    assert(!transport.hasRequest());
    assert(resp.requestId() == 9999);
}

// Custom transport to test invalid contract response from transport
class MalformedContractTransport final : public IWindowsDriverTransport {
public:
    SentinalStatus connect() override { return SENTINAL_STATUS_SUCCESS; }
    SentinalStatus disconnect() override { return SENTINAL_STATUS_SUCCESS; }
    bool isConnected() const noexcept override { return true; }

    SentinalStatus exchange(
        const SentinalDriverProtectionRequest& request,
        SentinalDriverProtectionResponse& outResponse
    ) override {
        (void)request;
        // Return a response with invalid size in header
        std::memset(&outResponse, 0, sizeof(outResponse));
        outResponse.header.size = 1; // invalid size
        return SENTINAL_STATUS_SUCCESS;
    }
};

static void test_malformed_response_rejected() {
    MalformedContractTransport transport;
    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/Data/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(801, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);

    // Output unchanged on malformed response
    assert(resp.requestId() == 9999);
}

// Custom transport to test invalid decision/status combinations
class CustomContractTransport final : public IWindowsDriverTransport {
public:
    uint32_t m_decision{0};
    uint32_t m_status{0};
    uint64_t m_requestId{0};

    SentinalStatus connect() override { return SENTINAL_STATUS_SUCCESS; }
    SentinalStatus disconnect() override { return SENTINAL_STATUS_SUCCESS; }
    bool isConnected() const noexcept override { return true; }

    SentinalStatus exchange(
        const SentinalDriverProtectionRequest& request,
        SentinalDriverProtectionResponse& outResponse
    ) override {
        (void)request;
        std::memset(&outResponse, 0, sizeof(outResponse));
        outResponse.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionResponse));
        outResponse.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
        outResponse.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
        outResponse.header.messageType = SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE;
        outResponse.header.reserved = 0;
        outResponse.requestId = m_requestId;
        outResponse.decision = m_decision;
        outResponse.status = m_status;
        outResponse.reserved = 0;
        return SENTINAL_STATUS_SUCCESS;
    }
};

static void test_invalid_decision_in_contract_rejected() {
    CustomContractTransport transport;
    transport.m_requestId = 901;
    transport.m_decision = 99; // invalid decision
    transport.m_status = SENTINAL_STATUS_SUCCESS;

    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/Data/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(901, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(resp.requestId() == 9999);
}

static void test_invalid_status_in_contract_rejected() {
    CustomContractTransport transport;
    transport.m_requestId = 1001;
    transport.m_decision = SENTINAL_DECISION_ALLOW;
    transport.m_status = 999; // invalid status

    WindowsDriverCommunication comm(transport);

    PathIdentity path("C:/Data/doc.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(1001, path, SENTINAL_OP_READ, ctx);

    DriverProtectionResponse resp = make_canary_response();

    SentinalStatus status = comm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(resp.requestId() == 9999);
}

static void test_integration_with_driver_communication_service() {
    TestWindowsDriverTransport transport;
    assert(transport.connect() == SENTINAL_STATUS_SUCCESS);
    transport.setResponse(1101, SENTINAL_DECISION_ALLOW, SENTINAL_STATUS_SUCCESS);

    WindowsDriverCommunication comm(transport);
    DriverCommunicationService service(comm);

    PathIdentity path("C:/Integration/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(1101, path, SENTINAL_OP_EXECUTE, ctx);

    DriverProtectionResponse resp;
    SentinalStatus status = service.requestProtectionDecision(req, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId() == 1101);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

int main() {
    std::cout << "[WindowsDriverCommunication Tests] Running..." << std::endl;

    test_invalid_request_rejected();
    test_successful_request_response_round_trip();
    test_request_contract_conversion_preserves_path_and_operation();
    test_mismatched_request_id_rejected();
    test_transport_disconnected_failure_propagated();
    test_transport_failure_propagated();
    test_adapter_failure_overlong_path();
    test_malformed_response_rejected();
    test_invalid_decision_in_contract_rejected();
    test_invalid_status_in_contract_rejected();
    test_integration_with_driver_communication_service();

    std::cout << "[WindowsDriverCommunication Tests] All tests passed." << std::endl;
    return 0;
}
