#include <cassert>
#include <iostream>
#include "service/driver_communication_service.h"
#include "service/test_driver_communication.h"

using namespace sentinel::service;

static void test_test_driver_communication_behavior() {
    TestDriverCommunication mockComm;

    PathIdentity path("C:/Secure/file.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(301, path, SENTINAL_OP_READ, ctx);

    // Initial state
    assert(!mockComm.hasRequest());

    // Configure response
    mockComm.setResponse(SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);

    DriverProtectionResponse resp;
    SentinalStatus status = mockComm.sendRequest(req, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(mockComm.hasRequest());
    assert(mockComm.lastRequest().requestId() == 301);
    assert(resp.requestId() == 301);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);

    // Configured failure returned
    mockComm.setFailure(SENTINAL_STATUS_ACCESS_DENIED);
    DriverProtectionResponse failureResp(999, SENTINAL_DECISION_AUDIT, DriverProtectionResponseStatus::SUCCESS);
    status = mockComm.sendRequest(req, failureResp);
    assert(status == SENTINAL_STATUS_ACCESS_DENIED);

    // Output unchanged on failure
    assert(failureResp.requestId() == 999);
    assert(failureResp.decision() == SENTINAL_DECISION_AUDIT);
    assert(failureResp.status() == DriverProtectionResponseStatus::SUCCESS);

    // Invalid request rejected
    mockComm.setFailure(SENTINAL_STATUS_SUCCESS);
    DriverProtectionRequest invalidReq;
    DriverProtectionResponse unchangedResp(555, SENTINAL_DECISION_DENY, DriverProtectionResponseStatus::SUCCESS);
    status = mockComm.sendRequest(invalidReq, unchangedResp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(unchangedResp.requestId() == 555);

    // Invalid configured response (REJECTED + ALLOW) rejected, outResponse unchanged
    mockComm.setResponse(SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::REJECTED);
    DriverProtectionResponse invalidConfiguredResp(666, SENTINAL_DECISION_DENY, DriverProtectionResponseStatus::SUCCESS);
    status = mockComm.sendRequest(req, invalidConfiguredResp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(invalidConfiguredResp.requestId() == 666);
    assert(invalidConfiguredResp.decision() == SENTINAL_DECISION_DENY);
    assert(invalidConfiguredResp.status() == DriverProtectionResponseStatus::SUCCESS);
}

class MalformedResponseCommunication final : public IUserModeDriverCommunication {
public:
    SentinalStatus sendRequest(
        const DriverProtectionRequest& request,
        DriverProtectionResponse& outResponse
    ) override {
        (void)request;
        // Intentionally provide an invalid response (e.g. requestId = 0, SUCCESS)
        outResponse = DriverProtectionResponse(0, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);
        return SENTINAL_STATUS_SUCCESS;
    }
};

static void test_driver_communication_service_invalid_response_rejected() {
    MalformedResponseCommunication badComm;
    DriverCommunicationService service(badComm);

    PathIdentity path("C:/Docs/important.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(405, path, SENTINAL_OP_WRITE, ctx);

    DriverProtectionResponse resp(999, SENTINAL_DECISION_AUDIT, DriverProtectionResponseStatus::SUCCESS);
    SentinalStatus status = service.requestProtectionDecision(req, resp);

    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    // outResponse must remain unchanged
    assert(resp.requestId() == 999);
    assert(resp.decision() == SENTINAL_DECISION_AUDIT);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_driver_communication_service_successful_request() {
    TestDriverCommunication mockComm;
    mockComm.setResponse(SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);

    DriverCommunicationService service(mockComm);

    PathIdentity path("C:/Docs/important.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(401, path, SENTINAL_OP_WRITE, ctx);

    DriverProtectionResponse resp;
    SentinalStatus status = service.requestProtectionDecision(req, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(mockComm.hasRequest());
    assert(mockComm.lastRequest().requestId() == 401);
    assert(resp.requestId() == 401);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_driver_communication_service_transport_failure() {
    TestDriverCommunication mockComm;
    mockComm.setFailure(SENTINAL_STATUS_UNSPECIFIED_ERROR);

    DriverCommunicationService service(mockComm);

    PathIdentity path("C:/Docs/important.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(402, path, SENTINAL_OP_WRITE, ctx);

    DriverProtectionResponse resp(888, SENTINAL_DECISION_AUDIT, DriverProtectionResponseStatus::SUCCESS);
    SentinalStatus status = service.requestProtectionDecision(req, resp);
    assert(status == SENTINAL_STATUS_UNSPECIFIED_ERROR);

    // Output unchanged on transport failure
    assert(resp.requestId() == 888);
    assert(resp.decision() == SENTINAL_DECISION_AUDIT);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_driver_communication_service_invalid_request() {
    TestDriverCommunication mockComm;
    mockComm.setResponse(SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);

    DriverCommunicationService service(mockComm);

    DriverProtectionRequest invalidReq;
    DriverProtectionResponse resp(777, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);

    SentinalStatus status = service.requestProtectionDecision(invalidReq, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);

    // Mock was never called, output unchanged
    assert(!mockComm.hasRequest());
    assert(resp.requestId() == 777);
}

static void test_driver_communication_service_deterministic() {
    TestDriverCommunication mockComm;
    mockComm.setResponse(SENTINAL_DECISION_DENY, DriverProtectionResponseStatus::REJECTED);

    DriverCommunicationService service(mockComm);

    PathIdentity path("C:/Docs/file.bin");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::KERNEL);
    DriverProtectionRequest req(403, path, SENTINAL_OP_EXECUTE, ctx);

    DriverProtectionResponse resp1;
    assert(service.requestProtectionDecision(req, resp1) == SENTINAL_STATUS_SUCCESS);
    assert(resp1.decision() == SENTINAL_DECISION_DENY);
    assert(resp1.status() == DriverProtectionResponseStatus::REJECTED);

    DriverProtectionResponse resp2;
    assert(service.requestProtectionDecision(req, resp2) == SENTINAL_STATUS_SUCCESS);
    assert(resp2.decision() == SENTINAL_DECISION_DENY);
    assert(resp2.status() == DriverProtectionResponseStatus::REJECTED);
}

int main() {
    std::cout << "[DriverCommunicationService Tests] Running..." << std::endl;

    test_test_driver_communication_behavior();
    test_driver_communication_service_invalid_response_rejected();
    test_driver_communication_service_successful_request();
    test_driver_communication_service_transport_failure();
    test_driver_communication_service_invalid_request();
    test_driver_communication_service_deterministic();

    std::cout << "[DriverCommunicationService Tests] All tests passed." << std::endl;
    return 0;
}
