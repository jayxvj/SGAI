#include <cassert>
#include <cstring>
#include <iostream>
#include "service/driver_contract_adapter.h"

using namespace sentinel::service;

static SentinalDriverProtectionResponse make_contract_response(
    uint64_t requestId,
    uint32_t decision,
    uint32_t status
) {
    SentinalDriverProtectionResponse resp;
    std::memset(&resp, 0, sizeof(resp));
    resp.header.size = static_cast<uint32_t>(sizeof(SentinalDriverProtectionResponse));
    resp.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    resp.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    resp.header.messageType = SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE;
    resp.header.reserved = 0;
    resp.requestId = requestId;
    resp.decision = decision;
    resp.status = status;
    resp.reserved = 0;
    return resp;
}

static void test_valid_request_to_contract() {
    PathIdentity path("C:/Protected/document.docx");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(500, path, SENTINAL_OP_WRITE, ctx);

    SentinalDriverProtectionRequest contract;
    std::memset(&contract, 0xFF, sizeof(contract));

    SentinalStatus status = DriverContractAdapter::toContract(req, contract);
    assert(status == SENTINAL_STATUS_SUCCESS);

    // Header checks
    assert(contract.header.size == sizeof(SentinalDriverProtectionRequest));
    assert(contract.header.majorVersion == SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION);
    assert(contract.header.minorVersion == SENTINAL_DRIVER_CONTRACT_MINOR_VERSION);
    assert(contract.header.messageType == SENTINAL_DRIVER_MESSAGE_PROTECTION_REQUEST);
    assert(contract.header.reserved == 0);

    // Payload checks
    assert(contract.requestId == 500);
    assert(contract.operation == SENTINAL_OP_WRITE);
    assert(contract.source == 1U); // USER_MODE
    assert(contract.pathLength == std::strlen("C:/Protected/document.docx"));
    assert(std::strcmp(contract.path, "C:/Protected/document.docx") == 0);
    assert(contract.path[contract.pathLength] == '\0');
    assert(contract.reserved == 0);
}

static void test_output_unchanged_on_invalid_request() {
    DriverProtectionRequest invalidReq; // default invalid

    SentinalDriverProtectionRequest contract;
    std::memset(&contract, 0xAA, sizeof(contract));
    SentinalDriverProtectionRequest copy = contract;

    SentinalStatus status = DriverContractAdapter::toContract(invalidReq, contract);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&contract, &copy, sizeof(contract)) == 0);
}

static void test_overlong_path_rejected() {
    // 1024 chars is maximum allowed buffer, pathLength must be < 1024
    std::string longPath = "C:/" + std::string(1025, 'a');
    PathIdentity path(longPath);

    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(501, path, SENTINAL_OP_READ, ctx);

    SentinalDriverProtectionRequest contract;
    std::memset(&contract, 0xBB, sizeof(contract));
    SentinalDriverProtectionRequest copy = contract;

    SentinalStatus status = DriverContractAdapter::toContract(req, contract);
    assert(status == SENTINAL_STATUS_BUFFER_TOO_SMALL);
    assert(std::memcmp(&contract, &copy, sizeof(contract)) == 0);
}

static void test_invalid_operation_rejected() {
    PathIdentity path("C:/test.txt");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(502, path, SENTINAL_OP_NONE, ctx);

    SentinalDriverProtectionRequest contract;
    std::memset(&contract, 0xCC, sizeof(contract));
    SentinalDriverProtectionRequest copy = contract;

    SentinalStatus status = DriverContractAdapter::toContract(req, contract);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&contract, &copy, sizeof(contract)) == 0);
}

static void test_invalid_context_rejected() {
    PathIdentity path("C:/test.txt");
    ProtectionEvaluationContext badCtx(static_cast<ProtectionRequestSource>(99));
    DriverProtectionRequest req(503, path, SENTINAL_OP_READ, badCtx);

    SentinalDriverProtectionRequest contract;
    std::memset(&contract, 0xDD, sizeof(contract));
    SentinalDriverProtectionRequest copy = contract;

    SentinalStatus status = DriverContractAdapter::toContract(req, contract);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
    assert(std::memcmp(&contract, &copy, sizeof(contract)) == 0);
}

static void test_valid_response_to_semantic_response() {
    SentinalDriverProtectionResponse contract = make_contract_response(
        777,
        SENTINAL_DECISION_ALLOW,
        SENTINAL_STATUS_SUCCESS
    );

    DriverProtectionResponse resp;
    SentinalStatus status = DriverContractAdapter::fromContract(contract, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(resp.isValid());
    assert(resp.requestId() == 777);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_valid_rejected_response_from_contract() {
    SentinalDriverProtectionResponse contract = make_contract_response(
        888,
        SENTINAL_DECISION_DENY,
        SENTINAL_STATUS_ACCESS_DENIED
    );

    DriverProtectionResponse resp;
    SentinalStatus status = DriverContractAdapter::fromContract(contract, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(resp.isValid());
    assert(resp.requestId() == 888);
    assert(resp.decision() == SENTINAL_DECISION_DENY);
    assert(resp.status() == DriverProtectionResponseStatus::REJECTED);
}

static void test_invalid_response_rejected() {
    // Decision 99 is invalid
    SentinalDriverProtectionResponse badContract = make_contract_response(
        999,
        99,
        SENTINAL_STATUS_SUCCESS
    );

    DriverProtectionResponse resp;
    SentinalStatus status = DriverContractAdapter::fromContract(badContract, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

static void test_output_unchanged_on_invalid_response() {
    SentinalDriverProtectionResponse badContract = make_contract_response(
        999,
        99,
        SENTINAL_STATUS_SUCCESS
    );

    DriverProtectionResponse resp(123, SENTINAL_DECISION_ALLOW, DriverProtectionResponseStatus::SUCCESS);
    SentinalStatus status = DriverContractAdapter::fromContract(badContract, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);

    // Unchanged
    assert(resp.requestId() == 123);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_valid_request_to_unicode_contract() {
    PathIdentity path("C:/Protected/document.docx");
    ProtectionEvaluationContext ctx(ProtectionRequestSource::USER_MODE);
    DriverProtectionRequest req(500, path, SENTINAL_OP_WRITE, ctx);

    SentinalDriverUnicodeProtectionRequest contract;
    std::memset(&contract, 0xFF, sizeof(contract));

    SentinalStatus status = DriverContractAdapter::toUnicodeContract(req, contract);
    assert(status == SENTINAL_STATUS_SUCCESS);

    // Header checks
    assert(contract.header.size == sizeof(SentinalDriverUnicodeProtectionRequest));
    assert(contract.header.majorVersion == SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION);
    assert(contract.header.minorVersion == SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION);
    assert(contract.header.messageType == SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST);
    assert(contract.header.reserved == 0);

    // Payload checks
    assert(contract.requestId == 500);
    assert(contract.operation == static_cast<uint32_t>(SENTINAL_OP_WRITE));
    assert(contract.source == SENTINAL_DRIVER_UNICODE_SOURCE_USER_MODE);
    assert(contract.pathLength == std::strlen("C:/Protected/document.docx"));
    assert(contract.path[0] == static_cast<uint16_t>('C'));
    assert(contract.path[contract.pathLength] == 0x0000u);
    assert(contract.reserved0 == 0);
    assert(contract.reserved == 0);
    assert(contract.reserved1 == 0);
    assert(SentinalDriverUnicodeValidateProtectionRequest(&contract) == SENTINAL_STATUS_SUCCESS);
}

static void test_valid_unicode_response_to_semantic_response() {
    SentinalDriverUnicodeProtectionResponse respContract;
    std::memset(&respContract, 0, sizeof(respContract));
    respContract.header.size = sizeof(respContract);
    respContract.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    respContract.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    respContract.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    respContract.requestId = 777;
    respContract.decision = static_cast<uint32_t>(SENTINAL_DECISION_ALLOW);
    respContract.status = static_cast<uint32_t>(SENTINAL_STATUS_SUCCESS);

    DriverProtectionResponse resp;
    SentinalStatus status = DriverContractAdapter::fromUnicodeContract(respContract, resp);
    assert(status == SENTINAL_STATUS_SUCCESS);
    assert(resp.requestId() == 777);
    assert(resp.decision() == SENTINAL_DECISION_ALLOW);
    assert(resp.status() == DriverProtectionResponseStatus::SUCCESS);
}

static void test_invalid_unicode_response_rejected() {
    SentinalDriverUnicodeProtectionResponse badContract;
    std::memset(&badContract, 0, sizeof(badContract));
    badContract.header.size = sizeof(badContract);
    badContract.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    badContract.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    badContract.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    badContract.requestId = 777;
    badContract.decision = 99; // invalid decision
    badContract.status = static_cast<uint32_t>(SENTINAL_STATUS_SUCCESS);

    DriverProtectionResponse resp;
    SentinalStatus status = DriverContractAdapter::fromUnicodeContract(badContract, resp);
    assert(status == SENTINAL_STATUS_INVALID_PARAMETER);
}

int main() {
    std::cout << "[DriverContractAdapter Tests] Running..." << std::endl;

    test_valid_request_to_contract();
    test_output_unchanged_on_invalid_request();
    test_overlong_path_rejected();
    test_invalid_operation_rejected();
    test_invalid_context_rejected();
    test_valid_response_to_semantic_response();
    test_valid_rejected_response_from_contract();
    test_invalid_response_rejected();
    test_output_unchanged_on_invalid_response();

    test_valid_request_to_unicode_contract();
    test_valid_unicode_response_to_semantic_response();
    test_invalid_unicode_response_rejected();

    std::cout << "[DriverContractAdapter Tests] All tests passed." << std::endl;
    return 0;
}
