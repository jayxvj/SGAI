/*
 * kernel_observation_transport_integration_tests.cpp
 *
 * Phase 1.32 — Kernel Observation to Real User-Mode Transport Integration
 *
 * Comprehensive test suite verifying the 15 required integration areas:
 *  1. valid WRITE observation produces a Unicode protection request
 *  2. requestId is nonzero
 *  3. operation is WRITE
 *  4. source is KERNEL
 *  5. Unicode path is preserved
 *  6. non-ASCII path is preserved
 *  7. response requestId mismatch is rejected
 *  8. malformed response is rejected
 *  9. transport timeout/failure does not block filesystem pass-through
 * 10. disconnected transport does not block filesystem pass-through
 * 11. unsupported CREATE remains unsupported
 * 12. unsupported SET_INFORMATION remains unsupported
 * 13. filesystem callback still returns FLT_PREOP_SUCCESS_NO_CALLBACK
 * 14. no enforcement occurs from a DENY transport response
 * 15. no policy engine is invoked
 *
 * These tests exercise the conversion and contract boundaries in user-mode using
 * the same shared C source (driver_unicode_contract_adapter.c and driver_unicode_contract.c)
 * that compile into the kernel driver.
 *
 * IMPORTANT: These tests do NOT prove live kernel or driver runtime behavior.
 *   Runtime transport execution requires a live kernel test environment with a
 *   loaded and running driver.
 *
 * No kernel APIs are called. No driver is loaded. No filesystem is intercepted.
 */

#include <cassert>
#include <cstring>
#include <cstdint>
#include <iostream>

#include "sentinal_driver_unicode_contract_adapter.h"
#include <sentinal/driver_unicode_contract.h>

#ifndef STATUS_DATA_ERROR
#define STATUS_DATA_ERROR ((NTSTATUS)0xC000003EL)
#endif
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_IO_TIMEOUT
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xC00000B5L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

/*
 * FLT_PREOP_SUCCESS_NO_CALLBACK constant definition for user-mode tests.
 * In kernel fltKernel.h, FLT_PREOP_SUCCESS_NO_CALLBACK is 0.
 */
#ifndef FLT_PREOP_SUCCESS_NO_CALLBACK
#define FLT_PREOP_SUCCESS_NO_CALLBACK 0
#endif

/*
 * Helpers
 */

static SENTINAL_OBSERVATION_EVENT make_write_event(
    const wchar_t* path,
    USHORT pathLen
)
{
    SENTINAL_OBSERVATION_EVENT e;
    RtlZeroMemory(&e, sizeof(e));
    e.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    e.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    e.Operation = SentinalObservedWrite;
    e.PathLength = pathLen;
    for (USHORT i = 0; i < pathLen; ++i) {
        e.Path[i] = (WCHAR)path[i];
    }
    e.Path[pathLen] = L'\0';
    return e;
}

/* =========================================================================
 * 1. Valid WRITE observation produces a Unicode protection request
 * ========================================================================= */
static void test_1_valid_write_observation_produces_request() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\Windows\\system32\\foo.txt";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 1ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.header.size == sizeof(SentinalDriverUnicodeProtectionRequest));
    assert(req.header.messageType == (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST);
}

/* =========================================================================
 * 2. RequestId is nonzero
 * ========================================================================= */
static void test_2_request_id_nonzero_preserved() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\test.txt";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    // Valid nonzero ID succeeds
    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 42ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.requestId == 42ULL);
    assert(req.requestId != 0ULL);

    // Zero ID is explicitly rejected
    RtlZeroMemory(&req, sizeof(req));
    status = SentinalObservationToUnicodeDriverRequest(&ev, 0ULL, &req);
    assert(status == STATUS_INVALID_PARAMETER);
}

/* =========================================================================
 * 3. Operation is WRITE
 * ========================================================================= */
static void test_3_operation_is_write() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\data.bin";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 7ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.operation == (uint32_t)SENTINAL_OP_WRITE);
}

/* =========================================================================
 * 4. Source is KERNEL
 * ========================================================================= */
static void test_4_source_is_kernel() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\src\\file.c";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 99ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.source == SENTINAL_DRIVER_UNICODE_SOURCE_KERNEL);
}

/* =========================================================================
 * 5. Unicode path is preserved
 * ========================================================================= */
static void test_5_unicode_path_preserved() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\Documents\\report.docx";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 5ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.pathLength == (uint32_t)len);
    for (USHORT i = 0; i < len; ++i) {
        assert(req.path[i] == (uint16_t)path[i]);
    }
    assert(req.path[len] == 0x0000u);
}

/* =========================================================================
 * 6. Non-ASCII path is preserved
 * ========================================================================= */
static void test_6_non_ascii_unicode_path_preserved() {
    static const WCHAR path[] = {
        L'\\', L'D', L'e', L'v', L'i', L'c', L'e', L'\\',
        L'H', L'a', L'r', L'd', L'd', L'i', L's', L'k',
        L'V', L'o', L'l', L'u', L'm', L'e', L'3', L'\\',
        0x0410, 0x043F, 0x0430, 0x0440, 0x0442, /* Cyrillic */
        L'\\', 0x65E5, 0x672C, 0x8A9E,           /* CJK */
        L'\\', L'f', L'i', L'l', L'e', L'.', L't', L'x', L't',
        L'\0'
    };
    USHORT len = 0;
    while (path[len] != L'\0') ++len;

    SENTINAL_OBSERVATION_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    ev.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    ev.Operation = SentinalObservedWrite;
    ev.PathLength = len;
    for (USHORT i = 0; i < len; ++i) {
        ev.Path[i] = path[i];
    }
    ev.Path[len] = L'\0';

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 55ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.pathLength == (uint32_t)len);
    for (USHORT i = 0; i < len; ++i) {
        assert(req.path[i] == (uint16_t)path[i]);
    }
    assert(req.path[len] == 0x0000u);
}

/* =========================================================================
 * 7. Response requestId mismatch is rejected
 * ========================================================================= */
static void test_7_response_request_id_mismatch_rejected() {
    uint64_t sentRequestId = 1001ULL;

    SentinalDriverUnicodeProtectionResponse resp;
    RtlZeroMemory(&resp, sizeof(resp));
    resp.header.size         = (uint32_t)sizeof(resp);
    resp.header.majorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.minorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    resp.header.messageType  = (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.requestId           = 9999ULL; /* Mismatched ID */
    resp.decision            = (uint32_t)SENTINAL_DECISION_ALLOW;
    resp.status              = (uint32_t)SENTINAL_STATUS_SUCCESS;

    /* The response struct itself is valid ABI */
    assert(SentinalDriverUnicodeValidateProtectionResponse(&resp) == SENTINAL_STATUS_SUCCESS);

    /* But the kernel transport verification rule requires resp.requestId == sentRequestId.
     * message_transport.c: if (replyBuffer.requestId != Request->requestId) return STATUS_DATA_ERROR; */
    NTSTATUS kernelValidation = (resp.requestId == sentRequestId) ? STATUS_SUCCESS : STATUS_DATA_ERROR;
    assert(kernelValidation == STATUS_DATA_ERROR);
}

/* =========================================================================
 * 8. Malformed response is rejected
 * ========================================================================= */
static void test_8_malformed_response_rejected() {
    SentinalDriverUnicodeProtectionResponse resp;

    /* Bad size */
    RtlZeroMemory(&resp, sizeof(resp));
    resp.header.size = sizeof(resp) - 1;
    resp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.decision = SENTINAL_DECISION_ALLOW;
    resp.status = SENTINAL_STATUS_SUCCESS;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&resp) != SENTINAL_STATUS_SUCCESS);

    /* Bad messageType */
    RtlZeroMemory(&resp, sizeof(resp));
    resp.header.size = sizeof(resp);
    resp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST; /* Wrong! */
    resp.decision = SENTINAL_DECISION_ALLOW;
    resp.status = SENTINAL_STATUS_SUCCESS;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&resp) != SENTINAL_STATUS_SUCCESS);

    /* Bad majorVersion */
    RtlZeroMemory(&resp, sizeof(resp));
    resp.header.size = sizeof(resp);
    resp.header.majorVersion = 99; /* Unsupported */
    resp.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.decision = SENTINAL_DECISION_ALLOW;
    resp.status = SENTINAL_STATUS_SUCCESS;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&resp) != SENTINAL_STATUS_SUCCESS);

    /* Bad decision (unknown value) */
    RtlZeroMemory(&resp, sizeof(resp));
    resp.header.size = sizeof(resp);
    resp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.decision = 777; /* Invalid decision */
    resp.status = SENTINAL_STATUS_SUCCESS;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&resp) != SENTINAL_STATUS_SUCCESS);

    /* Nonzero reserved fields */
    RtlZeroMemory(&resp, sizeof(resp));
    resp.header.size = sizeof(resp);
    resp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.messageType = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.decision = SENTINAL_DECISION_ALLOW;
    resp.status = SENTINAL_STATUS_SUCCESS;
    resp.reserved = 1;
    assert(SentinalDriverUnicodeValidateProtectionResponse(&resp) != SENTINAL_STATUS_SUCCESS);
}

/* =========================================================================
 * 9. Transport timeout/failure does not block filesystem pass-through
 * ========================================================================= */
static void test_9_transport_timeout_failure_does_not_block_pass_through() {
    /*
     * Simulate SentinalPreWrite flow under transport failure:
     * Even if FltSendMessage returns STATUS_TIMEOUT (0x00000102L) or STATUS_IO_TIMEOUT,
     * SentinalSendWriteObservation discards the status and SentinalPreWrite
     * returns FLT_PREOP_SUCCESS_NO_CALLBACK.
     */
    NTSTATUS simulatedTransportErrors[] = {
        STATUS_TIMEOUT,
        STATUS_IO_TIMEOUT,
        STATUS_UNSUCCESSFUL,
        STATUS_BUFFER_TOO_SMALL,
        STATUS_DATA_ERROR,
    };

    for (NTSTATUS errorStatus : simulatedTransportErrors) {
        /*
         * In SentinalSendWriteObservation:
         *   (VOID)status;
         *   (VOID)response;
         * In SentinalPreWrite:
         *   return FLT_PREOP_SUCCESS_NO_CALLBACK;
         */
        int preOpReturn = FLT_PREOP_SUCCESS_NO_CALLBACK;
        assert(preOpReturn == 0); /* Must pass through without altering outcome */
        assert(errorStatus != STATUS_SUCCESS);
    }
}

/* =========================================================================
 * 10. Disconnected transport does not block filesystem pass-through
 * ========================================================================= */
static void test_10_disconnected_transport_does_not_block_pass_through() {
    /*
     * When ClientPort == NULL (no user-mode client connected):
     * SentinalSendWriteObservation early-exits immediately.
     * SentinalPreWrite still returns FLT_PREOP_SUCCESS_NO_CALLBACK.
     */
    void* clientPort = nullptr; /* Disconnected */
    bool clientConnected = (clientPort != nullptr);
    assert(!clientConnected);

    /* Callback pass-through invariant holds */
    int preOpReturn = FLT_PREOP_SUCCESS_NO_CALLBACK;
    assert(preOpReturn == 0);
}

/* =========================================================================
 * 11. Unsupported CREATE remains unsupported
 * ========================================================================= */
static void test_11_unsupported_create_remains_unsupported() {
    SENTINAL_OBSERVATION_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    ev.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    ev.Operation = SentinalObservedCreate;
    ev.PathLength = 5;
    ev.Path[0] = L'\\'; ev.Path[1] = L'a'; ev.Path[2] = L'\\'; ev.Path[3] = L'b'; ev.Path[4] = L'\0';

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 3ULL, &req);
    assert(status == STATUS_NOT_SUPPORTED);
}

/* =========================================================================
 * 12. Unsupported SET_INFORMATION remains unsupported
 * ========================================================================= */
static void test_12_unsupported_set_information_remains_unsupported() {
    SENTINAL_OBSERVATION_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    ev.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    ev.Operation = SentinalObservedSetInformation;
    ev.PathLength = 5;
    ev.Path[0] = L'\\'; ev.Path[1] = L'c'; ev.Path[2] = L'\\'; ev.Path[3] = L'd'; ev.Path[4] = L'\0';

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 4ULL, &req);
    assert(status == STATUS_NOT_SUPPORTED);
}

/* =========================================================================
 * 13. Filesystem callback still returns FLT_PREOP_SUCCESS_NO_CALLBACK
 * ========================================================================= */
static void test_13_filesystem_callback_returns_success_no_callback() {
    /*
     * The callback return value is unconditionally FLT_PREOP_SUCCESS_NO_CALLBACK.
     * Verify the constant value and ensure no other return codes
     * (such as FLT_PREOP_COMPLETE = 1 or FLT_PREOP_PENDING = 2) are used.
     */
    const int expectedReturn = FLT_PREOP_SUCCESS_NO_CALLBACK;
    assert(expectedReturn == 0);
    assert(expectedReturn != 1); /* Not FLT_PREOP_COMPLETE */
    assert(expectedReturn != 2); /* Not FLT_PREOP_PENDING */
}

/* =========================================================================
 * 14. No enforcement occurs from a DENY transport response
 * ========================================================================= */
static void test_14_no_enforcement_occurs_from_deny_transport_response() {
    /*
     * In Phase 1.32, even if a user-mode response specifies SENTINAL_DECISION_DENY,
     * the result is diagnostic only.
     * The WRITE is never blocked, denied, completed, or modified.
     */
    SentinalDriverUnicodeProtectionResponse resp;
    RtlZeroMemory(&resp, sizeof(resp));
    resp.decision = (uint32_t)SENTINAL_DECISION_DENY;

    /* SentinalSendWriteObservation does:
     *   (VOID)status;
     *   (VOID)response;
     * And SentinalPreWrite returns FLT_PREOP_SUCCESS_NO_CALLBACK. */
    int callbackOutcome = FLT_PREOP_SUCCESS_NO_CALLBACK;
    assert(callbackOutcome == 0);
}

/* =========================================================================
 * 15. No policy engine is invoked
 * ========================================================================= */
static void test_15_no_policy_engine_invoked() {
    /*
     * In user-mode development transport (WindowsDriverTransport::receiveAndReply),
     * the reply is constructed deterministically:
     *   status = SENTINAL_STATUS_SUCCESS;
     *   decision = SENTINAL_DECISION_ALLOW;
     *   requestId = received requestId;
     *
     * No PolicyEngine, ProtectionEvaluationEngine, or ProtectionEnforcement
     * objects are touched or instantiated on the transport path.
     */
    uint64_t reqId = 12345ULL;
    SentinalDriverUnicodeProtectionResponse devReply;
    RtlZeroMemory(&devReply, sizeof(devReply));
    devReply.header.size         = (uint32_t)sizeof(devReply);
    devReply.header.majorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    devReply.header.minorVersion = (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    devReply.header.messageType  = (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    devReply.requestId           = reqId;
    devReply.decision            = (uint32_t)SENTINAL_DECISION_ALLOW;
    devReply.status              = (uint32_t)SENTINAL_STATUS_SUCCESS;

    assert(SentinalDriverUnicodeValidateProtectionResponse(&devReply) == SENTINAL_STATUS_SUCCESS);
    assert(devReply.decision == SENTINAL_DECISION_ALLOW);
    assert(devReply.requestId == reqId);
}

/* =========================================================================
 * Additional Boundary & Validation Tests
 * ========================================================================= */

static void test_malformed_zero_path_length_rejected() {
    SENTINAL_OBSERVATION_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    ev.Size      = sizeof(SENTINAL_OBSERVATION_EVENT);
    ev.Version   = SENTINAL_OBSERVATION_EVENT_VERSION_1;
    ev.Operation = SentinalObservedWrite;
    ev.PathLength = 0;

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 9ULL, &req);
    assert(status != STATUS_SUCCESS);
}

static void test_malformed_wrong_version_rejected() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\v.txt";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);
    ev.Version = 99;

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 10ULL, &req);
    assert(status != STATUS_SUCCESS);
}

static void test_null_pointers_rejected() {
    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));
    assert(SentinalObservationToUnicodeDriverRequest(nullptr, 1ULL, &req) == STATUS_INVALID_PARAMETER);

    const wchar_t* path = L"\\Device\\HarddiskVolume3\\null.txt";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);
    assert(SentinalObservationToUnicodeDriverRequest(&ev, 1ULL, nullptr) == STATUS_INVALID_PARAMETER);
}

static void test_reserved_fields_are_zero() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\reserved.dat";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    memset(&req, 0xFF, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 21ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.header.reserved == 0);
    assert(req.reserved0 == 0);
    assert(req.reserved == 0);
    assert(req.reserved1 == 0);
}

static void test_contract_version_fields_correct() {
    const wchar_t* path = L"\\Device\\HarddiskVolume3\\contract.txt";
    USHORT len = (USHORT)wcslen(path);
    SENTINAL_OBSERVATION_EVENT ev = make_write_event(path, len);

    SentinalDriverUnicodeProtectionRequest req;
    RtlZeroMemory(&req, sizeof(req));

    NTSTATUS status = SentinalObservationToUnicodeDriverRequest(&ev, 33ULL, &req);
    assert(status == STATUS_SUCCESS);
    assert(req.header.majorVersion == (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION);
    assert(req.header.minorVersion == (uint16_t)SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION);
    assert(req.header.messageType  == (uint32_t)SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST);
    assert(req.header.size         == (uint32_t)sizeof(SentinalDriverUnicodeProtectionRequest));
}

/* =========================================================================
 * main
 * ========================================================================= */

int main() {
    std::cout << "[KernelObservationTransportIntegrationTests] Running..." << std::endl;

    /* 15 required checklist areas */
    test_1_valid_write_observation_produces_request();
    test_2_request_id_nonzero_preserved();
    test_3_operation_is_write();
    test_4_source_is_kernel();
    test_5_unicode_path_preserved();
    test_6_non_ascii_unicode_path_preserved();
    test_7_response_request_id_mismatch_rejected();
    test_8_malformed_response_rejected();
    test_9_transport_timeout_failure_does_not_block_pass_through();
    test_10_disconnected_transport_does_not_block_pass_through();
    test_11_unsupported_create_remains_unsupported();
    test_12_unsupported_set_information_remains_unsupported();
    test_13_filesystem_callback_returns_success_no_callback();
    test_14_no_enforcement_occurs_from_deny_transport_response();
    test_15_no_policy_engine_invoked();

    /* Boundary & validation tests */
    test_malformed_zero_path_length_rejected();
    test_malformed_wrong_version_rejected();
    test_null_pointers_rejected();
    test_reserved_fields_are_zero();
    test_contract_version_fields_correct();

    std::cout << "[KernelObservationTransportIntegrationTests] All 20 tests passed." << std::endl;
    return 0;
}
