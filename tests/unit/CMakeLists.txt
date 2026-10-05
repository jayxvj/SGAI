add_test(
    NAME SentinelService_FoundationRun
    COMMAND SentinelService
)
set_tests_properties(SentinelService_FoundationRun PROPERTIES LABELS "unit")

add_executable(SentinalSharedCCompat
    shared_c_compat.c
)
target_link_libraries(SentinalSharedCCompat PRIVATE
    SentinalShared
)

add_executable(SentinalSharedCppCompat
    shared_cpp_compat.cpp
)
target_link_libraries(SentinalSharedCppCompat PRIVATE
    SentinalShared
)

add_test(
    NAME SentinalShared_C_Compatibility
    COMMAND SentinalSharedCCompat
)
set_tests_properties(SentinalShared_C_Compatibility PROPERTIES LABELS "unit")

add_test(
    NAME SentinalShared_CPP_Compatibility
    COMMAND SentinalSharedCppCompat
)
set_tests_properties(SentinalShared_CPP_Compatibility PROPERTIES LABELS "unit")

add_executable(SentinelServiceCoreTests
    service_core_tests.cpp
)
target_link_libraries(SentinelServiceCoreTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME SentinelService_CoreTests
    COMMAND SentinelServiceCoreTests
)
set_tests_properties(SentinelService_CoreTests PROPERTIES LABELS "unit")

add_executable(SentinalTargetModelTests
    target_model_tests.cpp
)
target_link_libraries(SentinalTargetModelTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_TargetModelTests
    COMMAND SentinalTargetModelTests
)
set_tests_properties(Sentinal_TargetModelTests PROPERTIES LABELS "unit")

add_executable(SentinalPathIdentityTests
    path_identity_tests.cpp
)
target_link_libraries(SentinalPathIdentityTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_PathIdentityTests
    COMMAND SentinalPathIdentityTests
)
set_tests_properties(Sentinal_PathIdentityTests PROPERTIES LABELS "unit")

add_executable(SentinalEvaluationSemanticsTests
    evaluation_semantics_tests.cpp
)
target_link_libraries(SentinalEvaluationSemanticsTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_EvaluationSemanticsTests
    COMMAND SentinalEvaluationSemanticsTests
)
set_tests_properties(Sentinal_EvaluationSemanticsTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionRequestTests
    protection_request_tests.cpp
)
target_link_libraries(SentinalProtectionRequestTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionRequestTests
    COMMAND SentinalProtectionRequestTests
)
set_tests_properties(Sentinal_ProtectionRequestTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionDecisionTests
    protection_decision_tests.cpp
)
target_link_libraries(SentinalProtectionDecisionTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionDecisionTests
    COMMAND SentinalProtectionDecisionTests
)
set_tests_properties(Sentinal_ProtectionDecisionTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionEvaluationContextTests
    protection_evaluation_context_tests.cpp
)
target_link_libraries(SentinalProtectionEvaluationContextTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionEvaluationContextTests
    COMMAND SentinalProtectionEvaluationContextTests
)
set_tests_properties(Sentinal_ProtectionEvaluationContextTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionEvaluationEngineTests
    protection_evaluation_engine_tests.cpp
)
target_link_libraries(SentinalProtectionEvaluationEngineTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionEvaluationEngineTests
    COMMAND SentinalProtectionEvaluationEngineTests
)
set_tests_properties(Sentinal_ProtectionEvaluationEngineTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionEnforcementTests
    protection_enforcement_tests.cpp
)
target_link_libraries(SentinalProtectionEnforcementTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionEnforcementTests
    COMMAND SentinalProtectionEnforcementTests
)
set_tests_properties(Sentinal_ProtectionEnforcementTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionOperationTests
    protection_operation_tests.cpp
)
target_link_libraries(SentinalProtectionOperationTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionOperationTests
    COMMAND SentinalProtectionOperationTests
)
set_tests_properties(Sentinal_ProtectionOperationTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionOperationAdapterTests
    protection_operation_adapter_tests.cpp
)
target_link_libraries(SentinalProtectionOperationAdapterTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionOperationAdapterTests
    COMMAND SentinalProtectionOperationAdapterTests
)
set_tests_properties(Sentinal_ProtectionOperationAdapterTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsPathAdapterTests
    windows_path_adapter_tests.cpp
)
target_link_libraries(SentinalWindowsPathAdapterTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsPathAdapterTests
    COMMAND SentinalWindowsPathAdapterTests
)
set_tests_properties(Sentinal_WindowsPathAdapterTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsOperationAdapterTests
    windows_operation_adapter_tests.cpp
)
target_link_libraries(SentinalWindowsOperationAdapterTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsOperationAdapterTests
    COMMAND SentinalWindowsOperationAdapterTests
)
set_tests_properties(Sentinal_WindowsOperationAdapterTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsProtectionEventTests
    windows_protection_event_tests.cpp
)
target_link_libraries(SentinalWindowsProtectionEventTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsProtectionEventTests
    COMMAND SentinalWindowsProtectionEventTests
)
set_tests_properties(Sentinal_WindowsProtectionEventTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionExecutionEngineTests
    protection_execution_engine_tests.cpp
)
target_link_libraries(SentinalProtectionExecutionEngineTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionExecutionEngineTests
    COMMAND SentinalProtectionExecutionEngineTests
)
set_tests_properties(Sentinal_ProtectionExecutionEngineTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionEventProcessorTests
    protection_event_processor_tests.cpp
)
target_link_libraries(SentinalProtectionEventProcessorTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionEventProcessorTests
    COMMAND SentinalProtectionEventProcessorTests
)
set_tests_properties(Sentinal_ProtectionEventProcessorTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsFileOperationObserverTests
    windows_file_operation_observer_tests.cpp
)
target_link_libraries(SentinalWindowsFileOperationObserverTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsFileOperationObserverTests
    COMMAND SentinalWindowsFileOperationObserverTests
)
set_tests_properties(Sentinal_WindowsFileOperationObserverTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionExecutionResultTests
    protection_execution_result_tests.cpp
)
target_link_libraries(SentinalProtectionExecutionResultTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionExecutionResultTests
    COMMAND SentinalProtectionExecutionResultTests
)
set_tests_properties(Sentinal_ProtectionExecutionResultTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionAuditEventTests
    protection_audit_event_tests.cpp
)
target_link_libraries(SentinalProtectionAuditEventTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionAuditEventTests
    COMMAND SentinalProtectionAuditEventTests
)
set_tests_properties(Sentinal_ProtectionAuditEventTests PROPERTIES LABELS "unit")

add_executable(SentinalProtectionServiceFacadeTests
    protection_service_facade_tests.cpp
)
target_link_libraries(SentinalProtectionServiceFacadeTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_ProtectionServiceFacadeTests
    COMMAND SentinalProtectionServiceFacadeTests
)
set_tests_properties(Sentinal_ProtectionServiceFacadeTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsProtectionEnforcementAdapterTests
    windows_protection_enforcement_adapter_tests.cpp
)
target_link_libraries(SentinalWindowsProtectionEnforcementAdapterTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsProtectionEnforcementAdapterTests
    COMMAND SentinalWindowsProtectionEnforcementAdapterTests
)
set_tests_properties(Sentinal_WindowsProtectionEnforcementAdapterTests PROPERTIES LABELS "unit")

add_executable(SentinalDriverContractCCompat
    driver_contract_c_compatibility.c
)
target_link_libraries(SentinalDriverContractCCompat PRIVATE
    SentinalDriverContract
)

add_test(
    NAME Sentinal_DriverContract_C_Compatibility
    COMMAND SentinalDriverContractCCompat
)
set_tests_properties(Sentinal_DriverContract_C_Compatibility PROPERTIES LABELS "unit")

add_executable(SentinalDriverContractCppCompat
    driver_contract_cpp_compatibility.cpp
)
target_link_libraries(SentinalDriverContractCppCompat PRIVATE
    SentinalDriverContract
)

add_test(
    NAME Sentinal_DriverContract_CPP_Compatibility
    COMMAND SentinalDriverContractCppCompat
)
set_tests_properties(Sentinal_DriverContract_CPP_Compatibility PROPERTIES LABELS "unit")

add_executable(SentinalDriverContractTests
    driver_contract_tests.cpp
)
target_link_libraries(SentinalDriverContractTests PRIVATE
    SentinalDriverContract
)

add_test(
    NAME Sentinal_DriverContractTests
    COMMAND SentinalDriverContractTests
)
set_tests_properties(Sentinal_DriverContractTests PROPERTIES LABELS "unit")

add_executable(SentinalDriverProtectionRequestTests
    driver_protection_request_tests.cpp
)
target_link_libraries(SentinalDriverProtectionRequestTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_DriverProtectionRequestTests
    COMMAND SentinalDriverProtectionRequestTests
)
set_tests_properties(Sentinal_DriverProtectionRequestTests PROPERTIES LABELS "unit")

add_executable(SentinalDriverProtectionResponseTests
    driver_protection_response_tests.cpp
)
target_link_libraries(SentinalDriverProtectionResponseTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_DriverProtectionResponseTests
    COMMAND SentinalDriverProtectionResponseTests
)
set_tests_properties(Sentinal_DriverProtectionResponseTests PROPERTIES LABELS "unit")

add_executable(SentinalDriverContractAdapterTests
    driver_contract_adapter_tests.cpp
)
target_link_libraries(SentinalDriverContractAdapterTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_DriverContractAdapterTests
    COMMAND SentinalDriverContractAdapterTests
)
set_tests_properties(Sentinal_DriverContractAdapterTests PROPERTIES LABELS "unit")

add_executable(SentinalDriverCommunicationServiceTests
    driver_communication_service_tests.cpp
)
target_link_libraries(SentinalDriverCommunicationServiceTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_DriverCommunicationServiceTests
    COMMAND SentinalDriverCommunicationServiceTests
)
set_tests_properties(Sentinal_DriverCommunicationServiceTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsDriverTransportTests
    windows_driver_transport_tests.cpp
)
target_link_libraries(SentinalWindowsDriverTransportTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsDriverTransportTests
    COMMAND SentinalWindowsDriverTransportTests
)
set_tests_properties(Sentinal_WindowsDriverTransportTests PROPERTIES LABELS "unit")

add_executable(SentinalWindowsDriverCommunicationTests
    windows_driver_communication_tests.cpp
)
target_link_libraries(SentinalWindowsDriverCommunicationTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME Sentinal_WindowsDriverCommunicationTests
    COMMAND SentinalWindowsDriverCommunicationTests
)
set_tests_properties(Sentinal_WindowsDriverCommunicationTests PROPERTIES LABELS "unit")

add_executable(SentinalDriverUnicodeContractCCompat
    driver_unicode_contract_c_compatibility.c
)
target_link_libraries(SentinalDriverUnicodeContractCCompat PRIVATE
    SentinalDriverUnicodeContract
)

add_test(
    NAME Sentinal_DriverUnicodeContract_C_Compatibility
    COMMAND SentinalDriverUnicodeContractCCompat
)
set_tests_properties(Sentinal_DriverUnicodeContract_C_Compatibility PROPERTIES LABELS "unit")

add_executable(SentinalDriverUnicodeContractCppCompat
    driver_unicode_contract_cpp_compatibility.cpp
)
target_link_libraries(SentinalDriverUnicodeContractCppCompat PRIVATE
    SentinalDriverUnicodeContract
)

add_test(
    NAME Sentinal_DriverUnicodeContract_CPP_Compatibility
    COMMAND SentinalDriverUnicodeContractCppCompat
)
set_tests_properties(Sentinal_DriverUnicodeContract_CPP_Compatibility PROPERTIES LABELS "unit")

add_executable(SentinalDriverUnicodeContractTests
    driver_unicode_contract_tests.cpp
    ${CMAKE_SOURCE_DIR}/driver/src/driver_unicode_contract_adapter.c
)
target_include_directories(SentinalDriverUnicodeContractTests PRIVATE
    ${CMAKE_SOURCE_DIR}/driver/include
)
target_link_libraries(SentinalDriverUnicodeContractTests PRIVATE
    SentinalDriverUnicodeContract
)

add_test(
    NAME Sentinal_DriverUnicodeContractTests
    COMMAND SentinalDriverUnicodeContractTests
)
set_tests_properties(Sentinal_DriverUnicodeContractTests PROPERTIES LABELS "unit")

# ---------------------------------------------------------------------------
# Phase 1.32 — Kernel Observation to Transport Integration tests
#
# Tests the conversion boundary:
#   SENTINAL_OBSERVATION_EVENT -> SentinalObservationToUnicodeDriverRequest
#
# Uses the user-mode shim definitions in sentinal_driver_unicode_contract_adapter.h
# to compile the shared kernel adapter source in user-mode test context.
# No kernel is loaded. No driver is installed.
# ---------------------------------------------------------------------------
add_executable(SentinalKernelObservationTransportTests
    kernel_observation_transport_integration_tests.cpp
    ${CMAKE_SOURCE_DIR}/driver/src/driver_unicode_contract_adapter.c
)
target_include_directories(SentinalKernelObservationTransportTests PRIVATE
    ${CMAKE_SOURCE_DIR}/driver/include
)
target_link_libraries(SentinalKernelObservationTransportTests PRIVATE
    SentinalDriverUnicodeContract
)

add_test(
    NAME Sentinal_KernelObservationTransportTests
    COMMAND SentinalKernelObservationTransportTests
)
set_tests_properties(Sentinal_KernelObservationTransportTests PROPERTIES LABELS "unit")
