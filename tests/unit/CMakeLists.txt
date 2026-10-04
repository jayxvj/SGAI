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
