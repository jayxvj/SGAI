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
