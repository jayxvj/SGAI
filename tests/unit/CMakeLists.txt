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
