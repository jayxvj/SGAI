add_executable(SentinelServiceLifecycleIntegrationTests
    service_lifecycle_integration_tests.cpp
)

target_link_libraries(SentinelServiceLifecycleIntegrationTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME SentinelService_LifecycleIntegrationTests
    COMMAND SentinelServiceLifecycleIntegrationTests
)
set_tests_properties(SentinelService_LifecycleIntegrationTests PROPERTIES LABELS "integration")
