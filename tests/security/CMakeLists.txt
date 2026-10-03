add_executable(SentinelPolicyBypassTests
    policy_bypass_tests.cpp
)

target_link_libraries(SentinelPolicyBypassTests PRIVATE
    SentinelServiceCore
)

add_test(
    NAME SentinelPolicy_BypassTests
    COMMAND SentinelPolicyBypassTests
)
set_tests_properties(SentinelPolicy_BypassTests PROPERTIES LABELS "security")
