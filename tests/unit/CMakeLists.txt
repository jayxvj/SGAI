add_test(
    NAME SentinelService_FoundationRun
    COMMAND SentinelService
)

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

add_test(
    NAME SentinalShared_CPP_Compatibility
    COMMAND SentinalSharedCppCompat
)
