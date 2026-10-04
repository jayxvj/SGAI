add_library(SentinelServiceCore STATIC
    src/config.cpp
    src/logger.cpp
    src/path_identity.cpp
    src/policy_engine.cpp
    src/protection_decision.cpp
    src/protection_evaluation_context.cpp
    src/protection_evaluation_engine.cpp
    src/protection_enforcement.cpp
    src/protection_event_processor.cpp
    src/protection_execution_engine.cpp
    src/protection_operation.cpp
    src/protection_operation_adapter.cpp
    src/protection_request.cpp
    src/service_core.cpp
    src/target.cpp
    src/windows_file_operation_observation.cpp
    src/windows_file_operation_observer.cpp
    src/windows_operation_adapter.cpp
    src/windows_path_adapter.cpp
    src/windows_protection_event.cpp
    src/windows_protection_event_adapter.cpp
)

target_include_directories(SentinelServiceCore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(SentinelServiceCore PUBLIC
    SentinalShared
)

add_executable(SentinelService
    src/main.cpp
)

target_link_libraries(SentinelService PRIVATE
    SentinelServiceCore
)
