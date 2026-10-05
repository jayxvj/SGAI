add_library(SentinelServiceCore STATIC
    src/config.cpp
    src/driver_communication_service.cpp
    src/driver_contract_adapter.cpp
    src/driver_protection_request.cpp
    src/driver_protection_response.cpp
    src/logger.cpp
    src/path_identity.cpp
    src/policy_engine.cpp
    src/protection_audit_event.cpp
    src/protection_decision.cpp
    src/protection_evaluation_context.cpp
    src/protection_evaluation_engine.cpp
    src/protection_enforcement.cpp
    src/protection_event_processor.cpp
    src/protection_execution_engine.cpp
    src/protection_execution_result.cpp
    src/protection_operation.cpp
    src/protection_operation_adapter.cpp
    src/protection_request.cpp
    src/protection_service_facade.cpp
    src/service_core.cpp
    src/target.cpp
    src/test_driver_communication.cpp
    src/test_windows_driver_transport.cpp
    src/windows_driver_communication.cpp
    src/windows_driver_transport.cpp
    src/windows_file_operation_observation.cpp
    src/windows_file_operation_observer.cpp
    src/windows_operation_adapter.cpp
    src/windows_path_adapter.cpp
    src/windows_protection_enforcement_adapter.cpp
    src/windows_protection_enforcement_result.cpp
    src/windows_protection_event.cpp
    src/windows_protection_event_adapter.cpp
)

target_include_directories(SentinelServiceCore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(SentinelServiceCore PUBLIC
    SentinalShared
    SentinalDriverContract
    SentinalDriverUnicodeContract
)

if (WIN32)
    target_link_libraries(SentinelServiceCore PUBLIC fltlib)
endif()

add_executable(SentinelService
    src/main.cpp
)

target_link_libraries(SentinelService PRIVATE
    SentinelServiceCore
)
