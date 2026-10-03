add_library(SentinelServiceCore STATIC
    src/config.cpp
    src/logger.cpp
    src/policy_engine.cpp
    src/service_core.cpp
    src/target.cpp
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
