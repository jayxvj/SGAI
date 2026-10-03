add_executable(SentinelService
    src/main.cpp
)

target_link_libraries(SentinelService PRIVATE
    SentinalShared
)
