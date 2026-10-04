add_library(SentinalShared INTERFACE)

target_include_directories(SentinalShared INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_library(SentinalDriverContract STATIC
    src/driver_contract.c
)

target_include_directories(SentinalDriverContract PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
