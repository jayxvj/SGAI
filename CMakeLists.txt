cmake_minimum_required(VERSION 3.20)

project(SentinalAI LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable CTest functionality
enable_testing()

# User-mode native components
add_subdirectory(shared)
add_subdirectory(service)

# Native tests
add_subdirectory(tests)
