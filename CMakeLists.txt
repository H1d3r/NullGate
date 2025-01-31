cmake_minimum_required(VERSION 3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-s -O3")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")
if (NULLGATE_CROSSCOMPILE)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
    set(CMAKE_ASM_COMPILER x86_64-w64-mingw32-g++)
endif()

project(nullgate CXX ASM)
project(sample)

# Nullgate
add_library(nullgate
    ./src/nullgate/syscalls.S
    ./src/nullgate/syscalls.cpp
    ./src/nullgate/obfuscation.cpp
)

target_include_directories(nullgate
    PRIVATE ./include/
)

# Sample
add_executable(sample
    ./src/sample/sample.cpp
)

target_include_directories(sample
    PRIVATE ./include/
)

target_link_libraries(sample
    PRIVATE nullgate
)

# Hasher
add_subdirectory(
    ./src/hasher/
)

