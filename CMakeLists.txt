cmake_minimum_required(VERSION 3.25)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-s -O3")
set(CMAKE_EXE_LINKER_FLAGS "-static")

if (CROSSCOMPILE)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
    set(CMAKE_ASM_COMPILER x86_64-w64-mingw32-g++)
endif()

project(sample CXX ASM)

add_executable(sample
    ./src/sample/sample.cpp
    ./src/nullgate/syscalls.S
    ./src/nullgate/syscalls.cpp
    ./src/nullgate/obfuscation.cpp
)

target_include_directories(sample
    PRIVATE ./include/
)

add_subdirectory(
    ./src/hasher/
)

