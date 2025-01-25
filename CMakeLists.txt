cmake_minimum_required(VERSION 3.25)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_ASM_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_CXX_FLAGS "-s -O3")
set(CMAKE_EXE_LINKER_FLAGS "-static")
set(CMAKE_CXX_STANDARD 23)

project(sample CXX ASM)

add_executable(sample
    ./src/sample/sample.cpp
    ./src/nullgate/syscalls.S
    ./src/nullgate/syscalls.cpp
    ./src/nullgate/hashing.cpp
)
target_include_directories(sample
    PRIVATE ./include/
    PRIVATE /usr/x86_64-w64-mingw32/include/
)

target_link_directories(sample
    PRIVATE /usr/x86_64-w64-mingw32/lib/
)
